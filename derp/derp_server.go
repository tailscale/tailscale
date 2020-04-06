// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

// TODO(crawshaw): with predefined serverKey in clients and HMAC on packets we could skip TLS

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sync/errgroup"
	"tailscale.com/metrics"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var debug, _ = strconv.ParseBool(os.Getenv("DERP_DEBUG_LOGS"))

const (
	perClientSendQueueDepth = 32 // packets buffered for sending
	writeTimeout            = 2 * time.Second
)

// Server is a DERP server.
type Server struct {
	// WriteTimeout, if non-zero, specifies how long to wait
	// before failing when writing to a client.
	WriteTimeout time.Duration

	privateKey key.Private
	publicKey  key.Public
	logf       logger.Logf
	memSys0    uint64 // runtime.MemStats.Sys at start (or early-ish)

	// Counters:
	packetsSent, bytesSent  expvar.Int
	packetsRecv, bytesRecv  expvar.Int
	packetsDropped          expvar.Int
	packetsDroppedReason    metrics.LabelMap
	packetsDroppedUnknown   *expvar.Int // unknown dst pubkey
	packetsDroppedGone      *expvar.Int // dst conn shutting down
	packetsDroppedQueueHead *expvar.Int // queue full, drop head packet
	packetsDroppedQueueTail *expvar.Int // queue full, drop tail packet
	packetsDroppedWrite     *expvar.Int // error writing to dst conn
	peerGoneFrames          expvar.Int  // number of peer gone frames sent
	accepts                 expvar.Int
	curClients              expvar.Int
	curHomeClients          expvar.Int // ones with preferred
	clientsReplaced         expvar.Int
	unknownFrames           expvar.Int
	homeMovesIn             expvar.Int // established clients announce home server moves in
	homeMovesOut            expvar.Int // established clients announce home server moves out

	mu          sync.Mutex
	closed      bool
	netConns    map[Conn]chan struct{} // chan is closed when conn closes
	clients     map[key.Public]*sclient
	clientsEver map[key.Public]bool // never deleted from, for stats; fine for now
}

// Conn is the subset of the underlying net.Conn the DERP Server needs.
// It is a defined type so that non-net connections can be used.
type Conn interface {
	io.Closer

	// The *Deadline methods follow the semantics of net.Conn.

	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// NewServer returns a new DERP server. It doesn't listen on its own.
// Connections are given to it via Server.Accept.
func NewServer(privateKey key.Private, logf logger.Logf) *Server {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	s := &Server{
		privateKey:           privateKey,
		publicKey:            privateKey.Public(),
		logf:                 logf,
		packetsDroppedReason: metrics.LabelMap{Label: "reason"},
		clients:              make(map[key.Public]*sclient),
		clientsEver:          make(map[key.Public]bool),
		netConns:             make(map[Conn]chan struct{}),
		memSys0:              ms.Sys,
	}
	s.packetsDroppedUnknown = s.packetsDroppedReason.Get("unknown_dest")
	s.packetsDroppedGone = s.packetsDroppedReason.Get("gone")
	s.packetsDroppedQueueHead = s.packetsDroppedReason.Get("queue_head")
	s.packetsDroppedQueueTail = s.packetsDroppedReason.Get("queue_tail")
	s.packetsDroppedWrite = s.packetsDroppedReason.Get("write_error")
	return s
}

// Close closes the server and waits for the connections to disconnect.
func (s *Server) Close() error {
	s.mu.Lock()
	wasClosed := s.closed
	s.closed = true
	s.mu.Unlock()
	if wasClosed {
		return nil
	}

	var closedChs []chan struct{}

	s.mu.Lock()
	for nc, closed := range s.netConns {
		nc.Close()
		closedChs = append(closedChs, closed)
	}
	s.mu.Unlock()

	for _, closed := range closedChs {
		<-closed
	}

	return nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Accept adds a new connection to the server and serves it.
//
// The provided bufio ReadWriter must be already connected to nc.
// Accept blocks until the Server is closed or the connection closes
// on its own.
//
// Accept closes nc.
func (s *Server) Accept(nc Conn, brw *bufio.ReadWriter, remoteAddr string) {
	closed := make(chan struct{})

	s.mu.Lock()
	s.accepts.Add(1)             // while holding s.mu for connNum read on next line
	connNum := s.accepts.Value() // expvar sadly doesn't return new value on Add(1)
	s.netConns[nc] = closed
	s.mu.Unlock()

	defer func() {
		nc.Close()
		close(closed)

		s.mu.Lock()
		delete(s.netConns, nc)
		s.mu.Unlock()
	}()

	if err := s.accept(nc, brw, remoteAddr, connNum); err != nil && !s.isClosed() {
		s.logf("derp: %s: %v", remoteAddr, err)
	}
}

// registerClient notes that client c is now authenticated and ready for packets.
// If c's public key was already connected with a different connection, the prior one is closed.
func (s *Server) registerClient(c *sclient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.clients[c.key]
	if old == nil {
		c.logf("adding connection")
	} else {
		s.clientsReplaced.Add(1)
		c.logf("adding connection, replacing %s", old.remoteAddr)
		go old.nc.Close()
	}
	s.clients[c.key] = c
	s.clientsEver[c.key] = true
	s.curClients.Add(1)
}

// unregisterClient removes a client from the server.
func (s *Server) unregisterClient(c *sclient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.clients[c.key]
	if cur == c {
		c.logf("removing connection")
		delete(s.clients, c.key)
	}

	s.curClients.Add(-1)
	if c.preferred {
		s.curHomeClients.Add(-1)
	}

	// Find still-connected peers to notify that we've gone away
	// so they can drop their route entries to us. (issue 150)
	for pubKey, connNum := range c.sentTo {
		if peer, ok := s.clients[pubKey]; ok && peer.connNum == connNum {
			go peer.requestPeerGoneWrite(c.key)
		}
	}
}

func (s *Server) accept(nc Conn, brw *bufio.ReadWriter, remoteAddr string, connNum int64) error {
	br, bw := brw.Reader, brw.Writer
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := s.sendServerKey(bw); err != nil {
		return fmt.Errorf("send server key: %v", err)
	}
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	clientKey, clientInfo, err := s.recvClientKey(br)
	if err != nil {
		return fmt.Errorf("receive client key: %v", err)
	}
	if err := s.verifyClient(clientKey, clientInfo); err != nil {
		return fmt.Errorf("client %x rejected: %v", clientKey, err)
	}

	// At this point we trust the client so we don't time out.
	nc.SetDeadline(time.Time{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &sclient{
		connNum:     connNum,
		s:           s,
		key:         clientKey,
		nc:          nc,
		br:          br,
		bw:          bw,
		logf:        logger.WithPrefix(s.logf, fmt.Sprintf("derp client %v/%x: ", remoteAddr, clientKey)),
		done:        ctx.Done(),
		remoteAddr:  remoteAddr,
		connectedAt: time.Now(),
		sendQueue:   make(chan pkt, perClientSendQueueDepth),
		peerGone:    make(chan key.Public),
		sentTo:      make(map[key.Public]int64),
	}
	if clientInfo != nil {
		c.info = *clientInfo
	}

	s.registerClient(c)
	defer s.unregisterClient(c)

	err = s.sendServerInfo(bw, clientKey)
	if err != nil {
		return fmt.Errorf("send server info: %v", err)
	}

	return c.run(ctx)
}

// run serves the client until there's an error.
// If the client hangs up or the server is closed, run returns nil, otherwise run returns an error.
func (c *sclient) run(ctx context.Context) error {
	// Launch sender, but don't return from run until sender goroutine is done.
	var grp errgroup.Group
	sendCtx, cancelSender := context.WithCancel(ctx)
	grp.Go(func() error { return c.sendLoop(sendCtx) })
	defer func() {
		cancelSender()
		if err := grp.Wait(); err != nil && !c.s.isClosed() {
			c.logf("sender failed: %v", err)
		}
	}()

	for {
		ft, fl, err := readFrameHeader(c.br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.logf("read EOF")
				return nil
			}
			if c.s.isClosed() {
				c.logf("closing; server closed")
				return nil
			}
			return fmt.Errorf("client %x: readFrameHeader: %w", c.key, err)
		}
		switch ft {
		case frameNotePreferred:
			err = c.handleFrameNotePreferred(ft, fl)
		case frameSendPacket:
			err = c.handleFrameSendPacket(ft, fl)
		default:
			err = c.handleUnknownFrame(ft, fl)
		}
		if err != nil {
			return err
		}
	}
}

func (c *sclient) handleUnknownFrame(ft frameType, fl uint32) error {
	_, err := io.CopyN(ioutil.Discard, c.br, int64(fl))
	return err
}

func (c *sclient) handleFrameNotePreferred(ft frameType, fl uint32) error {
	if fl != 1 {
		return fmt.Errorf("frameNotePreferred wrong size")
	}
	v, err := c.br.ReadByte()
	if err != nil {
		return fmt.Errorf("frameNotePreferred ReadByte: %v", err)
	}
	c.setPreferred(v != 0)
	return nil
}

func (c *sclient) handleFrameSendPacket(ft frameType, fl uint32) error {
	s := c.s

	dstKey, contents, err := s.recvPacket(c.br, fl)
	if err != nil {
		return fmt.Errorf("client %x: recvPacket: %v", c.key, err)
	}

	s.mu.Lock()
	dst := s.clients[dstKey]
	s.mu.Unlock()

	if dst == nil {
		s.packetsDropped.Add(1)
		s.packetsDroppedUnknown.Add(1)
		if debug {
			c.logf("dropping packet for unknown %x", dstKey)
		}
		return nil
	}

	// Track that we've sent to this peer, so if/when we
	// disconnect first, the server can inform all our old
	// recipients that we're gone. (Issue 150 optimization)
	c.sentTo[dstKey] = dst.connNum

	p := pkt{
		bs: contents,
	}
	if dst.info.Version >= protocolSrcAddrs {
		p.src = c.key
	}
	// Attempt to queue for sending up to 3 times. On each attempt, if
	// the queue is full, try to drop from queue head to prioritize
	// fresher packets.
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-dst.done:
			s.packetsDropped.Add(1)
			s.packetsDroppedGone.Add(1)
			if debug {
				c.logf("dropping packet for shutdown client %x", dstKey)
			}
			return nil
		default:
		}
		select {
		case dst.sendQueue <- p:
			return nil
		default:
		}

		select {
		case <-dst.sendQueue:
			s.packetsDropped.Add(1)
			s.packetsDroppedQueueHead.Add(1)
			if debug {
				c.logf("dropping packet from client %x queue head", dstKey)
			}
		default:
		}
	}
	// Failed to make room for packet. This can happen in a heavily
	// contended queue with racing writers. Give up and tail-drop in
	// this case to keep reader unblocked.
	s.packetsDropped.Add(1)
	s.packetsDroppedQueueTail.Add(1)
	if debug {
		c.logf("dropping packet from client %x queue tail", dstKey)
	}

	return nil
}

// requestPeerGoneWrite sends a request to write a "peer gone" frame
// that the provided peer has disconnected. It blocks until either the
// write request is scheduled, or the client has closed.
func (c *sclient) requestPeerGoneWrite(peer key.Public) {
	select {
	case c.peerGone <- peer:
	case <-c.done:
	}
}

func (s *Server) verifyClient(clientKey key.Public, info *clientInfo) error {
	// TODO(crawshaw): implement policy constraints on who can use the DERP server
	// TODO(bradfitz): ... and at what rate.
	return nil
}

func (s *Server) sendServerKey(bw *bufio.Writer) error {
	buf := make([]byte, 0, len(magic)+len(s.publicKey))
	buf = append(buf, magic...)
	buf = append(buf, s.publicKey[:]...)
	return writeFrame(bw, frameServerKey, buf)
}

type serverInfo struct {
	Version int // `json:"version,omitempty"`
}

func (s *Server) sendServerInfo(bw *bufio.Writer, clientKey key.Public) error {
	var nonce [24]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return err
	}
	msg, err := json.Marshal(serverInfo{Version: protocolVersion})
	if err != nil {
		return err
	}

	msgbox := box.Seal(nil, msg, &nonce, clientKey.B32(), s.privateKey.B32())
	if err := writeFrameHeader(bw, frameServerInfo, nonceLen+uint32(len(msgbox))); err != nil {
		return err
	}
	if _, err := bw.Write(nonce[:]); err != nil {
		return err
	}
	if _, err := bw.Write(msgbox); err != nil {
		return err
	}
	return bw.Flush()
}

// recvClientKey reads the frameClientInfo frame from the client (its
// proof of identity) upon its initial connection. It should be
// considered especially untrusted at this point.
func (s *Server) recvClientKey(br *bufio.Reader) (clientKey key.Public, info *clientInfo, err error) {
	fl, err := readFrameTypeHeader(br, frameClientInfo)
	if err != nil {
		return key.Public{}, nil, err
	}
	const minLen = keyLen + nonceLen
	if fl < minLen {
		return key.Public{}, nil, errors.New("short client info")
	}
	// We don't trust the client at all yet, so limit its input size to limit
	// things like JSON resource exhausting (http://github.com/golang/go/issues/31789).
	if fl > 256<<10 {
		return key.Public{}, nil, errors.New("long client info")
	}
	if _, err := io.ReadFull(br, clientKey[:]); err != nil {
		return key.Public{}, nil, err
	}
	var nonce [24]byte
	if _, err := io.ReadFull(br, nonce[:]); err != nil {
		return key.Public{}, nil, fmt.Errorf("nonce: %v", err)
	}
	msgLen := int(fl - minLen)
	msgbox := make([]byte, msgLen)
	if _, err := io.ReadFull(br, msgbox); err != nil {
		return key.Public{}, nil, fmt.Errorf("msgbox: %v", err)
	}
	msg, ok := box.Open(nil, msgbox, &nonce, (*[32]byte)(&clientKey), s.privateKey.B32())
	if !ok {
		return key.Public{}, nil, fmt.Errorf("msgbox: cannot open len=%d with client key %x", msgLen, clientKey[:])
	}
	info = new(clientInfo)
	if err := json.Unmarshal(msg, info); err != nil {
		return key.Public{}, nil, fmt.Errorf("msg: %v", err)
	}
	return clientKey, info, nil
}

func (s *Server) recvPacket(br *bufio.Reader, frameLen uint32) (dstKey key.Public, contents []byte, err error) {
	if frameLen < keyLen {
		return key.Public{}, nil, errors.New("short send packet frame")
	}
	if _, err := io.ReadFull(br, dstKey[:]); err != nil {
		return key.Public{}, nil, err
	}
	packetLen := frameLen - keyLen
	if packetLen > MaxPacketSize {
		return key.Public{}, nil, fmt.Errorf("data packet longer (%d) than max of %v", packetLen, MaxPacketSize)
	}
	contents = make([]byte, packetLen)
	if _, err := io.ReadFull(br, contents); err != nil {
		return key.Public{}, nil, err
	}
	s.packetsRecv.Add(1)
	s.bytesRecv.Add(int64(len(contents)))
	return dstKey, contents, nil
}

// sclient is a client connection to the server.
//
// (The "s" prefix is to more explicitly distinguish it from Client in derp_client.go)
type sclient struct {
	// Static after construction.
	connNum    int64 // process-wide unique counter, incremented each Accept
	s          *Server
	nc         Conn
	key        key.Public
	info       clientInfo
	logf       logger.Logf
	done       <-chan struct{} // closed when connection closes
	remoteAddr string          // usually ip:port from net.Conn.RemoteAddr().String()
	sendQueue  chan pkt        // packets queued to this client; never closed
	peerGone   chan key.Public // write request that a previous sender has disconnected

	// Owned by run, not thread-safe.
	br          *bufio.Reader
	connectedAt time.Time
	preferred   bool
	// sentTo tracks all the peers this client has ever sent a packet to, and at which
	// connection number.
	sentTo map[key.Public]int64 // recipient => rcpt's latest sclient.connNum

	// Owned by sender, not thread-safe.
	bw *bufio.Writer
}

// pkt is a request to write a data frame to an sclient.
type pkt struct {
	// src is the who's the sender of the packet.
	src key.Public

	// bs is the data packet bytes.
	// The memory is owned by pkt.
	bs []byte

	// TODO(danderson): enqueue time, to measure queue latency?
}

func (c *sclient) setPreferred(v bool) {
	if c.preferred == v {
		return
	}
	c.preferred = v
	var homeMove *expvar.Int
	if v {
		c.s.curHomeClients.Add(1)
		homeMove = &c.s.homeMovesIn
	} else {
		c.s.curHomeClients.Add(-1)
		homeMove = &c.s.homeMovesOut
	}

	// Keep track of varz for home serve moves in/out.  But ignore
	// the initial packet set when a client connects, which we
	// assume happens within 5 seconds. In any case, just for
	// graphs, so not important to miss a move. But it shouldn't:
	// the netcheck/re-STUNs in magicsock only happen about every
	// 30 seconds.
	if time.Since(c.connectedAt) > 5*time.Second {
		homeMove.Add(1)
	}
}

func (c *sclient) sendLoop(ctx context.Context) error {
	defer func() {
		// If the sender shuts down unilaterally due to an error, close so
		// that the receive loop unblocks and cleans up the rest.
		c.nc.Close()

		// Drain the send queue to count dropped packets
		for {
			select {
			case <-c.sendQueue:
				c.s.packetsDropped.Add(1)
				c.s.packetsDroppedGone.Add(1)
				if debug {
					c.logf("dropping packet for shutdown %x", c.key)
				}
			default:
				return
			}
		}
	}()

	jitterMs, err := crand.Int(crand.Reader, big.NewInt(5000))
	if err != nil {
		panic(err)
	}
	jitter := time.Duration(jitterMs.Int64()) * time.Millisecond
	keepAliveTick := time.NewTicker(keepAlive + jitter)
	defer keepAliveTick.Stop()

	var werr error // last write error
	for {
		if werr != nil {
			return werr
		}
		// First, a non-blocking select (with a default) that
		// does as many non-flushing writes as possible.
		select {
		case <-ctx.Done():
			return nil
		case peer := <-c.peerGone:
			werr = c.sendPeerGone(peer)
			continue
		case msg := <-c.sendQueue:
			werr = c.sendPacket(msg.src, msg.bs)
			continue
		case <-keepAliveTick.C:
			werr = c.sendKeepAlive()
			continue
		default:
			// Flush any writes from the 3 sends above, or from
			// the blocking loop below.
			if werr = c.bw.Flush(); werr != nil {
				return werr
			}
		}

		// Then a blocking select with same:
		select {
		case <-ctx.Done():
			return nil
		case peer := <-c.peerGone:
			werr = c.sendPeerGone(peer)
		case msg := <-c.sendQueue:
			werr = c.sendPacket(msg.src, msg.bs)
		case <-keepAliveTick.C:
			werr = c.sendKeepAlive()
		}
	}
}

func (c *sclient) setWriteDeadline() {
	c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
}

// sendKeepAlive sends a keep-alive frame, without flushing.
func (c *sclient) sendKeepAlive() error {
	c.setWriteDeadline()
	return writeFrameHeader(c.bw, frameKeepAlive, 0)
}

// sendPeerGone sends a peerGone frame, without flushing.
func (c *sclient) sendPeerGone(peer key.Public) error {
	c.s.peerGoneFrames.Add(1)
	c.setWriteDeadline()
	if err := writeFrameHeader(c.bw, framePeerGone, keyLen); err != nil {
		return err
	}
	_, err := c.bw.Write(peer[:])
	return err
}

// sendPacket writes contents to the client in a RecvPacket frame. If
// srcKey.IsZero, uses the old DERPv1 framing format, otherwise uses
// DERPv2. The bytes of contents are only valid until this function
// returns, do not retain slices.
// It does not flush its bufio.Writer.
func (c *sclient) sendPacket(srcKey key.Public, contents []byte) (err error) {
	defer func() {
		// Stats update.
		if err != nil {
			c.s.packetsDropped.Add(1)
			c.s.packetsDroppedWrite.Add(1)
			if debug {
				c.logf("dropping packet to %x: %v", c.key, err)
			}
		} else {
			c.s.packetsSent.Add(1)
			c.s.bytesSent.Add(int64(len(contents)))
		}
	}()

	c.setWriteDeadline()

	withKey := !srcKey.IsZero()
	pktLen := len(contents)
	if withKey {
		pktLen += len(srcKey)
	}
	if err = writeFrameHeader(c.bw, frameRecvPacket, uint32(pktLen)); err != nil {
		return err
	}
	if withKey {
		if _, err = c.bw.Write(srcKey[:]); err != nil {
			return err
		}
	}
	_, err = c.bw.Write(contents)
	return err
}

func (s *Server) expVarFunc(f func() interface{}) expvar.Func {
	return expvar.Func(func() interface{} {
		s.mu.Lock()
		defer s.mu.Unlock()
		return f()
	})
}

// ExpVar returns an expvar variable suitable for registering with expvar.Publish.
func (s *Server) ExpVar() expvar.Var {
	m := new(metrics.Set)
	m.Set("counter_unique_clients_ever", s.expVarFunc(func() interface{} { return len(s.clientsEver) }))
	m.Set("gauge_memstats_sys0", expvar.Func(func() interface{} { return int64(s.memSys0) }))
	m.Set("gauge_current_connnections", &s.curClients)
	m.Set("gauge_current_home_connnections", &s.curHomeClients)
	m.Set("accepts", &s.accepts)
	m.Set("clients_replaced", &s.clientsReplaced)
	m.Set("bytes_received", &s.bytesRecv)
	m.Set("bytes_sent", &s.bytesSent)
	m.Set("packets_dropped", &s.packetsDropped)
	m.Set("counter_packets_dropped_reason", &s.packetsDroppedReason)
	m.Set("packets_sent", &s.packetsSent)
	m.Set("packets_received", &s.packetsRecv)
	m.Set("unknown_frames", &s.unknownFrames)
	m.Set("home_moves_in", &s.homeMovesIn)
	m.Set("home_moves_out", &s.homeMovesOut)
	m.Set("peer_gone_frames", &s.peerGoneFrames)
	return m
}
