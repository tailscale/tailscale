// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

// TODO(crawshaw): send srcKey with packets to clients?
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
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
	"tailscale.com/metrics"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var debug, _ = strconv.ParseBool(os.Getenv("DERP_DEBUG_LOGS"))

const perClientSendQueueDepth = 32 // packets buffered for sending

// Server is a DERP server.
type Server struct {
	// WriteTimeout, if non-zero, specifies how long to wait
	// before failing when writing to a client.
	WriteTimeout time.Duration

	privateKey key.Private
	publicKey  key.Public
	logf       logger.Logf

	// Counters:
	packetsSent, bytesSent expvar.Int
	packetsRecv, bytesRecv expvar.Int
	packetsDropped         expvar.Int
	accepts                expvar.Int
	curClients             expvar.Int
	curHomeClients         expvar.Int // ones with preferred
	clientsReplaced        expvar.Int
	unknownFrames          expvar.Int
	homeMovesIn            expvar.Int // established clients announce home server moves in
	homeMovesOut           expvar.Int // established clients announce home server moves out

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
	s := &Server{
		privateKey:  privateKey,
		publicKey:   privateKey.Public(),
		logf:        logf,
		clients:     make(map[key.Public]*sclient),
		clientsEver: make(map[key.Public]bool),
		netConns:    make(map[Conn]chan struct{}),
	}
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

	s.accepts.Add(1)
	s.mu.Lock()
	s.netConns[nc] = closed
	s.mu.Unlock()

	defer func() {
		nc.Close()
		close(closed)

		s.mu.Lock()
		delete(s.netConns, nc)
		s.mu.Unlock()
	}()

	if err := s.accept(nc, brw, remoteAddr); err != nil && !s.isClosed() {
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
}

func (s *Server) accept(nc Conn, brw *bufio.ReadWriter, remoteAddr string) error {
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

	c := &sclient{
		s:           s,
		key:         clientKey,
		nc:          nc,
		br:          br,
		bw:          bw,
		logf:        logger.WithPrefix(s.logf, fmt.Sprintf("derp client %v/%x: ", remoteAddr, clientKey)),
		remoteAddr:  remoteAddr,
		connectedAt: time.Now(),
		sendQueue:   make(chan pkt, perClientSendQueueDepth),
	}
	if clientInfo != nil {
		c.info = *clientInfo
	}

	s.registerClient(c)
	err = s.sendServerInfo(bw, clientKey)
	if err != nil {
		return fmt.Errorf("send server info: %v", err)
	}
	defer s.unregisterClient(c)

	return c.run()
}

func (c *sclient) run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() {
		// Atomically close+remove send queue, so racing writers don't
		// send to closed channel.
		c.mu.Lock()
		close(c.sendQueue)
		c.sendQueue = nil
		c.mu.Unlock()
	}()

	go c.sender(ctx)

	for {
		ft, fl, err := readFrameHeader(c.br)
		if err != nil {
			return fmt.Errorf("client %x: readFrameHeader: %v", c.key, err)
		}
		switch ft {
		case frameNotePreferred:
			err = c.handleFrameNotePreferred(ft, fl)
		case frameSendPacket:
			err = c.handleFrameSendPacket(ctx, ft, fl)
		default:
			err = c.handleUnknownFrame(ctx, ft, fl)
		}
		if err != nil {
			return err
		}
	}
}

func (c *sclient) handleUnknownFrame(ctx context.Context, ft frameType, fl uint32) error {
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

func (c *sclient) handleFrameSendPacket(ctx context.Context, ft frameType, fl uint32) error {
	s := c.s

	dstKey, contents, err := s.recvPacket(ctx, c.br, fl)
	if err != nil {
		return fmt.Errorf("client %x: recvPacket: %v", c.key, err)
	}

	s.mu.Lock()
	dst := s.clients[dstKey]
	s.mu.Unlock()

	if dst == nil {
		s.packetsDropped.Add(1)
		if debug {
			c.logf("dropping packet for unknown %x", dstKey)
		}
		return nil
	}

	dst.mu.RLock()
	defer dst.mu.RUnlock()
	if dst.sendQueue == nil {
		s.packetsDropped.Add(1)
		if debug {
			c.logf("dropping packet for shutdown client %x", dstKey)
		}
	}

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
		case dst.sendQueue <- p:
			return nil
		default:
		}

		select {
		case <-dst.sendQueue:
			s.packetsDropped.Add(1)
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
	if debug {
		c.logf("dropping packet from client %x queue tail", dstKey)
	}

	return nil
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

func (s *Server) recvPacket(ctx context.Context, br *bufio.Reader, frameLen uint32) (dstKey key.Public, contents []byte, err error) {
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
	s          *Server
	nc         Conn
	key        key.Public
	info       clientInfo
	logf       logger.Logf
	remoteAddr string // usually ip:port from net.Conn.RemoteAddr().String()

	// Owned by run, not thread-safe.
	br          *bufio.Reader
	connectedAt time.Time
	preferred   bool

	// Owned by sender, not thread-safe.
	bw *bufio.Writer

	mu        sync.RWMutex // guards access to sendQueue for shutdown.
	sendQueue chan pkt     // packets queued to this client
}

type pkt struct {
	src key.Public
	bs  []byte
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

func (c *sclient) sender(ctx context.Context) {
	// If the sender shuts down unilaterally due to an error, close so
	// that the receive loop unblocks and cleans up the rest.
	defer c.nc.Close()
	if err := c.sendLoop(ctx); err != nil {
		c.logf("sender failed: %v", err)
	}
}

func (c *sclient) sendLoop(ctx context.Context) error {
	c.mu.RLock()
	queue := c.sendQueue
	c.mu.RUnlock()

	if queue == nil {
		// Uncommon race, sclient shut down before this loop ever
		// started. Nothing to do here, move along.
		return nil
	}

	defer func() {
		// Drain the send queue to count dropped packets
		for {
			_, ok := <-queue
			if !ok {
				break
			}
			c.s.packetsDropped.Add(1)
			if debug {
				c.logf("dropping packet for shutdown %x", c.key)
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

	for {
		select {
		case <-ctx.Done():
			return nil

		case pkt, ok := <-queue:
			if !ok {
				return nil
			}
			if err := c.sendPacket(pkt.src, pkt.bs); err != nil {
				return err
			}

		case <-keepAliveTick.C:
			if err := c.sendKeepalive(); err != nil {
				return err
			}
		}
	}
}

func (c *sclient) sendKeepalive() error {
	if c.s.WriteTimeout != 0 {
		c.nc.SetWriteDeadline(time.Now().Add(c.s.WriteTimeout))
	}
	if err := writeFrame(c.bw, frameKeepAlive, nil); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *sclient) sendPacket(srcKey key.Public, contents []byte) (err error) {
	defer func() {
		// Stats update.
		if err != nil {
			c.s.packetsDropped.Add(1)
			if debug {
				c.logf("dropping packet to %x: %v", c.key, err)
			}
		} else {
			c.s.packetsSent.Add(1)
			c.s.bytesSent.Add(int64(len(contents)))
		}
	}()

	if c.s.WriteTimeout != 0 {
		c.nc.SetWriteDeadline(time.Now().Add(c.s.WriteTimeout))
	}

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
	if _, err = c.bw.Write(contents); err != nil {
		return err
	}
	return c.bw.Flush()
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
	m.Set("gauge_current_connnections", &s.curClients)
	m.Set("gauge_current_home_connnections", &s.curHomeClients)
	m.Set("accepts", &s.accepts)
	m.Set("clients_replaced", &s.clientsReplaced)
	m.Set("bytes_received", &s.bytesRecv)
	m.Set("bytes_sent", &s.bytesSent)
	m.Set("packets_dropped", &s.packetsDropped)
	m.Set("packets_sent", &s.packetsSent)
	m.Set("packets_received", &s.packetsRecv)
	m.Set("unknown_frames", &s.unknownFrames)
	m.Set("home_moves_in", &s.homeMovesIn)
	m.Set("home_moves_out", &s.homeMovesOut)
	return m
}
