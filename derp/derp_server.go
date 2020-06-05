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
	meshKey    string

	// Counters:
	packetsSent, bytesSent   expvar.Int
	packetsRecv, bytesRecv   expvar.Int
	packetsDropped           expvar.Int
	packetsDroppedReason     metrics.LabelMap
	packetsDroppedUnknown    *expvar.Int // unknown dst pubkey
	packetsDroppedFwdUnknown *expvar.Int // unknown dst pubkey on forward
	packetsDroppedGone       *expvar.Int // dst conn shutting down
	packetsDroppedQueueHead  *expvar.Int // queue full, drop head packet
	packetsDroppedQueueTail  *expvar.Int // queue full, drop tail packet
	packetsDroppedWrite      *expvar.Int // error writing to dst conn
	packetsForwardedOut      expvar.Int
	packetsForwardedIn       expvar.Int
	peerGoneFrames           expvar.Int // number of peer gone frames sent
	accepts                  expvar.Int
	curClients               expvar.Int
	curHomeClients           expvar.Int // ones with preferred
	clientsReplaced          expvar.Int
	unknownFrames            expvar.Int
	homeMovesIn              expvar.Int // established clients announce home server moves in
	homeMovesOut             expvar.Int // established clients announce home server moves out
	multiForwarderCreated    expvar.Int
	multiForwarderDeleted    expvar.Int

	mu          sync.Mutex
	closed      bool
	netConns    map[Conn]chan struct{} // chan is closed when conn closes
	clients     map[key.Public]*sclient
	clientsEver map[key.Public]bool // never deleted from, for stats; fine for now
	watchers    map[*sclient]bool   // mesh peer -> true
	// clientsMesh tracks all clients in the cluster, both locally
	// and to mesh peers.  If the value is nil, that means the
	// peer is only remote (and thus in the clients Map).  If the
	// value is non-nil, it's only remote.
	clientsMesh map[key.Public]PacketForwarder
}

// PacketForwarder is something that can forward packets.
//
// It's mostly an inteface for circular dependency reasons; the
// typical implementation is derphttp.Client. The other implementation
// is a multiForwarder, which this package creates as needed if a
// public key gets more than one PacketForwarder registered for it.
type PacketForwarder interface {
	ForwardPacket(src, dst key.Public, payload []byte) error
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
		clientsMesh:          map[key.Public]PacketForwarder{},
		netConns:             make(map[Conn]chan struct{}),
		memSys0:              ms.Sys,
		watchers:             map[*sclient]bool{},
	}
	s.packetsDroppedUnknown = s.packetsDroppedReason.Get("unknown_dest")
	s.packetsDroppedFwdUnknown = s.packetsDroppedReason.Get("unknown_dest_on_fwd")
	s.packetsDroppedGone = s.packetsDroppedReason.Get("gone")
	s.packetsDroppedQueueHead = s.packetsDroppedReason.Get("queue_head")
	s.packetsDroppedQueueTail = s.packetsDroppedReason.Get("queue_tail")
	s.packetsDroppedWrite = s.packetsDroppedReason.Get("write_error")
	return s
}

// SetMesh sets the pre-shared key that regional DERP servers used to mesh
// amongst themselves.
//
// It must be called before serving begins.
func (s *Server) SetMeshKey(v string) {
	s.meshKey = v
}

// HasMeshKey reports whether the server is configured with a mesh key.
func (s *Server) HasMeshKey() bool { return s.meshKey != "" }

// MeshKey returns the configured mesh key, if any.
func (s *Server) MeshKey() string { return s.meshKey }

// PrivateKey returns the server's private key.
func (s *Server) PrivateKey() key.Private { return s.privateKey }

// PublicKey returns the server's public key.
func (s *Server) PublicKey() key.Public { return s.publicKey }

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
	if _, ok := s.clientsMesh[c.key]; !ok {
		s.clientsMesh[c.key] = nil // just for varz of total users in cluster
	}
	s.curClients.Add(1)
	s.broadcastPeerStateChangeLocked(c.key, true)
}

// broadcastPeerStateChangeLocked enqueues a message to all watchers
// (other DERP nodes in the region, or trusted clients) that peer's
// presence changed.
//
// s.mu must be held.
func (s *Server) broadcastPeerStateChangeLocked(peer key.Public, present bool) {
	for w := range s.watchers {
		w.peerStateChange = append(w.peerStateChange, peerConnState{peer: peer, present: present})
		go w.requestMeshUpdate()
	}
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
	if c.canMesh {
		delete(s.watchers, c)
	}
	if v, ok := s.clientsMesh[c.key]; ok && v == nil {
		delete(s.clientsMesh, c.key)
	}
	s.broadcastPeerStateChangeLocked(c.key, false)

	s.curClients.Add(-1)
	if c.preferred {
		s.curHomeClients.Add(-1)
	}

	// Find still-connected peers and either notify that we've gone away
	// so they can drop their route entries to us (issue 150)
	// or move them over to the active client (in case a replaced client
	// connection is being unregistered).
	for pubKey, connNum := range c.sentTo {
		if peer, ok := s.clients[pubKey]; ok && peer.connNum == connNum {
			if cur == c {
				go peer.requestPeerGoneWrite(c.key)
			} else {
				// Only if the current client has not already accepted a newer
				// connection from the peer.
				if _, ok := cur.sentTo[pubKey]; !ok {
					cur.sentTo[pubKey] = connNum
				}
			}
		}
	}
}

func (s *Server) addWatcher(c *sclient) {
	if !c.canMesh {
		panic("invariant: addWatcher called without permissions")
	}

	if c.key == s.publicKey {
		// We're connecting to ourself. Do nothing.
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Queue messages for each already-connected client.
	for peer := range s.clients {
		c.peerStateChange = append(c.peerStateChange, peerConnState{peer: peer, present: true})
	}

	// And enroll the watcher in future updates (of both
	// connections & disconnections).
	s.watchers[c] = true

	go c.requestMeshUpdate()
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
		canMesh:     clientInfo.MeshKey != "" && clientInfo.MeshKey == s.meshKey,
	}
	if c.canMesh {
		c.meshUpdate = make(chan struct{})
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
		case frameForwardPacket:
			err = c.handleFrameForwardPacket(ft, fl)
		case frameWatchConns:
			err = c.handleFrameWatchConns(ft, fl)
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

func (c *sclient) handleFrameWatchConns(ft frameType, fl uint32) error {
	if fl != 0 {
		return fmt.Errorf("handleFrameWatchConns wrong size")
	}
	if !c.canMesh {
		return fmt.Errorf("insufficient permissions")
	}
	c.s.addWatcher(c)
	return nil
}

// handleFrameForwardPacket reads a "forward packet" frame from the client
// (which must be a trusted client, a peer in our mesh).
func (c *sclient) handleFrameForwardPacket(ft frameType, fl uint32) error {
	if !c.canMesh {
		return fmt.Errorf("insufficient permissions")
	}
	s := c.s

	srcKey, dstKey, contents, err := s.recvForwardPacket(c.br, fl)
	if err != nil {
		return fmt.Errorf("client %x: recvForwardPacket: %v", c.key, err)
	}
	s.packetsForwardedIn.Add(1)

	s.mu.Lock()
	dst := s.clients[dstKey]
	// TODO(bradfitz): think about the sentTo/Issue 150 optimization
	// in the context of DERP meshes.
	s.mu.Unlock()

	if dst == nil {
		s.packetsDropped.Add(1)
		s.packetsDroppedFwdUnknown.Add(1)
		if debug {
			c.logf("dropping forwarded packet for unknown %x", dstKey)
		}
		return nil
	}

	return c.sendPkt(dst, pkt{
		bs:  contents,
		src: srcKey,
	})
}

// handleFrameSendPacket reads a "send packet" frame from the client.
func (c *sclient) handleFrameSendPacket(ft frameType, fl uint32) error {
	s := c.s

	dstKey, contents, err := s.recvPacket(c.br, fl)
	if err != nil {
		return fmt.Errorf("client %x: recvPacket: %v", c.key, err)
	}

	var fwd PacketForwarder
	s.mu.Lock()
	dst := s.clients[dstKey]
	if dst == nil {
		fwd = s.clientsMesh[dstKey]
	} else {
		// Track that we've sent to this peer, so if/when we
		// disconnect first, the server can inform all our old
		// recipients that we're gone. (Issue 150 optimization)
		c.sentTo[dstKey] = dst.connNum
	}
	s.mu.Unlock()

	if dst == nil {
		if fwd != nil {
			s.packetsForwardedOut.Add(1)
			if err := fwd.ForwardPacket(c.key, dstKey, contents); err != nil {
				// TODO:
				return nil
			}
			return nil
		}
		s.packetsDropped.Add(1)
		s.packetsDroppedUnknown.Add(1)
		if debug {
			c.logf("dropping packet for unknown %x", dstKey)
		}
		return nil
	}

	p := pkt{
		bs: contents,
	}
	if dst.info.Version >= protocolSrcAddrs {
		p.src = c.key
	}
	return c.sendPkt(dst, p)
}

func (c *sclient) sendPkt(dst *sclient, p pkt) error {
	s := c.s
	dstKey := dst.key

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

func (c *sclient) requestMeshUpdate() {
	if !c.canMesh {
		panic("unexpected requestMeshUpdate")
	}
	select {
	case c.meshUpdate <- struct{}{}:
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
		return zpub, nil, err
	}
	const minLen = keyLen + nonceLen
	if fl < minLen {
		return zpub, nil, errors.New("short client info")
	}
	// We don't trust the client at all yet, so limit its input size to limit
	// things like JSON resource exhausting (http://github.com/golang/go/issues/31789).
	if fl > 256<<10 {
		return zpub, nil, errors.New("long client info")
	}
	if _, err := io.ReadFull(br, clientKey[:]); err != nil {
		return zpub, nil, err
	}
	var nonce [24]byte
	if _, err := io.ReadFull(br, nonce[:]); err != nil {
		return zpub, nil, fmt.Errorf("nonce: %v", err)
	}
	msgLen := int(fl - minLen)
	msgbox := make([]byte, msgLen)
	if _, err := io.ReadFull(br, msgbox); err != nil {
		return zpub, nil, fmt.Errorf("msgbox: %v", err)
	}
	msg, ok := box.Open(nil, msgbox, &nonce, (*[32]byte)(&clientKey), s.privateKey.B32())
	if !ok {
		return zpub, nil, fmt.Errorf("msgbox: cannot open len=%d with client key %x", msgLen, clientKey[:])
	}
	info = new(clientInfo)
	if err := json.Unmarshal(msg, info); err != nil {
		return zpub, nil, fmt.Errorf("msg: %v", err)
	}
	return clientKey, info, nil
}

func (s *Server) recvPacket(br *bufio.Reader, frameLen uint32) (dstKey key.Public, contents []byte, err error) {
	if frameLen < keyLen {
		return zpub, nil, errors.New("short send packet frame")
	}
	if _, err := io.ReadFull(br, dstKey[:]); err != nil {
		return zpub, nil, err
	}
	packetLen := frameLen - keyLen
	if packetLen > MaxPacketSize {
		return zpub, nil, fmt.Errorf("data packet longer (%d) than max of %v", packetLen, MaxPacketSize)
	}
	contents = make([]byte, packetLen)
	if _, err := io.ReadFull(br, contents); err != nil {
		return zpub, nil, err
	}
	s.packetsRecv.Add(1)
	s.bytesRecv.Add(int64(len(contents)))
	return dstKey, contents, nil
}

// zpub is the key.Public zero value.
var zpub key.Public

func (s *Server) recvForwardPacket(br *bufio.Reader, frameLen uint32) (srcKey, dstKey key.Public, contents []byte, err error) {
	if frameLen < keyLen*2 {
		return zpub, zpub, nil, errors.New("short send packet frame")
	}
	if _, err := io.ReadFull(br, srcKey[:]); err != nil {
		return zpub, zpub, nil, err
	}
	if _, err := io.ReadFull(br, dstKey[:]); err != nil {
		return zpub, zpub, nil, err
	}
	packetLen := frameLen - keyLen*2
	if packetLen > MaxPacketSize {
		return zpub, zpub, nil, fmt.Errorf("data packet longer (%d) than max of %v", packetLen, MaxPacketSize)
	}
	contents = make([]byte, packetLen)
	if _, err := io.ReadFull(br, contents); err != nil {
		return zpub, zpub, nil, err
	}
	// TODO: was s.packetsRecv.Add(1)
	// TODO: was s.bytesRecv.Add(int64(len(contents)))
	return srcKey, dstKey, contents, nil
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
	peerGone   chan key.Public // write request that a previous sender has disconnected (not used by mesh peers)
	meshUpdate chan struct{}   // write request to write peerStateChange
	canMesh    bool            // clientInfo had correct mesh token for inter-region routing

	// Owned by run, not thread-safe.
	br          *bufio.Reader
	connectedAt time.Time
	preferred   bool

	// Owned by sender, not thread-safe.
	bw *bufio.Writer

	// Guarded by s.mu.
	//
	// sentTo tracks all the peers this client has ever sent a packet to, and at which
	// connection number.
	sentTo map[key.Public]int64 // recipient => rcpt's latest sclient.connNum

	// Guarded by s.mu
	//
	// peerStateChange is used by mesh peers (a set of regional
	// DERP servers) and contains records that need to be sent to
	// the client for them to update their map of who's connected
	// to this node.
	peerStateChange []peerConnState
}

// peerConnState represents whether a peer is connected to the server
// or not.
type peerConnState struct {
	peer    key.Public
	present bool
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
		case <-c.meshUpdate:
			werr = c.sendMeshUpdates()
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
		case <-c.meshUpdate:
			werr = c.sendMeshUpdates()
			continue
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

// sendPeerPresent sends a peerPresent frame, without flushing.
func (c *sclient) sendPeerPresent(peer key.Public) error {
	c.setWriteDeadline()
	if err := writeFrameHeader(c.bw, framePeerPresent, keyLen); err != nil {
		return err
	}
	_, err := c.bw.Write(peer[:])
	return err
}

// sendMeshUpdates drains as many mesh peerStateChange entries as
// possible into the write buffer WITHOUT flushing or otherwise
// blocking (as it holds c.s.mu while working). If it can't drain them
// all, it schedules itself to be called again in the future.
func (c *sclient) sendMeshUpdates() error {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()

	writes := 0
	for _, pcs := range c.peerStateChange {
		if c.bw.Available() <= frameHeaderLen+keyLen {
			break
		}
		var err error
		if pcs.present {
			err = c.sendPeerPresent(pcs.peer)
		} else {
			err = c.sendPeerGone(pcs.peer)
		}
		if err != nil {
			// Shouldn't happen, though, as we're writing
			// into available buffer space, not the
			// network.
			return err
		}
		writes++
	}

	remain := copy(c.peerStateChange, c.peerStateChange[writes:])
	c.peerStateChange = c.peerStateChange[:remain]

	// Did we manage to write them all into the bufio buffer without flushing?
	if len(c.peerStateChange) == 0 {
		if cap(c.peerStateChange) > 16 {
			c.peerStateChange = nil
		}
	} else {
		// Didn't finish in the buffer space provided; schedule a future run.
		go c.requestMeshUpdate()
	}
	return nil
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

// AddPacketForwarder registers fwd as a packet forwarder for dst.
// fwd must be comparable.
func (s *Server) AddPacketForwarder(dst key.Public, fwd PacketForwarder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.clientsMesh[dst]; ok {
		if prev == fwd {
			// Duplicate registration of same forwarder. Ignore.
			return
		}
		if m, ok := prev.(multiForwarder); ok {
			if _, ok := m[fwd]; !ok {
				// Duplicate registration of same forwarder in set; ignore.
				return
			}
			m[fwd] = m.maxVal() + 1
			return
		}
		if prev != nil {
			// Otherwise, the existing value is not a set,
			// not a dup, and not local-only (nil) so make
			// it a set.
			fwd = multiForwarder{
				prev: 1, // existed 1st, higher priority
				fwd:  2, // the passed in fwd is in 2nd place
			}
			s.multiForwarderCreated.Add(1)
		}
	}
	s.clientsMesh[dst] = fwd
}

// RemovePacketForwarder removes fwd as a packet forwarder for dst.
// fwd must be comparable.
func (s *Server) RemovePacketForwarder(dst key.Public, fwd PacketForwarder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.clientsMesh[dst]
	if !ok {
		return
	}
	if m, ok := v.(multiForwarder); ok {
		if len(m) < 2 {
			panic("unexpected")
		}
		delete(m, fwd)
		// If fwd was in m and we no longer need to be a
		// multiForwarder, replace the entry with the
		// remaining PacketForwarder.
		if len(m) == 1 {
			var remain PacketForwarder
			for k := range m {
				remain = k
			}
			s.clientsMesh[dst] = remain
			s.multiForwarderDeleted.Add(1)
		}
		return
	}
	if v != fwd {
		// Delete of an entry that wasn't in the
		// map. Harmless, so ignore.
		// (This might happen if a user is moving around
		// between nodes and/or the server sent duplicate
		// connection change broadcasts.)
		return
	}

	if _, isLocal := s.clients[dst]; isLocal {
		s.clientsMesh[dst] = nil
	} else {
		delete(s.clientsMesh, dst)
	}
}

// multiForwarder is a PacketForwarder that represents a set of
// forwarding options. It's used in the rare cases that a client is
// connected to multiple DERP nodes in a region. That shouldn't really
// happen except for perhaps during brief moments while the client is
// reconfiguring, in which case we don't want to forget where the
// client is. The map value is unique connection number; the lowest
// one has been seen the longest. It's used to make sure we forward
// packets consistently to the same node and don't pick randomly.
type multiForwarder map[PacketForwarder]uint8

func (m multiForwarder) maxVal() (max uint8) {
	for _, v := range m {
		if v > max {
			max = v
		}
	}
	return
}

func (m multiForwarder) ForwardPacket(src, dst key.Public, payload []byte) error {
	var fwd PacketForwarder
	var lowest uint8
	for k, v := range m {
		if fwd == nil || v < lowest {
			fwd = k
			lowest = v
		}
	}
	return fwd.ForwardPacket(src, dst, payload)
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
	m.Set("gauge_watchers", s.expVarFunc(func() interface{} { return len(s.watchers) }))
	m.Set("gauge_current_connnections", &s.curClients)
	m.Set("gauge_current_home_connnections", &s.curHomeClients)
	m.Set("gauge_clients_total", expvar.Func(func() interface{} { return len(s.clientsMesh) }))
	m.Set("gauge_clients_remote", expvar.Func(func() interface{} { return len(s.clientsMesh) - len(s.clients) }))
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
	m.Set("packets_forwarded_out", &s.packetsForwardedOut)
	m.Set("packets_forwarded_in", &s.packetsForwardedIn)
	m.Set("multiforwarder_created", &s.multiForwarderCreated)
	m.Set("multiforwarder_deleted", &s.multiForwarderDeleted)
	return m
}
