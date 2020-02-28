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
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/time/rate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// Server is a DERP server.
type Server struct {
	// BytesPerSecond, if non-zero, specifies how many bytes per
	// second to cap per-client reads at.
	BytesPerSecond int

	privateKey key.Private
	publicKey  key.Public
	logf       logger.Logf

	// Counters:
	packetsSent, bytesSent int64
	packetsRecv, bytesRecv int64
	packetsDropped         int64

	mu          sync.Mutex
	closed      bool
	accepts     int64
	netConns    map[net.Conn]chan struct{} // chan is closed when conn closes
	clients     map[key.Public]*sclient
	clientsEver map[key.Public]bool // never deleted from, for stats; fine for now
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
		netConns:    make(map[net.Conn]chan struct{}),
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
func (s *Server) Accept(nc net.Conn, brw *bufio.ReadWriter) {
	closed := make(chan struct{})

	s.mu.Lock()
	s.accepts++
	s.netConns[nc] = closed
	s.mu.Unlock()

	defer func() {
		nc.Close()
		close(closed)

		s.mu.Lock()
		delete(s.netConns, nc)
		s.mu.Unlock()
	}()

	if err := s.accept(nc, brw); err != nil && !s.isClosed() {
		s.logf("derp: %s: %v", nc.RemoteAddr(), err)
	}
}

// registerClient notes that client c is now authenticated and ready for packets.
// If c's public key was already connected with a different connection, the prior one is closed.
func (s *Server) registerClient(c *sclient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.clients[c.key]
	if old == nil {
		s.logf("derp: %s: client %x: adding connection", c.nc.RemoteAddr(), c.key)
	} else {
		old.nc.Close()
		s.logf("derp: %s: client %x: adding connection, replacing %s", c.nc.RemoteAddr(), c.key, old.nc.RemoteAddr())
	}
	s.clients[c.key] = c
	s.clientsEver[c.key] = true
}

// unregisterClient removes a client from the server.
func (s *Server) unregisterClient(c *sclient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.clients[c.key]
	if cur == c {
		s.logf("derp: %s: client %x: removing connection", c.nc.RemoteAddr(), c.key)
		delete(s.clients, c.key)
	}
}

func (s *Server) accept(nc net.Conn, brw *bufio.ReadWriter) error {
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
		key: clientKey,
		nc:  nc,
		br:  br,
		bw:  bw,
	}
	if clientInfo != nil {
		c.info = *clientInfo
	}

	// Once the client is registered, it can start receiving
	// traffic, but we want to make sure the first thing it
	// receives after its frameClientInfo is our frameServerInfo,
	// so acquire the c.mu lock (which guards writing to c.bw)
	// while we register.
	c.mu.Lock()
	s.registerClient(c)
	err = s.sendServerInfo(bw, clientKey)
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send server info: %v", err)
	}
	defer s.unregisterClient(c)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.sendClientKeepAlives(ctx, c)

	lim := rate.Inf
	if s.BytesPerSecond != 0 {
		lim = rate.Limit(s.BytesPerSecond)
	}
	const burstBytes = 1 << 20 // generous bandwidth delay product? must be over 64k max packet size.
	limiter := rate.NewLimiter(lim, burstBytes)

	for {
		ft, fl, err := readFrameHeader(c.br)
		if err != nil {
			return fmt.Errorf("client %x: readFrameHeader: %v", c.key, err)
		}
		if ft != frameSendPacket {
			// TODO: nothing else yet supported
			return fmt.Errorf("client %x: unsupported frame %v", c.key, ft)
		}
		dstKey, contents, err := s.recvPacket(ctx, c.br, fl, limiter)
		if err != nil {
			return fmt.Errorf("client %x: recvPacket: %v", c.key, err)
		}

		s.mu.Lock()
		dst := s.clients[dstKey]
		s.mu.Unlock()

		if dst == nil {
			atomic.AddInt64(&s.packetsDropped, 1)
			s.logf("derp: %s: client %x: dropping packet for unknown %x", nc.RemoteAddr(), c.key, dstKey)
			continue
		}

		dst.mu.Lock()
		err = s.sendPacket(dst.bw, c.key, contents)
		dst.mu.Unlock()

		if err != nil {
			s.logf("derp: %s: client %x: dropping packet for %x: %v", nc.RemoteAddr(), c.key, dstKey, err)

			// If we cannot send to a destination, shut it down.
			// Let its receive loop do the cleanup.
			s.mu.Lock()
			if s.clients[dstKey] == dst {
				s.clients[dstKey].nc.Close()
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) sendClientKeepAlives(ctx context.Context, c *sclient) {
	if err := c.keepAliveLoop(ctx); err != nil {
		s.logf("derp: %s: client %x: keep alive failed: %v", c.nc.RemoteAddr(), c.key, err)
	}
}

func (s *Server) verifyClient(clientKey key.Public, info *sclientInfo) error {
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

func (s *Server) sendServerInfo(bw *bufio.Writer, clientKey key.Public) error {
	var nonce [24]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return err
	}
	msg := []byte("{}") // no serverInfo for now
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
func (s *Server) recvClientKey(br *bufio.Reader) (clientKey key.Public, info *sclientInfo, err error) {
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
	info = new(sclientInfo)
	if err := json.Unmarshal(msg, info); err != nil {
		return key.Public{}, nil, fmt.Errorf("msg: %v", err)
	}
	return clientKey, info, nil
}

func (s *Server) sendPacket(bw *bufio.Writer, srcKey key.Public, contents []byte) error {
	atomic.AddInt64(&s.packetsSent, 1)
	atomic.AddInt64(&s.bytesSent, int64(len(contents)))
	if err := writeFrameHeader(bw, frameRecvPacket, uint32(len(contents))); err != nil {
		return err
	}
	if _, err := bw.Write(contents); err != nil {
		return err
	}
	return bw.Flush()
}

func (s *Server) recvPacket(ctx context.Context, br *bufio.Reader, frameLen uint32, limiter *rate.Limiter) (dstKey key.Public, contents []byte, err error) {
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
	if err := limiter.WaitN(ctx, int(packetLen)); err != nil {
		return key.Public{}, nil, fmt.Errorf("rate limit: %v", err)
	}
	contents = make([]byte, packetLen)
	if _, err := io.ReadFull(br, contents); err != nil {
		return key.Public{}, nil, err
	}
	atomic.AddInt64(&s.packetsRecv, 1)
	atomic.AddInt64(&s.bytesRecv, int64(len(contents)))
	return dstKey, contents, nil
}

// sclient is a client connection to the server.
//
// (The "s" prefix is to more explicitly distinguish it from Client in derp_client.go)
type sclient struct {
	nc   net.Conn
	key  key.Public
	info sclientInfo

	keepAliveTimer *time.Timer
	keepAliveReset chan struct{}

	mu sync.Mutex // mu guards writing to bw
	br *bufio.Reader
	bw *bufio.Writer
}

func (c *sclient) keepAliveLoop(ctx context.Context) error {
	jitterMs, err := crand.Int(crand.Reader, big.NewInt(5000))
	if err != nil {
		panic(err)
	}
	jitter := time.Duration(jitterMs.Int64()) * time.Millisecond
	c.keepAliveTimer = time.NewTimer(keepAlive + jitter)
	defer c.keepAliveTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.keepAliveReset:
			if c.keepAliveTimer.Stop() {
				<-c.keepAliveTimer.C
			}
			c.keepAliveTimer.Reset(keepAlive + jitter)
		case <-c.keepAliveTimer.C:
			c.mu.Lock()
			err := writeFrame(c.bw, frameKeepAlive, nil)
			if err == nil {
				err = c.bw.Flush()
			}
			c.mu.Unlock()

			if err != nil {
				c.nc.Close()
				return err
			}
		}
	}
}

// sclientInfo is the client info sent by the client to the server.
type sclientInfo struct {
}

type serverInfo struct {
}

// Stats returns stats about the server.
func (s *Server) Stats() *ServerStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &ServerStats{
		BytesPerSecondLimit: s.BytesPerSecond,
		CurrentConnections:  len(s.netConns),
		UniqueClientsEver:   len(s.clientsEver),
		TotalAccepts:        s.accepts,
		BytesReceived:       atomic.LoadInt64(&s.bytesRecv),
		BytesSent:           atomic.LoadInt64(&s.bytesSent),
		PacketsDropped:      atomic.LoadInt64(&s.packetsDropped),
		PacketsReceived:     atomic.LoadInt64(&s.packetsRecv),
		PacketsSent:         atomic.LoadInt64(&s.packetsSent),
	}
}

// ExpVar returns an expvar variable suitable for registering with expvar.Publish.
func (s *Server) ExpVar() expvar.Var {
	return expVar{s}
}

type expVar struct{ *Server }

// String implements the expvar.Var interface, returning the current server stats as JSON.
func (v expVar) String() string {
	ss := v.Server.Stats()
	j, err := json.MarshalIndent(ss, "", "\t")
	if err != nil {
		return "{}"
	}
	return string(j)
}

// ServerStats are returned by Server.Stats.
//
// It is JSON-ified by expVar for the expvar package.
type ServerStats struct {
	BytesPerSecondLimit int   `json:"bytesPerSecondLimit"`
	CurrentConnections  int   `json:"currentClients"`
	UniqueClientsEver   int   `json:"uniqueClientsEver"`
	TotalAccepts        int64 `json:"totalAccepts"`
	BytesReceived       int64 `json:"bytesReceived"`
	BytesSent           int64 `json:"bytesSent"`
	PacketsDropped      int64 `json:"packetsDropped"`
	PacketsReceived     int64 `json:"packetsReceived"`
	PacketsSent         int64 `json:"packetsSent"`
}
