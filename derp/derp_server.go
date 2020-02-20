// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

// TODO(crawshaw): revise protocol so unknown type packets have a predictable length for skipping.
// TODO(crawshaw): send srcKey with packets to clients?
// TODO(crawshaw): with predefined serverKey in clients and HMAC on packets we could skip TLS

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// Server is a DERP server.
type Server struct {
	privateKey key.Private
	publicKey  key.Public
	logf       logger.Logf

	mu       sync.Mutex
	netConns map[net.Conn]chan struct{} // chan is closed when conn closes
	clients  map[key.Public]*sclient
}

// NewServer returns a new DERP server. It doesn't listen on its own.
// Connections are given to it via Server.Accept.
func NewServer(privateKey key.Private, logf logger.Logf) *Server {
	s := &Server{
		privateKey: privateKey,
		publicKey:  privateKey.Public(),
		logf:       logf,
		clients:    make(map[key.Public]*sclient),
		netConns:   make(map[net.Conn]chan struct{}),
	}
	return s
}

// Close closes the server and waits for the connections to disconnect.
func (s *Server) Close() error {
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

// Accept adds a new connection to the server.
// The provided bufio ReadWriter must be already connected to nc.
// Accept blocks until the Server is closed or the connection closes
// on its own.
func (s *Server) Accept(nc net.Conn, brw *bufio.ReadWriter) {
	closed := make(chan struct{})

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

	if err := s.accept(nc, brw); err != nil {
		s.logf("derp: %s: %v", nc.RemoteAddr(), err)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &sclient{
		key: clientKey,
		nc:  nc,
		br:  br,
		bw:  bw,
	}
	if clientInfo != nil {
		c.info = *clientInfo
	}
	go func() {
		if err := c.keepAlive(ctx); err != nil {
			s.logf("derp: %s: client %x: keep alive failed: %v", nc.RemoteAddr(), c.key, err)
		}
	}()

	defer func() {
		s.mu.Lock()
		curClient := s.clients[c.key]
		if curClient != nil && curClient.nc == nc {
			s.logf("derp: %s: client %x: removing connection", nc.RemoteAddr(), c.key)
			delete(s.clients, c.key)
		}
		s.mu.Unlock()
	}()

	// Hold mu while we add the new client to the clients list and under
	// the same acquisition send server info. This ensure that both:
	// 1. by the time the client receives the server info, it can be addressed.
	// 2. the server info is the very first
	c.mu.Lock()
	s.mu.Lock()
	oldClient := s.clients[c.key]
	s.clients[c.key] = c
	s.mu.Unlock()
	if err := s.sendServerInfo(c.bw, clientKey); err != nil {
		return fmt.Errorf("send server info: %v", err)
	}
	c.mu.Unlock()

	if oldClient == nil {
		s.logf("derp: %s: client %x: adding connection", nc.RemoteAddr(), c.key)
	} else {
		oldClient.nc.Close()
		s.logf("derp: %s: client %x: adding connection, replacing %s", nc.RemoteAddr(), c.key, oldClient.nc.RemoteAddr())
	}

	for {
		dstKey, contents, err := s.recvPacket(c.br)
		if err != nil {
			return fmt.Errorf("client %x: recv: %v", c.key, err)
		}

		s.mu.Lock()
		dst := s.clients[dstKey]
		s.mu.Unlock()

		if dst == nil {
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

func (s *Server) verifyClient(clientKey key.Public, info *sclientInfo) error {
	// TODO(crawshaw): implement policy constraints on who can use the DERP server
	return nil
}

func (s *Server) sendServerKey(bw *bufio.Writer) error {
	if err := putUint32(bw, magic); err != nil {
		return err
	}
	if err := typeServerKey.Write(bw); err != nil {
		return err
	}
	if _, err := bw.Write(s.publicKey[:]); err != nil {
		return err
	}
	return bw.Flush()
}

func (s *Server) sendServerInfo(bw *bufio.Writer, clientKey key.Public) error {
	var nonce [24]byte
	if _, err := crand.Read(nonce[:]); err != nil {
		return err
	}
	msg := []byte("{}") // no serverInfo for now
	msgbox := box.Seal(nil, msg, &nonce, clientKey.B32(), s.privateKey.B32())

	if err := typeServerInfo.Write(bw); err != nil {
		return err
	}
	if _, err := bw.Write(nonce[:]); err != nil {
		return err
	}
	if err := putUint32(bw, uint32(len(msgbox))); err != nil {
		return err
	}
	if _, err := bw.Write(msgbox); err != nil {
		return err
	}
	return bw.Flush()
}

// recvClientKey reads the client's hello (its proof of identity) upon its initial connection.
// It should be considered especially untrusted at this point.
func (s *Server) recvClientKey(br *bufio.Reader) (clientKey key.Public, info *sclientInfo, err error) {
	if _, err := io.ReadFull(br, clientKey[:]); err != nil {
		return key.Public{}, nil, err
	}
	var nonce [24]byte
	if _, err := io.ReadFull(br, nonce[:]); err != nil {
		return key.Public{}, nil, fmt.Errorf("nonce: %v", err)
	}
	// We don't trust the client at all yet, so limit its input size to limit
	// things like JSON resource exhausting (http://github.com/golang/go/issues/31789).
	msgLen, err := readUint32(br, 256<<10)
	if err != nil {
		return key.Public{}, nil, fmt.Errorf("msglen: %v", err)
	}
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
	if err := typeRecvPacket.Write(bw); err != nil {
		return err
	}
	if err := putUint32(bw, uint32(len(contents))); err != nil {
		return err
	}
	if _, err := bw.Write(contents); err != nil {
		return err
	}
	return bw.Flush()
}

func (s *Server) recvPacket(br *bufio.Reader) (dstKey key.Public, contents []byte, err error) {
	if err := readType(br, typeSendPacket); err != nil {
		return key.Public{}, nil, err
	}
	if _, err := io.ReadFull(br, dstKey[:]); err != nil {
		return key.Public{}, nil, err
	}
	packetLen, err := readUint32(br, oneMB)
	if err != nil {
		return key.Public{}, nil, err
	}
	contents = make([]byte, packetLen)
	if _, err := io.ReadFull(br, contents); err != nil {
		return key.Public{}, nil, err
	}
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

func (c *sclient) keepAlive(ctx context.Context) error {
	jitterMs, err := crand.Int(crand.Reader, big.NewInt(5000))
	if err != nil {
		panic(err)
	}
	jitter := time.Duration(jitterMs.Int64()) * time.Millisecond
	c.keepAliveTimer = time.NewTimer(keepAlive + jitter)

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
			err := typeKeepAlive.Write(c.bw)
			if err == nil {
				err = c.bw.Flush()
			}
			c.mu.Unlock()

			if err != nil {
				// TODO log
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
