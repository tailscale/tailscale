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
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"tailscale.com/types/logger"
)

const magic = 0x44c55250 // "DERP" with a non-ASCII high-bit

const (
	typeServerKey  = 0x01
	typeServerInfo = 0x02
	typeSendPacket = 0x03
	typeRecvPacket = 0x04
	typeKeepAlive  = 0x05
)

const keepAlive = 60 * time.Second

var bin = binary.BigEndian

const oneMB = 1 << 20

type Server struct {
	privateKey [32]byte // TODO(crawshaw): make this wgcfg.PrivateKey?
	publicKey  [32]byte
	logf       logger.Logf

	mu       sync.Mutex
	netConns map[net.Conn]chan struct{}
	clients  map[[32]byte]*client
}

func NewServer(privateKey [32]byte, logf logger.Logf) *Server {
	s := &Server{
		privateKey: privateKey,
		logf:       logf,
		clients:    make(map[[32]byte]*client),
		netConns:   make(map[net.Conn]chan struct{}),
	}
	curve25519.ScalarBaseMult(&s.publicKey, &s.privateKey)
	return s
}

func (s *Server) Close() error {
	var closedChs []chan struct{}

	s.mu.Lock()
	for netConn, closed := range s.netConns {
		netConn.Close()
		closedChs = append(closedChs, closed)
	}
	s.mu.Unlock()

	for _, closed := range closedChs {
		<-closed
	}

	return nil
}

func (s *Server) Accept(netConn net.Conn, conn *bufio.ReadWriter) {
	closed := make(chan struct{})

	s.mu.Lock()
	s.netConns[netConn] = closed
	s.mu.Unlock()

	defer func() {
		netConn.Close()
		close(closed)

		s.mu.Lock()
		delete(s.netConns, netConn)
		s.mu.Unlock()
	}()

	if err := s.accept(netConn, conn); err != nil {
		s.logf("derp: %s: %v", netConn.RemoteAddr(), err)
	}
}

func (s *Server) accept(netConn net.Conn, conn *bufio.ReadWriter) error {
	netConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := s.sendServerKey(conn); err != nil {
		return fmt.Errorf("send server key: %v", err)
	}
	netConn.SetDeadline(time.Now().Add(10 * time.Second))
	clientKey, clientInfo, err := s.recvClientKey(conn)
	if err != nil {
		return fmt.Errorf("receive client key: %v", err)
	}
	if err := s.verifyClient(clientKey, clientInfo); err != nil {
		return fmt.Errorf("client %x rejected: %v", clientKey, err)
	}

	// At this point we trust the client so we don't time out.
	netConn.SetDeadline(time.Time{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &client{
		key:     clientKey,
		netConn: netConn,
		conn:    conn,
	}
	if clientInfo != nil {
		c.info = *clientInfo
	}
	go func() {
		if err := c.keepAlive(ctx); err != nil {
			s.logf("derp: %s: client %x: keep alive failed: %v", netConn.RemoteAddr(), c.key, err)
		}
	}()

	defer func() {
		s.mu.Lock()
		curClient := s.clients[c.key]
		if curClient != nil && curClient.conn == conn {
			s.logf("derp: %s: client %x: removing connection", netConn.RemoteAddr(), c.key)
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
	if err := s.sendServerInfo(conn, clientKey); err != nil {
		return fmt.Errorf("send server info: %v", err)
	}
	c.mu.Unlock()

	if oldClient == nil {
		s.logf("derp: %s: client %x: adding connection", netConn.RemoteAddr(), c.key)
	} else {
		oldClient.netConn.Close()
		s.logf("derp: %s: client %x: adding connection, replacing %s", netConn.RemoteAddr(), c.key, oldClient.netConn.RemoteAddr())
	}

	for {
		dstKey, contents, err := s.recvPacket(c.conn)
		if err != nil {
			return fmt.Errorf("client %x: recv: %v", c.key, err)
		}

		s.mu.Lock()
		dst := s.clients[dstKey]
		s.mu.Unlock()

		if dst == nil {
			s.logf("derp: %s: client %x: dropping packet for unknown %x", netConn.RemoteAddr(), c.key, dstKey)
			continue
		}

		dst.mu.Lock()
		err = s.sendPacket(dst.conn, c.key, contents)
		dst.mu.Unlock()

		if err != nil {
			s.logf("derp: %s: client %x: dropping packet for %x: %v", netConn.RemoteAddr(), c.key, dstKey, err)

			// If we cannot send to a destination, shut it down.
			// Let its receive loop do the cleanup.
			s.mu.Lock()
			if s.clients[dstKey].conn == dst.conn {
				s.clients[dstKey].netConn.Close()
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) verifyClient(clientKey [32]byte, info *clientInfo) error {
	// TODO(crawshaw): implement policy constraints on who can use the DERP server
	return nil
}

func (s *Server) sendServerKey(conn *bufio.ReadWriter) error {
	if err := putUint32(conn, magic); err != nil {
		return err
	}
	if err := conn.WriteByte(typeServerKey); err != nil {
		return err
	}
	if _, err := conn.Write(s.publicKey[:]); err != nil {
		return err
	}
	return conn.Flush()
}

func (s *Server) sendServerInfo(conn *bufio.ReadWriter, clientKey [32]byte) error {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	msg := []byte("{}") // no serverInfo for now
	msgbox := box.Seal(nil, msg, &nonce, &clientKey, &s.privateKey)

	if err := conn.WriteByte(typeServerInfo); err != nil {
		return err
	}
	if _, err := conn.Write(nonce[:]); err != nil {
		return err
	}
	if err := putUint32(conn, uint32(len(msgbox))); err != nil {
		return err
	}
	if _, err := conn.Write(msgbox); err != nil {
		return err
	}
	return conn.Flush()
}

func (s *Server) recvClientKey(conn *bufio.ReadWriter) (clientKey [32]byte, info *clientInfo, err error) {
	if _, err := io.ReadFull(conn, clientKey[:]); err != nil {
		return [32]byte{}, nil, err
	}
	var nonce [24]byte
	if _, err := io.ReadFull(conn, nonce[:]); err != nil {
		return [32]byte{}, nil, fmt.Errorf("nonce: %v", err)
	}
	msgLen, err := readUint32(conn, oneMB)
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("msglen: %v", err)
	}
	msgbox := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msgbox); err != nil {
		return [32]byte{}, nil, fmt.Errorf("msgbox: %v", err)
	}
	msg, ok := box.Open(nil, msgbox, &nonce, &clientKey, &s.privateKey)
	if !ok {
		return [32]byte{}, nil, fmt.Errorf("msgbox: cannot open len=%d with client key %x", msgLen, clientKey[:])
	}
	info = new(clientInfo)
	if err := json.Unmarshal(msg, info); err != nil {
		return [32]byte{}, nil, fmt.Errorf("msg: %v", err)
	}
	return clientKey, info, nil
}

func (s *Server) sendPacket(conn *bufio.ReadWriter, srcKey [32]byte, contents []byte) error {
	if err := conn.WriteByte(typeRecvPacket); err != nil {
		return err
	}
	if err := putUint32(conn.Writer, uint32(len(contents))); err != nil {
		return err
	}
	if _, err := conn.Write(contents); err != nil {
		return err
	}
	return conn.Flush()
}

func (s *Server) recvPacket(conn *bufio.ReadWriter) (dstKey [32]byte, contents []byte, err error) {
	if err := readType(conn.Reader, typeSendPacket); err != nil {
		return [32]byte{}, nil, err
	}
	if _, err := io.ReadFull(conn, dstKey[:]); err != nil {
		return [32]byte{}, nil, err
	}
	packetLen, err := readUint32(conn.Reader, oneMB)
	if err != nil {
		return [32]byte{}, nil, err
	}
	contents = make([]byte, packetLen)
	if _, err := io.ReadFull(conn, contents); err != nil {
		return [32]byte{}, nil, err
	}
	return dstKey, contents, nil
}

type client struct {
	netConn net.Conn
	key     [32]byte
	info    clientInfo

	keepAliveTimer *time.Timer
	keepAliveReset chan struct{}

	mu   sync.Mutex
	conn *bufio.ReadWriter
}

func (c *client) keepAlive(ctx context.Context) error {
	jitterMs, err := rand.Int(rand.Reader, big.NewInt(5000))
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
			err := c.conn.WriteByte(typeKeepAlive)
			if err == nil {
				err = c.conn.Flush()
			}
			c.mu.Unlock()

			if err != nil {
				// TODO log
				c.netConn.Close()
				return err
			}
		}
	}
}

type clientInfo struct {
}

type serverInfo struct {
}

func readType(r *bufio.Reader, t uint8) error {
	packetType, err := r.ReadByte()
	if err != nil {
		return err
	}
	if packetType != t {
		return fmt.Errorf("bad packet type 0x%X, want 0x%X", packetType, t)
	}
	return nil
}

func putUint32(w io.Writer, v uint32) error {
	var b [4]byte
	bin.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func readUint32(r io.Reader, maxVal uint32) (uint32, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	val := bin.Uint32(b)
	if val > maxVal {
		return 0, fmt.Errorf("uint32 %d exceeds limit %d", val, maxVal)
	}
	return val, nil
}
