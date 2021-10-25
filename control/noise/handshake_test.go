// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noise

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	tsnettest "tailscale.com/net/nettest"
	"tailscale.com/types/key"
)

func TestHandshake(t *testing.T) {
	var (
		clientConn, serverConn = tsnettest.NewConn("noise", 128000)
		serverKey              = key.NewMachine()
		clientKey              = key.NewMachine()
		server                 *Conn
		serverErr              = make(chan error, 1)
	)
	go func() {
		var err error
		server, err = Server(context.Background(), serverConn, serverKey)
		serverErr <- err
	}()

	client, err := Client(context.Background(), clientConn, clientKey, serverKey.Public())
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server connection failed: %v", err)
	}

	if client.HandshakeHash() != server.HandshakeHash() {
		t.Fatal("client and server disagree on handshake hash")
	}

	if client.ProtocolVersion() != int(protocolVersion) {
		t.Fatalf("client reporting wrong protocol version %d, want %d", client.ProtocolVersion(), protocolVersion)
	}
	if client.ProtocolVersion() != server.ProtocolVersion() {
		t.Fatalf("peers disagree on protocol version, client=%d server=%d", client.ProtocolVersion(), server.ProtocolVersion())
	}
	if client.Peer() != serverKey.Public() {
		t.Fatal("client peer key isn't serverKey")
	}
	if server.Peer() != clientKey.Public() {
		t.Fatal("client peer key isn't serverKey")
	}
}

// Check that handshaking repeatedly with the same long-term keys
// result in different handshake hashes and wire traffic.
func TestNoReuse(t *testing.T) {
	var (
		hashes           = map[[32]byte]bool{}
		clientHandshakes = map[[96]byte]bool{}
		serverHandshakes = map[[48]byte]bool{}
		packets          = map[[32]byte]bool{}
	)
	for i := 0; i < 10; i++ {
		var (
			clientRaw, serverRaw = tsnettest.NewConn("noise", 128000)
			clientBuf, serverBuf bytes.Buffer
			clientConn           = &readerConn{clientRaw, io.TeeReader(clientRaw, &clientBuf)}
			serverConn           = &readerConn{serverRaw, io.TeeReader(serverRaw, &serverBuf)}
			serverKey            = key.NewMachine()
			clientKey            = key.NewMachine()
			server               *Conn
			serverErr            = make(chan error, 1)
		)
		go func() {
			var err error
			server, err = Server(context.Background(), serverConn, serverKey)
			serverErr <- err
		}()

		client, err := Client(context.Background(), clientConn, clientKey, serverKey.Public())
		if err != nil {
			t.Fatalf("client connection failed: %v", err)
		}
		if err := <-serverErr; err != nil {
			t.Fatalf("server connection failed: %v", err)
		}

		var clientHS [96]byte
		copy(clientHS[:], serverBuf.Bytes())
		if clientHandshakes[clientHS] {
			t.Fatal("client handshake seen twice")
		}
		clientHandshakes[clientHS] = true

		var serverHS [48]byte
		copy(serverHS[:], clientBuf.Bytes())
		if serverHandshakes[serverHS] {
			t.Fatal("server handshake seen twice")
		}
		serverHandshakes[serverHS] = true

		clientBuf.Reset()
		serverBuf.Reset()
		cb := sinkReads(client)
		sb := sinkReads(server)

		if hashes[client.HandshakeHash()] {
			t.Fatalf("handshake hash %v seen twice", client.HandshakeHash())
		}
		hashes[client.HandshakeHash()] = true

		// Sending 14 bytes turns into 32 bytes on the wire (+16 for
		// the chacha20poly1305 overhead, +2 length header)
		if _, err := io.WriteString(client, strings.Repeat("a", 14)); err != nil {
			t.Fatalf("client>server write failed: %v", err)
		}
		if _, err := io.WriteString(server, strings.Repeat("b", 14)); err != nil {
			t.Fatalf("server>client write failed: %v", err)
		}

		// Wait for the bytes to be read, so we know they've traveled end to end
		cb.String(14)
		sb.String(14)

		var clientWire, serverWire [32]byte
		copy(clientWire[:], clientBuf.Bytes())
		copy(serverWire[:], serverBuf.Bytes())

		if packets[clientWire] {
			t.Fatalf("client wire traffic seen twice")
		}
		packets[clientWire] = true
		if packets[serverWire] {
			t.Fatalf("server wire traffic seen twice")
		}
		packets[serverWire] = true
	}
}

// tamperReader wraps a reader and mutates the Nth byte.
type tamperReader struct {
	r     io.Reader
	n     int
	total int
}

func (r *tamperReader) Read(bs []byte) (int, error) {
	n, err := r.r.Read(bs)
	if off := r.n - r.total; off >= 0 && off < n {
		bs[off] += 1
	}
	r.total += n
	return n, err
}

func TestTampering(t *testing.T) {
	// Tamper with every byte of the client initiation message.
	for i := 0; i < 101; i++ {
		var (
			clientConn, serverRaw = tsnettest.NewConn("noise", 128000)
			serverConn            = &readerConn{serverRaw, &tamperReader{serverRaw, i, 0}}
			serverKey             = key.NewMachine()
			clientKey             = key.NewMachine()
			serverErr             = make(chan error, 1)
		)
		go func() {
			_, err := Server(context.Background(), serverConn, serverKey)
			// If the server failed, we have to close the Conn to
			// unblock the client.
			if err != nil {
				serverConn.Close()
			}
			serverErr <- err
		}()

		_, err := Client(context.Background(), clientConn, clientKey, serverKey.Public())
		if err == nil {
			t.Fatal("client connection succeeded despite tampering")
		}
		if err := <-serverErr; err == nil {
			t.Fatalf("server connection succeeded despite tampering")
		}
	}

	// Tamper with every byte of the server response message.
	for i := 0; i < 53; i++ {
		var (
			clientRaw, serverConn = tsnettest.NewConn("noise", 128000)
			clientConn            = &readerConn{clientRaw, &tamperReader{clientRaw, i, 0}}
			serverKey             = key.NewMachine()
			clientKey             = key.NewMachine()
			serverErr             = make(chan error, 1)
		)
		go func() {
			_, err := Server(context.Background(), serverConn, serverKey)
			serverErr <- err
		}()

		_, err := Client(context.Background(), clientConn, clientKey, serverKey.Public())
		if err == nil {
			t.Fatal("client connection succeeded despite tampering")
		}
		// The server shouldn't fail, because the tampering took place
		// in its response.
		if err := <-serverErr; err != nil {
			t.Fatalf("server connection failed despite no tampering: %v", err)
		}
	}

	// Tamper with every byte of the first server>client transport message.
	for i := 0; i < 32; i++ {
		var (
			clientRaw, serverConn = tsnettest.NewConn("noise", 128000)
			clientConn            = &readerConn{clientRaw, &tamperReader{clientRaw, 53 + i, 0}}
			serverKey             = key.NewMachine()
			clientKey             = key.NewMachine()
			serverErr             = make(chan error, 1)
		)
		go func() {
			server, err := Server(context.Background(), serverConn, serverKey)
			serverErr <- err
			_, err = io.WriteString(server, strings.Repeat("a", 14))
			serverErr <- err
		}()

		client, err := Client(context.Background(), clientConn, clientKey, serverKey.Public())
		if err != nil {
			t.Fatalf("client handshake failed: %v", err)
		}
		// The server shouldn't fail, because the tampering took place
		// in its response.
		if err := <-serverErr; err != nil {
			t.Fatalf("server handshake failed: %v", err)
		}

		// The client needs a timeout if the tampering is hitting the length header.
		if i == 3 || i == 4 {
			client.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		}

		var bs [100]byte
		n, err := client.Read(bs[:])
		if err == nil {
			t.Fatal("read succeeded despite tampering")
		}
		if n != 0 {
			t.Fatal("conn yielded some bytes despite tampering")
		}
	}

	// Tamper with every byte of the first client>server transport message.
	for i := 0; i < 32; i++ {
		var (
			clientConn, serverRaw = tsnettest.NewConn("noise", 128000)
			serverConn            = &readerConn{serverRaw, &tamperReader{serverRaw, 101 + i, 0}}
			serverKey             = key.NewMachine()
			clientKey             = key.NewMachine()
			serverErr             = make(chan error, 1)
		)
		go func() {
			server, err := Server(context.Background(), serverConn, serverKey)
			serverErr <- err
			var bs [100]byte
			// The server needs a timeout if the tampering is hitting the length header.
			if i == 3 || i == 4 {
				server.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			}
			n, err := server.Read(bs[:])
			if n != 0 {
				panic("server got bytes despite tampering")
			} else {
				serverErr <- err
			}
		}()

		client, err := Client(context.Background(), clientConn, clientKey, serverKey.Public())
		if err != nil {
			t.Fatalf("client handshake failed: %v", err)
		}
		if err := <-serverErr; err != nil {
			t.Fatalf("server handshake failed: %v", err)
		}

		if _, err := io.WriteString(client, strings.Repeat("a", 14)); err != nil {
			t.Fatalf("client>server write failed: %v", err)
		}
		if err := <-serverErr; err == nil {
			t.Fatal("server successfully received bytes despite tampering")
		}
	}
}
