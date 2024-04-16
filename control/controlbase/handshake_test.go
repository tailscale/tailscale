// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlbase

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/memnet"
	"tailscale.com/types/key"
)

func TestHandshake(t *testing.T) {
	var (
		clientConn, serverConn = memnet.NewConn("noise", 128000)
		serverKey              = key.NewMachine()
		clientKey              = key.NewMachine()
		server                 *Conn
		serverErr              = make(chan error, 1)
	)
	go func() {
		var err error
		server, err = Server(context.Background(), serverConn, serverKey, nil)
		serverErr <- err
	}()

	client, err := Client(context.Background(), clientConn, clientKey, serverKey.Public(), testProtocolVersion)
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server connection failed: %v", err)
	}

	if client.HandshakeHash() != server.HandshakeHash() {
		t.Fatal("client and server disagree on handshake hash")
	}

	if client.ProtocolVersion() != int(testProtocolVersion) {
		t.Fatalf("client reporting wrong protocol version %d, want %d", client.ProtocolVersion(), testProtocolVersion)
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
	for range 10 {
		var (
			clientRaw, serverRaw = memnet.NewConn("noise", 128000)
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
			server, err = Server(context.Background(), serverConn, serverKey, nil)
			serverErr <- err
		}()

		client, err := Client(context.Background(), clientConn, clientKey, serverKey.Public(), testProtocolVersion)
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

		server.Close()
		client.Close()
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
	for i := range 101 {
		var (
			clientConn, serverRaw = memnet.NewConn("noise", 128000)
			serverConn            = &readerConn{serverRaw, &tamperReader{serverRaw, i, 0}}
			serverKey             = key.NewMachine()
			clientKey             = key.NewMachine()
			serverErr             = make(chan error, 1)
		)
		go func() {
			_, err := Server(context.Background(), serverConn, serverKey, nil)
			// If the server failed, we have to close the Conn to
			// unblock the client.
			if err != nil {
				serverConn.Close()
			}
			serverErr <- err
		}()

		_, err := Client(context.Background(), clientConn, clientKey, serverKey.Public(), testProtocolVersion)
		if err == nil {
			t.Fatal("client connection succeeded despite tampering")
		}
		if err := <-serverErr; err == nil {
			t.Fatalf("server connection succeeded despite tampering")
		}
	}

	// Tamper with every byte of the server response message.
	for i := range 51 {
		var (
			clientRaw, serverConn = memnet.NewConn("noise", 128000)
			clientConn            = &readerConn{clientRaw, &tamperReader{clientRaw, i, 0}}
			serverKey             = key.NewMachine()
			clientKey             = key.NewMachine()
			serverErr             = make(chan error, 1)
		)
		go func() {
			_, err := Server(context.Background(), serverConn, serverKey, nil)
			serverErr <- err
		}()

		_, err := Client(context.Background(), clientConn, clientKey, serverKey.Public(), testProtocolVersion)
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
	for i := range 30 {
		var (
			clientRaw, serverConn = memnet.NewConn("noise", 128000)
			clientConn            = &readerConn{clientRaw, &tamperReader{clientRaw, 51 + i, 0}}
			serverKey             = key.NewMachine()
			clientKey             = key.NewMachine()
			serverErr             = make(chan error, 1)
		)
		go func() {
			server, err := Server(context.Background(), serverConn, serverKey, nil)
			serverErr <- err
			_, err = io.WriteString(server, strings.Repeat("a", 14))
			serverErr <- err
		}()

		client, err := Client(context.Background(), clientConn, clientKey, serverKey.Public(), testProtocolVersion)
		if err != nil {
			t.Fatalf("client handshake failed: %v", err)
		}
		// The server shouldn't fail, because the tampering took place
		// in its response.
		if err := <-serverErr; err != nil {
			t.Fatalf("server handshake failed: %v", err)
		}

		// The client needs a timeout if the tampering is hitting the length header.
		if i == 1 || i == 2 {
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
	for i := range 30 {
		var (
			clientConn, serverRaw = memnet.NewConn("noise", 128000)
			serverConn            = &readerConn{serverRaw, &tamperReader{serverRaw, 101 + i, 0}}
			serverKey             = key.NewMachine()
			clientKey             = key.NewMachine()
			serverErr             = make(chan error, 1)
		)
		go func() {
			server, err := Server(context.Background(), serverConn, serverKey, nil)
			serverErr <- err
			var bs [100]byte
			// The server needs a timeout if the tampering is hitting the length header.
			if i == 1 || i == 2 {
				server.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			}
			n, err := server.Read(bs[:])
			if n != 0 {
				panic("server got bytes despite tampering")
			} else {
				serverErr <- err
			}
		}()

		client, err := Client(context.Background(), clientConn, clientKey, serverKey.Public(), testProtocolVersion)
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
