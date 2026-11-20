// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package pumptcp

import (
	"bytes"
	"io"
	"net"
	"testing"

	"tailscale.com/types/nettype"
	"tailscale.com/util/must"
)

func TestCopy(t *testing.T) {
	// makePeer makes a "peer", ie. an approximation of a computer that we are
	// talking to over a TCP connection.
	// peer is the end that we use to pretend to be the other computer.
	// proxy is the end that we use to talk to the other computer.
	makePeer := func() (peer, proxy net.Conn, cleanup func()) {
		t.Helper()
		ln := must.Get(net.Listen("tcp", "127.0.0.1:0"))
		peerCh := make(chan net.Conn, 1)
		go func() {
			peerCh <- must.Get(ln.Accept())
		}()
		proxy = must.Get(net.Dial("tcp", ln.Addr().String()))
		peer = <-peerCh
		return peer, proxy, func() {
			ln.Close()
			peer.Close()
			proxy.Close()
		}
	}

	// Create a "backend" server to forward connections to.
	backend, toBackend, cleanupBackend := makePeer()
	defer cleanupBackend()

	// Backend server reads a request and sends back a response.
	// Requests and responses are sufficiently long to notice an
	// incomplete read.
	request := bytes.Repeat([]byte("q"), 1<<20)
	response := bytes.Repeat([]byte("r"), 1<<20)
	go func() {
		got, err := io.ReadAll(backend)
		if err != nil {
			t.Fatalf("backend read: %v", err)
		}
		if !bytes.Equal(got, request) {
			t.Fatalf("backend read: expected request length %v, got %v", len(request), len(got))
		}
		if _, err = backend.Write(response); err != nil {
			t.Fatalf("backend write: %v", err)
		}
		backend.Close()
	}()

	// Create a "client" to receive a connection from.
	client, toClient, cleanupClient := makePeer()
	defer cleanupClient()

	// Client server does the opposite of the backend server;
	// first writes a request and then writes a response.
	// It half-closes its write end after it's done writing to
	// test [Copy].
	go func() {
		if _, err := client.Write(request); err != nil {
			t.Fatalf("client write: %v", err)
		}
		if err := client.(nettype.TCPWriteCloser).CloseWrite(); err != nil {
			t.Fatalf("client closewrite: %v", err)
		}
		got, err := io.ReadAll(client)
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		if !bytes.Equal(got, response) {
			t.Fatalf("client read: expected response length %v, got %v", len(response), len(got))
		}
	}()

	// Test the actual pumping functionality, by connecting
	// the two proxies together.
	errc := make(chan error, 2)
	go func() { errc <- Copy(toBackend, toClient, "backend <- client") }()
	go func() { errc <- Copy(toClient, toBackend, "client <- backend") }()

	for range 2 {
		err := <-errc
		if err != nil {
			t.Fatalf("Copy: %v", err)
		}
	}
}
