// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

import (
	"bufio"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func TestSendRecv(t *testing.T) {
	const numClients = 3
	var serverPrivateKey [32]byte
	if _, err := rand.Read(serverPrivateKey[:]); err != nil {
		t.Fatal(err)
	}
	var clientPrivateKeys [][32]byte
	for i := 0; i < numClients; i++ {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		clientPrivateKeys = append(clientPrivateKeys, key)
	}
	var clientKeys [][32]byte
	for _, privKey := range clientPrivateKeys {
		var key [32]byte
		curve25519.ScalarBaseMult(&key, &privKey)
		clientKeys = append(clientKeys, key)
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	var clientConns []net.Conn
	for i := 0; i < numClients; i++ {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clientConns = append(clientConns, conn)
	}
	s := NewServer(serverPrivateKey, t.Logf)
	defer s.Close()
	for i := 0; i < numClients; i++ {
		netConn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		conn := bufio.NewReadWriter(bufio.NewReader(netConn), bufio.NewWriter(netConn))
		go s.Accept(netConn, conn)
	}

	var clients []*Client
	var recvChs []chan []byte
	errCh := make(chan error, 3)
	for i := 0; i < numClients; i++ {
		key := clientPrivateKeys[i]
		netConn := clientConns[i]
		conn := bufio.NewReadWriter(bufio.NewReader(netConn), bufio.NewWriter(netConn))
		c, err := NewClient(key, netConn, conn, t.Logf)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		clients = append(clients, c)
		recvChs = append(recvChs, make(chan []byte))

		go func(i int) {
			for {
				b := make([]byte, 1<<16)
				n, err := c.Recv(b)
				if err != nil {
					errCh <- err
					return
				}
				b = b[:n]
				recvChs[i] <- b
			}
		}(i)
	}

	recv := func(i int, want string) {
		t.Helper()
		select {
		case b := <-recvChs[i]:
			if got := string(b); got != want {
				t.Errorf("client1.Recv=%q, want %q", got, want)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("client%d.Recv, got nothing, want %q", i, want)
		}
	}
	recvNothing := func(i int) {
		t.Helper()
		select {
		case b := <-recvChs[0]:
			t.Errorf("client%d.Recv=%q, want nothing", i, string(b))
		default:
		}
	}

	msg1 := []byte("hello 0->1\n")
	if err := clients[0].Send(clientKeys[1], msg1); err != nil {
		t.Fatal(err)
	}
	recv(1, string(msg1))
	recvNothing(0)
	recvNothing(2)

	msg2 := []byte("hello 1->2\n")
	if err := clients[1].Send(clientKeys[2], msg2); err != nil {
		t.Fatal(err)
	}
	recv(2, string(msg2))
	recvNothing(0)
	recvNothing(1)
}
