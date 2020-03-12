// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

import (
	"bufio"
	crand "crypto/rand"
	"net"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func newPrivateKey(t *testing.T) (k key.Private) {
	if _, err := crand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSendRecv(t *testing.T) {
	serverPrivateKey := newPrivateKey(t)
	s := NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	const numClients = 3
	var clientPrivateKeys []key.Private
	var clientKeys []key.Public
	for i := 0; i < numClients; i++ {
		priv := newPrivateKey(t)
		clientPrivateKeys = append(clientPrivateKeys, priv)
		clientKeys = append(clientKeys, priv.Public())
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var clients []*Client
	var connsOut []net.Conn
	var recvChs []chan []byte
	errCh := make(chan error, 3)

	for i := 0; i < numClients; i++ {
		t.Logf("Connecting client %d ...", i)
		cout, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer cout.Close()
		connsOut = append(connsOut, cout)

		cin, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer cin.Close()
		brwServer := bufio.NewReadWriter(bufio.NewReader(cin), bufio.NewWriter(cin))
		go s.Accept(cin, brwServer, fmt.Sprintf("test-client-%d", i))

		key := clientPrivateKeys[i]
		brw := bufio.NewReadWriter(bufio.NewReader(cout), bufio.NewWriter(cout))
		c, err := NewClient(key, cout, brw, t.Logf)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		clients = append(clients, c)
		recvChs = append(recvChs, make(chan []byte))
		t.Logf("Connected client %d.", i)
	}

	t.Logf("Starting read loops")
	for i := 0; i < numClients; i++ {
		go func(i int) {
			for {
				b := make([]byte, 1<<16)
				m, err := clients[i].Recv(b)
				if err != nil {
					errCh <- err
					return
				}
				switch m := m.(type) {
				default:
					t.Errorf("unexpected message type %T", m)
					continue
				case ReceivedPacket:
					if m.Source.IsZero() {
						t.Errorf("zero Source address in ReceivedPacket")
					}
					recvChs[i] <- m.Data
				}
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

	wantActive := func(total, home int64) {
		t.Helper()
		dl := time.Now().Add(5 * time.Second)
		var gotTotal, gotHome int64
		for time.Now().Before(dl) {
			gotTotal, gotHome = s.curClients.Value(), s.curHomeClients.Value()
			if gotTotal == total && gotHome == home {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Errorf("total/home=%v/%v; want %v/%v", gotTotal, gotHome, total, home)
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

	wantActive(3, 0)
	clients[0].NotePreferred(true)
	wantActive(3, 1)
	clients[0].NotePreferred(true)
	wantActive(3, 1)
	clients[0].NotePreferred(false)
	wantActive(3, 0)
	clients[0].NotePreferred(false)
	wantActive(3, 0)
	clients[1].NotePreferred(true)
	wantActive(3, 1)
	connsOut[1].Close()
	wantActive(2, 0)
	clients[2].NotePreferred(true)
	wantActive(2, 1)
	clients[2].NotePreferred(false)
	wantActive(2, 0)
	connsOut[2].Close()
	wantActive(1, 0)

	t.Logf("passed")
	s.Close()
}
