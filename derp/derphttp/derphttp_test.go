// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphttp

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/net/netns"
	"tailscale.com/types/key"
)

func init() {
	netns.TestOnlySkipPrivilegedOps()
}

func TestSendRecv(t *testing.T) {
	const numClients = 3
	var serverPrivateKey key.Private
	if _, err := crand.Read(serverPrivateKey[:]); err != nil {
		t.Fatal(err)
	}
	var clientPrivateKeys []key.Private
	for i := 0; i < numClients; i++ {
		var key key.Private
		if _, err := crand.Read(key[:]); err != nil {
			t.Fatal(err)
		}
		clientPrivateKeys = append(clientPrivateKeys, key)
	}
	var clientKeys []key.Public
	for _, privKey := range clientPrivateKeys {
		clientKeys = append(clientKeys, privKey.Public())
	}

	s := derp.NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      Handler(s),
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL := "http://" + ln.Addr().String()
	t.Logf("server URL: %s", serverURL)

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if err == http.ErrServerClosed {
				return
			}
			panic(err)
		}
	}()

	var clients []*Client
	var recvChs []chan []byte
	done := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(done)
		for _, c := range clients {
			c.Close()
		}
		wg.Wait()
	}()
	for i := 0; i < numClients; i++ {
		key := clientPrivateKeys[i]
		c, err := NewClient(key, serverURL, t.Logf)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		if err := c.Connect(context.Background()); err != nil {
			t.Fatalf("client %d Connect: %v", i, err)
		}
		clients = append(clients, c)
		recvChs = append(recvChs, make(chan []byte))

		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				b := make([]byte, 1<<16)
				m, err := c.Recv(b)
				if err != nil {
					t.Logf("client%d: %v", i, err)
					break
				}
				switch m := m.(type) {
				default:
					t.Errorf("unexpected message type %T", m)
					continue
				case derp.PeerGoneMessage:
					// Ignore.
				case derp.ReceivedPacket:
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
