// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derp

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/nettest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func newPrivateKey(t *testing.T) (k key.Private) {
	t.Helper()
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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var clients []*Client
	var connsOut []Conn
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

	var peerGoneCount expvar.Int

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
				case PeerGoneMessage:
					peerGoneCount.Add(1)
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

	wantClosedPeers := func(want int64) {
		t.Helper()
		var got int64
		dl := time.Now().Add(5 * time.Second)
		for time.Now().Before(dl) {
			if got = peerGoneCount.Value(); got == want {
				return
			}
		}
		t.Errorf("peer gone count = %v; want %v", got, want)
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
	wantClosedPeers(1)
	clients[2].NotePreferred(true)
	wantActive(2, 1)
	clients[2].NotePreferred(false)
	wantActive(2, 0)
	connsOut[2].Close()
	wantActive(1, 0)
	wantClosedPeers(1)

	t.Logf("passed")
	s.Close()

}

func TestSendFreeze(t *testing.T) {
	serverPrivateKey := newPrivateKey(t)
	s := NewServer(serverPrivateKey, t.Logf)
	defer s.Close()
	s.WriteTimeout = 100 * time.Millisecond

	// We send two streams of messages:
	//
	//	alice --> bob
	//	alice --> cathy
	//
	// Then cathy stops processing messsages.
	// That should not interfere with alice talking to bob.

	newClient := func(name string, k key.Private) (c *Client, clientConn nettest.Conn) {
		t.Helper()
		c1, c2 := nettest.NewConn(name, 1024)
		go s.Accept(c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), name)

		brw := bufio.NewReadWriter(bufio.NewReader(c2), bufio.NewWriter(c2))
		c, err := NewClient(k, c2, brw, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		return c, c2
	}

	aliceKey := newPrivateKey(t)
	aliceClient, aliceConn := newClient("alice", aliceKey)

	bobKey := newPrivateKey(t)
	bobClient, bobConn := newClient("bob", bobKey)

	cathyKey := newPrivateKey(t)
	cathyClient, cathyConn := newClient("cathy", cathyKey)

	var (
		aliceCh = make(chan struct{}, 32)
		bobCh   = make(chan struct{}, 32)
		cathyCh = make(chan struct{}, 32)
	)
	chs := func(name string) chan struct{} {
		switch name {
		case "alice":
			return aliceCh
		case "bob":
			return bobCh
		case "cathy":
			return cathyCh
		default:
			panic("unknown ch: " + name)
		}
	}

	errCh := make(chan error, 4)
	recv := func(name string, client *Client) {
		ch := chs(name)
		for {
			b := make([]byte, 1<<9)
			m, err := client.Recv(b)
			if err != nil {
				errCh <- fmt.Errorf("%s: %w", name, err)
				return
			}
			switch m := m.(type) {
			default:
				errCh <- fmt.Errorf("%s: unexpected message type %T", name, m)
				return
			case ReceivedPacket:
				if m.Source.IsZero() {
					errCh <- fmt.Errorf("%s: zero Source address in ReceivedPacket", name)
					return
				}
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
	go recv("alice", aliceClient)
	go recv("bob", bobClient)
	go recv("cathy", cathyClient)

	var cancel func()
	go func() {
		t := time.NewTicker(2 * time.Millisecond)
		defer t.Stop()
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		for {
			select {
			case <-t.C:
			case <-ctx.Done():
				errCh <- nil
				return
			}

			msg1 := []byte("hello alice->bob\n")
			if err := aliceClient.Send(bobKey.Public(), msg1); err != nil {
				errCh <- fmt.Errorf("alice send to bob: %w", err)
				return
			}
			msg2 := []byte("hello alice->cathy\n")

			// TODO: an error is expected here.
			// We ignore it, maybe we should log it somehow?
			aliceClient.Send(cathyKey.Public(), msg2)
		}
	}()

	drainAny := func(ch chan struct{}) {
		// We are draining potentially infinite sources,
		// so place some reasonable upper limit.
		//
		// The important thing here is to make sure that
		// if any tokens remain in the channel, they
		// must have been generated after drainAny was
		// called.
		for i := 0; i < cap(ch); i++ {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
	drain := func(t *testing.T, name string) bool {
		t.Helper()
		timer := time.NewTimer(1 * time.Second)
		defer timer.Stop()

		// Ensure ch has at least one element.
		ch := chs(name)
		select {
		case <-ch:
		case <-timer.C:
			t.Errorf("no packet received by %s", name)
			return false
		}
		// Drain remaining.
		drainAny(ch)
		return true
	}
	isEmpty := func(t *testing.T, name string) {
		t.Helper()
		select {
		case <-chs(name):
			t.Errorf("packet received by %s, want none", name)
		default:
		}
	}

	t.Run("initial send", func(t *testing.T) {
		drain(t, "bob")
		drain(t, "cathy")
		isEmpty(t, "alice")
	})

	t.Run("block cathy", func(t *testing.T) {
		// Block cathy. Now the cathyConn buffer will fill up quickly,
		// and the derp server will back up.
		cathyConn.SetReadBlock(true)
		time.Sleep(2 * s.WriteTimeout)

		drain(t, "bob")
		drainAny(chs("cathy"))
		isEmpty(t, "alice")

		// Now wait a little longer, and ensure packets still flow to bob
		if !drain(t, "bob") {
			t.Errorf("connection alice->bob frozen by alice->cathy")
		}
	})

	// Cleanup, make sure we process all errors.
	t.Logf("TEST COMPLETE, cancelling sender")
	cancel()
	t.Logf("closing connections")
	aliceConn.Close()
	bobConn.Close()
	cathyConn.Close()

	for i := 0; i < cap(errCh); i++ {
		err := <-errCh
		if err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			t.Error(err)
		}
	}
}

type testServer struct {
	s    *Server
	ln   net.Listener
	logf logger.Logf

	mu      sync.Mutex
	pubName map[key.Public]string
	clients map[*testClient]bool
}

func (ts *testServer) addTestClient(c *testClient) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.clients[c] = true
}

func (ts *testServer) addKeyName(k key.Public, name string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.pubName[k] = name
	ts.logf("test adding named key %q for %x", name, k)
}

func (ts *testServer) keyName(k key.Public) string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if name, ok := ts.pubName[k]; ok {
		return name
	}
	return k.ShortString()
}

func (ts *testServer) close(t *testing.T) error {
	ts.ln.Close()
	ts.s.Close()
	for c := range ts.clients {
		c.close(t)
	}
	return nil
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	logf := logger.WithPrefix(t.Logf, "derp-server: ")
	s := NewServer(newPrivateKey(t), logf)
	s.SetMeshKey("mesh-key")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		i := 0
		for {
			i++
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// TODO: register c in ts so Close also closes it?
			go func(i int) {
				brwServer := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
				go s.Accept(c, brwServer, fmt.Sprintf("test-client-%d", i))
			}(i)
		}
	}()
	return &testServer{
		s:       s,
		ln:      ln,
		logf:    logf,
		clients: map[*testClient]bool{},
		pubName: map[key.Public]string{},
	}
}

type testClient struct {
	name   string
	c      *Client
	nc     net.Conn
	pub    key.Public
	ts     *testServer
	closed bool
}

func newTestClient(t *testing.T, ts *testServer, name string, newClient func(net.Conn, key.Private, logger.Logf) (*Client, error)) *testClient {
	t.Helper()
	nc, err := net.Dial("tcp", ts.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	key := newPrivateKey(t)
	ts.addKeyName(key.Public(), name)
	c, err := newClient(nc, key, logger.WithPrefix(t.Logf, "client-"+name+": "))
	if err != nil {
		t.Fatal(err)
	}
	tc := &testClient{
		name: name,
		nc:   nc,
		c:    c,
		ts:   ts,
		pub:  key.Public(),
	}
	ts.addTestClient(tc)
	return tc
}

func newRegularClient(t *testing.T, ts *testServer, name string) *testClient {
	return newTestClient(t, ts, name, func(nc net.Conn, priv key.Private, logf logger.Logf) (*Client, error) {
		brw := bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
		return NewClient(priv, nc, brw, logf)
	})
}

func newTestWatcher(t *testing.T, ts *testServer, name string) *testClient {
	return newTestClient(t, ts, name, func(nc net.Conn, priv key.Private, logf logger.Logf) (*Client, error) {
		brw := bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
		c, err := NewClient(priv, nc, brw, logf, MeshKey("mesh-key"))
		if err != nil {
			return nil, err
		}
		if err := c.WatchConnectionChanges(); err != nil {
			return nil, err
		}
		return c, nil
	})
}

func (tc *testClient) wantPresent(t *testing.T, peers ...key.Public) {
	t.Helper()
	want := map[key.Public]bool{}
	for _, k := range peers {
		want[k] = true
	}

	var buf [64 << 10]byte
	for {
		m, err := tc.c.recvTimeout(buf[:], time.Second)
		if err != nil {
			t.Fatal(err)
		}
		switch m := m.(type) {
		case PeerPresentMessage:
			got := key.Public(m)
			if !want[got] {
				t.Fatalf("got peer present for %v; want present for %v", tc.ts.keyName(got), logger.ArgWriter(func(bw *bufio.Writer) {
					for _, pub := range peers {
						fmt.Fprintf(bw, "%s ", tc.ts.keyName(pub))
					}
				}))
			}
			delete(want, got)
			if len(want) == 0 {
				return
			}
		default:
			t.Fatalf("unexpected message type %T", m)
		}
	}
}

func (tc *testClient) wantGone(t *testing.T, peer key.Public) {
	t.Helper()
	var buf [64 << 10]byte
	m, err := tc.c.recvTimeout(buf[:], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	switch m := m.(type) {
	case PeerGoneMessage:
		got := key.Public(m)
		if peer != got {
			t.Errorf("got gone message for %v; want gone for %v", tc.ts.keyName(got), tc.ts.keyName(peer))
		}
	default:
		t.Fatalf("unexpected message type %T", m)
	}
}

func (c *testClient) close(t *testing.T) {
	t.Helper()
	if c.closed {
		return
	}
	c.closed = true
	t.Logf("closing client %q (%x)", c.name, c.pub)
	c.nc.Close()
}

// TestWatch tests the connection watcher mechanism used by regional
// DERP nodes to mesh up with each other.
func TestWatch(t *testing.T) {
	ts := newTestServer(t)
	defer ts.close(t)

	w1 := newTestWatcher(t, ts, "w1")
	w1.wantPresent(t, w1.pub)

	c1 := newRegularClient(t, ts, "c1")
	w1.wantPresent(t, c1.pub)

	c2 := newRegularClient(t, ts, "c2")
	w1.wantPresent(t, c2.pub)

	w2 := newTestWatcher(t, ts, "w2")
	w1.wantPresent(t, w2.pub)
	w2.wantPresent(t, w1.pub, w2.pub, c1.pub, c2.pub)

	c3 := newRegularClient(t, ts, "c3")
	w1.wantPresent(t, c3.pub)
	w2.wantPresent(t, c3.pub)

	c2.close(t)
	w1.wantGone(t, c2.pub)
	w2.wantGone(t, c2.pub)

	w3 := newTestWatcher(t, ts, "w3")
	w1.wantPresent(t, w3.pub)
	w2.wantPresent(t, w3.pub)
	w3.wantPresent(t, c1.pub, c3.pub, w1.pub, w2.pub, w3.pub)

	c1.close(t)
	w1.wantGone(t, c1.pub)
	w2.wantGone(t, c1.pub)
	w3.wantGone(t, c1.pub)
}

type testFwd int

func (testFwd) ForwardPacket(key.Public, key.Public, []byte) error { panic("not called in tests") }

func pubAll(b byte) (ret key.Public) {
	for i := range ret {
		ret[i] = b
	}
	return
}

func TestForwarderRegistration(t *testing.T) {
	s := &Server{
		clients:     make(map[key.Public]*sclient),
		clientsMesh: map[key.Public]PacketForwarder{},
	}
	want := func(want map[key.Public]PacketForwarder) {
		t.Helper()
		if got := s.clientsMesh; !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch\n got: %v\nwant: %v\n", got, want)
		}
	}
	wantCounter := func(c *expvar.Int, want int) {
		t.Helper()
		if got := c.Value(); got != int64(want) {
			t.Errorf("counter = %v; want %v", got, want)
		}
	}

	u1 := pubAll(1)
	u2 := pubAll(2)
	u3 := pubAll(3)

	s.AddPacketForwarder(u1, testFwd(1))
	s.AddPacketForwarder(u2, testFwd(2))
	want(map[key.Public]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Verify a remove of non-registered forwarder is no-op.
	s.RemovePacketForwarder(u2, testFwd(999))
	want(map[key.Public]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Verify a remove of non-registered user is no-op.
	s.RemovePacketForwarder(u3, testFwd(1))
	want(map[key.Public]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Actual removal.
	s.RemovePacketForwarder(u2, testFwd(2))
	want(map[key.Public]PacketForwarder{
		u1: testFwd(1),
	})

	// Adding a dup for a user.
	wantCounter(&s.multiForwarderCreated, 0)
	s.AddPacketForwarder(u1, testFwd(100))
	want(map[key.Public]PacketForwarder{
		u1: multiForwarder{
			testFwd(1):   1,
			testFwd(100): 2,
		},
	})
	wantCounter(&s.multiForwarderCreated, 1)

	// Removing a forwarder in a multi set that doesn't exist; does nothing.
	s.RemovePacketForwarder(u1, testFwd(55))
	want(map[key.Public]PacketForwarder{
		u1: multiForwarder{
			testFwd(1):   1,
			testFwd(100): 2,
		},
	})

	// Removing a forwarder in a multi set that does exist should collapse it away
	// from being a multiForwarder.
	wantCounter(&s.multiForwarderDeleted, 0)
	s.RemovePacketForwarder(u1, testFwd(1))
	want(map[key.Public]PacketForwarder{
		u1: testFwd(100),
	})
	wantCounter(&s.multiForwarderDeleted, 1)

	// Removing an entry for a client that's still connected locally should result
	// in a nil forwarder.
	u1c := &sclient{
		key:  u1,
		logf: logger.Discard,
	}
	s.clients[u1] = u1c
	s.RemovePacketForwarder(u1, testFwd(100))
	want(map[key.Public]PacketForwarder{
		u1: nil,
	})

	// But once that client disconnects, it should go away.
	s.unregisterClient(u1c)
	want(map[key.Public]PacketForwarder{})

	// But if it already has a forwarder, it's not removed.
	s.AddPacketForwarder(u1, testFwd(2))
	s.unregisterClient(u1c)
	want(map[key.Public]PacketForwarder{
		u1: testFwd(2),
	})
}
