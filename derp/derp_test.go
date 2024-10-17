// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"go4.org/mem"
	"golang.org/x/time/rate"
	"tailscale.com/disco"
	"tailscale.com/net/memnet"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestClientInfoUnmarshal(t *testing.T) {
	for i, in := range []string{
		`{"Version":5,"MeshKey":"abc"}`,
		`{"version":5,"meshKey":"abc"}`,
	} {
		var got clientInfo
		if err := json.Unmarshal([]byte(in), &got); err != nil {
			t.Fatalf("[%d]: %v", i, err)
		}
		want := clientInfo{Version: 5, MeshKey: "abc"}
		if got != want {
			t.Errorf("[%d]: got %+v; want %+v", i, got, want)
		}
	}
}

func TestSendRecv(t *testing.T) {
	serverPrivateKey := key.NewNode()
	s := NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	const numClients = 3
	var clientPrivateKeys []key.NodePrivate
	var clientKeys []key.NodePublic
	for range numClients {
		priv := key.NewNode()
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

	for i := range numClients {
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

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		brwServer := bufio.NewReadWriter(bufio.NewReader(cin), bufio.NewWriter(cin))
		go s.Accept(ctx, cin, brwServer, fmt.Sprintf("[abc::def]:%v", i))

		key := clientPrivateKeys[i]
		brw := bufio.NewReadWriter(bufio.NewReader(cout), bufio.NewWriter(cout))
		c, err := NewClient(key, cout, brw, t.Logf)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		waitConnect(t, c)

		clients = append(clients, c)
		recvChs = append(recvChs, make(chan []byte))
		t.Logf("Connected client %d.", i)
	}

	var peerGoneCountDisconnected expvar.Int
	var peerGoneCountNotHere expvar.Int

	t.Logf("Starting read loops")
	for i := range numClients {
		go func(i int) {
			for {
				m, err := clients[i].Recv()
				if err != nil {
					errCh <- err
					return
				}
				switch m := m.(type) {
				default:
					t.Errorf("unexpected message type %T", m)
					continue
				case PeerGoneMessage:
					switch m.Reason {
					case PeerGoneReasonDisconnected:
						peerGoneCountDisconnected.Add(1)
					case PeerGoneReasonNotHere:
						peerGoneCountNotHere.Add(1)
					default:
						t.Errorf("unexpected PeerGone reason %v", m.Reason)
					}
				case ReceivedPacket:
					if m.Source.IsZero() {
						t.Errorf("zero Source address in ReceivedPacket")
					}
					recvChs[i] <- bytes.Clone(m.Data)
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
		case <-time.After(5 * time.Second):
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
			if got = peerGoneCountDisconnected.Value(); got == want {
				return
			}
		}
		t.Errorf("peer gone count = %v; want %v", got, want)
	}

	wantUnknownPeers := func(want int64) {
		t.Helper()
		var got int64
		dl := time.Now().Add(5 * time.Second)
		for time.Now().Before(dl) {
			if got = peerGoneCountNotHere.Value(); got == want {
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

	// Send messages to a non-existent node
	neKey := key.NewNode().Public()
	msg4 := []byte("not a CallMeMaybe->unknown destination\n")
	if err := clients[1].Send(neKey, msg4); err != nil {
		t.Fatal(err)
	}
	wantUnknownPeers(0)

	callMe := neKey.AppendTo([]byte(disco.Magic))
	callMeHeader := make([]byte, disco.NonceLen)
	callMe = append(callMe, callMeHeader...)
	if err := clients[1].Send(neKey, callMe); err != nil {
		t.Fatal(err)
	}
	wantUnknownPeers(1)

	// PeerGoneNotHere is rate-limited to 3 times a second
	for range 5 {
		if err := clients[1].Send(neKey, callMe); err != nil {
			t.Fatal(err)
		}
	}
	wantUnknownPeers(3)

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
	serverPrivateKey := key.NewNode()
	s := NewServer(serverPrivateKey, t.Logf)
	defer s.Close()
	s.WriteTimeout = 100 * time.Millisecond

	// We send two streams of messages:
	//
	//	alice --> bob
	//	alice --> cathy
	//
	// Then cathy stops processing messages.
	// That should not interfere with alice talking to bob.

	newClient := func(ctx context.Context, name string, k key.NodePrivate) (c *Client, clientConn memnet.Conn) {
		t.Helper()
		c1, c2 := memnet.NewConn(name, 1024)
		go s.Accept(ctx, c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), name)

		brw := bufio.NewReadWriter(bufio.NewReader(c2), bufio.NewWriter(c2))
		c, err := NewClient(k, c2, brw, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		waitConnect(t, c)
		return c, c2
	}

	ctx, clientCtxCancel := context.WithCancel(context.Background())
	defer clientCtxCancel()

	aliceKey := key.NewNode()
	aliceClient, aliceConn := newClient(ctx, "alice", aliceKey)

	bobKey := key.NewNode()
	bobClient, bobConn := newClient(ctx, "bob", bobKey)

	cathyKey := key.NewNode()
	cathyClient, cathyConn := newClient(ctx, "cathy", cathyKey)

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
			m, err := client.Recv()
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
		for range cap(ch) {
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
	// Close bob before alice.
	// Starting with alice can cause a PeerGoneMessage to reach
	// bob before bob is closed, causing a test flake (issue 2668).
	bobConn.Close()
	aliceConn.Close()
	cathyConn.Close()

	for range cap(errCh) {
		err := <-errCh
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
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
	pubName map[key.NodePublic]string
	clients map[*testClient]bool
}

func (ts *testServer) addTestClient(c *testClient) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.clients[c] = true
}

func (ts *testServer) addKeyName(k key.NodePublic, name string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.pubName[k] = name
	ts.logf("test adding named key %q for %x", name, k)
}

func (ts *testServer) keyName(k key.NodePublic) string {
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

func newTestServer(t *testing.T, ctx context.Context) *testServer {
	t.Helper()
	logf := logger.WithPrefix(t.Logf, "derp-server: ")
	s := NewServer(key.NewNode(), logf)
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
				go s.Accept(ctx, c, brwServer, c.RemoteAddr().String())
			}(i)
		}
	}()
	return &testServer{
		s:       s,
		ln:      ln,
		logf:    logf,
		clients: map[*testClient]bool{},
		pubName: map[key.NodePublic]string{},
	}
}

type testClient struct {
	name   string
	c      *Client
	nc     net.Conn
	pub    key.NodePublic
	ts     *testServer
	closed bool
}

func newTestClient(t *testing.T, ts *testServer, name string, newClient func(net.Conn, key.NodePrivate, logger.Logf) (*Client, error)) *testClient {
	t.Helper()
	nc, err := net.Dial("tcp", ts.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	k := key.NewNode()
	ts.addKeyName(k.Public(), name)
	c, err := newClient(nc, k, logger.WithPrefix(t.Logf, "client-"+name+": "))
	if err != nil {
		t.Fatal(err)
	}
	tc := &testClient{
		name: name,
		nc:   nc,
		c:    c,
		ts:   ts,
		pub:  k.Public(),
	}
	ts.addTestClient(tc)
	return tc
}

func newRegularClient(t *testing.T, ts *testServer, name string) *testClient {
	return newTestClient(t, ts, name, func(nc net.Conn, priv key.NodePrivate, logf logger.Logf) (*Client, error) {
		brw := bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
		c, err := NewClient(priv, nc, brw, logf)
		if err != nil {
			return nil, err
		}
		waitConnect(t, c)
		return c, nil

	})
}

func newTestWatcher(t *testing.T, ts *testServer, name string) *testClient {
	return newTestClient(t, ts, name, func(nc net.Conn, priv key.NodePrivate, logf logger.Logf) (*Client, error) {
		brw := bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
		c, err := NewClient(priv, nc, brw, logf, MeshKey("mesh-key"))
		if err != nil {
			return nil, err
		}
		waitConnect(t, c)
		if err := c.WatchConnectionChanges(); err != nil {
			return nil, err
		}
		return c, nil
	})
}

func (tc *testClient) wantPresent(t *testing.T, peers ...key.NodePublic) {
	t.Helper()
	want := map[key.NodePublic]bool{}
	for _, k := range peers {
		want[k] = true
	}

	for {
		m, err := tc.c.recvTimeout(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		switch m := m.(type) {
		case PeerPresentMessage:
			got := m.Key
			if !want[got] {
				t.Fatalf("got peer present for %v; want present for %v", tc.ts.keyName(got), logger.ArgWriter(func(bw *bufio.Writer) {
					for _, pub := range peers {
						fmt.Fprintf(bw, "%s ", tc.ts.keyName(pub))
					}
				}))
			}
			t.Logf("got present with IP %v, flags=%v", m.IPPort, m.Flags)
			switch m.Flags {
			case PeerPresentIsMeshPeer, PeerPresentIsRegular:
				// Okay
			default:
				t.Errorf("unexpected PeerPresentIsMeshPeer flags %v", m.Flags)
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

func (tc *testClient) wantGone(t *testing.T, peer key.NodePublic) {
	t.Helper()
	m, err := tc.c.recvTimeout(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	switch m := m.(type) {
	case PeerGoneMessage:
		got := key.NodePublic(m.Peer)
		if peer != got {
			t.Errorf("got gone message for %v; want gone for %v", tc.ts.keyName(got), tc.ts.keyName(peer))
		}
		reason := m.Reason
		if reason != PeerGoneReasonDisconnected {
			t.Errorf("got gone message for reason %v; wanted %v", reason, PeerGoneReasonDisconnected)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts := newTestServer(t, ctx)
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

func (testFwd) ForwardPacket(key.NodePublic, key.NodePublic, []byte) error {
	panic("not called in tests")
}
func (testFwd) String() string {
	panic("not called in tests")
}

func pubAll(b byte) (ret key.NodePublic) {
	var bs [32]byte
	for i := range bs {
		bs[i] = b
	}
	return key.NodePublicFromRaw32(mem.B(bs[:]))
}

func TestForwarderRegistration(t *testing.T) {
	s := &Server{
		clients:     make(map[key.NodePublic]*clientSet),
		clientsMesh: map[key.NodePublic]PacketForwarder{},
	}
	want := func(want map[key.NodePublic]PacketForwarder) {
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
	singleClient := func(c *sclient) *clientSet {
		cs := &clientSet{}
		cs.activeClient.Store(c)
		return cs
	}

	u1 := pubAll(1)
	u2 := pubAll(2)
	u3 := pubAll(3)

	s.AddPacketForwarder(u1, testFwd(1))
	s.AddPacketForwarder(u2, testFwd(2))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Verify a remove of non-registered forwarder is no-op.
	s.RemovePacketForwarder(u2, testFwd(999))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Verify a remove of non-registered user is no-op.
	s.RemovePacketForwarder(u3, testFwd(1))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Actual removal.
	s.RemovePacketForwarder(u2, testFwd(2))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(1),
	})

	// Adding a dup for a user.
	wantCounter(&s.multiForwarderCreated, 0)
	s.AddPacketForwarder(u1, testFwd(100))
	s.AddPacketForwarder(u1, testFwd(100)) // dup to trigger dup path
	want(map[key.NodePublic]PacketForwarder{
		u1: newMultiForwarder(testFwd(1), testFwd(100)),
	})
	wantCounter(&s.multiForwarderCreated, 1)

	// Removing a forwarder in a multi set that doesn't exist; does nothing.
	s.RemovePacketForwarder(u1, testFwd(55))
	want(map[key.NodePublic]PacketForwarder{
		u1: newMultiForwarder(testFwd(1), testFwd(100)),
	})

	// Removing a forwarder in a multi set that does exist should collapse it away
	// from being a multiForwarder.
	wantCounter(&s.multiForwarderDeleted, 0)
	s.RemovePacketForwarder(u1, testFwd(1))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(100),
	})
	wantCounter(&s.multiForwarderDeleted, 1)

	// Removing an entry for a client that's still connected locally should result
	// in a nil forwarder.
	u1c := &sclient{
		key:  u1,
		logf: logger.Discard,
	}
	s.clients[u1] = singleClient(u1c)
	s.RemovePacketForwarder(u1, testFwd(100))
	want(map[key.NodePublic]PacketForwarder{
		u1: nil,
	})

	// But once that client disconnects, it should go away.
	s.unregisterClient(u1c)
	want(map[key.NodePublic]PacketForwarder{})

	// But if it already has a forwarder, it's not removed.
	s.AddPacketForwarder(u1, testFwd(2))
	s.unregisterClient(u1c)
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(2),
	})

	// Now pretend u1 was already connected locally (so clientsMesh[u1] is nil), and then we heard
	// that they're also connected to a peer of ours. That shouldn't transition the forwarder
	// from nil to the new one, not a multiForwarder.
	s.clients[u1] = singleClient(u1c)
	s.clientsMesh[u1] = nil
	want(map[key.NodePublic]PacketForwarder{
		u1: nil,
	})
	s.AddPacketForwarder(u1, testFwd(3))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(3),
	})
}

type channelFwd struct {
	// id is to ensure that different instances that reference the
	// same channel are not equal, as they are used as keys in the
	// multiForwarder map.
	id int
	c  chan []byte
}

func (f channelFwd) String() string { return "" }
func (f channelFwd) ForwardPacket(_ key.NodePublic, _ key.NodePublic, packet []byte) error {
	f.c <- packet
	return nil
}

func TestMultiForwarder(t *testing.T) {
	received := 0
	var wg sync.WaitGroup
	ch := make(chan []byte)
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		clients:     make(map[key.NodePublic]*clientSet),
		clientsMesh: map[key.NodePublic]PacketForwarder{},
	}
	u := pubAll(1)
	s.AddPacketForwarder(u, channelFwd{1, ch})

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ch:
				received += 1
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			s.AddPacketForwarder(u, channelFwd{2, ch})
			s.AddPacketForwarder(u, channelFwd{3, ch})
			s.RemovePacketForwarder(u, channelFwd{2, ch})
			s.RemovePacketForwarder(u, channelFwd{1, ch})
			s.AddPacketForwarder(u, channelFwd{1, ch})
			s.RemovePacketForwarder(u, channelFwd{3, ch})
			if ctx.Err() != nil {
				return
			}
		}
	}()

	// Number of messages is chosen arbitrarily, just for this loop to
	// run long enough concurrently with {Add,Remove}PacketForwarder loop above.
	numMsgs := 5000
	var fwd PacketForwarder
	for i := range numMsgs {
		s.mu.Lock()
		fwd = s.clientsMesh[u]
		s.mu.Unlock()
		fwd.ForwardPacket(u, u, []byte(strconv.Itoa(i)))
	}

	cancel()
	wg.Wait()
	if received != numMsgs {
		t.Errorf("expected %d messages to be forwarded; got %d", numMsgs, received)
	}
}
func TestMetaCert(t *testing.T) {
	priv := key.NewNode()
	pub := priv.Public()
	s := NewServer(priv, t.Logf)

	certBytes := s.MetaCert()
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatal(err)
	}
	if fmt.Sprint(cert.SerialNumber) != fmt.Sprint(ProtocolVersion) {
		t.Errorf("serial = %v; want %v", cert.SerialNumber, ProtocolVersion)
	}
	if g, w := cert.Subject.CommonName, fmt.Sprintf("derpkey%s", pub.UntypedHexString()); g != w {
		t.Errorf("CommonName = %q; want %q", g, w)
	}
	if n := len(cert.Extensions); n != 1 {
		t.Fatalf("got %d extensions; want 1", n)
	}

	// oidExtensionBasicConstraints is the Basic Constraints ID copied
	// from the x509 package.
	oidExtensionBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}

	if id := cert.Extensions[0].Id; !id.Equal(oidExtensionBasicConstraints) {
		t.Errorf("extension ID = %v; want %v", id, oidExtensionBasicConstraints)
	}
}

type dummyNetConn struct {
	net.Conn
}

func (dummyNetConn) SetReadDeadline(time.Time) error { return nil }

func TestClientRecv(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  any
	}{
		{
			name: "ping",
			input: []byte{
				byte(framePing), 0, 0, 0, 8,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			want: PingMessage{1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			name: "pong",
			input: []byte{
				byte(framePong), 0, 0, 0, 8,
				1, 2, 3, 4, 5, 6, 7, 8,
			},
			want: PongMessage{1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			name: "health_bad",
			input: []byte{
				byte(frameHealth), 0, 0, 0, 3,
				byte('B'), byte('A'), byte('D'),
			},
			want: HealthMessage{Problem: "BAD"},
		},
		{
			name: "health_ok",
			input: []byte{
				byte(frameHealth), 0, 0, 0, 0,
			},
			want: HealthMessage{},
		},
		{
			name: "server_restarting",
			input: []byte{
				byte(frameRestarting), 0, 0, 0, 8,
				0, 0, 0, 1,
				0, 0, 0, 2,
			},
			want: ServerRestartingMessage{
				ReconnectIn: 1 * time.Millisecond,
				TryFor:      2 * time.Millisecond,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				nc:    dummyNetConn{},
				br:    bufio.NewReader(bytes.NewReader(tt.input)),
				logf:  t.Logf,
				clock: &tstest.Clock{},
			}
			got, err := c.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v; want %#v", got, tt.want)
			}
		})
	}
}

func TestClientSendPing(t *testing.T) {
	var buf bytes.Buffer
	c := &Client{
		bw: bufio.NewWriter(&buf),
	}
	if err := c.SendPing([8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		byte(framePing), 0, 0, 0, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("unexpected output\nwrote: % 02x\n want: % 02x", buf.Bytes(), want)
	}
}

func TestClientSendPong(t *testing.T) {
	var buf bytes.Buffer
	c := &Client{
		bw: bufio.NewWriter(&buf),
	}
	if err := c.SendPong([8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		byte(framePong), 0, 0, 0, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("unexpected output\nwrote: % 02x\n want: % 02x", buf.Bytes(), want)
	}
}

func TestServerDupClients(t *testing.T) {
	serverPriv := key.NewNode()
	var s *Server

	clientPriv := key.NewNode()
	clientPub := clientPriv.Public()

	var c1, c2, c3 *sclient
	var clientName map[*sclient]string

	// run starts a new test case and resets clients back to their zero values.
	run := func(name string, dupPolicy dupPolicy, f func(t *testing.T)) {
		s = NewServer(serverPriv, t.Logf)
		s.dupPolicy = dupPolicy
		c1 = &sclient{key: clientPub, logf: logger.WithPrefix(t.Logf, "c1: ")}
		c2 = &sclient{key: clientPub, logf: logger.WithPrefix(t.Logf, "c2: ")}
		c3 = &sclient{key: clientPub, logf: logger.WithPrefix(t.Logf, "c3: ")}
		clientName = map[*sclient]string{
			c1: "c1",
			c2: "c2",
			c3: "c3",
		}
		t.Run(name, f)
	}
	runBothWays := func(name string, f func(t *testing.T)) {
		run(name+"_disablefighters", disableFighters, f)
		run(name+"_lastwriteractive", lastWriterIsActive, f)
	}
	wantSingleClient := func(t *testing.T, want *sclient) {
		t.Helper()
		got, ok := s.clients[want.key]
		if !ok {
			t.Error("no clients for key")
			return
		}
		if got.dup != nil {
			t.Errorf("unexpected dup set for single client")
		}
		cur := got.activeClient.Load()
		if cur != want {
			t.Errorf("active client = %q; want %q", clientName[cur], clientName[want])
		}
		if cur != nil {
			if cur.isDup.Load() {
				t.Errorf("unexpected isDup on singleClient")
			}
			if cur.isDisabled.Load() {
				t.Errorf("unexpected isDisabled on singleClient")
			}
		}
	}
	wantNoClient := func(t *testing.T) {
		t.Helper()
		_, ok := s.clients[clientPub]
		if !ok {
			// Good
			return
		}
		t.Errorf("got client; want empty")
	}
	wantDupSet := func(t *testing.T) *dupClientSet {
		t.Helper()
		cs, ok := s.clients[clientPub]
		if !ok {
			t.Fatal("no set for key; want dup set")
			return nil
		}
		if cs.dup != nil {
			return cs.dup
		}
		t.Fatalf("no dup set for key; want dup set")
		return nil
	}
	wantActive := func(t *testing.T, want *sclient) {
		t.Helper()
		set, ok := s.clients[clientPub]
		if !ok {
			t.Error("no set for key")
			return
		}
		got := set.activeClient.Load()
		if got != want {
			t.Errorf("active client = %q; want %q", clientName[got], clientName[want])
		}
	}
	checkDup := func(t *testing.T, c *sclient, want bool) {
		t.Helper()
		if got := c.isDup.Load(); got != want {
			t.Errorf("client %q isDup = %v; want %v", clientName[c], got, want)
		}
	}
	checkDisabled := func(t *testing.T, c *sclient, want bool) {
		t.Helper()
		if got := c.isDisabled.Load(); got != want {
			t.Errorf("client %q isDisabled = %v; want %v", clientName[c], got, want)
		}
	}
	wantDupConns := func(t *testing.T, want int) {
		t.Helper()
		if got := s.dupClientConns.Value(); got != int64(want) {
			t.Errorf("dupClientConns = %v; want %v", got, want)
		}
	}
	wantDupKeys := func(t *testing.T, want int) {
		t.Helper()
		if got := s.dupClientKeys.Value(); got != int64(want) {
			t.Errorf("dupClientKeys = %v; want %v", got, want)
		}
	}

	// Common case: a single client comes and goes, with no dups.
	runBothWays("one_comes_and_goes", func(t *testing.T) {
		wantNoClient(t)
		s.registerClient(c1)
		wantSingleClient(t, c1)
		s.unregisterClient(c1)
		wantNoClient(t)
	})

	// A still somewhat common case: a single client was
	// connected and then their wifi dies or laptop closes
	// or they switch networks and connect from a
	// different network. They have two connections but
	// it's not very bad. Only their new one is
	// active. The last one, being dead, doesn't send and
	// thus the new one doesn't get disabled.
	runBothWays("small_overlap_replacement", func(t *testing.T) {
		wantNoClient(t)
		s.registerClient(c1)
		wantSingleClient(t, c1)
		wantActive(t, c1)
		wantDupKeys(t, 0)
		wantDupKeys(t, 0)

		s.registerClient(c2) // wifi dies; c2 replacement connects
		wantDupSet(t)
		wantDupConns(t, 2)
		wantDupKeys(t, 1)
		checkDup(t, c1, true)
		checkDup(t, c2, true)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)
		wantActive(t, c2) // sends go to the replacement

		s.unregisterClient(c1) // c1 finally times out
		wantSingleClient(t, c2)
		checkDup(t, c2, false) // c2 is longer a dup
		wantActive(t, c2)
		wantDupConns(t, 0)
		wantDupKeys(t, 0)
	})

	// Key cloning situation with concurrent clients, both trying
	// to write.
	run("concurrent_dups_get_disabled", disableFighters, func(t *testing.T) {
		wantNoClient(t)
		s.registerClient(c1)
		wantSingleClient(t, c1)
		wantActive(t, c1)
		s.registerClient(c2)
		wantDupSet(t)
		wantDupKeys(t, 1)
		wantDupConns(t, 2)
		wantActive(t, c2)
		checkDup(t, c1, true)
		checkDup(t, c2, true)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)

		s.noteClientActivity(c2)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)
		s.noteClientActivity(c1)
		checkDisabled(t, c1, true)
		checkDisabled(t, c2, true)
		wantActive(t, nil)

		s.registerClient(c3)
		wantActive(t, c3)
		checkDisabled(t, c3, false)
		wantDupKeys(t, 1)
		wantDupConns(t, 3)

		s.unregisterClient(c3)
		wantActive(t, nil)
		wantDupKeys(t, 1)
		wantDupConns(t, 2)

		s.unregisterClient(c2)
		wantSingleClient(t, c1)
		wantDupKeys(t, 0)
		wantDupConns(t, 0)
	})

	// Key cloning with an A->B->C->A series instead.
	run("concurrent_dups_three_parties", disableFighters, func(t *testing.T) {
		wantNoClient(t)
		s.registerClient(c1)
		s.registerClient(c2)
		s.registerClient(c3)
		s.noteClientActivity(c1)
		checkDisabled(t, c1, true)
		checkDisabled(t, c2, true)
		checkDisabled(t, c3, true)
		wantActive(t, nil)
	})

	run("activity_promotes_primary_when_nil", disableFighters, func(t *testing.T) {
		wantNoClient(t)

		// Last registered client is the active one...
		s.registerClient(c1)
		wantActive(t, c1)
		s.registerClient(c2)
		wantActive(t, c2)
		s.registerClient(c3)
		s.noteClientActivity(c2)
		wantActive(t, c3)

		// But if the last one goes away, the one with the
		// most recent activity wins.
		s.unregisterClient(c3)
		wantActive(t, c2)
	})

	run("concurrent_dups_three_parties_last_writer", lastWriterIsActive, func(t *testing.T) {
		wantNoClient(t)

		s.registerClient(c1)
		wantActive(t, c1)
		s.registerClient(c2)
		wantActive(t, c2)

		s.noteClientActivity(c1)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)
		wantActive(t, c1)

		s.noteClientActivity(c2)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)
		wantActive(t, c2)

		s.unregisterClient(c2)
		checkDisabled(t, c1, false)
		wantActive(t, c1)
	})
}

func TestLimiter(t *testing.T) {
	rl := rate.NewLimiter(rate.Every(time.Minute), 100)
	for i := range 200 {
		r := rl.Reserve()
		d := r.Delay()
		t.Logf("i=%d, allow=%v, d=%v", i, r.OK(), d)
	}
}

// BenchmarkConcurrentStreams exercises mutex contention on a
// single Server instance with multiple concurrent client flows.
func BenchmarkConcurrentStreams(b *testing.B) {
	serverPrivateKey := key.NewNode()
	s := NewServer(serverPrivateKey, logger.Discard)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for ctx.Err() == nil {
			connIn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				b.Error(err)
				return
			}

			brwServer := bufio.NewReadWriter(bufio.NewReader(connIn), bufio.NewWriter(connIn))
			go s.Accept(ctx, connIn, brwServer, "test-client")
		}
	}()

	newClient := func(t testing.TB) *Client {
		t.Helper()
		connOut, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		t.Cleanup(func() { connOut.Close() })

		k := key.NewNode()

		brw := bufio.NewReadWriter(bufio.NewReader(connOut), bufio.NewWriter(connOut))
		client, err := NewClient(k, connOut, brw, logger.Discard)
		if err != nil {
			b.Fatalf("client: %v", err)
		}
		return client
	}

	b.RunParallel(func(pb *testing.PB) {
		c1, c2 := newClient(b), newClient(b)
		const packetSize = 100
		msg := make([]byte, packetSize)
		for pb.Next() {
			if err := c1.Send(c2.PublicKey(), msg); err != nil {
				b.Fatal(err)
			}
			_, err := c2.Recv()
			if err != nil {
				return
			}
		}
	})
}

func BenchmarkSendRecv(b *testing.B) {
	for _, size := range []int{10, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("msgsize=%d", size), func(b *testing.B) { benchmarkSendRecvSize(b, size) })
	}
}

func benchmarkSendRecvSize(b *testing.B, packetSize int) {
	serverPrivateKey := key.NewNode()
	s := NewServer(serverPrivateKey, logger.Discard)
	defer s.Close()

	k := key.NewNode()
	clientKey := k.Public()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	connOut, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer connOut.Close()

	connIn, err := ln.Accept()
	if err != nil {
		b.Fatal(err)
	}
	defer connIn.Close()

	brwServer := bufio.NewReadWriter(bufio.NewReader(connIn), bufio.NewWriter(connIn))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Accept(ctx, connIn, brwServer, "test-client")

	brw := bufio.NewReadWriter(bufio.NewReader(connOut), bufio.NewWriter(connOut))
	client, err := NewClient(k, connOut, brw, logger.Discard)
	if err != nil {
		b.Fatalf("client: %v", err)
	}

	go func() {
		for {
			_, err := client.Recv()
			if err != nil {
				return
			}
		}
	}()

	msg := make([]byte, packetSize)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := client.Send(clientKey, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteUint32(b *testing.B) {
	w := bufio.NewWriter(io.Discard)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		writeUint32(w, 0x0ba3a)
	}
}

type nopRead struct{}

func (r nopRead) Read(p []byte) (int, error) {
	return len(p), nil
}

var sinkU32 uint32

func BenchmarkReadUint32(b *testing.B) {
	r := bufio.NewReader(nopRead{})
	var err error
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sinkU32, err = readUint32(r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func waitConnect(t testing.TB, c *Client) {
	t.Helper()
	if m, err := c.Recv(); err != nil {
		t.Fatalf("client first Recv: %v", err)
	} else if v, ok := m.(ServerInfoMessage); !ok {
		t.Fatalf("client first Recv was unexpected type %T", v)
	}
}

func TestParseSSOutput(t *testing.T) {
	contents, err := os.ReadFile("testdata/example_ss.txt")
	if err != nil {
		t.Errorf("os.ReadFile(example_ss.txt) failed: %v", err)
	}
	seen := parseSSOutput(string(contents))
	if len(seen) == 0 {
		t.Errorf("parseSSOutput expected non-empty map")
	}
}

type countWriter struct {
	mu     sync.Mutex
	writes int
	bytes  int64
}

func (w *countWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	w.bytes += int64(len(p))
	return len(p), nil
}

func (w *countWriter) Stats() (writes int, bytes int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes, w.bytes
}

func (w *countWriter) ResetStats() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes, w.bytes = 0, 0
}

func TestClientSendRateLimiting(t *testing.T) {
	cw := new(countWriter)
	c := &Client{
		bw:    bufio.NewWriter(cw),
		clock: &tstest.Clock{},
	}
	c.setSendRateLimiter(ServerInfoMessage{})

	pkt := make([]byte, 1000)
	if err := c.send(key.NodePublic{}, pkt); err != nil {
		t.Fatal(err)
	}
	writes1, bytes1 := cw.Stats()
	if writes1 != 1 {
		t.Errorf("writes = %v, want 1", writes1)
	}

	// Flood should all succeed.
	cw.ResetStats()
	for range 1000 {
		if err := c.send(key.NodePublic{}, pkt); err != nil {
			t.Fatal(err)
		}
	}
	writes1K, bytes1K := cw.Stats()
	if writes1K != 1000 {
		t.Logf("writes = %v; want 1000", writes1K)
	}
	if got, want := bytes1K, bytes1*1000; got != want {
		t.Logf("bytes = %v; want %v", got, want)
	}

	// Set a rate limiter
	cw.ResetStats()
	c.setSendRateLimiter(ServerInfoMessage{
		TokenBucketBytesPerSecond: 1,
		TokenBucketBytesBurst:     int(bytes1 * 2),
	})
	for range 1000 {
		if err := c.send(key.NodePublic{}, pkt); err != nil {
			t.Fatal(err)
		}
	}
	writesLimited, bytesLimited := cw.Stats()
	if writesLimited == 0 || writesLimited == writes1K {
		t.Errorf("limited conn's write count = %v; want non-zero, less than 1k", writesLimited)
	}
	if bytesLimited < bytes1*2 || bytesLimited >= bytes1K {
		t.Errorf("limited conn's bytes count = %v; want >=%v, <%v", bytesLimited, bytes1K*2, bytes1K)
	}
}

func TestServerRepliesToPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts := newTestServer(t, ctx)
	defer ts.close(t)

	tc := newRegularClient(t, ts, "alice")

	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 42}

	if err := tc.c.SendPing(data); err != nil {
		t.Fatal(err)
	}

	for {
		m, err := tc.c.recvTimeout(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		switch m := m.(type) {
		case PongMessage:
			if ([8]byte(m)) != data {
				t.Fatalf("got pong %2x; want %2x", [8]byte(m), data)
			}
			return
		}
	}
}
