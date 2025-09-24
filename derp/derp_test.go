// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/disco"
	"tailscale.com/metrics"
	"tailscale.com/net/memnet"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

type (
	ClientInfo = derp.ClientInfo
	Conn       = derp.Conn
	Client     = derp.Client
)

func TestClientInfoUnmarshal(t *testing.T) {
	for i, in := range map[string]struct {
		json    string
		want    *ClientInfo
		wantErr string
	}{
		"empty": {
			json: `{}`,
			want: &ClientInfo{},
		},
		"valid": {
			json: `{"Version":5,"MeshKey":"6d529e9d4ef632d22d4a4214cb49da8f1ba1b72697061fb24e312984c35ec8d8"}`,
			want: &ClientInfo{MeshKey: must.Get(key.ParseDERPMesh("6d529e9d4ef632d22d4a4214cb49da8f1ba1b72697061fb24e312984c35ec8d8")), Version: 5},
		},
		"validLowerMeshKey": {
			json: `{"version":5,"meshKey":"6d529e9d4ef632d22d4a4214cb49da8f1ba1b72697061fb24e312984c35ec8d8"}`,
			want: &ClientInfo{MeshKey: must.Get(key.ParseDERPMesh("6d529e9d4ef632d22d4a4214cb49da8f1ba1b72697061fb24e312984c35ec8d8")), Version: 5},
		},
		"invalidMeshKeyToShort": {
			json:    `{"version":5,"meshKey":"abcdefg"}`,
			wantErr: "invalid mesh key",
		},
		"invalidMeshKeyToLong": {
			json:    `{"version":5,"meshKey":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`,
			wantErr: "invalid mesh key",
		},
	} {
		t.Run(i, func(t *testing.T) {
			t.Parallel()
			var got ClientInfo
			err := json.Unmarshal([]byte(in.json), &got)
			if in.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), in.wantErr) {
					t.Errorf("Unmarshal(%q) = %v, want error containing %q", in.json, err, in.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal(%q) = %v, want no error", in.json, err)
			}
			if !got.Equal(in.want) {
				t.Errorf("Unmarshal(%q) = %+v, want %+v", in.json, got, in.want)
			}
		})
	}
}

func TestSendRecv(t *testing.T) {
	serverPrivateKey := key.NewNode()
	s := derpserver.New(serverPrivateKey, t.Logf)
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
		c, err := derp.NewClient(key, cout, brw, t.Logf)
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
				case derp.PeerGoneMessage:
					switch m.Reason {
					case derp.PeerGoneReasonDisconnected:
						peerGoneCountDisconnected.Add(1)
					case derp.PeerGoneReasonNotHere:
						peerGoneCountNotHere.Add(1)
					default:
						t.Errorf("unexpected PeerGone reason %v", m.Reason)
					}
				case derp.ReceivedPacket:
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

	serverMetrics := s.ExpVar().(*metrics.Set)

	wantActive := func(total, home int64) {
		t.Helper()
		dl := time.Now().Add(5 * time.Second)
		var gotTotal, gotHome int64
		for time.Now().Before(dl) {
			gotTotal = serverMetrics.Get("gauge_current_connections").(*expvar.Int).Value()
			gotHome = serverMetrics.Get("gauge_current_home_connections").(*expvar.Int).Value()
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
	s := derpserver.New(serverPrivateKey, t.Logf)
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
		c, err := derp.NewClient(k, c2, brw, t.Logf)
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
			case derp.ReceivedPacket:
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
	s    *derpserver.Server
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

const testMeshKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T, ctx context.Context) *testServer {
	t.Helper()
	logf := logger.WithPrefix(t.Logf, "derp-server: ")
	s := derpserver.New(key.NewNode(), logf)
	s.SetMeshKey(testMeshKey)
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
		c, err := derp.NewClient(priv, nc, brw, logf)
		if err != nil {
			return nil, err
		}
		waitConnect(t, c)
		return c, nil

	})
}

func newTestWatcher(t *testing.T, ts *testServer, name string) *testClient {
	return newTestClient(t, ts, name, func(nc net.Conn, priv key.NodePrivate, logf logger.Logf) (*Client, error) {
		mk, err := key.ParseDERPMesh(testMeshKey)
		if err != nil {
			return nil, err
		}
		brw := bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
		c, err := derp.NewClient(priv, nc, brw, logf, derp.MeshKey(mk))
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
		m, err := tc.c.RecvTimeoutForTest(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		switch m := m.(type) {
		case derp.PeerPresentMessage:
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
			case derp.PeerPresentIsMeshPeer, derp.PeerPresentIsRegular:
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
	m, err := tc.c.RecvTimeoutForTest(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	switch m := m.(type) {
	case derp.PeerGoneMessage:
		got := key.NodePublic(m.Peer)
		if peer != got {
			t.Errorf("got gone message for %v; want gone for %v", tc.ts.keyName(got), tc.ts.keyName(peer))
		}
		reason := m.Reason
		if reason != derp.PeerGoneReasonDisconnected {
			t.Errorf("got gone message for reason %v; wanted %v", reason, derp.PeerGoneReasonDisconnected)
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

func waitConnect(t testing.TB, c *Client) {
	t.Helper()
	if m, err := c.Recv(); err != nil {
		t.Fatalf("client first Recv: %v", err)
	} else if v, ok := m.(derp.ServerInfoMessage); !ok {
		t.Fatalf("client first Recv was unexpected type %T", v)
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
		m, err := tc.c.RecvTimeoutForTest(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		switch m := m.(type) {
		case derp.PongMessage:
			if ([8]byte(m)) != data {
				t.Fatalf("got pong %2x; want %2x", [8]byte(m), data)
			}
			return
		}
	}
}
