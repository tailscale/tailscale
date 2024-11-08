// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/net/netmon"
	"tailscale.com/tstest/deptest"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

func TestSendRecv(t *testing.T) {
	serverPrivateKey := key.NewNode()

	netMon := netmon.NewStatic()

	const numClients = 3
	var clientPrivateKeys []key.NodePrivate
	var clientKeys []key.NodePublic
	for range numClients {
		priv := key.NewNode()
		clientPrivateKeys = append(clientPrivateKeys, priv)
		clientKeys = append(clientKeys, priv.Public())
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
	for i := range numClients {
		key := clientPrivateKeys[i]
		c, err := NewClient(key, serverURL, t.Logf, netMon)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		if err := c.Connect(context.Background()); err != nil {
			t.Fatalf("client %d Connect: %v", i, err)
		}
		waitConnect(t, c)
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
				m, err := c.Recv()
				if err != nil {
					select {
					case <-done:
						return
					default:
					}
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

func waitConnect(t testing.TB, c *Client) {
	t.Helper()
	if m, err := c.Recv(); err != nil {
		t.Fatalf("client first Recv: %v", err)
	} else if v, ok := m.(derp.ServerInfoMessage); !ok {
		t.Fatalf("client first Recv was unexpected type %T", v)
	}
}

func TestPing(t *testing.T) {
	serverPrivateKey := key.NewNode()
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

	c, err := NewClient(key.NewNode(), serverURL, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("client Connect: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		for {
			m, err := c.Recv()
			if err != nil {
				errc <- err
				return
			}
			t.Logf("Recv: %T", m)
		}
	}()
	err = c.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func newTestServer(t *testing.T, k key.NodePrivate) (serverURL string, s *derp.Server) {
	s = derp.NewServer(k, t.Logf)
	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      Handler(s),
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL = "http://" + ln.Addr().String()
	s.SetMeshKey("1234")

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if err == http.ErrServerClosed {
				t.Logf("server closed")
				return
			}
			panic(err)
		}
	}()
	return
}

func newWatcherClient(t *testing.T, watcherPrivateKey key.NodePrivate, serverToWatchURL string) (c *Client) {
	c, err := NewClient(watcherPrivateKey, serverToWatchURL, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatal(err)
	}
	c.MeshKey = "1234"
	return
}

// breakConnection breaks the connection, which should trigger a reconnect.
func (c *Client) breakConnection(brokenClient *derp.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != brokenClient {
		return
	}
	if c.netConn != nil {
		c.netConn.Close()
		c.netConn = nil
	}
	c.client = nil
}

// Test that a watcher connection successfully reconnects and processes peer
// updates after a different thread breaks and reconnects the connection, while
// the watcher is waiting on recv().
func TestBreakWatcherConnRecv(t *testing.T) {
	// Set the wait time before a retry after connection failure to be much lower.
	// This needs to be early in the test, for defer to run right at the end after
	// the DERP client has finished.
	origRetryInterval := retryInterval
	retryInterval = 50 * time.Millisecond
	defer func() { retryInterval = origRetryInterval }()

	var wg sync.WaitGroup
	defer wg.Wait()
	// Make the watcher server
	serverPrivateKey1 := key.NewNode()
	_, s1 := newTestServer(t, serverPrivateKey1)
	defer s1.Close()

	// Make the watched server
	serverPrivateKey2 := key.NewNode()
	serverURL2, s2 := newTestServer(t, serverPrivateKey2)
	defer s2.Close()

	// Make the watcher (but it is not connected yet)
	watcher1 := newWatcherClient(t, serverPrivateKey1, serverURL2)
	defer watcher1.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcherChan := make(chan int, 1)

	// Start the watcher thread (which connects to the watched server)
	wg.Add(1) // To avoid using t.Logf after the test ends. See https://golang.org/issue/40343
	go func() {
		defer wg.Done()
		var peers int
		add := func(m derp.PeerPresentMessage) {
			t.Logf("add: %v", m.Key.ShortString())
			peers++
			// Signal that the watcher has run
			watcherChan <- peers
		}
		remove := func(m derp.PeerGoneMessage) { t.Logf("remove: %v", m.Peer.ShortString()); peers-- }

		watcher1.RunWatchConnectionLoop(ctx, serverPrivateKey1.Public(), t.Logf, add, remove)
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	// Wait for the watcher to run, then break the connection and check if it
	// reconnected and received peer updates.
	for range 10 {
		select {
		case peers := <-watcherChan:
			if peers != 1 {
				t.Fatal("wrong number of peers added during watcher connection")
			}
		case <-timer.C:
			t.Fatalf("watcher did not process the peer update")
		}
		watcher1.breakConnection(watcher1.client)
		// re-establish connection by sending a packet
		watcher1.ForwardPacket(key.NodePublic{}, key.NodePublic{}, []byte("bogus"))

		timer.Reset(5 * time.Second)
	}
}

// Test that a watcher connection successfully reconnects and processes peer
// updates after a different thread breaks and reconnects the connection, while
// the watcher is not waiting on recv().
func TestBreakWatcherConn(t *testing.T) {
	// Set the wait time before a retry after connection failure to be much lower.
	// This needs to be early in the test, for defer to run right at the end after
	// the DERP client has finished.
	origRetryInterval := retryInterval
	retryInterval = 50 * time.Millisecond
	defer func() { retryInterval = origRetryInterval }()

	var wg sync.WaitGroup
	defer wg.Wait()
	// Make the watcher server
	serverPrivateKey1 := key.NewNode()
	_, s1 := newTestServer(t, serverPrivateKey1)
	defer s1.Close()

	// Make the watched server
	serverPrivateKey2 := key.NewNode()
	serverURL2, s2 := newTestServer(t, serverPrivateKey2)
	defer s2.Close()

	// Make the watcher (but it is not connected yet)
	watcher1 := newWatcherClient(t, serverPrivateKey1, serverURL2)
	defer watcher1.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcherChan := make(chan int, 1)
	breakerChan := make(chan bool, 1)

	// Start the watcher thread (which connects to the watched server)
	wg.Add(1) // To avoid using t.Logf after the test ends. See https://golang.org/issue/40343
	go func() {
		defer wg.Done()
		var peers int
		add := func(m derp.PeerPresentMessage) {
			t.Logf("add: %v", m.Key.ShortString())
			peers++
			// Signal that the watcher has run
			watcherChan <- peers
			// Wait for breaker to run
			<-breakerChan
		}
		remove := func(m derp.PeerGoneMessage) { t.Logf("remove: %v", m.Peer.ShortString()); peers-- }

		watcher1.RunWatchConnectionLoop(ctx, serverPrivateKey1.Public(), t.Logf, add, remove)
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	// Wait for the watcher to run, then break the connection and check if it
	// reconnected and received peer updates.
	for range 10 {
		select {
		case peers := <-watcherChan:
			if peers != 1 {
				t.Fatal("wrong number of peers added during watcher connection")
			}
		case <-timer.C:
			t.Fatalf("watcher did not process the peer update")
		}
		watcher1.breakConnection(watcher1.client)
		// re-establish connection by sending a packet
		watcher1.ForwardPacket(key.NodePublic{}, key.NodePublic{}, []byte("bogus"))
		// signal that the breaker is done
		breakerChan <- true

		timer.Reset(5 * time.Second)
	}
}

func noopAdd(derp.PeerPresentMessage) {}
func noopRemove(derp.PeerGoneMessage) {}

func TestRunWatchConnectionLoopServeConnect(t *testing.T) {
	defer func() { testHookWatchLookConnectResult = nil }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	priv := key.NewNode()
	serverURL, s := newTestServer(t, priv)
	defer s.Close()

	pub := priv.Public()

	watcher := newWatcherClient(t, priv, serverURL)
	defer watcher.Close()

	// Test connecting to ourselves, and that we get hung up on.
	testHookWatchLookConnectResult = func(err error, wasSelfConnect bool) bool {
		t.Helper()
		if err != nil {
			t.Fatalf("error connecting to server: %v", err)
		}
		if !wasSelfConnect {
			t.Error("wanted self-connect; wasn't")
		}
		return false
	}
	watcher.RunWatchConnectionLoop(ctx, pub, t.Logf, noopAdd, noopRemove)

	// Test connecting to the server with a zero value for ignoreServerKey,
	// so we should always connect.
	testHookWatchLookConnectResult = func(err error, wasSelfConnect bool) bool {
		t.Helper()
		if err != nil {
			t.Fatalf("error connecting to server: %v", err)
		}
		if wasSelfConnect {
			t.Error("wanted normal connect; got self connect")
		}
		return false
	}
	watcher.RunWatchConnectionLoop(ctx, key.NodePublic{}, t.Logf, noopAdd, noopRemove)
}

// verify that the LocalAddr method doesn't acquire the mutex.
// See https://github.com/tailscale/tailscale/issues/11519
func TestLocalAddrNoMutex(t *testing.T) {
	var c Client
	c.mu.Lock()
	defer c.mu.Unlock() // not needed in test but for symmetry

	_, err := c.LocalAddr()
	if got, want := fmt.Sprint(err), "client not connected"; got != want {
		t.Errorf("got error %q; want %q", got, want)
	}
}

func TestProbe(t *testing.T) {
	h := Handler(nil)

	tests := []struct {
		path string
		want int
	}{
		{"/derp/probe", 200},
		{"/derp/latency-check", 200},
		{"/derp/sdf", http.StatusUpgradeRequired},
	}

	for _, tt := range tests {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", tt.path, nil))
		if got := rec.Result().StatusCode; got != tt.want {
			t.Errorf("for path %q got HTTP status %v; want %v", tt.path, got, tt.want)
		}
	}
}

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "darwin",
		GOARCH: "arm64",
		BadDeps: map[string]string{
			"github.com/coder/websocket": "shouldn't link websockets except on js/wasm",
		},
	}.Check(t)

	deptest.DepChecker{
		GOOS:   "darwin",
		GOARCH: "arm64",
		Tags:   "ts_debug_websockets",
		WantDeps: set.Of(
			"github.com/coder/websocket",
		),
	}.Check(t)

}
