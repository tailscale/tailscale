// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/memnet"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netx"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
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

	s := derpserver.New(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      derpserver.Handler(s),
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

	var clients []*derphttp.Client
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
		c, err := derphttp.NewClient(key, serverURL, t.Logf, netMon)
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

func waitConnect(t testing.TB, c *derphttp.Client) {
	t.Helper()
	if m, err := c.Recv(); err != nil {
		t.Fatalf("client first Recv: %v", err)
	} else if v, ok := m.(derp.ServerInfoMessage); !ok {
		t.Fatalf("client first Recv was unexpected type %T", v)
	}
}

func TestPing(t *testing.T) {
	serverPrivateKey := key.NewNode()
	s := derpserver.New(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      derpserver.Handler(s),
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

	c, err := derphttp.NewClient(key.NewNode(), serverURL, t.Logf, netmon.NewStatic())
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

const testMeshKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T, k key.NodePrivate) (serverURL string, s *derpserver.Server, ln *memnet.Listener) {
	s = derpserver.New(k, t.Logf)
	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      derpserver.Handler(s),
	}

	ln = memnet.Listen("localhost:0")

	serverURL = "http://" + ln.Addr().String()
	s.SetMeshKey(testMeshKey)

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			panic(err)
		}
	}()
	return
}

func newWatcherClient(t *testing.T, watcherPrivateKey key.NodePrivate, serverToWatchURL string, ln *memnet.Listener) (c *derphttp.Client) {
	c, err := derphttp.NewClient(watcherPrivateKey, serverToWatchURL, t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatal(err)
	}
	k, err := key.ParseDERPMesh(testMeshKey)
	if err != nil {
		t.Fatal(err)
	}
	c.MeshKey = k
	c.SetURLDialer(ln.Dial)
	return
}

// Test that a watcher connection successfully reconnects and processes peer
// updates after a different thread breaks and reconnects the connection, while
// the watcher is waiting on recv().
func TestBreakWatcherConnRecv(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Set the wait time before a retry after connection failure to be much lower.
		// This needs to be early in the test, for defer to run right at the end after
		// the DERP client has finished.
		tstest.Replace(t, derphttp.RetryInterval, 50*time.Millisecond)

		var wg sync.WaitGroup
		// Make the watcher server
		serverPrivateKey1 := key.NewNode()
		_, s1, ln1 := newTestServer(t, serverPrivateKey1)
		defer s1.Close()
		defer ln1.Close()

		// Make the watched server
		serverPrivateKey2 := key.NewNode()
		serverURL2, s2, ln2 := newTestServer(t, serverPrivateKey2)
		defer s2.Close()
		defer ln2.Close()

		// Make the watcher (but it is not connected yet)
		watcher := newWatcherClient(t, serverPrivateKey1, serverURL2, ln2)
		defer watcher.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		watcherChan := make(chan int, 1)
		defer close(watcherChan)
		errChan := make(chan error, 1)

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
			notifyErr := func(err error) {
				select {
				case errChan <- err:
				case <-ctx.Done():
				}
			}

			watcher.RunWatchConnectionLoop(ctx, serverPrivateKey1.Public(), t.Logf, add, remove, notifyErr)
		}()

		synctest.Wait()

		// Wait for the watcher to run, then break the connection and check if it
		// reconnected and received peer updates.
		for range 10 {
			select {
			case peers := <-watcherChan:
				if peers != 1 {
					t.Fatalf("wrong number of peers added during watcher connection: have %d, want 1", peers)
				}
			case err := <-errChan:
				if err.Error() != "derp.Recv: EOF" {
					t.Fatalf("expected notifyError connection error to be EOF, got %v", err)
				}
			}

			synctest.Wait()

			watcher.BreakConnection(watcher)
			// re-establish connection by sending a packet
			watcher.ForwardPacket(key.NodePublic{}, key.NodePublic{}, []byte("bogus"))
		}
		cancel() // Cancel the context to stop the watcher loop.
		wg.Wait()
	})
}

// Test that a watcher connection successfully reconnects and processes peer
// updates after a different thread breaks and reconnects the connection, while
// the watcher is not waiting on recv().
func TestBreakWatcherConn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Set the wait time before a retry after connection failure to be much lower.
		// This needs to be early in the test, for defer to run right at the end after
		// the DERP client has finished.
		tstest.Replace(t, derphttp.RetryInterval, 50*time.Millisecond)

		var wg sync.WaitGroup
		// Make the watcher server
		serverPrivateKey1 := key.NewNode()
		_, s1, ln1 := newTestServer(t, serverPrivateKey1)
		defer s1.Close()
		defer ln1.Close()

		// Make the watched server
		serverPrivateKey2 := key.NewNode()
		serverURL2, s2, ln2 := newTestServer(t, serverPrivateKey2)
		defer s2.Close()
		defer ln2.Close()

		// Make the watcher (but it is not connected yet)
		watcher1 := newWatcherClient(t, serverPrivateKey1, serverURL2, ln2)
		defer watcher1.Close()

		ctx, cancel := context.WithCancel(context.Background())

		watcherChan := make(chan int, 1)
		breakerChan := make(chan bool, 1)
		errorChan := make(chan error, 1)

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
				select {
				case <-ctx.Done():
					return
				// Wait for breaker to run
				case <-breakerChan:
				}
			}
			remove := func(m derp.PeerGoneMessage) { t.Logf("remove: %v", m.Peer.ShortString()); peers-- }
			notifyError := func(err error) {
				errorChan <- err
			}

			watcher1.RunWatchConnectionLoop(ctx, serverPrivateKey1.Public(), t.Logf, add, remove, notifyError)
		}()

		synctest.Wait()

		// Wait for the watcher to run, then break the connection and check if it
		// reconnected and received peer updates.
		for range 10 {
			select {
			case peers := <-watcherChan:
				if peers != 1 {
					t.Fatalf("wrong number of peers added during watcher connection have %d, want 1", peers)
				}
			case err := <-errorChan:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("expected notifyError connection error to fail with ErrClosed, got %v", err)
				}
			}

			synctest.Wait()

			watcher1.BreakConnection(watcher1)
			// re-establish connection by sending a packet
			watcher1.ForwardPacket(key.NodePublic{}, key.NodePublic{}, []byte("bogus"))
			// signal that the breaker is done
			breakerChan <- true
		}
		watcher1.Close()
		cancel()
		wg.Wait()
	})
}

func noopAdd(derp.PeerPresentMessage) {}
func noopRemove(derp.PeerGoneMessage) {}
func noopNotifyError(error)           {}

func TestRunWatchConnectionLoopServeConnect(t *testing.T) {
	defer derphttp.SetTestHookWatchLookConnectResult(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	priv := key.NewNode()
	serverURL, s, ln := newTestServer(t, priv)
	defer s.Close()
	defer ln.Close()

	pub := priv.Public()

	watcher := newWatcherClient(t, priv, serverURL, ln)
	defer watcher.Close()

	// Test connecting to ourselves, and that we get hung up on.
	derphttp.SetTestHookWatchLookConnectResult(func(err error, wasSelfConnect bool) bool {
		t.Helper()
		if err != nil {
			t.Fatalf("error connecting to server: %v", err)
		}
		if !wasSelfConnect {
			t.Error("wanted self-connect; wasn't")
		}
		return false
	})
	watcher.RunWatchConnectionLoop(ctx, pub, t.Logf, noopAdd, noopRemove, noopNotifyError)

	// Test connecting to the server with a zero value for ignoreServerKey,
	// so we should always connect.
	derphttp.SetTestHookWatchLookConnectResult(func(err error, wasSelfConnect bool) bool {
		t.Helper()
		if err != nil {
			t.Fatalf("error connecting to server: %v", err)
		}
		if wasSelfConnect {
			t.Error("wanted normal connect; got self connect")
		}
		return false
	})
	watcher.RunWatchConnectionLoop(ctx, key.NodePublic{}, t.Logf, noopAdd, noopRemove, noopNotifyError)
}

// verify that the LocalAddr method doesn't acquire the mutex.
// See https://github.com/tailscale/tailscale/issues/11519
func TestLocalAddrNoMutex(t *testing.T) {
	var c derphttp.Client

	_, err := c.LocalAddr()
	if got, want := fmt.Sprint(err), "client not connected"; got != want {
		t.Errorf("got error %q; want %q", got, want)
	}
}

func TestProbe(t *testing.T) {
	h := derpserver.Handler(nil)

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

func TestNotifyError(t *testing.T) {
	defer derphttp.SetTestHookWatchLookConnectResult(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	priv := key.NewNode()
	serverURL, s, ln := newTestServer(t, priv)
	defer s.Close()
	defer ln.Close()

	pub := priv.Public()

	// Test early error notification when c.connect fails.
	watcher := newWatcherClient(t, priv, serverURL, ln)
	watcher.SetURLDialer(netx.DialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		t.Helper()
		return nil, fmt.Errorf("test error: %s", addr)
	}))
	defer watcher.Close()

	derphttp.SetTestHookWatchLookConnectResult(func(err error, wasSelfConnect bool) bool {
		t.Helper()
		if err == nil {
			t.Fatal("expected error connecting to server, got nil")
		}
		if wasSelfConnect {
			t.Error("wanted normal connect; got self connect")
		}
		return false
	})

	errChan := make(chan error, 1)
	notifyError := func(err error) {
		errChan <- err
	}
	watcher.RunWatchConnectionLoop(ctx, pub, t.Logf, noopAdd, noopRemove, notifyError)

	select {
	case err := <-errChan:
		if !strings.Contains(err.Error(), "test") {
			t.Errorf("expected test error, got %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("context done before receiving error: %v", ctx.Err())
	}
}

var liveNetworkTest = flag.Bool("live-net-tests", false, "run live network tests")

func TestManualDial(t *testing.T) {
	if !*liveNetworkTest {
		t.Skip("skipping live network test without --live-net-tests")
	}
	dm := &tailcfg.DERPMap{}
	res, err := http.Get("https://controlplane.tailscale.com/derpmap/default")
	if err != nil {
		t.Fatalf("fetching DERPMap: %v", err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(dm); err != nil {
		t.Fatalf("decoding DERPMap: %v", err)
	}

	region := slices.Sorted(maps.Keys(dm.Regions))[0]

	netMon := netmon.NewStatic()
	rc := derphttp.NewRegionClient(key.NewNode(), t.Logf, netMon, func() *tailcfg.DERPRegion {
		return dm.Regions[region]
	})
	defer rc.Close()

	if err := rc.Connect(context.Background()); err != nil {
		t.Fatalf("rc.Connect: %v", err)
	}
}

func TestURLDial(t *testing.T) {
	if !*liveNetworkTest {
		t.Skip("skipping live network test without --live-net-tests")
	}
	dm := &tailcfg.DERPMap{}
	res, err := http.Get("https://controlplane.tailscale.com/derpmap/default")
	if err != nil {
		t.Fatalf("fetching DERPMap: %v", err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(dm); err != nil {
		t.Fatalf("decoding DERPMap: %v", err)
	}

	// find a valid target DERP host to test against
	var hostname string
	for _, reg := range dm.Regions {
		for _, node := range reg.Nodes {
			if !node.STUNOnly && node.CanPort80 && node.CertName == "" || node.CertName == node.HostName {
				hostname = node.HostName
				break
			}
		}
		if hostname != "" {
			break
		}
	}
	netMon := netmon.NewStatic()
	c, err := derphttp.NewClient(key.NewNode(), "https://"+hostname+"/", t.Logf, netMon)
	if err != nil {
		t.Errorf("NewClient: %v", err)
	}
	defer c.Close()

	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("rc.Connect: %v", err)
	}
}
