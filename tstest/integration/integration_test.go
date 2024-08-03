// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package integration

//go:generate go run gen_deps.go

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/client/tailscale"
	"tailscale.com/clientupdate"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/safesocket"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/util/must"
	"tailscale.com/util/rands"
	"tailscale.com/version"
)

var (
	verboseTailscaled = flag.Bool("verbose-tailscaled", false, "verbose tailscaled logging")
	verboseTailscale  = flag.Bool("verbose-tailscale", false, "verbose tailscale CLI logging")
)

var mainError syncs.AtomicValue[error]

func TestMain(m *testing.M) {
	// Have to disable UPnP which hits the network, otherwise it fails due to HTTP proxy.
	os.Setenv("TS_DISABLE_UPNP", "true")
	flag.Parse()
	v := m.Run()
	CleanupBinaries()
	if v != 0 {
		os.Exit(v)
	}
	if err := mainError.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// Tests that tailscaled starts up in TUN mode, and also without data races:
// https://github.com/tailscale/tailscale/issues/7894
func TestTUNMode(t *testing.T) {
	tstest.Shard(t)
	if os.Getuid() != 0 {
		t.Skip("skipping when not root")
	}
	tstest.Parallel(t)
	env := newTestEnv(t)
	env.tunMode = true
	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon()

	n1.AwaitResponding()
	n1.MustUp()

	t.Logf("Got IP: %v", n1.AwaitIP4())
	n1.AwaitRunning()

	d1.MustCleanShutdown(t)
}

func TestOneNodeUpNoAuth(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon()
	n1.AwaitResponding()
	n1.MustUp()

	t.Logf("Got IP: %v", n1.AwaitIP4())
	n1.AwaitRunning()

	d1.MustCleanShutdown(t)

	t.Logf("number of HTTP logcatcher requests: %v", env.LogCatcher.numRequests())
}

func TestOneNodeExpiredKey(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon()
	n1.AwaitResponding()
	n1.MustUp()
	n1.AwaitRunning()

	nodes := env.Control.AllNodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d nodes", len(nodes))
	}

	nodeKey := nodes[0].Key
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := env.Control.AwaitNodeInMapRequest(ctx, nodeKey); err != nil {
		t.Fatal(err)
	}
	cancel()

	env.Control.SetExpireAllNodes(true)
	n1.AwaitNeedsLogin()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	if err := env.Control.AwaitNodeInMapRequest(ctx, nodeKey); err != nil {
		t.Fatal(err)
	}
	cancel()

	env.Control.SetExpireAllNodes(false)
	n1.AwaitRunning()

	d1.MustCleanShutdown(t)
}

func TestControlKnobs(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon()
	defer d1.MustCleanShutdown(t)
	n1.AwaitResponding()
	n1.MustUp()

	t.Logf("Got IP: %v", n1.AwaitIP4())
	n1.AwaitRunning()

	cmd := n1.Tailscale("debug", "control-knobs")
	cmd.Stdout = nil // in case --verbose-tailscale was set
	cmd.Stderr = nil // in case --verbose-tailscale was set
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("control-knobs output:\n%s", out)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if got, want := m["DisableUPnP"], true; got != want {
		t.Errorf("control-knobs DisableUPnP = %v; want %v", got, want)
	}
}

func TestCollectPanic(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	n := newTestNode(t, env)

	cmd := exec.Command(env.daemon, "--cleanup")
	cmd.Env = append(os.Environ(),
		"TS_PLEASE_PANIC=1",
		"TS_LOG_TARGET="+n.env.LogCatcherServer.URL,
	)
	got, _ := cmd.CombinedOutput() // we expect it to fail, ignore err
	t.Logf("initial run: %s", got)

	// Now we run it again, and on start, it will upload the logs to logcatcher.
	cmd = exec.Command(env.daemon, "--cleanup")
	cmd.Env = append(os.Environ(), "TS_LOG_TARGET="+n.env.LogCatcherServer.URL)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cleanup failed: %v: %q", err, out)
	}
	if err := tstest.WaitFor(20*time.Second, func() error {
		const sub = `panic`
		if !n.env.LogCatcher.logsContains(mem.S(sub)) {
			return fmt.Errorf("log catcher didn't see %#q; got %s", sub, n.env.LogCatcher.logsString())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestControlTimeLogLine(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	env.LogCatcher.StoreRawJSON()
	n := newTestNode(t, env)

	n.StartDaemon()
	n.AwaitResponding()
	n.MustUp()
	n.AwaitRunning()

	if err := tstest.WaitFor(20*time.Second, func() error {
		const sub = `"controltime":"2020-08-03T00:00:00.000000001Z"`
		if !n.env.LogCatcher.logsContains(mem.S(sub)) {
			return fmt.Errorf("log catcher didn't see %#q; got %s", sub, n.env.LogCatcher.logsString())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// test Issue 2321: Start with UpdatePrefs should save prefs to disk
func TestStateSavedOnStart(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon()
	n1.AwaitResponding()
	n1.MustUp()

	t.Logf("Got IP: %v", n1.AwaitIP4())
	n1.AwaitRunning()

	p1 := n1.diskPrefs()
	t.Logf("Prefs1: %v", p1.Pretty())

	// Bring it down, to prevent an EditPrefs call in the
	// subsequent "up", as we want to test the bug when
	// cmd/tailscale implements "up" via LocalBackend.Start.
	n1.MustDown()

	// And change the hostname to something:
	if err := n1.Tailscale("up", "--login-server="+n1.env.controlURL(), "--hostname=foo").Run(); err != nil {
		t.Fatalf("up: %v", err)
	}

	p2 := n1.diskPrefs()
	if pretty := p1.Pretty(); pretty == p2.Pretty() {
		t.Errorf("Prefs didn't change on disk after 'up', still: %s", pretty)
	}
	if p2.Hostname != "foo" {
		t.Errorf("Prefs.Hostname = %q; want foo", p2.Hostname)
	}

	d1.MustCleanShutdown(t)
}

func TestOneNodeUpAuth(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t, configureControl(func(control *testcontrol.Server) {
		control.RequireAuth = true
	}))

	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon()

	n1.AwaitListening()

	st := n1.MustStatus()
	t.Logf("Status: %s", st.BackendState)

	t.Logf("Running up --login-server=%s ...", env.controlURL())

	cmd := n1.Tailscale("up", "--login-server="+env.controlURL())
	var authCountAtomic int32
	cmd.Stdout = &authURLParserWriter{fn: func(urlStr string) error {
		if env.Control.CompleteAuth(urlStr) {
			atomic.AddInt32(&authCountAtomic, 1)
			t.Logf("completed auth path %s", urlStr)
			return nil
		}
		err := fmt.Errorf("Failed to complete auth path to %q", urlStr)
		t.Log(err)
		return err
	}}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("up: %v", err)
	}
	t.Logf("Got IP: %v", n1.AwaitIP4())

	n1.AwaitRunning()

	if n := atomic.LoadInt32(&authCountAtomic); n != 1 {
		t.Errorf("Auth URLs completed = %d; want 1", n)
	}

	d1.MustCleanShutdown(t)
}

func TestConfigFileAuthKey(t *testing.T) {
	tstest.SkipOnUnshardedCI(t)
	tstest.Shard(t)
	t.Parallel()
	const authKey = "opensesame"
	env := newTestEnv(t, configureControl(func(control *testcontrol.Server) {
		control.RequireAuthKey = authKey
	}))

	n1 := newTestNode(t, env)
	n1.configFile = filepath.Join(n1.dir, "config.json")
	authKeyFile := filepath.Join(n1.dir, "my-auth-key")
	must.Do(os.WriteFile(authKeyFile, fmt.Appendf(nil, "%s\n", authKey), 0666))
	must.Do(os.WriteFile(n1.configFile, must.Get(json.Marshal(ipn.ConfigVAlpha{
		Version:   "alpha0",
		AuthKey:   ptr.To("file:" + authKeyFile),
		ServerURL: ptr.To(n1.env.ControlServer.URL),
	})), 0644))
	d1 := n1.StartDaemon()

	n1.AwaitListening()
	t.Logf("Got IP: %v", n1.AwaitIP4())
	n1.AwaitRunning()

	d1.MustCleanShutdown(t)
}

func TestTwoNodes(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)

	// Create two nodes:
	n1 := newTestNode(t, env)
	n1SocksAddrCh := n1.socks5AddrChan()
	d1 := n1.StartDaemon()

	n2 := newTestNode(t, env)
	n2SocksAddrCh := n2.socks5AddrChan()
	d2 := n2.StartDaemon()

	// Drop some logs to disk on test failure.
	//
	// TODO(bradfitz): make all nodes for all tests do this? give each node a
	// unique integer within the test? But for now only do this test because
	// this is what we often saw flaking.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		n1.mu.Lock()
		n2.mu.Lock()
		defer n1.mu.Unlock()
		defer n2.mu.Unlock()

		rxNoDates := regexp.MustCompile(`(?m)^\d{4}.\d{2}.\d{2}.\d{2}:\d{2}:\d{2}`)
		cleanLog := func(n *testNode) []byte {
			b := n.tailscaledParser.allBuf.Bytes()
			b = rxNoDates.ReplaceAll(b, nil)
			return b
		}

		t.Logf("writing tailscaled logs to n1.log and n2.log")
		os.WriteFile("n1.log", cleanLog(n1), 0666)
		os.WriteFile("n2.log", cleanLog(n2), 0666)
	})

	n1Socks := n1.AwaitSocksAddr(n1SocksAddrCh)
	n2Socks := n1.AwaitSocksAddr(n2SocksAddrCh)
	t.Logf("node1 SOCKS5 addr: %v", n1Socks)
	t.Logf("node2 SOCKS5 addr: %v", n2Socks)

	n1.AwaitListening()
	t.Logf("n1 is listening")
	n2.AwaitListening()
	t.Logf("n2 is listening")
	n1.MustUp()
	t.Logf("n1 is up")
	n2.MustUp()
	t.Logf("n2 is up")
	n1.AwaitRunning()
	t.Logf("n1 is running")
	n2.AwaitRunning()
	t.Logf("n2 is running")

	if err := tstest.WaitFor(2*time.Second, func() error {
		st := n1.MustStatus()
		if len(st.Peer) == 0 {
			return errors.New("no peers")
		}
		if len(st.Peer) > 1 {
			return fmt.Errorf("got %d peers; want 1", len(st.Peer))
		}
		peer := st.Peer[st.Peers()[0]]
		if peer.ID == st.Self.ID {
			return errors.New("peer is self")
		}

		if len(st.TailscaleIPs) == 0 {
			return errors.New("no Tailscale IPs")
		}

		return nil
	}); err != nil {
		t.Error(err)
	}

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}

// tests two nodes where the first gets a incremental MapResponse (with only
// PeersRemoved set) saying that the second node disappeared.
func TestIncrementalMapUpdatePeersRemoved(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)

	// Create one node:
	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon()
	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()

	all := env.Control.AllNodes()
	if len(all) != 1 {
		t.Fatalf("expected 1 node, got %d nodes", len(all))
	}
	tnode1 := all[0]

	n2 := newTestNode(t, env)
	d2 := n2.StartDaemon()
	n2.AwaitListening()
	n2.MustUp()
	n2.AwaitRunning()

	all = env.Control.AllNodes()
	if len(all) != 2 {
		t.Fatalf("expected 2 node, got %d nodes", len(all))
	}
	var tnode2 *tailcfg.Node
	for _, n := range all {
		if n.ID != tnode1.ID {
			tnode2 = n
			break
		}
	}
	if tnode2 == nil {
		t.Fatalf("failed to find second node ID (two dups?)")
	}

	t.Logf("node1=%v, node2=%v", tnode1.ID, tnode2.ID)

	if err := tstest.WaitFor(2*time.Second, func() error {
		st := n1.MustStatus()
		if len(st.Peer) == 0 {
			return errors.New("no peers")
		}
		if len(st.Peer) > 1 {
			return fmt.Errorf("got %d peers; want 1", len(st.Peer))
		}
		peer := st.Peer[st.Peers()[0]]
		if peer.ID == st.Self.ID {
			return errors.New("peer is self")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	t.Logf("node1 saw node2")

	// Now tell node1 that node2 is removed.
	if !env.Control.AddRawMapResponse(tnode1.Key, &tailcfg.MapResponse{
		PeersRemoved: []tailcfg.NodeID{tnode2.ID},
	}) {
		t.Fatalf("failed to add map response")
	}

	// And see that node1 saw that.
	if err := tstest.WaitFor(2*time.Second, func() error {
		st := n1.MustStatus()
		if len(st.Peer) == 0 {
			return nil
		}
		return fmt.Errorf("got %d peers; want 0", len(st.Peer))
	}); err != nil {
		t.Fatal(err)
	}

	t.Logf("node1 saw node2 disappear")

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}

func TestNodeAddressIPFields(t *testing.T) {
	tstest.Shard(t)
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/7008")
	tstest.Parallel(t)
	env := newTestEnv(t)
	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon()

	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()

	testNodes := env.Control.AllNodes()

	if len(testNodes) != 1 {
		t.Errorf("Expected %d nodes, got %d", 1, len(testNodes))
	}
	node := testNodes[0]
	if len(node.Addresses) == 0 {
		t.Errorf("Empty Addresses field in node")
	}
	if len(node.AllowedIPs) == 0 {
		t.Errorf("Empty AllowedIPs field in node")
	}

	d1.MustCleanShutdown(t)
}

func TestAddPingRequest(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	n1 := newTestNode(t, env)
	n1.StartDaemon()

	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()

	gotPing := make(chan bool, 1)
	waitPing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPing <- true
	}))
	defer waitPing.Close()

	nodes := env.Control.AllNodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d nodes", len(nodes))
	}

	nodeKey := nodes[0].Key

	// Check that we get at least one ping reply after 10 tries.
	for try := 1; try <= 10; try++ {
		t.Logf("ping %v ...", try)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := env.Control.AwaitNodeInMapRequest(ctx, nodeKey); err != nil {
			t.Fatal(err)
		}
		cancel()

		pr := &tailcfg.PingRequest{URL: fmt.Sprintf("%s/ping-%d", waitPing.URL, try), Log: true}
		if !env.Control.AddPingRequest(nodeKey, pr) {
			t.Logf("failed to AddPingRequest")
			continue
		}

		// Wait for PingRequest to come back
		pingTimeout := time.NewTimer(2 * time.Second)
		defer pingTimeout.Stop()
		select {
		case <-gotPing:
			t.Logf("got ping; success")
			return
		case <-pingTimeout.C:
			// Try again.
		}
	}
	t.Error("all ping attempts failed")
}

func TestC2NPingRequest(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)

	env := newTestEnv(t)

	gotPing := make(chan bool, 1)
	env.Control.HandleC2N = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected ping method %q", r.Method)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ping body read error: %v", err)
		}
		const want = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nabc"
		if string(got) != want {
			t.Errorf("body error\n got: %q\nwant: %q", got, want)
		}
		gotPing <- true
	})

	n1 := newTestNode(t, env)
	n1.StartDaemon()

	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()

	nodes := env.Control.AllNodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d nodes", len(nodes))
	}

	nodeKey := nodes[0].Key

	// Check that we get at least one ping reply after 10 tries.
	for try := 1; try <= 10; try++ {
		t.Logf("ping %v ...", try)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := env.Control.AwaitNodeInMapRequest(ctx, nodeKey); err != nil {
			t.Fatal(err)
		}
		cancel()

		pr := &tailcfg.PingRequest{
			URL:     fmt.Sprintf("https://unused/some-c2n-path/ping-%d", try),
			Log:     true,
			Types:   "c2n",
			Payload: []byte("POST /echo HTTP/1.0\r\nContent-Length: 3\r\n\r\nabc"),
		}
		if !env.Control.AddPingRequest(nodeKey, pr) {
			t.Logf("failed to AddPingRequest")
			continue
		}

		// Wait for PingRequest to come back
		pingTimeout := time.NewTimer(2 * time.Second)
		defer pingTimeout.Stop()
		select {
		case <-gotPing:
			t.Logf("got ping; success")
			return
		case <-pingTimeout.C:
			// Try again.
		}
	}
	t.Error("all ping attempts failed")
}

// Issue 2434: when "down" (WantRunning false), tailscaled shouldn't
// be connected to control.
func TestNoControlConnWhenDown(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon()
	n1.AwaitResponding()

	// Come up the first time.
	n1.MustUp()
	ip1 := n1.AwaitIP4()
	n1.AwaitRunning()

	// Then bring it down and stop the daemon.
	n1.MustDown()
	d1.MustCleanShutdown(t)

	env.LogCatcher.Reset()
	d2 := n1.StartDaemon()
	n1.AwaitResponding()

	n1.AwaitBackendState("Stopped")

	ip2 := n1.AwaitIP4()
	if ip1 != ip2 {
		t.Errorf("IPs different: %q vs %q", ip1, ip2)
	}

	// The real test: verify our daemon doesn't have an HTTP request open.
	if n := env.Control.InServeMap(); n != 0 {
		t.Errorf("in serve map = %d; want 0", n)
	}

	d2.MustCleanShutdown(t)
}

// Issue 2137: make sure Windows tailscaled works with the CLI alone,
// without the GUI to kick off a Start.
func TestOneNodeUpWindowsStyle(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	n1 := newTestNode(t, env)
	n1.upFlagGOOS = "windows"

	d1 := n1.StartDaemonAsIPNGOOS("windows")
	n1.AwaitResponding()
	n1.MustUp("--unattended")

	t.Logf("Got IP: %v", n1.AwaitIP4())
	n1.AwaitRunning()

	d1.MustCleanShutdown(t)
}

// TestClientSideJailing tests that when one node is jailed for another, the
// jailed node cannot initiate connections to the other node however the other
// node can initiate connections to the jailed node.
func TestClientSideJailing(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	registerNode := func() (*testNode, key.NodePublic) {
		n := newTestNode(t, env)
		n.StartDaemon()
		n.AwaitListening()
		n.MustUp()
		n.AwaitRunning()
		k := n.MustStatus().Self.PublicKey
		return n, k
	}
	n1, k1 := registerNode()
	n2, k2 := registerNode()

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	lc1 := &tailscale.LocalClient{
		Socket:        n1.sockFile,
		UseSocketOnly: true,
	}
	lc2 := &tailscale.LocalClient{
		Socket:        n2.sockFile,
		UseSocketOnly: true,
	}

	ip1 := n1.AwaitIP4()
	ip2 := n2.AwaitIP4()

	tests := []struct {
		name          string
		n1JailedForN2 bool
		n2JailedForN1 bool
	}{
		{
			name:          "not_jailed",
			n1JailedForN2: false,
			n2JailedForN1: false,
		},
		{
			name:          "uni_jailed",
			n1JailedForN2: true,
			n2JailedForN1: false,
		},
		{
			name:          "bi_jailed", // useless config?
			n1JailedForN2: true,
			n2JailedForN1: true,
		},
	}

	testDial := func(t *testing.T, lc *tailscale.LocalClient, ip netip.Addr, port uint16, shouldFail bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c, err := lc.DialTCP(ctx, ip.String(), port)
		failed := err != nil
		if failed != shouldFail {
			t.Errorf("failed = %v; want %v", failed, shouldFail)
		}
		if c != nil {
			c.Close()
		}
	}

	b1, err := lc1.WatchIPNBus(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := lc2.WatchIPNBus(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	waitPeerIsJailed := func(t *testing.T, b *tailscale.IPNBusWatcher, jailed bool) {
		t.Helper()
		for {
			n, err := b.Next()
			if err != nil {
				t.Fatal(err)
			}
			if n.NetMap == nil {
				continue
			}
			if len(n.NetMap.Peers) == 0 {
				continue
			}
			if j := n.NetMap.Peers[0].IsJailed(); j == jailed {
				break
			}
		}
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env.Control.SetJailed(k1, k2, tc.n2JailedForN1)
			env.Control.SetJailed(k2, k1, tc.n1JailedForN2)

			// Wait for the jailed status to propagate.
			waitPeerIsJailed(t, b1, tc.n2JailedForN1)
			waitPeerIsJailed(t, b2, tc.n1JailedForN2)

			testDial(t, lc1, ip2, port, tc.n1JailedForN2)
			testDial(t, lc2, ip1, port, tc.n2JailedForN1)
		})
	}
}

// TestNATPing creates two nodes, n1 and n2, sets up masquerades for both and
// tries to do bi-directional pings between them.
func TestNATPing(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/12169")
	tstest.Shard(t)
	tstest.Parallel(t)
	for _, v6 := range []bool{false, true} {
		env := newTestEnv(t)
		registerNode := func() (*testNode, key.NodePublic) {
			n := newTestNode(t, env)
			n.StartDaemon()
			n.AwaitListening()
			n.MustUp()
			n.AwaitRunning()
			k := n.MustStatus().Self.PublicKey
			return n, k
		}
		n1, k1 := registerNode()
		n2, k2 := registerNode()

		var n1IP, n2IP netip.Addr
		if v6 {
			n1IP = n1.AwaitIP6()
			n2IP = n2.AwaitIP6()
		} else {
			n1IP = n1.AwaitIP4()
			n2IP = n2.AwaitIP4()
		}

		n1ExternalIP := netip.MustParseAddr("100.64.1.1")
		n2ExternalIP := netip.MustParseAddr("100.64.2.1")
		if v6 {
			n1ExternalIP = netip.MustParseAddr("fd7a:115c:a1e0::1a")
			n2ExternalIP = netip.MustParseAddr("fd7a:115c:a1e0::1b")
		}

		tests := []struct {
			name       string
			pairs      []testcontrol.MasqueradePair
			n1SeesN2IP netip.Addr
			n2SeesN1IP netip.Addr
		}{
			{
				name:       "no_nat",
				n1SeesN2IP: n2IP,
				n2SeesN1IP: n1IP,
			},
			{
				name: "n1_has_external_ip",
				pairs: []testcontrol.MasqueradePair{
					{
						Node:              k1,
						Peer:              k2,
						NodeMasqueradesAs: n1ExternalIP,
					},
				},
				n1SeesN2IP: n2IP,
				n2SeesN1IP: n1ExternalIP,
			},
			{
				name: "n2_has_external_ip",
				pairs: []testcontrol.MasqueradePair{
					{
						Node:              k2,
						Peer:              k1,
						NodeMasqueradesAs: n2ExternalIP,
					},
				},
				n1SeesN2IP: n2ExternalIP,
				n2SeesN1IP: n1IP,
			},
			{
				name: "both_have_external_ips",
				pairs: []testcontrol.MasqueradePair{
					{
						Node:              k1,
						Peer:              k2,
						NodeMasqueradesAs: n1ExternalIP,
					},
					{
						Node:              k2,
						Peer:              k1,
						NodeMasqueradesAs: n2ExternalIP,
					},
				},
				n1SeesN2IP: n2ExternalIP,
				n2SeesN1IP: n1ExternalIP,
			},
		}

		for _, tc := range tests {
			t.Run(fmt.Sprintf("v6=%t/%v", v6, tc.name), func(t *testing.T) {
				env.Control.SetMasqueradeAddresses(tc.pairs)

				ipIdx := 0
				if v6 {
					ipIdx = 1
				}

				s1 := n1.MustStatus()
				n2AsN1Peer := s1.Peer[k2]
				if got := n2AsN1Peer.TailscaleIPs[ipIdx]; got != tc.n1SeesN2IP {
					t.Fatalf("n1 sees n2 as %v; want %v", got, tc.n1SeesN2IP)
				}

				s2 := n2.MustStatus()
				n1AsN2Peer := s2.Peer[k1]
				if got := n1AsN2Peer.TailscaleIPs[ipIdx]; got != tc.n2SeesN1IP {
					t.Fatalf("n2 sees n1 as %v; want %v", got, tc.n2SeesN1IP)
				}

				if err := n1.Tailscale("ping", tc.n1SeesN2IP.String()).Run(); err != nil {
					t.Fatal(err)
				}

				if err := n1.Tailscale("ping", "-peerapi", tc.n1SeesN2IP.String()).Run(); err != nil {
					t.Fatal(err)
				}

				if err := n2.Tailscale("ping", tc.n2SeesN1IP.String()).Run(); err != nil {
					t.Fatal(err)
				}

				if err := n2.Tailscale("ping", "-peerapi", tc.n2SeesN1IP.String()).Run(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestLogoutRemovesAllPeers(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)
	// Spin up some nodes.
	nodes := make([]*testNode, 2)
	for i := range nodes {
		nodes[i] = newTestNode(t, env)
		nodes[i].StartDaemon()
		nodes[i].AwaitResponding()
		nodes[i].MustUp()
		nodes[i].AwaitIP4()
		nodes[i].AwaitRunning()
	}
	expectedPeers := len(nodes) - 1

	// Make every node ping every other node.
	// This makes sure magicsock is fully populated.
	for i := range nodes {
		for j := range nodes {
			if i <= j {
				continue
			}
			if err := tstest.WaitFor(20*time.Second, func() error {
				return nodes[i].Ping(nodes[j])
			}); err != nil {
				t.Fatalf("ping %v -> %v: %v", nodes[i].AwaitIP4(), nodes[j].AwaitIP4(), err)
			}
		}
	}

	// wantNode0PeerCount waits until node[0] status includes exactly want peers.
	wantNode0PeerCount := func(want int) {
		if err := tstest.WaitFor(20*time.Second, func() error {
			s := nodes[0].MustStatus()
			if peers := s.Peers(); len(peers) != want {
				return fmt.Errorf("want %d peer(s) in status, got %v", want, peers)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	wantNode0PeerCount(expectedPeers) // all other nodes are peers
	nodes[0].MustLogOut()
	wantNode0PeerCount(0) // node[0] is logged out, so it should not have any peers

	nodes[0].MustUp() // This will create a new node
	expectedPeers++

	nodes[0].AwaitIP4()
	wantNode0PeerCount(expectedPeers) // all existing peers and the new node
}

func TestAutoUpdateDefaults(t *testing.T) {
	if !clientupdate.CanAutoUpdate() {
		t.Skip("auto-updates not supported on this platform")
	}
	tstest.Shard(t)
	tstest.Parallel(t)
	env := newTestEnv(t)

	checkDefault := func(n *testNode, want bool) error {
		enabled, ok := n.diskPrefs().AutoUpdate.Apply.Get()
		if !ok {
			return fmt.Errorf("auto-update for node is unset, should be set as %v", want)
		}
		if enabled != want {
			return fmt.Errorf("auto-update for node is %v, should be set as %v", enabled, want)
		}
		return nil
	}

	sendAndCheckDefault := func(t *testing.T, n *testNode, send, want bool) {
		t.Helper()
		if !env.Control.AddRawMapResponse(n.MustStatus().Self.PublicKey, &tailcfg.MapResponse{
			DefaultAutoUpdate: opt.NewBool(send),
		}) {
			t.Fatal("failed to send MapResponse to node")
		}
		if err := tstest.WaitFor(2*time.Second, func() error {
			return checkDefault(n, want)
		}); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		desc string
		run  func(t *testing.T, n *testNode)
	}{
		{
			desc: "tailnet-default-false",
			run: func(t *testing.T, n *testNode) {
				// First received default "false".
				sendAndCheckDefault(t, n, false, false)
				// Should not be changed even if sent "true" later.
				sendAndCheckDefault(t, n, true, false)
				// But can be changed explicitly by the user.
				if out, err := n.TailscaleForOutput("set", "--auto-update").CombinedOutput(); err != nil {
					t.Fatalf("failed to enable auto-update on node: %v\noutput: %s", err, out)
				}
				sendAndCheckDefault(t, n, false, true)
			},
		},
		{
			desc: "tailnet-default-true",
			run: func(t *testing.T, n *testNode) {
				// First received default "true".
				sendAndCheckDefault(t, n, true, true)
				// Should not be changed even if sent "false" later.
				sendAndCheckDefault(t, n, false, true)
				// But can be changed explicitly by the user.
				if out, err := n.TailscaleForOutput("set", "--auto-update=false").CombinedOutput(); err != nil {
					t.Fatalf("failed to disable auto-update on node: %v\noutput: %s", err, out)
				}
				sendAndCheckDefault(t, n, true, false)
			},
		},
		{
			desc: "user-sets-first",
			run: func(t *testing.T, n *testNode) {
				// User sets auto-update first, before receiving defaults.
				if out, err := n.TailscaleForOutput("set", "--auto-update=false").CombinedOutput(); err != nil {
					t.Fatalf("failed to disable auto-update on node: %v\noutput: %s", err, out)
				}
				// Defaults sent from control should be ignored.
				sendAndCheckDefault(t, n, true, false)
				sendAndCheckDefault(t, n, false, false)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			n := newTestNode(t, env)
			d := n.StartDaemon()
			defer d.MustCleanShutdown(t)

			n.AwaitResponding()
			n.MustUp()
			n.AwaitRunning()

			tt.run(t, n)
		})
	}
}

// testEnv contains the test environment (set of servers) used by one
// or more nodes.
type testEnv struct {
	t       testing.TB
	tunMode bool
	cli     string
	daemon  string

	LogCatcher       *LogCatcher
	LogCatcherServer *httptest.Server

	Control       *testcontrol.Server
	ControlServer *httptest.Server

	TrafficTrap       *trafficTrap
	TrafficTrapServer *httptest.Server
}

// controlURL returns e.ControlServer.URL, panicking if it's the empty string,
// which it should never be in tests.
func (e *testEnv) controlURL() string {
	s := e.ControlServer.URL
	if s == "" {
		panic("control server not set")
	}
	return s
}

type testEnvOpt interface {
	modifyTestEnv(*testEnv)
}

type configureControl func(*testcontrol.Server)

func (f configureControl) modifyTestEnv(te *testEnv) {
	f(te.Control)
}

// newTestEnv starts a bunch of services and returns a new test environment.
// newTestEnv arranges for the environment's resources to be cleaned up on exit.
func newTestEnv(t testing.TB, opts ...testEnvOpt) *testEnv {
	if runtime.GOOS == "windows" {
		t.Skip("not tested/working on Windows yet")
	}
	derpMap := RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	logc := new(LogCatcher)
	control := &testcontrol.Server{
		DERPMap: derpMap,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	trafficTrap := new(trafficTrap)
	e := &testEnv{
		t:                 t,
		cli:               TailscaleBinary(t),
		daemon:            TailscaledBinary(t),
		LogCatcher:        logc,
		LogCatcherServer:  httptest.NewServer(logc),
		Control:           control,
		ControlServer:     control.HTTPTestServer,
		TrafficTrap:       trafficTrap,
		TrafficTrapServer: httptest.NewServer(trafficTrap),
	}
	for _, o := range opts {
		o.modifyTestEnv(e)
	}
	control.HTTPTestServer.Start()
	t.Cleanup(func() {
		// Shut down e.
		if err := e.TrafficTrap.Err(); err != nil {
			e.t.Errorf("traffic trap: %v", err)
			e.t.Logf("logs: %s", e.LogCatcher.logsString())
		}
		e.LogCatcherServer.Close()
		e.TrafficTrapServer.Close()
		e.ControlServer.Close()
	})
	t.Logf("control URL: %v", e.controlURL())
	return e
}

// testNode is a machine with a tailscale & tailscaled.
// Currently, the test is simplistic and user==node==machine.
// That may grow complexity later to test more.
type testNode struct {
	env              *testEnv
	tailscaledParser *nodeOutputParser

	dir        string // temp dir for sock & state
	configFile string // or empty for none
	sockFile   string
	stateFile  string
	upFlagGOOS string // if non-empty, sets TS_DEBUG_UP_FLAG_GOOS for cmd/tailscale CLI

	mu        sync.Mutex
	onLogLine []func([]byte)
}

// newTestNode allocates a temp directory for a new test node.
// The node is not started automatically.
func newTestNode(t *testing.T, env *testEnv) *testNode {
	dir := t.TempDir()
	sockFile := filepath.Join(dir, "tailscale.sock")
	if len(sockFile) >= 104 {
		// Maximum length for a unix socket on darwin. Try something else.
		sockFile = filepath.Join(os.TempDir(), rands.HexString(8)+".sock")
		t.Cleanup(func() { os.Remove(sockFile) })
	}
	n := &testNode{
		env:       env,
		dir:       dir,
		sockFile:  sockFile,
		stateFile: filepath.Join(dir, "tailscale.state"),
	}

	// Look for a data race. Once we see the start marker, start logging the rest.
	var sawRace bool
	var sawPanic bool
	n.addLogLineHook(func(line []byte) {
		lineB := mem.B(line)
		if mem.Contains(lineB, mem.S("WARNING: DATA RACE")) {
			sawRace = true
		}
		if mem.HasPrefix(lineB, mem.S("panic: ")) {
			sawPanic = true
		}
		if sawRace || sawPanic {
			t.Logf("%s", line)
		}
	})

	return n
}

func (n *testNode) diskPrefs() *ipn.Prefs {
	t := n.env.t
	t.Helper()
	if _, err := os.ReadFile(n.stateFile); err != nil {
		t.Fatalf("reading prefs: %v", err)
	}
	fs, err := store.NewFileStore(nil, n.stateFile)
	if err != nil {
		t.Fatalf("reading prefs, NewFileStore: %v", err)
	}
	p, err := ipnlocal.ReadStartupPrefsForTest(t.Logf, fs)
	if err != nil {
		t.Fatalf("reading prefs, ReadDiskPrefsForTest: %v", err)
	}
	return p.AsStruct()
}

// AwaitResponding waits for n's tailscaled to be up enough to be
// responding, but doesn't wait for any particular state.
func (n *testNode) AwaitResponding() {
	t := n.env.t
	t.Helper()
	n.AwaitListening()

	st := n.MustStatus()
	t.Logf("Status: %s", st.BackendState)

	if err := tstest.WaitFor(20*time.Second, func() error {
		const sub = `Program starting: `
		if !n.env.LogCatcher.logsContains(mem.S(sub)) {
			return fmt.Errorf("log catcher didn't see %#q; got %s", sub, n.env.LogCatcher.logsString())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// addLogLineHook registers a hook f to be called on each tailscaled
// log line output.
func (n *testNode) addLogLineHook(f func([]byte)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onLogLine = append(n.onLogLine, f)
}

// socks5AddrChan returns a channel that receives the address (e.g. "localhost:23874")
// of the node's SOCKS5 listener, once started.
func (n *testNode) socks5AddrChan() <-chan string {
	ch := make(chan string, 1)
	n.addLogLineHook(func(line []byte) {
		const sub = "SOCKS5 listening on "
		i := mem.Index(mem.B(line), mem.S(sub))
		if i == -1 {
			return
		}
		addr := strings.TrimSpace(string(line)[i+len(sub):])
		select {
		case ch <- addr:
		default:
		}
	})
	return ch
}

func (n *testNode) AwaitSocksAddr(ch <-chan string) string {
	t := n.env.t
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v
	case <-timer.C:
		t.Fatal("timeout waiting for node to log its SOCK5 listening address")
		panic("unreachable")
	}
}

// nodeOutputParser parses stderr of tailscaled processes, calling the
// per-line callbacks previously registered via
// testNode.addLogLineHook.
type nodeOutputParser struct {
	allBuf      bytes.Buffer
	pendLineBuf bytes.Buffer
	n           *testNode
}

func (op *nodeOutputParser) Write(p []byte) (n int, err error) {
	tn := op.n
	tn.mu.Lock()
	defer tn.mu.Unlock()

	op.allBuf.Write(p)
	n, err = op.pendLineBuf.Write(p)
	op.parseLinesLocked()
	return
}

func (op *nodeOutputParser) parseLinesLocked() {
	n := op.n
	buf := op.pendLineBuf.Bytes()
	for len(buf) > 0 {
		nl := bytes.IndexByte(buf, '\n')
		if nl == -1 {
			break
		}
		line := buf[:nl+1]
		buf = buf[nl+1:]

		for _, f := range n.onLogLine {
			f(line)
		}
	}
	if len(buf) == 0 {
		op.pendLineBuf.Reset()
	} else {
		io.CopyN(io.Discard, &op.pendLineBuf, int64(op.pendLineBuf.Len()-len(buf)))
	}
}

type Daemon struct {
	Process *os.Process
}

func (d *Daemon) MustCleanShutdown(t testing.TB) {
	d.Process.Signal(os.Interrupt)
	ps, err := d.Process.Wait()
	if err != nil {
		t.Fatalf("tailscaled Wait: %v", err)
	}
	if ps.ExitCode() != 0 {
		t.Errorf("tailscaled ExitCode = %d; want 0", ps.ExitCode())
	}
}

// StartDaemon starts the node's tailscaled, failing if it fails to start.
// StartDaemon ensures that the process will exit when the test completes.
func (n *testNode) StartDaemon() *Daemon {
	return n.StartDaemonAsIPNGOOS(runtime.GOOS)
}

func (n *testNode) StartDaemonAsIPNGOOS(ipnGOOS string) *Daemon {
	t := n.env.t
	cmd := exec.Command(n.env.daemon)
	cmd.Args = append(cmd.Args,
		"--state="+n.stateFile,
		"--socket="+n.sockFile,
		"--socks5-server=localhost:0",
	)
	if *verboseTailscaled {
		cmd.Args = append(cmd.Args, "-verbose=2")
	}
	if !n.env.tunMode {
		cmd.Args = append(cmd.Args,
			"--tun=userspace-networking",
		)
	}
	if n.configFile != "" {
		cmd.Args = append(cmd.Args, "--config="+n.configFile)
	}
	cmd.Env = append(os.Environ(),
		"TS_DEBUG_PERMIT_HTTP_C2N=1",
		"TS_LOG_TARGET="+n.env.LogCatcherServer.URL,
		"HTTP_PROXY="+n.env.TrafficTrapServer.URL,
		"HTTPS_PROXY="+n.env.TrafficTrapServer.URL,
		"TS_DEBUG_FAKE_GOOS="+ipnGOOS,
		"TS_LOGS_DIR="+t.TempDir(),
		"TS_NETCHECK_GENERATE_204_URL="+n.env.ControlServer.URL+"/generate_204",
		"TS_ASSUME_NETWORK_UP_FOR_TEST=1", // don't pause control client in airplane mode (no wifi, etc)
		"TS_PANIC_IF_HIT_MAIN_CONTROL=1",
		"TS_DISABLE_PORTMAPPER=1", // shouldn't be needed; test is all localhost
		"TS_DEBUG_LOG_RATE=all",
	)
	if version.IsRace() {
		cmd.Env = append(cmd.Env, "GORACE=halt_on_error=1")
	}
	n.tailscaledParser = &nodeOutputParser{n: n}
	cmd.Stderr = n.tailscaledParser
	if *verboseTailscaled {
		cmd.Stdout = os.Stdout
		cmd.Stderr = io.MultiWriter(cmd.Stderr, os.Stderr)
	}
	if runtime.GOOS != "windows" {
		pr, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pw.Close() })
		cmd.ExtraFiles = append(cmd.ExtraFiles, pr)
		cmd.Env = append(cmd.Env, "TS_PARENT_DEATH_FD=3")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tailscaled: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	return &Daemon{
		Process: cmd.Process,
	}
}

func (n *testNode) MustUp(extraArgs ...string) {
	t := n.env.t
	t.Helper()
	args := []string{
		"up",
		"--login-server=" + n.env.controlURL(),
		"--reset",
	}
	args = append(args, extraArgs...)
	cmd := n.Tailscale(args...)
	t.Logf("Running %v ...", cmd)
	cmd.Stdout = nil // in case --verbose-tailscale was set
	cmd.Stderr = nil // in case --verbose-tailscale was set
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("up: %v, %v", string(b), err)
	}
}

func (n *testNode) MustDown() {
	t := n.env.t
	t.Logf("Running down ...")
	if err := n.Tailscale("down", "--accept-risk=all").Run(); err != nil {
		t.Fatalf("down: %v", err)
	}
}

func (n *testNode) MustLogOut() {
	t := n.env.t
	t.Logf("Running logout ...")
	if err := n.Tailscale("logout").Run(); err != nil {
		t.Fatalf("logout: %v", err)
	}
}

func (n *testNode) Ping(otherNode *testNode) error {
	t := n.env.t
	ip := otherNode.AwaitIP4().String()
	t.Logf("Running ping %v (from %v)...", ip, n.AwaitIP4())
	return n.Tailscale("ping", ip).Run()
}

// AwaitListening waits for the tailscaled to be serving local clients
// over its localhost IPC mechanism. (Unix socket, etc)
func (n *testNode) AwaitListening() {
	t := n.env.t
	if err := tstest.WaitFor(20*time.Second, func() (err error) {
		c, err := safesocket.ConnectContext(context.Background(), n.sockFile)
		if err == nil {
			c.Close()
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (n *testNode) AwaitIPs() []netip.Addr {
	t := n.env.t
	t.Helper()
	var addrs []netip.Addr
	if err := tstest.WaitFor(20*time.Second, func() error {
		cmd := n.Tailscale("ip")
		cmd.Stdout = nil // in case --verbose-tailscale was set
		cmd.Stderr = nil // in case --verbose-tailscale was set
		out, err := cmd.Output()
		if err != nil {
			return err
		}
		ips := string(out)
		ipslice := strings.Fields(ips)
		addrs = make([]netip.Addr, len(ipslice))

		for i, ip := range ipslice {
			netIP, err := netip.ParseAddr(ip)
			if err != nil {
				t.Fatal(err)
			}
			addrs[i] = netIP
		}
		return nil
	}); err != nil {
		t.Fatalf("awaiting an IP address: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatalf("returned IP address was blank")
	}
	return addrs
}

// AwaitIP4 returns the IPv4 address of n.
func (n *testNode) AwaitIP4() netip.Addr {
	t := n.env.t
	t.Helper()
	ips := n.AwaitIPs()
	return ips[0]
}

// AwaitIP6 returns the IPv6 address of n.
func (n *testNode) AwaitIP6() netip.Addr {
	t := n.env.t
	t.Helper()
	ips := n.AwaitIPs()
	return ips[1]
}

// AwaitRunning waits for n to reach the IPN state "Running".
func (n *testNode) AwaitRunning() {
	n.AwaitBackendState("Running")
}

func (n *testNode) AwaitBackendState(state string) {
	t := n.env.t
	t.Helper()
	if err := tstest.WaitFor(20*time.Second, func() error {
		st, err := n.Status()
		if err != nil {
			return err
		}
		if st.BackendState != state {
			return fmt.Errorf("in state %q; want %q", st.BackendState, state)
		}
		return nil
	}); err != nil {
		t.Fatalf("failure/timeout waiting for transition to Running status: %v", err)
	}
}

// AwaitNeedsLogin waits for n to reach the IPN state "NeedsLogin".
func (n *testNode) AwaitNeedsLogin() {
	t := n.env.t
	t.Helper()
	if err := tstest.WaitFor(20*time.Second, func() error {
		st, err := n.Status()
		if err != nil {
			return err
		}
		if st.BackendState != "NeedsLogin" {
			return fmt.Errorf("in state %q", st.BackendState)
		}
		return nil
	}); err != nil {
		t.Fatalf("failure/timeout waiting for transition to NeedsLogin status: %v", err)
	}
}

func (n *testNode) TailscaleForOutput(arg ...string) *exec.Cmd {
	cmd := n.Tailscale(arg...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd
}

// Tailscale returns a command that runs the tailscale CLI with the provided arguments.
// It does not start the process.
func (n *testNode) Tailscale(arg ...string) *exec.Cmd {
	cmd := exec.Command(n.env.cli)
	cmd.Args = append(cmd.Args, "--socket="+n.sockFile)
	cmd.Args = append(cmd.Args, arg...)
	cmd.Dir = n.dir
	cmd.Env = append(os.Environ(),
		"TS_DEBUG_UP_FLAG_GOOS="+n.upFlagGOOS,
		"TS_LOGS_DIR="+n.env.t.TempDir(),
	)
	if *verboseTailscale {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd
}

func (n *testNode) Status() (*ipnstate.Status, error) {
	cmd := n.Tailscale("status", "--json")
	cmd.Stdout = nil // in case --verbose-tailscale was set
	cmd.Stderr = nil // in case --verbose-tailscale was set
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("running tailscale status: %v, %s", err, out)
	}
	st := new(ipnstate.Status)
	if err := json.Unmarshal(out, st); err != nil {
		return nil, fmt.Errorf("decoding tailscale status JSON: %w", err)
	}
	return st, nil
}

func (n *testNode) MustStatus() *ipnstate.Status {
	tb := n.env.t
	tb.Helper()
	st, err := n.Status()
	if err != nil {
		tb.Fatal(err)
	}
	return st
}

// trafficTrap is an HTTP proxy handler to note whether any
// HTTP traffic tries to leave localhost from tailscaled. We don't
// expect any, so any request triggers a failure.
type trafficTrap struct {
	atomicErr syncs.AtomicValue[error]
}

func (tt *trafficTrap) Err() error {
	return tt.atomicErr.Load()
}

func (tt *trafficTrap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var got bytes.Buffer
	r.Write(&got)
	err := fmt.Errorf("unexpected HTTP request via proxy: %s", got.Bytes())
	mainError.Store(err)
	if tt.Err() == nil {
		// Best effort at remembering the first request.
		tt.atomicErr.Store(err)
	}
	log.Printf("Error: %v", err)
	w.WriteHeader(403)
}

type authURLParserWriter struct {
	buf bytes.Buffer
	fn  func(urlStr string) error
}

var authURLRx = regexp.MustCompile(`(https?://\S+/auth/\S+)`)

func (w *authURLParserWriter) Write(p []byte) (n int, err error) {
	n, err = w.buf.Write(p)
	m := authURLRx.FindSubmatch(w.buf.Bytes())
	if m != nil {
		urlStr := string(m[1])
		w.buf.Reset() // so it's not matched again
		if err := w.fn(urlStr); err != nil {
			return 0, err
		}
	}
	return n, err
}
