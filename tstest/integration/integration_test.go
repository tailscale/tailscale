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
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	"go4.org/mem"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/feature"
	_ "tailscale.com/feature/clientupdate"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/net/udprelay/status"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
)

func TestMain(m *testing.M) {
	// Have to disable UPnP which hits the network, otherwise it fails due to HTTP proxy.
	os.Setenv("TS_DISABLE_UPNP", "true")
	flag.Parse()
	v := m.Run()
	if v != 0 {
		os.Exit(v)
	}
	if err := MainError.Load(); err != nil {
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
	env := NewTestEnv(t)
	env.tunMode = true
	n1 := NewTestNode(t, env)
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
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)

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
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)

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
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)

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
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/15865")
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)
	n := NewTestNode(t, env)

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
	env := NewTestEnv(t)
	env.LogCatcher.StoreRawJSON()
	n := NewTestNode(t, env)

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
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)

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
	if err := n1.Tailscale("up", "--login-server="+n1.env.ControlURL(), "--hostname=foo").Run(); err != nil {
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
	for _, tt := range []struct {
		name string
		args []string
		//
		// What auth key should we use for control?
		authKey string
		//
		// Is tailscaled already logged in before we run this `up` command?
		alreadyLoggedIn bool
		//
		// Do we need to log in again with a new /auth/ URL?
		needsNewAuthURL bool
	}{
		{
			name:            "up",
			args:            []string{"up"},
			needsNewAuthURL: true,
		},
		{
			name:            "up-with-force-reauth",
			args:            []string{"up", "--force-reauth"},
			needsNewAuthURL: true,
		},
		{
			name:            "up-with-auth-key",
			args:            []string{"up", "--auth-key=opensesame"},
			authKey:         "opensesame",
			needsNewAuthURL: false,
		},
		{
			name:            "up-with-force-reauth-and-auth-key",
			args:            []string{"up", "--force-reauth", "--auth-key=opensesame"},
			authKey:         "opensesame",
			needsNewAuthURL: false,
		},
		{
			name:            "up-after-login",
			args:            []string{"up"},
			alreadyLoggedIn: true,
			needsNewAuthURL: false,
		},
		{
			name:            "up-with-force-reauth-after-login",
			args:            []string{"up", "--force-reauth"},
			alreadyLoggedIn: true,
			needsNewAuthURL: true,
		},
		{
			name:            "up-with-auth-key-after-login",
			args:            []string{"up", "--auth-key=opensesame"},
			authKey:         "opensesame",
			alreadyLoggedIn: true,
			needsNewAuthURL: false,
		},
		{
			name:            "up-with-force-reauth-and-auth-key-after-login",
			args:            []string{"up", "--force-reauth", "--auth-key=opensesame"},
			authKey:         "opensesame",
			alreadyLoggedIn: true,
			needsNewAuthURL: false,
		},
	} {
		tstest.Shard(t)

		for _, useSeamlessKeyRenewal := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s-seamless-%t", tt.name, useSeamlessKeyRenewal), func(t *testing.T) {
				tstest.Parallel(t)

				env := NewTestEnv(t, ConfigureControl(
					func(control *testcontrol.Server) {
						if tt.authKey != "" {
							control.RequireAuthKey = tt.authKey
						} else {
							control.RequireAuth = true
						}

						control.AllNodesSameUser = true

						if useSeamlessKeyRenewal {
							control.DefaultNodeCapabilities = &tailcfg.NodeCapMap{
								tailcfg.NodeAttrSeamlessKeyRenewal: []tailcfg.RawMessage{},
							}
						}
					},
				))

				n1 := NewTestNode(t, env)
				d1 := n1.StartDaemon()
				defer d1.MustCleanShutdown(t)

				cmdArgs := append(tt.args, "--login-server="+env.ControlURL())

				// This handler looks for /auth/ URLs in the stdout from "tailscale up",
				// and if it sees them, completes the auth process.
				//
				// It counts how many auth URLs it's seen.
				var authCountAtomic atomic.Int32
				authURLHandler := &authURLParserWriter{fn: func(urlStr string) error {
					t.Logf("saw auth URL %q", urlStr)
					if env.Control.CompleteAuth(urlStr) {
						if authCountAtomic.Add(1) > 1 {
							err := errors.New("completed multiple auth URLs")
							t.Error(err)
							return err
						}
						t.Logf("completed login to %s", urlStr)
						return nil
					} else {
						err := fmt.Errorf("Failed to complete initial login to %q", urlStr)
						t.Fatal(err)
						return err
					}
				}}

				// If we should be logged in at the start of the test case, go ahead
				// and run the login command.
				//
				// Otherwise, just wait for tailscaled to be listening.
				if tt.alreadyLoggedIn {
					t.Logf("Running initial login: %s", strings.Join(cmdArgs, " "))
					cmd := n1.Tailscale(cmdArgs...)
					cmd.Stdout = authURLHandler
					cmd.Stderr = cmd.Stdout
					if err := cmd.Run(); err != nil {
						t.Fatalf("up: %v", err)
					}
					authCountAtomic.Store(0)
					n1.AwaitRunning()
				} else {
					n1.AwaitListening()
				}

				st := n1.MustStatus()
				t.Logf("Status: %s", st.BackendState)

				t.Logf("Running command: %s", strings.Join(cmdArgs, " "))
				cmd := n1.Tailscale(cmdArgs...)
				cmd.Stdout = authURLHandler
				cmd.Stderr = cmd.Stdout

				if err := cmd.Run(); err != nil {
					t.Fatalf("up: %v", err)
				}
				t.Logf("Got IP: %v", n1.AwaitIP4())

				n1.AwaitRunning()

				var expectedAuthUrls int32
				if tt.needsNewAuthURL {
					expectedAuthUrls = 1
				}
				if n := authCountAtomic.Load(); n != expectedAuthUrls {
					t.Errorf("Auth URLs completed = %d; want %d", n, expectedAuthUrls)
				}
			})
		}
	}
}

func TestConfigFileAuthKey(t *testing.T) {
	tstest.SkipOnUnshardedCI(t)
	tstest.Shard(t)
	t.Parallel()
	const authKey = "opensesame"
	env := NewTestEnv(t, ConfigureControl(func(control *testcontrol.Server) {
		control.RequireAuthKey = authKey
	}))

	n1 := NewTestNode(t, env)
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
	env := NewTestEnv(t)

	// Create two nodes:
	n1 := NewTestNode(t, env)
	n1SocksAddrCh := n1.socks5AddrChan()
	d1 := n1.StartDaemon()

	n2 := NewTestNode(t, env)
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
		cleanLog := func(n *TestNode) []byte {
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
	env := NewTestEnv(t)

	// Create one node:
	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()

	all := env.Control.AllNodes()
	if len(all) != 1 {
		t.Fatalf("expected 1 node, got %d nodes", len(all))
	}
	tnode1 := all[0]

	n2 := NewTestNode(t, env)
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
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)
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
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)
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

	env := NewTestEnv(t)

	n1 := NewTestNode(t, env)
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

		ctx, cancel = context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "POST", "/echo", bytes.NewReader([]byte("abc")))
		if err != nil {
			t.Errorf("failed to create request: %v", err)
			continue
		}
		r, err := env.Control.NodeRoundTripper(nodeKey).RoundTrip(req)
		if err != nil {
			t.Errorf("RoundTrip failed: %v", err)
			continue
		}
		if r.StatusCode != 200 {
			t.Errorf("unexpected status code: %d", r.StatusCode)
			continue
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("error reading body: %v", err)
			continue
		}
		if string(b) != "abc" {
			t.Errorf("body = %q; want %q", b, "abc")
			continue
		}
		return
	}
	t.Error("all ping attempts failed")
}

// Issue 2434: when "down" (WantRunning false), tailscaled shouldn't
// be connected to control.
func TestNoControlConnWhenDown(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)

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
	env := NewTestEnv(t)
	n1 := NewTestNode(t, env)
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
	env := NewTestEnv(t)
	registerNode := func() (*TestNode, key.NodePublic) {
		n := NewTestNode(t, env)
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

	lc1 := &local.Client{
		Socket:        n1.sockFile,
		UseSocketOnly: true,
	}
	lc2 := &local.Client{
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

	testDial := func(t *testing.T, lc *local.Client, ip netip.Addr, port uint16, shouldFail bool) {
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
		env := NewTestEnv(t)
		registerNode := func() (*TestNode, key.NodePublic) {
			n := NewTestNode(t, env)
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
	env := NewTestEnv(t)
	// Spin up some nodes.
	nodes := make([]*TestNode, 2)
	for i := range nodes {
		nodes[i] = NewTestNode(t, env)
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
	if !feature.CanAutoUpdate() {
		t.Skip("auto-updates not supported on this platform")
	}
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)

	checkDefault := func(n *TestNode, want bool) error {
		enabled, ok := n.diskPrefs().AutoUpdate.Apply.Get()
		if !ok {
			return fmt.Errorf("auto-update for node is unset, should be set as %v", want)
		}
		if enabled != want {
			return fmt.Errorf("auto-update for node is %v, should be set as %v", enabled, want)
		}
		return nil
	}

	sendAndCheckDefault := func(t *testing.T, n *TestNode, send, want bool) {
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
		run  func(t *testing.T, n *TestNode)
	}{
		{
			desc: "tailnet-default-false",
			run: func(t *testing.T, n *TestNode) {
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
			run: func(t *testing.T, n *TestNode) {
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
			run: func(t *testing.T, n *TestNode) {
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
			n := NewTestNode(t, env)
			d := n.StartDaemon()
			defer d.MustCleanShutdown(t)

			n.AwaitResponding()
			n.MustUp()
			n.AwaitRunning()

			tt.run(t, n)
		})
	}
}

// TestDNSOverTCPIntervalResolver tests that the quad-100 resolver successfully
// serves TCP queries. It exercises the host's TCP stack, a TUN device, and
// gVisor/netstack.
// https://github.com/tailscale/corp/issues/22511
func TestDNSOverTCPIntervalResolver(t *testing.T) {
	tstest.Shard(t)
	if os.Getuid() != 0 {
		t.Skip("skipping when not root")
	}
	env := NewTestEnv(t)
	env.tunMode = true
	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()

	n1.AwaitResponding()
	n1.MustUp()
	n1.AwaitRunning()

	const dnsSymbolicFQDN = "magicdns.localhost-tailscale-daemon."

	cases := []struct {
		network     string
		serviceAddr netip.Addr
	}{
		{
			"tcp4",
			tsaddr.TailscaleServiceIP(),
		},
		{
			"tcp6",
			tsaddr.TailscaleServiceIPv6(),
		},
	}
	for _, c := range cases {
		err := tstest.WaitFor(time.Second*5, func() error {
			m := new(dns.Msg)
			m.SetQuestion(dnsSymbolicFQDN, dns.TypeA)
			conn, err := net.DialTimeout(c.network, net.JoinHostPort(c.serviceAddr.String(), "53"), time.Second*1)
			if err != nil {
				return err
			}
			defer conn.Close()
			dnsConn := &dns.Conn{
				Conn: conn,
			}
			dnsClient := &dns.Client{}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			resp, _, err := dnsClient.ExchangeWithConnContext(ctx, m, dnsConn)
			if err != nil {
				return err
			}
			if len(resp.Answer) != 1 {
				return fmt.Errorf("unexpected DNS resp: %s", resp)
			}
			var gotAddr net.IP
			answer, ok := resp.Answer[0].(*dns.A)
			if !ok {
				return fmt.Errorf("unexpected answer type: %s", resp.Answer[0])
			}
			gotAddr = answer.A
			if !bytes.Equal(gotAddr, tsaddr.TailscaleServiceIP().AsSlice()) {
				return fmt.Errorf("got (%s) != want (%s)", gotAddr, tsaddr.TailscaleServiceIP())
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	d1.MustCleanShutdown(t)
}

// TestNetstackTCPLoopback tests netstack loopback of a TCP stream, in both
// directions.
func TestNetstackTCPLoopback(t *testing.T) {
	tstest.Shard(t)
	if os.Getuid() != 0 {
		t.Skip("skipping when not root")
	}

	env := NewTestEnv(t)
	env.tunMode = true
	loopbackPort := 5201
	env.loopbackPort = &loopbackPort
	loopbackPortStr := strconv.Itoa(loopbackPort)
	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()

	n1.AwaitResponding()
	n1.MustUp()

	n1.AwaitIP4()
	n1.AwaitRunning()

	cases := []struct {
		lisAddr  string
		network  string
		dialAddr string
	}{
		{
			lisAddr:  net.JoinHostPort("127.0.0.1", loopbackPortStr),
			network:  "tcp4",
			dialAddr: net.JoinHostPort(tsaddr.TailscaleServiceIPString, loopbackPortStr),
		},
		{
			lisAddr:  net.JoinHostPort("::1", loopbackPortStr),
			network:  "tcp6",
			dialAddr: net.JoinHostPort(tsaddr.TailscaleServiceIPv6String, loopbackPortStr),
		},
	}

	writeBufSize := 128 << 10 // 128KiB, exercise GSO if enabled
	writeBufIterations := 100 // allow TCP send window to open up
	wantTotal := writeBufSize * writeBufIterations

	for _, c := range cases {
		lis, err := net.Listen(c.network, c.lisAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer lis.Close()

		writeFn := func(conn net.Conn) error {
			for i := 0; i < writeBufIterations; i++ {
				toWrite := make([]byte, writeBufSize)
				var wrote int
				for {
					n, err := conn.Write(toWrite)
					if err != nil {
						return err
					}
					wrote += n
					if wrote == len(toWrite) {
						break
					}
				}
			}
			return nil
		}

		readFn := func(conn net.Conn) error {
			var read int
			for {
				b := make([]byte, writeBufSize)
				n, err := conn.Read(b)
				if err != nil {
					return err
				}
				read += n
				if read == wantTotal {
					return nil
				}
			}
		}

		lisStepCh := make(chan error)
		go func() {
			conn, err := lis.Accept()
			if err != nil {
				lisStepCh <- err
				return
			}
			lisStepCh <- readFn(conn)
			lisStepCh <- writeFn(conn)
		}()

		var conn net.Conn
		err = tstest.WaitFor(time.Second*5, func() error {
			conn, err = net.DialTimeout(c.network, c.dialAddr, time.Second*1)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		dialerStepCh := make(chan error)
		go func() {
			dialerStepCh <- writeFn(conn)
			dialerStepCh <- readFn(conn)
		}()

		var (
			dialerSteps int
			lisSteps    int
		)
		for {
			select {
			case lisErr := <-lisStepCh:
				if lisErr != nil {
					t.Fatal(err)
				}
				lisSteps++
				if dialerSteps == 2 && lisSteps == 2 {
					return
				}
			case dialerErr := <-dialerStepCh:
				if dialerErr != nil {
					t.Fatal(err)
				}
				dialerSteps++
				if dialerSteps == 2 && lisSteps == 2 {
					return
				}
			}
		}
	}

	d1.MustCleanShutdown(t)
}

// TestNetstackUDPLoopback tests netstack loopback of UDP packets, in both
// directions.
func TestNetstackUDPLoopback(t *testing.T) {
	tstest.Shard(t)
	if os.Getuid() != 0 {
		t.Skip("skipping when not root")
	}

	env := NewTestEnv(t)
	env.tunMode = true
	loopbackPort := 5201
	env.loopbackPort = &loopbackPort
	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()

	n1.AwaitResponding()
	n1.MustUp()

	ip4 := n1.AwaitIP4()
	ip6 := n1.AwaitIP6()
	n1.AwaitRunning()

	cases := []struct {
		pingerLAddr *net.UDPAddr
		pongerLAddr *net.UDPAddr
		network     string
		dialAddr    *net.UDPAddr
	}{
		{
			pingerLAddr: &net.UDPAddr{IP: ip4.AsSlice(), Port: loopbackPort + 1},
			pongerLAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: loopbackPort},
			network:     "udp4",
			dialAddr:    &net.UDPAddr{IP: tsaddr.TailscaleServiceIP().AsSlice(), Port: loopbackPort},
		},
		{
			pingerLAddr: &net.UDPAddr{IP: ip6.AsSlice(), Port: loopbackPort + 1},
			pongerLAddr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: loopbackPort},
			network:     "udp6",
			dialAddr:    &net.UDPAddr{IP: tsaddr.TailscaleServiceIPv6().AsSlice(), Port: loopbackPort},
		},
	}

	writeBufSize := int(tstun.DefaultTUNMTU()) - 40 - 8 // mtu - ipv6 header - udp header
	wantPongs := 100

	for _, c := range cases {
		pongerConn, err := net.ListenUDP(c.network, c.pongerLAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer pongerConn.Close()

		var pingerConn *net.UDPConn
		err = tstest.WaitFor(time.Second*5, func() error {
			pingerConn, err = net.DialUDP(c.network, c.pingerLAddr, c.dialAddr)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		defer pingerConn.Close()

		pingerFn := func(conn *net.UDPConn) error {
			b := make([]byte, writeBufSize)
			n, err := conn.Write(b)
			if err != nil {
				return err
			}
			if n != len(b) {
				return fmt.Errorf("bad write size: %d", n)
			}
			err = conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
			if err != nil {
				return err
			}
			n, err = conn.Read(b)
			if err != nil {
				return err
			}
			if n != len(b) {
				return fmt.Errorf("bad read size: %d", n)
			}
			return nil
		}

		pongerFn := func(conn *net.UDPConn) error {
			for {
				b := make([]byte, writeBufSize)
				n, from, err := conn.ReadFromUDP(b)
				if err != nil {
					return err
				}
				if n != len(b) {
					return fmt.Errorf("bad read size: %d", n)
				}
				n, err = conn.WriteToUDP(b, from)
				if err != nil {
					return err
				}
				if n != len(b) {
					return fmt.Errorf("bad write size: %d", n)
				}
			}
		}

		pongerErrCh := make(chan error, 1)
		go func() {
			pongerErrCh <- pongerFn(pongerConn)
		}()

		err = tstest.WaitFor(time.Second*5, func() error {
			err = pingerFn(pingerConn)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		var pongsRX int
		for {
			pingerErrCh := make(chan error)
			go func() {
				pingerErrCh <- pingerFn(pingerConn)
			}()

			select {
			case err := <-pongerErrCh:
				t.Fatal(err)
			case err := <-pingerErrCh:
				if err != nil {
					t.Fatal(err)
				}
			}

			pongsRX++
			if pongsRX == wantPongs {
				break
			}
		}
	}

	d1.MustCleanShutdown(t)
}

func TestEncryptStateMigration(t *testing.T) {
	if !hostinfo.New().TPM.Present() {
		t.Skip("TPM not available")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("--encrypt-state for tailscaled state not supported on this platform")
	}
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)
	n := NewTestNode(t, env)

	runNode := func(t *testing.T, wantStateKeys []string) {
		t.Helper()

		// Run the node.
		d := n.StartDaemon()
		n.AwaitResponding()
		n.MustUp()
		n.AwaitRunning()

		// Check the contents of the state file.
		buf, err := os.ReadFile(n.stateFile)
		if err != nil {
			t.Fatalf("reading %q: %v", n.stateFile, err)
		}
		t.Logf("state file content:\n%s", buf)
		var content map[string]any
		if err := json.Unmarshal(buf, &content); err != nil {
			t.Fatalf("parsing %q: %v", n.stateFile, err)
		}
		for _, k := range wantStateKeys {
			if _, ok := content[k]; !ok {
				t.Errorf("state file is missing key %q", k)
			}
		}

		// Stop the node.
		d.MustCleanShutdown(t)
	}

	wantPlaintextStateKeys := []string{"_machinekey", "_current-profile", "_profiles"}
	wantEncryptedStateKeys := []string{"key", "nonce", "data"}
	t.Run("regular-state", func(t *testing.T) {
		n.encryptState = false
		runNode(t, wantPlaintextStateKeys)
	})
	t.Run("migrate-to-encrypted", func(t *testing.T) {
		n.encryptState = true
		runNode(t, wantEncryptedStateKeys)
	})
	t.Run("migrate-to-plaintext", func(t *testing.T) {
		n.encryptState = false
		runNode(t, wantPlaintextStateKeys)
	})
}

// TestPeerRelayPing creates three nodes with one acting as a peer relay.
// The test succeeds when "tailscale ping" flows through the peer
// relay between all 3 nodes, and "tailscale debug peer-relay-sessions" returns
// expected values.
func TestPeerRelayPing(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)

	env := NewTestEnv(t, ConfigureControl(func(server *testcontrol.Server) {
		server.PeerRelayGrants = true
	}))
	env.neverDirectUDP = true
	env.relayServerUseLoopback = true

	n1 := NewTestNode(t, env)
	n2 := NewTestNode(t, env)
	peerRelay := NewTestNode(t, env)

	allNodes := []*TestNode{n1, n2, peerRelay}
	wantPeerRelayServers := make(set.Set[string])
	for _, n := range allNodes {
		n.StartDaemon()
		n.AwaitResponding()
		n.MustUp()
		wantPeerRelayServers.Add(n.AwaitIP4().String())
		n.AwaitRunning()
	}

	if err := peerRelay.Tailscale("set", "--relay-server-port=0").Run(); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error)
	for _, a := range allNodes {
		go func() {
			err := tstest.WaitFor(time.Second*5, func() error {
				out, err := a.Tailscale("debug", "peer-relay-servers").CombinedOutput()
				if err != nil {
					return fmt.Errorf("debug peer-relay-servers failed: %v", err)
				}
				servers := make([]string, 0)
				err = json.Unmarshal(out, &servers)
				if err != nil {
					return fmt.Errorf("failed to unmarshal debug peer-relay-servers: %v", err)
				}
				gotPeerRelayServers := make(set.Set[string])
				for _, server := range servers {
					gotPeerRelayServers.Add(server)
				}
				if !gotPeerRelayServers.Equal(wantPeerRelayServers) {
					return fmt.Errorf("got peer relay servers: %v want: %v", gotPeerRelayServers, wantPeerRelayServers)
				}
				return nil
			})
			errCh <- err
		}()
	}
	for range allNodes {
		err := <-errCh
		if err != nil {
			t.Fatal(err)
		}
	}

	pingPairs := make([][2]*TestNode, 0)
	for _, a := range allNodes {
		for _, z := range allNodes {
			if a == z {
				continue
			}
			pingPairs = append(pingPairs, [2]*TestNode{a, z})
		}
	}
	for _, pair := range pingPairs {
		go func() {
			a := pair[0]
			z := pair[1]
			err := tstest.WaitFor(time.Second*10, func() error {
				remoteKey := z.MustStatus().Self.PublicKey
				if err := a.Tailscale("ping", "--until-direct=false", "--c=1", "--timeout=1s", z.AwaitIP4().String()).Run(); err != nil {
					return err
				}
				remotePeer, ok := a.MustStatus().Peer[remoteKey]
				if !ok {
					return fmt.Errorf("%v->%v remote peer not found", a.MustStatus().Self.ID, z.MustStatus().Self.ID)
				}
				if len(remotePeer.PeerRelay) == 0 {
					return fmt.Errorf("%v->%v not using peer relay, curAddr=%v relay=%v", a.MustStatus().Self.ID, z.MustStatus().Self.ID, remotePeer.CurAddr, remotePeer.Relay)
				}
				t.Logf("%v->%v using peer relay addr: %v", a.MustStatus().Self.ID, z.MustStatus().Self.ID, remotePeer.PeerRelay)
				return nil
			})
			errCh <- err
		}()
	}
	for range pingPairs {
		err := <-errCh
		if err != nil {
			t.Fatal(err)
		}
	}

	allControlNodes := env.Control.AllNodes()
	wantSessionsForDiscoShorts := make(set.Set[[2]string])
	for i, a := range allControlNodes {
		if i == len(allControlNodes)-1 {
			break
		}
		for _, z := range allControlNodes[i+1:] {
			wantSessionsForDiscoShorts.Add([2]string{a.DiscoKey.ShortString(), z.DiscoKey.ShortString()})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	debugSessions, err := peerRelay.LocalClient().DebugPeerRelaySessions(ctx)
	cancel()
	if err != nil {
		t.Fatalf("debug peer-relay-sessions failed: %v", err)
	}
	if len(debugSessions.Sessions) != len(wantSessionsForDiscoShorts) {
		t.Errorf("got %d peer relay sessions, want %d", len(debugSessions.Sessions), len(wantSessionsForDiscoShorts))
	}
	for _, session := range debugSessions.Sessions {
		if !wantSessionsForDiscoShorts.Contains([2]string{session.Client1.ShortDisco, session.Client2.ShortDisco}) &&
			!wantSessionsForDiscoShorts.Contains([2]string{session.Client2.ShortDisco, session.Client1.ShortDisco}) {
			t.Errorf("peer relay session for disco keys %s<->%s not found in debug peer-relay-sessions: %+v", session.Client1.ShortDisco, session.Client2.ShortDisco, debugSessions.Sessions)
		}
		for _, client := range []status.ClientInfo{session.Client1, session.Client2} {
			if client.BytesTx == 0 {
				t.Errorf("unexpected 0 bytes TX counter in peer relay session: %+v", session)
			}
			if client.PacketsTx == 0 {
				t.Errorf("unexpected 0 packets TX counter in peer relay session: %+v", session)
			}
			if !client.Endpoint.IsValid() {
				t.Errorf("unexpected endpoint zero value in peer relay session: %+v", session)
			}
			if len(client.ShortDisco) == 0 {
				t.Errorf("unexpected zero len short disco in peer relay session: %+v", session)
			}
		}
	}
}

func TestC2NDebugNetmap(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t, ConfigureControl(func(s *testcontrol.Server) {
		s.CollectServices = opt.False
	}))

	var testNodes []*TestNode
	var nodes []*tailcfg.Node
	for i := range 2 {
		n := NewTestNode(t, env)
		d := n.StartDaemon()
		defer d.MustCleanShutdown(t)

		n.AwaitResponding()
		n.MustUp()
		n.AwaitRunning()
		testNodes = append(testNodes, n)

		controlNodes := env.Control.AllNodes()
		if len(controlNodes) != i+1 {
			t.Fatalf("expected %d nodes, got %d nodes", i+1, len(controlNodes))
		}
		for _, cn := range controlNodes {
			if n.MustStatus().Self.PublicKey == cn.Key {
				nodes = append(nodes, cn)
				break
			}
		}
	}

	// getC2NNetmap fetches the current netmap. If a candidate map response is provided,
	// a candidate netmap is also fetched and compared to the current netmap.
	getC2NNetmap := func(node key.NodePublic, cand *tailcfg.MapResponse) *netmap.NetworkMap {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		var req *http.Request
		if cand != nil {
			body := must.Get(json.Marshal(&tailcfg.C2NDebugNetmapRequest{Candidate: cand}))
			req = must.Get(http.NewRequestWithContext(ctx, "POST", "/debug/netmap", bytes.NewReader(body)))
		} else {
			req = must.Get(http.NewRequestWithContext(ctx, "GET", "/debug/netmap", nil))
		}
		httpResp := must.Get(env.Control.NodeRoundTripper(node).RoundTrip(req))
		defer httpResp.Body.Close()

		if httpResp.StatusCode != 200 {
			t.Errorf("unexpected status code: %d", httpResp.StatusCode)
			return nil
		}

		respBody := must.Get(io.ReadAll(httpResp.Body))
		var resp tailcfg.C2NDebugNetmapResponse
		must.Do(json.Unmarshal(respBody, &resp))

		var current netmap.NetworkMap
		must.Do(json.Unmarshal(resp.Current, &current))

		if !current.PrivateKey.IsZero() {
			t.Errorf("current netmap has non-zero private key: %v", current.PrivateKey)
		}
		// Check candidate netmap if we sent a map response.
		if cand != nil {
			var candidate netmap.NetworkMap
			must.Do(json.Unmarshal(resp.Candidate, &candidate))
			if !candidate.PrivateKey.IsZero() {
				t.Errorf("candidate netmap has non-zero private key: %v", candidate.PrivateKey)
			}
			if diff := cmp.Diff(current.SelfNode, candidate.SelfNode); diff != "" {
				t.Errorf("SelfNode differs (-current +candidate):\n%s", diff)
			}
			if diff := cmp.Diff(current.Peers, candidate.Peers); diff != "" {
				t.Errorf("Peers differ (-current +candidate):\n%s", diff)
			}
		}
		return &current
	}

	for _, n := range nodes {
		mr := must.Get(env.Control.MapResponse(&tailcfg.MapRequest{NodeKey: n.Key}))
		nm := getC2NNetmap(n.Key, mr)

		// Make sure peers do not have "testcap" initially (we'll change this later).
		if len(nm.Peers) != 1 || nm.Peers[0].CapMap().Contains("testcap") {
			t.Fatalf("expected 1 peer without testcap, got: %v", nm.Peers)
		}

		// Make sure nodes think each other are offline initially.
		if nm.Peers[0].Online().Get() {
			t.Fatalf("expected 1 peer to be offline, got: %v", nm.Peers)
		}
	}

	// Send a delta update to n0, setting "testcap" on node 1.
	env.Control.AddRawMapResponse(nodes[0].Key, &tailcfg.MapResponse{
		PeersChangedPatch: []*tailcfg.PeerChange{{
			NodeID: nodes[1].ID, CapMap: tailcfg.NodeCapMap{"testcap": []tailcfg.RawMessage{}},
		}},
	})

	// node 0 should see node 1 with "testcap".
	must.Do(tstest.WaitFor(5*time.Second, func() error {
		st := testNodes[0].MustStatus()
		p, ok := st.Peer[nodes[1].Key]
		if !ok {
			return fmt.Errorf("node 0 (%s) doesn't see node 1 (%s) as peer\n%v", nodes[0].Key, nodes[1].Key, st)
		}
		if _, ok := p.CapMap["testcap"]; !ok {
			return fmt.Errorf("node 0 (%s) sees node 1 (%s) as peer but without testcap\n%v", nodes[0].Key, nodes[1].Key, p)
		}
		return nil
	}))

	// Check that node 0's current netmap has "testcap" for node 1.
	nm := getC2NNetmap(nodes[0].Key, nil)
	if len(nm.Peers) != 1 || !nm.Peers[0].CapMap().Contains("testcap") {
		t.Errorf("current netmap missing testcap: %v", nm.Peers[0].CapMap())
	}

	// Send a delta update to n1, marking node 0 as online.
	env.Control.AddRawMapResponse(nodes[1].Key, &tailcfg.MapResponse{
		PeersChangedPatch: []*tailcfg.PeerChange{{
			NodeID: nodes[0].ID, Online: ptr.To(true),
		}},
	})

	// node 1 should see node 0 as online.
	must.Do(tstest.WaitFor(5*time.Second, func() error {
		st := testNodes[1].MustStatus()
		p, ok := st.Peer[nodes[0].Key]
		if !ok || !p.Online {
			return fmt.Errorf("node 0 (%s) doesn't see node 1 (%s) as an online peer\n%v", nodes[0].Key, nodes[1].Key, st)
		}
		return nil
	}))

	// The netmap from node 1 should show node 0 as online.
	nm = getC2NNetmap(nodes[1].Key, nil)
	if len(nm.Peers) != 1 || !nm.Peers[0].Online().Get() {
		t.Errorf("expected peer to be online; got %+v", nm.Peers[0].AsStruct())
	}
}
