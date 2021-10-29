// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
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
	"inet.af/netaddr"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

var (
	verboseTailscaled = flag.Bool("verbose-tailscaled", false, "verbose tailscaled logging")
	verboseTailscale  = flag.Bool("verbose-tailscale", false, "verbose tailscale CLI logging")
)

var mainError atomic.Value // of error

func TestMain(m *testing.M) {
	// Have to disable UPnP which hits the network, otherwise it fails due to HTTP proxy.
	os.Setenv("TS_DISABLE_UPNP", "true")
	flag.Parse()
	v := m.Run()
	if v != 0 {
		os.Exit(v)
	}
	if err, ok := mainError.Load().(error); ok {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestOneNodeUp_NoAuth(t *testing.T) {
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon(t)
	defer d1.Kill()
	n1.AwaitResponding(t)
	n1.MustUp()

	t.Logf("Got IP: %v", n1.AwaitIP(t))
	n1.AwaitRunning(t)

	d1.MustCleanShutdown(t)

	t.Logf("number of HTTP logcatcher requests: %v", env.LogCatcher.numRequests())
}

func TestOneNodeExpiredKey(t *testing.T) {
	t.Skip("Test to exercise a problem which is not fixed yet.")
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon(t)
	defer d1.Kill()
	n1.AwaitResponding(t)
	n1.MustUp()
	n1.AwaitRunning(t)

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
	n1.AwaitNeedsLogin(t)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	if err := env.Control.AwaitNodeInMapRequest(ctx, nodeKey); err != nil {
		t.Fatal(err)
	}
	cancel()

	env.Control.SetExpireAllNodes(false)
	n1.AwaitRunning(t)

	d1.MustCleanShutdown(t)
}

func TestCollectPanic(t *testing.T) {
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n := newTestNode(t, env)

	cmd := exec.Command(n.env.Binaries.Daemon, "--cleanup")
	cmd.Env = append(os.Environ(),
		"TS_PLEASE_PANIC=1",
		"TS_LOG_TARGET="+n.env.LogCatcherServer.URL,
	)
	got, _ := cmd.CombinedOutput() // we expect it to fail, ignore err
	t.Logf("initial run: %s", got)

	// Now we run it again, and on start, it will upload the logs to logcatcher.
	cmd = exec.Command(n.env.Binaries.Daemon, "--cleanup")
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

// test Issue 2321: Start with UpdatePrefs should save prefs to disk
func TestStateSavedOnStart(t *testing.T) {
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon(t)
	defer d1.Kill()
	n1.AwaitResponding(t)
	n1.MustUp()

	t.Logf("Got IP: %v", n1.AwaitIP(t))
	n1.AwaitRunning(t)

	p1 := n1.diskPrefs(t)
	t.Logf("Prefs1: %v", p1.Pretty())

	// Bring it down, to prevent an EditPrefs call in the
	// subsequent "up", as we want to test the bug when
	// cmd/tailscale implements "up" via LocalBackend.Start.
	n1.MustDown()

	// And change the hostname to something:
	if err := n1.Tailscale("up", "--login-server="+n1.env.ControlServer.URL, "--hostname=foo").Run(); err != nil {
		t.Fatalf("up: %v", err)
	}

	p2 := n1.diskPrefs(t)
	if pretty := p1.Pretty(); pretty == p2.Pretty() {
		t.Errorf("Prefs didn't change on disk after 'up', still: %s", pretty)
	}
	if p2.Hostname != "foo" {
		t.Errorf("Prefs.Hostname = %q; want foo", p2.Hostname)
	}

	d1.MustCleanShutdown(t)
}

func TestOneNodeUp_Auth(t *testing.T) {
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins, configureControl(func(control *testcontrol.Server) {
		control.RequireAuth = true
	}))
	defer env.Close()

	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon(t)
	defer d1.Kill()

	n1.AwaitListening(t)

	st := n1.MustStatus(t)
	t.Logf("Status: %s", st.BackendState)

	t.Logf("Running up --login-server=%s ...", env.ControlServer.URL)

	cmd := n1.Tailscale("up", "--login-server="+env.ControlServer.URL)
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
	t.Logf("Got IP: %v", n1.AwaitIP(t))

	n1.AwaitRunning(t)

	if n := atomic.LoadInt32(&authCountAtomic); n != 1 {
		t.Errorf("Auth URLs completed = %d; want 1", n)
	}

	d1.MustCleanShutdown(t)
}

func TestTwoNodes(t *testing.T) {
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	// Create two nodes:
	n1 := newTestNode(t, env)
	n1SocksAddrCh := n1.socks5AddrChan()
	d1 := n1.StartDaemon(t)
	defer d1.Kill()

	n2 := newTestNode(t, env)
	n2SocksAddrCh := n2.socks5AddrChan()
	d2 := n2.StartDaemon(t)
	defer d2.Kill()

	n1Socks := n1.AwaitSocksAddr(t, n1SocksAddrCh)
	n2Socks := n1.AwaitSocksAddr(t, n2SocksAddrCh)
	t.Logf("node1 SOCKS5 addr: %v", n1Socks)
	t.Logf("node2 SOCKS5 addr: %v", n2Socks)

	n1.AwaitListening(t)
	n2.AwaitListening(t)
	n1.MustUp()
	n2.MustUp()
	n1.AwaitRunning(t)
	n2.AwaitRunning(t)

	if err := tstest.WaitFor(2*time.Second, func() error {
		st := n1.MustStatus(t)
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
		t.Error(err)
	}

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}

func TestNodeAddressIPFields(t *testing.T) {
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon(t)
	defer d1.Kill()

	n1.AwaitListening(t)
	n1.MustUp()
	n1.AwaitRunning(t)

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
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon(t)
	defer d1.Kill()

	n1.AwaitListening(t)
	n1.MustUp()
	n1.AwaitRunning(t)

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

// Issue 2434: when "down" (WantRunning false), tailscaled shouldn't
// be connected to control.
func TestNoControlConnWhenDown(t *testing.T) {
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon(t)
	defer d1.Kill()
	n1.AwaitResponding(t)

	// Come up the first time.
	n1.MustUp()
	ip1 := n1.AwaitIP(t)
	n1.AwaitRunning(t)

	// Then bring it down and stop the daemon.
	n1.MustDown()
	d1.MustCleanShutdown(t)

	env.LogCatcher.Reset()
	d2 := n1.StartDaemon(t)
	defer d2.Kill()
	n1.AwaitResponding(t)

	st := n1.MustStatus(t)
	if got, want := st.BackendState, "Stopped"; got != want {
		t.Fatalf("after restart, state = %q; want %q", got, want)
	}

	ip2 := n1.AwaitIP(t)
	if ip1 != ip2 {
		t.Errorf("IPs different: %q vs %q", ip1, ip2)
	}

	// The real test: verify our daemon doesn't have an HTTP request open.:
	if n := env.Control.InServeMap(); n != 0 {
		t.Errorf("in serve map = %d; want 0", n)
	}

	d2.MustCleanShutdown(t)
}

// Issue 2137: make sure Windows tailscaled works with the CLI alone,
// without the GUI to kick off a Start.
func TestOneNodeUpWindowsStyle(t *testing.T) {
	t.Parallel()
	bins := BuildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n1 := newTestNode(t, env)
	n1.upFlagGOOS = "windows"

	d1 := n1.StartDaemonAsIPNGOOS(t, "windows")
	defer d1.Kill()
	n1.AwaitResponding(t)
	n1.MustUp("--unattended")

	t.Logf("Got IP: %v", n1.AwaitIP(t))
	n1.AwaitRunning(t)

	d1.MustCleanShutdown(t)
}

// testEnv contains the test environment (set of servers) used by one
// or more nodes.
type testEnv struct {
	t        testing.TB
	Binaries *Binaries

	LogCatcher       *LogCatcher
	LogCatcherServer *httptest.Server

	Control       *testcontrol.Server
	ControlServer *httptest.Server

	TrafficTrap       *trafficTrap
	TrafficTrapServer *httptest.Server
}

type testEnvOpt interface {
	modifyTestEnv(*testEnv)
}

type configureControl func(*testcontrol.Server)

func (f configureControl) modifyTestEnv(te *testEnv) {
	f(te.Control)
}

// newTestEnv starts a bunch of services and returns a new test
// environment.
//
// Call Close to shut everything down.
func newTestEnv(t testing.TB, bins *Binaries, opts ...testEnvOpt) *testEnv {
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
		Binaries:          bins,
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
	return e
}

func (e *testEnv) Close() error {
	if err := e.TrafficTrap.Err(); err != nil {
		e.t.Errorf("traffic trap: %v", err)
		e.t.Logf("logs: %s", e.LogCatcher.logsString())
	}

	e.LogCatcherServer.Close()
	e.TrafficTrapServer.Close()
	e.ControlServer.Close()
	return nil
}

// testNode is a machine with a tailscale & tailscaled.
// Currently, the test is simplistic and user==node==machine.
// That may grow complexity later to test more.
type testNode struct {
	env *testEnv

	dir        string // temp dir for sock & state
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
		t.Fatalf("sockFile path %q (len %v) is too long, must be < 104", sockFile, len(sockFile))
	}
	return &testNode{
		env:       env,
		dir:       dir,
		sockFile:  sockFile,
		stateFile: filepath.Join(dir, "tailscale.state"),
	}
}

func (n *testNode) diskPrefs(t testing.TB) *ipn.Prefs {
	t.Helper()
	if _, err := ioutil.ReadFile(n.stateFile); err != nil {
		t.Fatalf("reading prefs: %v", err)
	}
	fs, err := ipn.NewFileStore(n.stateFile)
	if err != nil {
		t.Fatalf("reading prefs, NewFileStore: %v", err)
	}
	prefBytes, err := fs.ReadState(ipn.GlobalDaemonStateKey)
	if err != nil {
		t.Fatalf("reading prefs, ReadState: %v", err)
	}
	p := new(ipn.Prefs)
	if err := json.Unmarshal(prefBytes, p); err != nil {
		t.Fatalf("reading prefs, JSON unmarshal: %v", err)
	}
	return p
}

// AwaitResponding waits for n's tailscaled to be up enough to be
// responding, but doesn't wait for any particular state.
func (n *testNode) AwaitResponding(t testing.TB) {
	t.Helper()
	n.AwaitListening(t)

	st := n.MustStatus(t)
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
		addr := string(line)[i+len(sub):]
		select {
		case ch <- addr:
		default:
		}
	})
	return ch
}

func (n *testNode) AwaitSocksAddr(t testing.TB, ch <-chan string) string {
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
	buf bytes.Buffer
	n   *testNode
}

func (op *nodeOutputParser) Write(p []byte) (n int, err error) {
	n, err = op.buf.Write(p)
	op.parseLines()
	return
}

func (op *nodeOutputParser) parseLines() {
	n := op.n
	buf := op.buf.Bytes()
	for len(buf) > 0 {
		nl := bytes.IndexByte(buf, '\n')
		if nl == -1 {
			break
		}
		line := buf[:nl+1]
		buf = buf[nl+1:]
		lineTrim := bytes.TrimSpace(line)

		n.mu.Lock()
		for _, f := range n.onLogLine {
			f(lineTrim)
		}
		n.mu.Unlock()
	}
	if len(buf) == 0 {
		op.buf.Reset()
	} else {
		io.CopyN(ioutil.Discard, &op.buf, int64(op.buf.Len()-len(buf)))
	}
}

type Daemon struct {
	Process *os.Process
}

func (d *Daemon) Kill() {
	d.Process.Kill()
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

// StartDaemon starts the node's tailscaled, failing if it fails to
// start.
func (n *testNode) StartDaemon(t testing.TB) *Daemon {
	return n.StartDaemonAsIPNGOOS(t, runtime.GOOS)
}

func (n *testNode) StartDaemonAsIPNGOOS(t testing.TB, ipnGOOS string) *Daemon {
	cmd := exec.Command(n.env.Binaries.Daemon,
		"--tun=userspace-networking",
		"--state="+n.stateFile,
		"--socket="+n.sockFile,
		"--socks5-server=localhost:0",
	)
	cmd.Env = append(os.Environ(),
		"TS_LOG_TARGET="+n.env.LogCatcherServer.URL,
		"HTTP_PROXY="+n.env.TrafficTrapServer.URL,
		"HTTPS_PROXY="+n.env.TrafficTrapServer.URL,
		"TS_DEBUG_TAILSCALED_IPN_GOOS="+ipnGOOS,
		"TS_LOGS_DIR="+t.TempDir(),
	)
	cmd.Stderr = &nodeOutputParser{n: n}
	if *verboseTailscaled {
		cmd.Stdout = os.Stdout
		cmd.Stderr = io.MultiWriter(cmd.Stderr, os.Stderr)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tailscaled: %v", err)
	}
	return &Daemon{
		Process: cmd.Process,
	}
}

func (n *testNode) MustUp(extraArgs ...string) {
	t := n.env.t
	args := []string{
		"up",
		"--login-server=" + n.env.ControlServer.URL,
	}
	args = append(args, extraArgs...)
	t.Logf("Running %v ...", args)
	if b, err := n.Tailscale(args...).CombinedOutput(); err != nil {
		t.Fatalf("up: %v, %v", string(b), err)
	}
}

func (n *testNode) MustDown() {
	t := n.env.t
	t.Logf("Running down ...")
	if err := n.Tailscale("down").Run(); err != nil {
		t.Fatalf("down: %v", err)
	}
}

// AwaitListening waits for the tailscaled to be serving local clients
// over its localhost IPC mechanism. (Unix socket, etc)
func (n *testNode) AwaitListening(t testing.TB) {
	if err := tstest.WaitFor(20*time.Second, func() (err error) {
		c, err := safesocket.Connect(n.sockFile, 41112)
		if err != nil {
			return err
		}
		c.Close()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (n *testNode) AwaitIPs(t testing.TB) []netaddr.IP {
	t.Helper()
	var addrs []netaddr.IP
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
		addrs = make([]netaddr.IP, len(ipslice))

		for i, ip := range ipslice {
			netIP, err := netaddr.ParseIP(ip)
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

// AwaitIP returns the IP address of n.
func (n *testNode) AwaitIP(t testing.TB) netaddr.IP {
	t.Helper()
	ips := n.AwaitIPs(t)
	return ips[0]
}

// AwaitRunning waits for n to reach the IPN state "Running".
func (n *testNode) AwaitRunning(t testing.TB) {
	t.Helper()
	if err := tstest.WaitFor(20*time.Second, func() error {
		st, err := n.Status()
		if err != nil {
			return err
		}
		if st.BackendState != "Running" {
			return fmt.Errorf("in state %q", st.BackendState)
		}
		return nil
	}); err != nil {
		t.Fatalf("failure/timeout waiting for transition to Running status: %v", err)
	}
}

// AwaitNeedsLogin waits for n to reach the IPN state "NeedsLogin".
func (n *testNode) AwaitNeedsLogin(t testing.TB) {
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

// Tailscale returns a command that runs the tailscale CLI with the provided arguments.
// It does not start the process.
func (n *testNode) Tailscale(arg ...string) *exec.Cmd {
	cmd := exec.Command(n.env.Binaries.CLI, "--socket="+n.sockFile)
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

func (n *testNode) MustStatus(tb testing.TB) *ipnstate.Status {
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
	atomicErr atomic.Value // of error
}

func (tt *trafficTrap) Err() error {
	if err, ok := tt.atomicErr.Load().(error); ok {
		return err
	}
	return nil
}

func (tt *trafficTrap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var got bytes.Buffer
	r.Write(&got)
	err := fmt.Errorf("unexpected HTTP proxy via proxy: %s", got.Bytes())
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
