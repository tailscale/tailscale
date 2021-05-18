// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package integration contains Tailscale integration tests.
package integration

import (
	"bytes"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/safesocket"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/version"
)

var verbose = flag.Bool("verbose", false, "verbose debug logs")

var mainError atomic.Value // of error

func TestMain(m *testing.M) {
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
	bins := buildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	n1 := newTestNode(t, env)

	d1 := n1.StartDaemon(t)
	defer d1.Kill()

	n1.AwaitListening(t)

	st := n1.MustStatus(t)
	t.Logf("Status: %s", st.BackendState)

	if err := tstest.WaitFor(20*time.Second, func() error {
		const sub = `Program starting: `
		if !env.LogCatcher.logsContains(mem.S(sub)) {
			return fmt.Errorf("log catcher didn't see %#q; got %s", sub, env.LogCatcher.logsString())
		}
		return nil
	}); err != nil {
		t.Error(err)
	}

	n1.MustUp()

	if d, _ := time.ParseDuration(os.Getenv("TS_POST_UP_SLEEP")); d > 0 {
		t.Logf("Sleeping for %v to give 'up' time to misbehave (https://github.com/tailscale/tailscale/issues/1840) ...", d)
		time.Sleep(d)
	}

	t.Logf("Got IP: %v", n1.AwaitIP(t))
	n1.AwaitRunning(t)

	d1.MustCleanShutdown(t)

	t.Logf("number of HTTP logcatcher requests: %v", env.LogCatcher.numRequests())
}

func TestOneNodeUp_Auth(t *testing.T) {
	t.Parallel()
	bins := buildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()
	env.Control.RequireAuth = true

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
	bins := buildTestBinaries(t)

	env := newTestEnv(t, bins)
	defer env.Close()

	// Create two nodes:
	n1 := newTestNode(t, env)
	d1 := n1.StartDaemon(t)
	defer d1.Kill()

	n2 := newTestNode(t, env)
	d2 := n2.StartDaemon(t)
	defer d2.Kill()

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
	bins := buildTestBinaries(t)

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

// testBinaries are the paths to a tailscaled and tailscale binary.
// These can be shared by multiple nodes.
type testBinaries struct {
	dir    string // temp dir for tailscale & tailscaled
	daemon string // tailscaled
	cli    string // tailscale
}

// buildTestBinaries builds tailscale and tailscaled, failing the test
// if they fail to compile.
func buildTestBinaries(t testing.TB) *testBinaries {
	td := t.TempDir()
	build(t, td, "tailscale.com/cmd/tailscaled", "tailscale.com/cmd/tailscale")
	return &testBinaries{
		dir:    td,
		daemon: filepath.Join(td, "tailscaled"+exe()),
		cli:    filepath.Join(td, "tailscale"+exe()),
	}
}

// testEnv contains the test environment (set of servers) used by one
// or more nodes.
type testEnv struct {
	t        testing.TB
	Binaries *testBinaries

	LogCatcher       *logCatcher
	LogCatcherServer *httptest.Server

	Control       *testcontrol.Server
	ControlServer *httptest.Server

	TrafficTrap       *trafficTrap
	TrafficTrapServer *httptest.Server

	derpShutdown func()
}

// newTestEnv starts a bunch of services and returns a new test
// environment.
//
// Call Close to shut everything down.
func newTestEnv(t testing.TB, bins *testBinaries) *testEnv {
	if runtime.GOOS == "windows" {
		t.Skip("not tested/working on Windows yet")
	}
	derpMap, derpShutdown := runDERPAndStun(t, logger.Discard)
	logc := new(logCatcher)
	control := &testcontrol.Server{
		DERPMap: derpMap,
	}
	trafficTrap := new(trafficTrap)
	e := &testEnv{
		t:                 t,
		Binaries:          bins,
		LogCatcher:        logc,
		LogCatcherServer:  httptest.NewServer(logc),
		Control:           control,
		ControlServer:     httptest.NewServer(control),
		TrafficTrap:       trafficTrap,
		TrafficTrapServer: httptest.NewServer(trafficTrap),
		derpShutdown:      derpShutdown,
	}
	e.Control.BaseURL = e.ControlServer.URL
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
	e.derpShutdown()
	return nil
}

// testNode is a machine with a tailscale & tailscaled.
// Currently, the test is simplistic and user==node==machine.
// That may grow complexity later to test more.
type testNode struct {
	env *testEnv

	dir       string // temp dir for sock & state
	sockFile  string
	stateFile string
}

// newTestNode allocates a temp directory for a new test node.
// The node is not started automatically.
func newTestNode(t *testing.T, env *testEnv) *testNode {
	dir := t.TempDir()
	return &testNode{
		env:       env,
		dir:       dir,
		sockFile:  filepath.Join(dir, "tailscale.sock"),
		stateFile: filepath.Join(dir, "tailscale.state"),
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
	cmd := exec.Command(n.env.Binaries.daemon,
		"--tun=userspace-networking",
		"--state="+n.stateFile,
		"--socket="+n.sockFile,
	)
	cmd.Env = append(os.Environ(),
		"TS_LOG_TARGET="+n.env.LogCatcherServer.URL,
		"HTTP_PROXY="+n.env.TrafficTrapServer.URL,
		"HTTPS_PROXY="+n.env.TrafficTrapServer.URL,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tailscaled: %v", err)
	}
	return &Daemon{
		Process: cmd.Process,
	}
}

func (n *testNode) MustUp() {
	t := n.env.t
	t.Logf("Running up --login-server=%s ...", n.env.ControlServer.URL)
	if err := n.Tailscale("up", "--login-server="+n.env.ControlServer.URL).Run(); err != nil {
		t.Fatalf("up: %v", err)
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

func (n *testNode) AwaitIP(t testing.TB) (ips string) {
	t.Helper()
	if err := tstest.WaitFor(20*time.Second, func() error {
		out, err := n.Tailscale("ip").Output()
		if err != nil {
			return err
		}
		ips = string(out)
		return nil
	}); err != nil {
		t.Fatalf("awaiting an IP address: %v", err)
	}
	if ips == "" {
		t.Fatalf("returned IP address was blank")
	}
	return ips
}

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

// Tailscale returns a command that runs the tailscale CLI with the provided arguments.
// It does not start the process.
func (n *testNode) Tailscale(arg ...string) *exec.Cmd {
	cmd := exec.Command(n.env.Binaries.cli, "--socket="+n.sockFile)
	cmd.Args = append(cmd.Args, arg...)
	cmd.Dir = n.dir
	return cmd
}

func (n *testNode) Status() (*ipnstate.Status, error) {
	out, err := n.Tailscale("status", "--json").CombinedOutput()
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

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func findGo(t testing.TB) string {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go"+exe())
	if fi, err := os.Stat(goBin); err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("failed to find go at %v", goBin)
		}
		t.Fatalf("looking for go binary: %v", err)
	} else if !fi.Mode().IsRegular() {
		t.Fatalf("%v is unexpected %v", goBin, fi.Mode())
	}
	return goBin
}

// buildMu limits our use of "go build" to one at a time, so we don't
// fight Go's built-in caching trying to do the same build concurrently.
var buildMu sync.Mutex

func build(t testing.TB, outDir string, targets ...string) {
	buildMu.Lock()
	defer buildMu.Unlock()

	t0 := time.Now()
	defer func() { t.Logf("built %s in %v", targets, time.Since(t0).Round(time.Millisecond)) }()

	goBin := findGo(t)
	cmd := exec.Command(goBin, "install")
	if version.IsRace() {
		cmd.Args = append(cmd.Args, "-race")
	}
	cmd.Args = append(cmd.Args, targets...)
	cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH, "GOBIN="+outDir)
	errOut, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	if strings.Contains(string(errOut), "when GOBIN is set") {
		// Fallback slow path for cross-compiled binaries.
		for _, target := range targets {
			outFile := filepath.Join(outDir, path.Base(target)+exe())
			cmd := exec.Command(goBin, "build", "-o", outFile, target)
			cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH)
			if errOut, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("failed to build %v with %v: %v, %s", target, goBin, err, errOut)
			}
		}
		return
	}
	t.Fatalf("failed to build %v with %v: %v, %s", targets, goBin, err, errOut)
}

// logCatcher is a minimal logcatcher for the logtail upload client.
type logCatcher struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	gotErr error
	reqs   int
}

func (lc *logCatcher) logsContains(sub mem.RO) bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return mem.Contains(mem.B(lc.buf.Bytes()), sub)
}

func (lc *logCatcher) numRequests() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.reqs
}

func (lc *logCatcher) logsString() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.buf.String()
}

func (lc *logCatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "zstd" {
		var err error
		body, err = smallzstd.NewDecoder(body)
		if err != nil {
			log.Printf("bad caught zstd: %v", err)
			http.Error(w, err.Error(), 400)
			return
		}
	}
	bodyBytes, _ := ioutil.ReadAll(body)

	type Entry struct {
		Logtail struct {
			ClientTime time.Time `json:"client_time"`
			ServerTime time.Time `json:"server_time"`
			Error      struct {
				BadData string `json:"bad_data"`
			} `json:"error"`
		} `json:"logtail"`
		Text string `json:"text"`
	}
	var jreq []Entry
	var err error
	if len(bodyBytes) > 0 && bodyBytes[0] == '[' {
		err = json.Unmarshal(bodyBytes, &jreq)
	} else {
		var ent Entry
		err = json.Unmarshal(bodyBytes, &ent)
		jreq = append(jreq, ent)
	}

	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.reqs++
	if lc.gotErr == nil && err != nil {
		lc.gotErr = err
	}
	if err != nil {
		fmt.Fprintf(&lc.buf, "error from %s of %#q: %v\n", r.Method, bodyBytes, err)
	} else {
		for _, ent := range jreq {
			fmt.Fprintf(&lc.buf, "%s\n", strings.TrimSpace(ent.Text))
			if *verbose {
				fmt.Fprintf(os.Stderr, "%s\n", strings.TrimSpace(ent.Text))
			}
		}
	}
	w.WriteHeader(200) // must have no content, but not a 204
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

func runDERPAndStun(t testing.TB, logf logger.Logf) (derpMap *tailcfg.DERPMap, cleanup func()) {
	var serverPrivateKey key.Private
	if _, err := crand.Read(serverPrivateKey[:]); err != nil {
		t.Fatal(err)
	}
	d := derp.NewServer(serverPrivateKey, logf)

	httpsrv := httptest.NewUnstartedServer(derphttp.Handler(d))
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()

	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})

	m := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:         "t1",
						RegionID:     1,
						HostName:     "127.0.0.1", // to bypass HTTP proxy
						IPv4:         "127.0.0.1",
						IPv6:         "none",
						STUNPort:     stunAddr.Port,
						DERPTestPort: httpsrv.Listener.Addr().(*net.TCPAddr).Port,
						STUNTestIP:   stunAddr.IP.String(),
					},
				},
			},
		},
	}

	cleanup = func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
	}

	return m, cleanup
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
