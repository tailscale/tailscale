// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package integration contains Tailscale integration tests.
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/smallzstd"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
)

func TestIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not tested/working on Windows yet")
	}

	bins := buildTestBinaries(t)

	env := newTestEnv(bins)
	defer env.Close()

	n1 := newTestNode(t, env)

	dcmd := n1.StartDaemon(t)
	defer dcmd.Process.Kill()

	var json []byte
	if err := tstest.WaitFor(20*time.Second, func() (err error) {
		json, err = n1.Tailscale("status", "--json").CombinedOutput()
		if err != nil {
			return fmt.Errorf("running tailscale status: %v, %s", err, json)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := tstest.WaitFor(20*time.Second, func() error {
		const sub = `Program starting: `
		if !env.LogCatcher.logsContains(mem.S(sub)) {
			return fmt.Errorf("log catcher didn't see %#q; got %s", sub, env.LogCatcher.logsString())
		}
		return nil
	}); err != nil {
		t.Error(err)
	}

	if err := n1.Tailscale("up", "--login-server="+env.ControlServer.URL).Run(); err != nil {
		t.Fatalf("up: %v", err)
	}

	var ip string
	if err := tstest.WaitFor(20*time.Second, func() error {
		out, err := n1.Tailscale("ip").Output()
		if err != nil {
			return err
		}
		ip = string(out)
		return nil
	}); err != nil {
		t.Error(err)
	}
	t.Logf("Got IP: %v", ip)

	dcmd.Process.Signal(os.Interrupt)

	ps, err := dcmd.Process.Wait()
	if err != nil {
		t.Fatalf("tailscaled Wait: %v", err)
	}
	if ps.ExitCode() != 0 {
		t.Errorf("tailscaled ExitCode = %d; want 0", ps.ExitCode())
	}

	t.Logf("number of HTTP logcatcher requests: %v", env.LogCatcher.numRequests())
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
	return &testBinaries{
		dir:    td,
		daemon: build(t, td, "tailscale.com/cmd/tailscaled"),
		cli:    build(t, td, "tailscale.com/cmd/tailscale"),
	}
}

// testEnv contains the test environment (set of servers) used by one
// or more nodes.
type testEnv struct {
	Binaries *testBinaries

	LogCatcher       *logCatcher
	LogCatcherServer *httptest.Server

	Control       *testcontrol.Server
	ControlServer *httptest.Server

	// CatchBadTrafficServer is an HTTP server that panics the process
	// if it receives any traffic. We point the HTTP_PROXY to this,
	// so any accidental traffic leaving tailscaled goes here and fails
	// the test. (localhost traffic bypasses HTTP_PROXY)
	CatchBadTrafficServer *httptest.Server
}

// newTestEnv starts a bunch of services and returns a new test
// environment.
//
// Call Close to shut everything down.
func newTestEnv(bins *testBinaries) *testEnv {
	logc := new(logCatcher)
	control := new(testcontrol.Server)
	return &testEnv{
		Binaries:              bins,
		LogCatcher:            logc,
		LogCatcherServer:      httptest.NewServer(logc),
		CatchBadTrafficServer: httptest.NewServer(http.HandlerFunc(catchUnexpectedTraffic)),
		Control:               control,
		ControlServer:         httptest.NewServer(control),
	}
}

func (e *testEnv) Close() error {
	e.LogCatcherServer.Close()
	e.CatchBadTrafficServer.Close()
	e.ControlServer.Close()
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

// StartDaemon starts the node's tailscaled, failing if it fails to
// start.
func (n *testNode) StartDaemon(t testing.TB) *exec.Cmd {
	cmd := exec.Command(n.env.Binaries.daemon,
		"--tun=userspace-networking",
		"--state="+n.stateFile,
		"--socket="+n.sockFile,
	)
	cmd.Env = append(os.Environ(),
		"TS_LOG_TARGET="+n.env.LogCatcherServer.URL,
		"HTTP_PROXY="+n.env.CatchBadTrafficServer.URL,
		"HTTPS_PROXY="+n.env.CatchBadTrafficServer.URL,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tailscaled: %v", err)
	}
	return cmd
}

// Tailscale returns a command that runs the tailscale CLI with the provided arguments.
// It does not start the process.
func (n *testNode) Tailscale(arg ...string) *exec.Cmd {
	cmd := exec.Command(n.env.Binaries.cli, "--socket="+n.sockFile)
	cmd.Args = append(cmd.Args, arg...)
	cmd.Dir = n.dir
	return cmd
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
	t.Logf("using go binary %v", goBin)
	return goBin
}

func build(t testing.TB, outDir, target string) string {
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	bin := filepath.Join(outDir, path.Base(target)) + exe
	errOut, err := exec.Command(findGo(t), "build", "-o", bin, target).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build %v: %v, %s", target, err, errOut)
	}
	return bin
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
		}
	}
	w.WriteHeader(200) // must have no content, but not a 204
}

// catchUnexpectedTraffic is an HTTP proxy handler to blow up
// if any HTTP traffic tries to leave localhost from
// tailscaled.
func catchUnexpectedTraffic(w http.ResponseWriter, r *http.Request) {
	var got bytes.Buffer
	r.Write(&got)
	err := fmt.Errorf("unexpected HTTP proxy via proxy: %s", got.Bytes())
	go panic(err)
}
