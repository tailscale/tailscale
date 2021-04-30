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
)

func TestIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not tested/working on Windows yet")
	}
	td := t.TempDir()
	daemonExe := build(t, td, "tailscale.com/cmd/tailscaled")
	cliExe := build(t, td, "tailscale.com/cmd/tailscale")

	logc := new(logCatcher)
	ts := httptest.NewServer(logc)
	defer ts.Close()

	httpProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got bytes.Buffer
		r.Write(&got)
		err := fmt.Errorf("unexpected HTTP proxy via proxy: %s", got.Bytes())
		t.Error(err)
		go panic(err)
	}))
	defer httpProxy.Close()

	socketPath := filepath.Join(td, "tailscale.sock")
	dcmd := exec.Command(daemonExe,
		"--tun=userspace-networking",
		"--state="+filepath.Join(td, "tailscale.state"),
		"--socket="+socketPath,
	)
	dcmd.Env = append(os.Environ(),
		"TS_LOG_TARGET="+ts.URL,
		"HTTP_PROXY="+httpProxy.URL,
		"HTTPS_PROXY="+httpProxy.URL,
	)
	if err := dcmd.Start(); err != nil {
		t.Fatalf("starting tailscaled: %v", err)
	}
	defer dcmd.Process.Kill()

	var json []byte
	if err := tstest.WaitFor(20*time.Second, func() (err error) {
		json, err = exec.Command(cliExe, "--socket="+socketPath, "status", "--json").CombinedOutput()
		if err != nil {
			return fmt.Errorf("running tailscale status: %v, %s", err, json)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if os.Getenv("TS_RUN_TEST") == "failing_up" {
		// Force a connection through the HTTP proxy to panic and fail.
		exec.Command(cliExe, "--socket="+socketPath, "up").Run()
	}

	if err := tstest.WaitFor(20*time.Second, func() error {
		const sub = `Program starting: `
		if !logc.logsContains(mem.S(sub)) {
			return fmt.Errorf("log catcher didn't see %#q; got %s", sub, logc.logsString())
		}
		return nil
	}); err != nil {
		t.Error(err)
	}

	dcmd.Process.Signal(os.Interrupt)

	ps, err := dcmd.Process.Wait()
	if err != nil {
		t.Fatalf("tailscaled Wait: %v", err)
	}
	if ps.ExitCode() != 0 {
		t.Errorf("tailscaled ExitCode = %d; want 0", ps.ExitCode())
	}

	t.Logf("number of HTTP logcatcher requests: %v", logc.numRequests())
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func findGo(t *testing.T) string {
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

func build(t *testing.T, outDir, target string) string {
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
