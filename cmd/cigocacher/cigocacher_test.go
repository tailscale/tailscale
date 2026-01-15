// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bradfitz/go-tool-cache/gocached"
)

func TestResultsAreCached(t *testing.T) {
	tmp := t.TempDir()

	addr, debugAddr, cleanup := startGocached(t, tmp)
	defer cleanup()

	bin := buildCigocacher(t, tmp)
	cacheDir := filepath.Join(tmp, "cache")

	for i := range 2 {
		initialGets, initialPuts := getsAndPuts(t, debugAddr)
		if err := os.RemoveAll(cacheDir); err != nil {
			t.Fatalf("removing cache dir before run %d: %v", i, err)
		}
		cmd := exec.Command("go", "test", "-run", "TestCacheable", "-v", "tailscale.com/cmd/cigocacher/testpkg")
		cmd.Env = append(
			os.Environ(),
			fmt.Sprintf(`GOCACHEPROG=%s --cache-dir=%s --cigocached-url http://%s`, bin, cacheDir, addr),
			// "GODEBUG=gocachetest=1",
			"GODEBUG=gocachehash=1",
		)
		t.Logf("running tests, i=%d", i)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("first go test run failed: %v\nOutput:\n%s", err, out)
		}
		t.Logf("go test run %d output:\n%s", i, out)
		finalGets, finalPuts := getsAndPuts(t, debugAddr)
		t.Logf("run %d: gets %d -> %d, puts %d -> %d", i, initialGets, finalGets, initialPuts, finalPuts)
		if i == 1 && !strings.Contains(string(out), "(cached)") {
			t.Fatalf("second go test run was not cached; output:\n%s", out)
		}
	}
}

func startGocached(t *testing.T, tmp string) (addr, debugAddr string, cleanup func()) {
	t.Helper()
	t.Log("starting gocached")
	srv, err := gocached.NewServer(
		gocached.WithShutdownCtx(t.Context()),
		gocached.WithDir(filepath.Join(tmp, "gocached")),
	)
	if err != nil {
		t.Fatalf("starting server: %v", err)
	}

	debugMux := http.NewServeMux()
	debugMux.HandleFunc("/", srv.ServeHTTPDebug)
	debugLn, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("starting debug listener: %v", err)
	}
	debugSrv := &http.Server{
		Handler: debugMux,
	}
	go func() {
		t.Logf("debug server listening on %v", debugLn.Addr())
		if err := debugSrv.Serve(debugLn); err != nil && err != http.ErrServerClosed {
			t.Logf("error serving debug: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.ServeHTTP)
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("starting listener: %v", err)
	}
	hSrv := &http.Server{
		Handler: mux,
	}
	go func() {
		t.Logf("server listening on %v", ln.Addr())
		if err := hSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("error serving: %v", err)
		}
	}()
	return ln.Addr().String(), debugLn.Addr().String(), func() {
		hSrv.Shutdown(t.Context())
		debugSrv.Shutdown(t.Context())
	}
}

func buildCigocacher(t *testing.T, tmp string) string {
	t.Helper()
	t.Log("building cigocacher")
	p := filepath.Join(tmp, "cigocacher")
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", p, "tailscale.com/cmd/cigocacher")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building cigocacher: %v\nOutput:\n%s", err, out)
	}
	return p
}

func getsAndPuts(t *testing.T, debugAddr string) (gets, puts int) {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://%s/metrics", debugAddr))
	if err != nil {
		t.Fatalf("getting metrics: %v", err)
	}
	defer resp.Body.Close()
	metrics, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading metrics body: %v", err)
	}
	for _, line := range strings.Split(string(metrics), "\n") {
		if strings.HasPrefix(line, "gocached_gets ") {
			fmt.Sscanf(line, "gocached_gets %d", &gets)
		}
		if strings.HasPrefix(line, "gocached_puts ") {
			fmt.Sscanf(line, "gocached_puts %d", &puts)
		}
	}

	return gets, puts
}
