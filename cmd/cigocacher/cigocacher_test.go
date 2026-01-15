// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bradfitz/go-tool-cache/gocached"
)

func TestResultsAreCached(t *testing.T) {
	tmp := t.TempDir()

	addr, cleanup := startGocached(t, tmp)
	defer cleanup()

	bin := buildCigocacher(t, tmp)
	cacheDir := filepath.Join(tmp, "cache")

	for i := range 2 {
		if err := os.RemoveAll(cacheDir); err != nil {
			t.Fatalf("removing cache dir before run %d: %v", i, err)
		}
		cmd := exec.Command("go", "test", "-run", "TestCacheable", "-v", "tailscale.com/cmd/cigocacher/testpkg")
		cmd.Env = append(
			os.Environ(),
			fmt.Sprintf(`GOCACHEPROG=%s --cache-dir=%s --cigocached-url http://%s`, bin, cacheDir, addr),
			"GODEBUG=gocachetest=1",
		)
		t.Logf("running tests, i=%d", i)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("first go test run failed: %v\nOutput:\n%s", err, out)
		}
		t.Logf("go test run %d output:\n%s", i, out)
		if i == 1 && !strings.Contains(string(out), "(cached)") {
			t.Fatalf("second go test run was not cached; output:\n%s", out)
		}
	}
}

func startGocached(t *testing.T, tmp string) (addr string, cleanup func()) {
	t.Log("starting gocached")
	srv, err := gocached.NewServer(
		gocached.WithShutdownCtx(t.Context()),
		gocached.WithDir(filepath.Join(tmp, "gocached")),
	)
	if err != nil {
		t.Fatalf("starting server: %v", err)
	}

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
			t.Fatalf("serving: %v", err)
		}
	}()
	return ln.Addr().String(), func() {
		hSrv.Shutdown(t.Context())
	}
}

func buildCigocacher(t *testing.T, tmp string) string {
	t.Log("building cigocacher")
	p := filepath.Join(tmp, "cigocacher")
	cmd := exec.Command("go", "build", "-o", p, "tailscale.com/cmd/cigocacher")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building cigocacher: %v\nOutput:\n%s", err, out)
	}
	return p
}
