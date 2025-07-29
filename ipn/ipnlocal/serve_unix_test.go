// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package ipnlocal

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
)

func TestServeUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets not supported on Windows")
	}

	// Create a temporary directory for our socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create a test HTTP server on Unix socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix socket listener: %v", err)
	}
	defer listener.Close()

	testResponse := "Hello from Unix socket!"
	testServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, testResponse)
		}),
	}

	go testServer.Serve(listener)
	defer testServer.Close()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Create LocalBackend with test logger
	logf := tstest.WhileTestRunningLogger(t)
	b := &LocalBackend{
		logf: logf,
		sys:  &tsd.System{},
	}

	// Test creating proxy handler for Unix socket
	handler, err := b.proxyHandlerForBackend("unix:" + socketPath)
	if err != nil {
		t.Fatalf("proxyHandlerForBackend failed: %v", err)
	}

	// Create test request
	req := httptest.NewRequest("GET", "http://foo.test.ts.net/", nil)
	rec := httptest.NewRecorder()

	// Serve the request without identity headers (avoid WhoIs complexity)
	handler.ServeHTTP(rec, req)

	// Check response
	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if body != testResponse {
		t.Errorf("got body %q, want %q", body, testResponse)
	}
}

func TestServeUnixSocketErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets not supported on Windows")
	}

	logf := tstest.WhileTestRunningLogger(t)
	b := &LocalBackend{
		logf: logf,
	}

	// Test non-existent socket
	nonExistentSocket := "/tmp/this-socket-does-not-exist-" + fmt.Sprint(time.Now().UnixNano()) + ".sock"
	handler, err := b.proxyHandlerForBackend("unix:" + nonExistentSocket)
	if err != nil {
		t.Fatalf("proxyHandlerForBackend failed: %v", err)
	}

	req := httptest.NewRequest("GET", "http://foo.test.ts.net/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should get a 502 Bad Gateway when socket doesn't exist
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestExpandProxyArgUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets not supported on Windows")
	}

	tests := []struct {
		input        string
		wantURL      string
		wantInsecure bool
	}{
		{
			input:   "unix:/tmp/test.sock",
			wantURL: "unix:/tmp/test.sock",
		},
		{
			input:   "unix:/var/run/service.sock",
			wantURL: "unix:/var/run/service.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotURL, gotInsecure := expandProxyArg(tt.input)
			if gotURL != tt.wantURL {
				t.Errorf("expandProxyArg(%q) url = %q, want %q", tt.input, gotURL, tt.wantURL)
			}
			if gotInsecure != tt.wantInsecure {
				t.Errorf("expandProxyArg(%q) insecure = %v, want %v", tt.input, gotInsecure, tt.wantInsecure)
			}
		})
	}
}

func TestServeConfigUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets not supported on Windows")
	}

	// Test that Unix socket URLs are preserved in ServeConfig
	sc := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"foo.test.ts.net:443": {
				Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "unix:/tmp/test.sock"},
				},
			},
		},
	}

	// Verify the proxy value is preserved
	handler := sc.Web["foo.test.ts.net:443"].Handlers["/"]
	if handler.Proxy != "unix:/tmp/test.sock" {
		t.Errorf("proxy = %q, want %q", handler.Proxy, "unix:/tmp/test.sock")
	}
}
