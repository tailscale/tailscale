// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package ipnlocal

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/tstest"
)

func TestExpandProxyArgUnix(t *testing.T) {
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
			input:   "unix:/var/run/docker.sock",
			wantURL: "unix:/var/run/docker.sock",
		},
		{
			input:   "unix:./relative.sock",
			wantURL: "unix:./relative.sock",
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

func TestServeUnixSocket(t *testing.T) {
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
	time.Sleep(50 * time.Millisecond)

	// Create LocalBackend with test logger
	logf := tstest.WhileTestRunningLogger(t)
	b := newTestBackend(t)
	b.logf = logf

	// Test creating proxy handler for Unix socket
	handler, err := b.proxyHandlerForBackend("unix:" + socketPath)
	if err != nil {
		t.Fatalf("proxyHandlerForBackend failed: %v", err)
	}

	// Verify it's a reverseProxy with correct socketPath
	rp, ok := handler.(*reverseProxy)
	if !ok {
		t.Fatalf("expected *reverseProxy, got %T", handler)
	}
	if rp.socketPath != socketPath {
		t.Errorf("socketPath = %q, want %q", rp.socketPath, socketPath)
	}
	if rp.url.Host != "localhost" {
		t.Errorf("url.Host = %q, want %q", rp.url.Host, "localhost")
	}
}

func TestServeUnixSocketErrors(t *testing.T) {
	logf := tstest.WhileTestRunningLogger(t)
	b := newTestBackend(t)
	b.logf = logf

	// Test empty socket path
	_, err := b.proxyHandlerForBackend("unix:")
	if err == nil {
		t.Error("expected error for empty socket path")
	}

	// Test non-existent socket - should create handler but fail on request
	nonExistentSocket := filepath.Join(t.TempDir(), "nonexistent.sock")
	handler, err := b.proxyHandlerForBackend("unix:" + nonExistentSocket)
	if err != nil {
		t.Fatalf("proxyHandlerForBackend failed: %v", err)
	}

	req := httptest.NewRequest("GET", "http://foo.test.ts.net/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should get a 502 Bad Gateway when socket doesn't exist
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got status %d, want %d for non-existent socket", rec.Code, http.StatusBadGateway)
	}
}

func TestReverseProxyConfigurationUnix(t *testing.T) {
	b := newTestBackend(t)

	// Test that Unix socket backend creates proper reverseProxy
	backend := "unix:/var/run/test.sock"
	handler, err := b.proxyHandlerForBackend(backend)
	if err != nil {
		t.Fatalf("proxyHandlerForBackend failed: %v", err)
	}

	rp, ok := handler.(*reverseProxy)
	if !ok {
		t.Fatalf("expected *reverseProxy, got %T", handler)
	}

	// Verify configuration
	if rp.socketPath != "/var/run/test.sock" {
		t.Errorf("socketPath = %q, want %q", rp.socketPath, "/var/run/test.sock")
	}
	if rp.backend != backend {
		t.Errorf("backend = %q, want %q", rp.backend, backend)
	}
	if rp.insecure {
		t.Error("insecure should be false for unix sockets")
	}
	expectedURL := url.URL{Scheme: "http", Host: "localhost"}
	if rp.url.Scheme != expectedURL.Scheme || rp.url.Host != expectedURL.Host {
		t.Errorf("url = %v, want %v", rp.url, expectedURL)
	}
}

func TestServeBlocksTailscaledSocket(t *testing.T) {
	// Use /tmp to avoid macOS socket path length limits
	tmpDir, err := os.MkdirTemp("/tmp", "ts-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tailscaledSocket := filepath.Join(tmpDir, "ts.sock")

	// Create actual socket file
	listener, err := net.Listen("unix", tailscaledSocket)
	if err != nil {
		t.Fatalf("failed to create tailscaled socket: %v", err)
	}
	defer listener.Close()

	b := newTestBackend(t)
	b.sys.SocketPath = tailscaledSocket

	// Direct path to tailscaled socket should be blocked
	_, err = b.proxyHandlerForBackend("unix:" + tailscaledSocket)
	if !errors.Is(err, ErrProxyToTailscaledSocket) {
		t.Errorf("direct path: got err=%v, want ErrProxyToTailscaledSocket", err)
	}

	// Symlink to tailscaled socket should be blocked
	symlinkPath := filepath.Join(tmpDir, "link")
	if err := os.Symlink(tailscaledSocket, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	_, err = b.proxyHandlerForBackend("unix:" + symlinkPath)
	if !errors.Is(err, ErrProxyToTailscaledSocket) {
		t.Errorf("symlink: got err=%v, want ErrProxyToTailscaledSocket", err)
	}

	// Different socket should work
	otherSocket := filepath.Join(tmpDir, "ok.sock")
	listener2, err := net.Listen("unix", otherSocket)
	if err != nil {
		t.Fatalf("failed to create other socket: %v", err)
	}
	defer listener2.Close()

	handler, err := b.proxyHandlerForBackend("unix:" + otherSocket)
	if err != nil {
		t.Errorf("legitimate socket should not be blocked: %v", err)
	}
	if handler == nil {
		t.Error("expected valid handler for legitimate socket")
	}
}
