// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix && !ts_omit_serve

package ipnlocal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tstest"
)

func TestExpandProxyArgUnix(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantURL      string
		wantInsecure bool
	}{
		{
			name:    "unix-tmp-sock",
			input:   "unix:/tmp/test.sock",
			wantURL: "unix:/tmp/test.sock",
		},
		{
			name:    "unix-var-run-docker-sock",
			input:   "unix:/var/run/docker.sock",
			wantURL: "unix:/var/run/docker.sock",
		},
		{
			name:    "unix-relative-sock",
			input:   "unix:./relative.sock",
			wantURL: "unix:./relative.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

	req := httptest.NewRequest("GET", "http://foo.test.ts.net/", nil)
	rec := httptest.NewRecorder()

	rp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal("unexpected response code:", rec.Code)
	}
	resp := rec.Result()
	defer resp.Body.Close()
	respB, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("read error:", err)
	}
	if string(respB) != testResponse {
		t.Fatalf("unexpected response: want: '%s'; got: '%s'", testResponse, string(respB))
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

func TestTCPForwardUnixSocket(t *testing.T) {
	tmpDir := t.TempDir()

	socketPath := filepath.Join(tmpDir, "backend.sock")

	// Create a Unix socket echo server
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create unix socket listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) // echo
			}()
		}
	}()

	// Set up a LocalBackend with a ServeConfig that forwards TCP port 3128 to the unix socket
	b := newTestBackend(t)
	b.logf = tstest.WhileTestRunningLogger(t)

	conf := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			3128: {TCPForward: "unix:" + socketPath},
		},
	}
	if err := b.SetServeConfig(conf, ""); err != nil {
		t.Fatal("setting serve config:", err)
	}

	// Get the handler from tcpHandlerForServe
	srcAddr := netip.MustParseAddrPort("100.100.100.1:12345")
	handler := b.tcpHandlerForServe(3128, srcAddr, nil)
	if handler == nil {
		t.Fatal("tcpHandlerForServe returned nil handler")
	}

	// Create a pipe to simulate an incoming connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Run the handler in a goroutine
	handlerDone := make(chan error, 1)
	go func() {
		handlerDone <- handler(serverConn)
	}()

	// Write data through the "client" side and read the echo back
	testData := []byte("hello via tcpHandlerForServe")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != string(testData) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, testData)
	}

	// Close client side, handler should finish
	clientConn.Close()
	select {
	case err := <-handlerDone:
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish in time")
	}
}

// unixSocketTestDir returns a directory for creating unix sockets, on a
// path short enough for sockaddr_un's sun_path limit.
func unixSocketTestDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ts-serve-unix-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// mustListenUnix binds a unix listener at path, removing any existing file
// there first (mkTempSocket leaves a regular file behind).
func mustListenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); os.Remove(path) })
	return ln
}

// serveUnixEchoListener binds an echoing unix listener at path.
func serveUnixEchoListener(t *testing.T, path string) {
	t.Helper()
	ln := mustListenUnix(t, path)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
}

// TestRefuseIfConnectedToTailscaledSocket verifies the post-dial peer
// check: the peer of a unix connection is named by the path its listener
// was bound to, not the path dialed, so a connection to the tailscaled
// socket is refused, including one made through a symlink
func TestRefuseIfConnectedToTailscaledSocket(t *testing.T) {
	dir := unixSocketTestDir(t)
	tsSock := filepath.Join(dir, "tailscaled.sock")
	mustListenUnix(t, tsSock)

	b := newTestBackend(t)
	b.sys.SocketPath = tsSock

	// Skip if this platform does not name path-bound peers.
	c, err := net.Dial("unix", tsSock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ua, ok := c.RemoteAddr().(*net.UnixAddr)
	if !ok || ua.Name == "" {
		t.Skipf("platform does not name unix socket peers (RemoteAddr = %v)", c.RemoteAddr())
	}

	if err := b.refuseIfConnectedToTailscaledSocket(c); !errors.Is(err, ErrProxyToTailscaledSocket) {
		t.Fatalf("refuseIfConnectedToTailscaledSocket(tailscaled peer) = %v; want ErrProxyToTailscaledSocket", err)
	}

	// A connection through a symlink still names the bound path.
	alias := filepath.Join(dir, "alias.sock")
	if err := os.Symlink(tsSock, alias); err != nil {
		t.Fatal(err)
	}
	c, err = net.Dial("unix", alias)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := b.refuseIfConnectedToTailscaledSocket(c); !errors.Is(err, ErrProxyToTailscaledSocket) {
		t.Fatalf("refuseIfConnectedToTailscaledSocket(symlinked tailscaled peer) = %v; want ErrProxyToTailscaledSocket", err)
	}

	// A connection to any other socket is left alone.
	benign := filepath.Join(dir, "benign.sock")
	mustListenUnix(t, benign)
	c, err = net.Dial("unix", benign)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := b.refuseIfConnectedToTailscaledSocket(c); err != nil {
		t.Fatalf("refuseIfConnectedToTailscaledSocket(benign peer) = %v; want nil", err)
	}
}

// TestDialServeUnixSocketServesBenignBackend dials a benign unix backend
// end to end through dialServeUnixSocket and checks that traffic flows.
func TestDialServeUnixSocketServesBenignBackend(t *testing.T) {
	dir := unixSocketTestDir(t)
	// The backend is behind a symlink, as a serve config may reference it.
	backend := filepath.Join(dir, "backend.sock")
	serveUnixEchoListener(t, backend)
	alias := filepath.Join(dir, "alias.sock")
	if err := os.Symlink(backend, alias); err != nil {
		t.Fatal(err)
	}

	b := newTestBackend(t)

	conn, err := b.dialServeUnixSocket(context.Background(), alias)
	if err != nil {
		t.Fatalf("dialServeUnixSocket(%q) = %v; want connection", alias, err)
	}
	defer conn.Close()

	msg := []byte("hello backend")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo = %q; want %q", got, msg)
	}
}
