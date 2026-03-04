// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package porttrack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
)

func TestCollectorAndListen(t *testing.T) {
	c := NewCollector(t)

	labels := []string{"main", "plaintext", "debug"}
	ports := make([]int, len(labels))

	for i, label := range labels {
		ln, err := Listen("tcp", c.Addr(label))
		if err != nil {
			t.Fatalf("Listen(%q): %v", label, err)
		}
		defer ln.Close()
		p, err := c.Port(t.Context(), label)
		if err != nil {
			t.Fatalf("Port(%q): %v", label, err)
		}
		ports[i] = p
	}

	// All ports should be distinct non-zero values.
	seen := map[int]string{}
	for i, label := range labels {
		if ports[i] == 0 {
			t.Errorf("Port(%q) = 0", label)
		}
		if prev, ok := seen[ports[i]]; ok {
			t.Errorf("Port(%q) = Port(%q) = %d", label, prev, ports[i])
		}
		seen[ports[i]] = label
	}
}

func TestListenPassthrough(t *testing.T) {
	ln, err := Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Listen passthrough: %v", err)
	}
	defer ln.Close()
	if ln.Addr().(*net.TCPAddr).Port == 0 {
		t.Fatal("expected non-zero port")
	}
}

func TestRoundTrip(t *testing.T) {
	c := NewCollector(t)

	ln, err := Listen("tcp", c.Addr("http"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Start a server on the listener.
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	port, err := c.Port(t.Context(), "http")
	if err != nil {
		t.Fatalf("Port: %v", err)
	}
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/", port))
	if err != nil {
		t.Fatalf("http.Get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestPortContextCancelled(t *testing.T) {
	c := NewCollector(t)
	// Nobody will ever report "never", so Port should block until ctx is done.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := c.Port(ctx, "never")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Port with cancelled context: got %v, want %v", err, context.Canceled)
	}
}
