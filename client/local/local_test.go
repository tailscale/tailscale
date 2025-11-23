// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package local

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/deptest"
	"tailscale.com/tstest/nettest"
	"tailscale.com/types/key"
)

func TestGetServeConfigFromJSON(t *testing.T) {
	sc, err := getServeConfigFromJSON([]byte("null"))
	if sc != nil {
		t.Errorf("want nil for null")
	}
	if err != nil {
		t.Errorf("reading null: %v", err)
	}

	sc, err = getServeConfigFromJSON([]byte(`{"TCP":{}}`))
	if err != nil {
		t.Errorf("reading object: %v", err)
	} else if sc == nil {
		t.Errorf("want non-nil for object")
	} else if sc.TCP == nil {
		t.Errorf("want non-nil TCP for object")
	}
}

func TestWhoIsPeerNotFound(t *testing.T) {
	nw := nettest.GetNetwork(t)
	ts := nettest.NewHTTPServer(nw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer ts.Close()

	lc := &Client{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nw.Dial(ctx, network, ts.Listener.Addr().String())
		},
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte("nodekey:5c8f86d5fc70d924e55f02446165a5dae8f822994ad26bcf4b08fd841f9bf261")); err != nil {
		t.Fatal(err)
	}
	res, err := lc.WhoIsNodeKey(context.Background(), k)
	if err != ErrPeerNotFound {
		t.Errorf("got (%v, %v), want ErrPeerNotFound", res, err)
	}
	res, err = lc.WhoIs(context.Background(), "1.2.3.4:5678")
	if err != ErrPeerNotFound {
		t.Errorf("got (%v, %v), want ErrPeerNotFound", res, err)
	}
}

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			// Make sure we don't again accidentally bring in a dependency on
			// drive or its transitive dependencies
			"testing":                        "do not use testing package in production code",
			"tailscale.com/drive/driveimpl":  "https://github.com/tailscale/tailscale/pull/10631",
			"github.com/studio-b12/gowebdav": "https://github.com/tailscale/tailscale/pull/10631",
		},
	}.Check(t)
}

func TestClient_Socket(t *testing.T) {
	tests := []struct {
		name       string
		client     *Client
		wantSocket string
	}{
		{
			name:       "default_socket",
			client:     &Client{},
			wantSocket: "", // Will use platform default
		},
		{
			name:       "custom_socket",
			client:     &Client{Socket: "/custom/socket"},
			wantSocket: "/custom/socket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.client.socket()
			if tt.wantSocket != "" && got != tt.wantSocket {
				t.Errorf("socket() = %q, want %q", got, tt.wantSocket)
			}
		})
	}
}

func TestErrPeerNotFound(t *testing.T) {
	if ErrPeerNotFound == nil {
		t.Error("ErrPeerNotFound should not be nil")
	}
	expected := "peer not found"
	if ErrPeerNotFound.Error() != expected {
		t.Errorf("ErrPeerNotFound.Error() = %q, want %q", ErrPeerNotFound.Error(), expected)
	}
}

func TestAccessDeniedError(t *testing.T) {
	err := AccessDeniedError{Authenticated: false}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "access denied") {
		t.Errorf("expected error message to contain 'access denied', got %q", errMsg)
	}

	err2 := AccessDeniedError{Authenticated: true}
	errMsg2 := err2.Error()
	if !strings.Contains(errMsg2, "access denied") {
		t.Errorf("expected error message to contain 'access denied', got %q", errMsg2)
	}
}

func TestPreconditionsFailedError(t *testing.T) {
	err := PreconditionsFailedError{Reason: "test failure"}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "preconditions failed") {
		t.Errorf("expected error message to contain 'preconditions failed', got %q", errMsg)
	}
	if !strings.Contains(errMsg, "test failure") {
		t.Errorf("expected error message to contain 'test failure', got %q", errMsg)
	}
}

func TestInvalidVersionError(t *testing.T) {
	err := InvalidVersionError{}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "tailscaled") {
		t.Errorf("expected error message to contain 'tailscaled', got %q", errMsg)
	}
}

func TestClient_UseSocketOnly(t *testing.T) {
	client := &Client{UseSocketOnly: true}
	if !client.UseSocketOnly {
		t.Error("UseSocketOnly should be true")
	}

	client2 := &Client{UseSocketOnly: false}
	if client2.UseSocketOnly {
		t.Error("UseSocketOnly should be false")
	}
}

func TestClient_OmitAuth(t *testing.T) {
	client := &Client{OmitAuth: true}
	if !client.OmitAuth {
		t.Error("OmitAuth should be true")
	}

	client2 := &Client{OmitAuth: false}
	if client2.OmitAuth {
		t.Error("OmitAuth should be false")
	}
}

func TestBugReportOpts(t *testing.T) {
	opts := BugReportOpts{
		Note:   "test note",
		NoLogs: true,
	}
	if opts.Note != "test note" {
		t.Errorf("Note = %q, want %q", opts.Note, "test note")
	}
	if !opts.NoLogs {
		t.Error("NoLogs should be true")
	}
}

func TestPingOpts(t *testing.T) {
	opts := PingOpts{
		UseTSMP:    true,
		Icmp:       false,
		Verbose:    true,
		PeerAPIPort: 8080,
	}
	if !opts.UseTSMP {
		t.Error("UseTSMP should be true")
	}
	if opts.Icmp {
		t.Error("Icmp should be false")
	}
	if !opts.Verbose {
		t.Error("Verbose should be true")
	}
	if opts.PeerAPIPort != 8080 {
		t.Errorf("PeerAPIPort = %d, want 8080", opts.PeerAPIPort)
	}
}

func TestDebugPortmapOpts(t *testing.T) {
	opts := &DebugPortmapOpts{
		Duration: 30 * time.Second,
		GatewayAddr: "192.168.1.1",
	}
	if opts.Duration != 30*time.Second {
		t.Errorf("Duration = %v, want 30s", opts.Duration)
	}
	if opts.GatewayAddr != "192.168.1.1" {
		t.Errorf("GatewayAddr = %q, want %q", opts.GatewayAddr, "192.168.1.1")
	}
}
