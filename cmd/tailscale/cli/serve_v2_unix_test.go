// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package cli

import (
	"path/filepath"
	"runtime"
	"testing"

	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
)

func TestServeUnixSocketCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets not supported on Windows")
	}

	// Create a temporary directory for our socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create a mock tailscale.LocalClient
	lc := &tailscale.LocalClient{}

	// Create test environment
	e := &serveEnv{
		lc: lc,
	}

	// Test applying web serve with Unix socket
	sc := &ipn.ServeConfig{}
	err := e.applyWebServe(sc, "foo.test.ts.net", 443, true, "/", "unix:"+socketPath, "test.ts.net")
	if err != nil {
		t.Fatalf("applyWebServe failed: %v", err)
	}

	// Verify the configuration
	hp := ipn.HostPort("foo.test.ts.net:443")
	if _, ok := sc.Web[hp]; !ok {
		t.Fatal("expected web config for foo.test.ts.net:443")
	}

	handler := sc.Web[hp].Handlers["/"]
	if handler == nil {
		t.Fatal("expected handler for /")
	}

	if handler.Proxy != "unix:"+socketPath {
		t.Errorf("handler.Proxy = %q, want %q", handler.Proxy, "unix:"+socketPath)
	}
}

func TestServeUnixSocketPlatformCheck(t *testing.T) {
	// This test verifies that unix socket targets are rejected on Windows
	// when using ExpandProxyTargetValue

	tests := []struct {
		goos    string
		target  string
		wantErr bool
	}{
		{
			goos:    "linux",
			target:  "unix:/tmp/test.sock",
			wantErr: false,
		},
		{
			goos:    "darwin",
			target:  "unix:/tmp/test.sock",
			wantErr: false,
		},
		{
			goos:    "windows",
			target:  "unix:/tmp/test.sock",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			if runtime.GOOS != tt.goos {
				t.Skipf("skipping test for %s on %s", tt.goos, runtime.GOOS)
			}

			_, err := ipn.ExpandProxyTargetValue(tt.target, []string{"http", "unix"}, "http")
			gotErr := err != nil
			if gotErr != tt.wantErr {
				t.Errorf("ExpandProxyTargetValue(%q) on %s: got error %v, wantErr %v",
					tt.target, tt.goos, err, tt.wantErr)
			}
		})
	}
}
