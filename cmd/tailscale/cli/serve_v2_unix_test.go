// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package cli

import (
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
)

func TestServeUnixSocketCLI(t *testing.T) {
	// Create a temporary directory for our socket path
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Test that Unix socket targets are accepted by ExpandProxyTargetValue
	target := "unix:" + socketPath
	result, err := ipn.ExpandProxyTargetValue(target, []string{"http", "https", "https+insecure", "unix"}, "http")
	if err != nil {
		t.Fatalf("ExpandProxyTargetValue failed: %v", err)
	}

	if result != target {
		t.Errorf("ExpandProxyTargetValue(%q) = %q, want %q", target, result, target)
	}
}

func TestServeUnixSocketConfigPreserved(t *testing.T) {
	// Test that Unix socket URLs are preserved in ServeConfig
	sc := &ipn.ServeConfig{
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"foo.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{
				"/": {Proxy: "unix:/tmp/test.sock"},
			}},
		},
	}

	// Verify the proxy value is preserved
	handler := sc.Web["foo.test.ts.net:443"].Handlers["/"]
	if handler.Proxy != "unix:/tmp/test.sock" {
		t.Errorf("proxy = %q, want %q", handler.Proxy, "unix:/tmp/test.sock")
	}
}

func TestServeUnixSocketVariousPaths(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{
			name:   "absolute-path",
			target: "unix:/var/run/docker.sock",
		},
		{
			name:   "tmp-path",
			target: "unix:/tmp/myservice.sock",
		},
		{
			name:   "relative-path",
			target: "unix:./local.sock",
		},
		{
			name:   "home-path",
			target: "unix:/home/user/.local/service.sock",
		},
		{
			name:    "empty-path",
			target:  "unix:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ipn.ExpandProxyTargetValue(tt.target, []string{"http", "https", "unix"}, "http")
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandProxyTargetValue(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}
