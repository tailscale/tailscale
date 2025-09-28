// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"runtime"
	"testing"
)

func TestExpandProxyTargetValue(t *testing.T) {
	tests := []struct {
		name             string
		target           string
		supportedSchemes []string
		defaultScheme    string
		want             string
		wantErr          bool
		skipOnWindows    bool
	}{
		// Existing test cases
		{
			name:             "port-number",
			target:           "8080",
			supportedSchemes: []string{"http", "https"},
			defaultScheme:    "http",
			want:             "http://127.0.0.1:8080",
		},
		{
			name:             "localhost-port",
			target:           "localhost:8080",
			supportedSchemes: []string{"http", "https"},
			defaultScheme:    "http",
			want:             "http://localhost:8080",
		},
		{
			name:             "full-http-url",
			target:           "http://localhost:8080",
			supportedSchemes: []string{"http", "https"},
			defaultScheme:    "http",
			want:             "http://localhost:8080",
		},
		{
			name:             "https-insecure",
			target:           "https+insecure://127.0.0.1:4430",
			supportedSchemes: []string{"http", "https", "https+insecure"},
			defaultScheme:    "http",
			want:             "https+insecure://127.0.0.1:4430",
		},
		{
			name:             "unsupported-scheme",
			target:           "ftp://localhost:21",
			supportedSchemes: []string{"http", "https"},
			defaultScheme:    "http",
			wantErr:          true,
		},
		{
			name:             "non-localhost",
			target:           "example.com:8080",
			supportedSchemes: []string{"http", "https"},
			defaultScheme:    "http",
			wantErr:          true,
		},
		// Unix socket test cases
		{
			name:             "unix-socket-absolute-path",
			target:           "unix:/tmp/myservice.sock",
			supportedSchemes: []string{"http", "https", "unix"},
			defaultScheme:    "http",
			want:             "unix:/tmp/myservice.sock",
			skipOnWindows:    true,
		},
		{
			name:             "unix-socket-relative-path",
			target:           "unix:./myservice.sock",
			supportedSchemes: []string{"http", "https", "unix"},
			defaultScheme:    "http",
			want:             "unix:./myservice.sock",
			skipOnWindows:    true,
		},
		{
			name:             "unix-socket-empty-path",
			target:           "unix:",
			supportedSchemes: []string{"http", "https", "unix"},
			defaultScheme:    "http",
			wantErr:          true,
			skipOnWindows:    true,
		},
		{
			name:             "unix-socket-not-supported",
			target:           "unix:/tmp/myservice.sock",
			supportedSchemes: []string{"http", "https"},
			defaultScheme:    "http",
			wantErr:          true,
		},
		{
			name:             "unix-socket-on-windows",
			target:           "unix:/tmp/myservice.sock",
			supportedSchemes: []string{"http", "https", "unix"},
			defaultScheme:    "http",
			wantErr:          runtime.GOOS == "windows",
			want:             "unix:/tmp/myservice.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnWindows && runtime.GOOS == "windows" {
				t.Skip("skipping unix socket test on Windows")
			}

			got, err := ExpandProxyTargetValue(tt.target, tt.supportedSchemes, tt.defaultScheme)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandProxyTargetValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ExpandProxyTargetValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
