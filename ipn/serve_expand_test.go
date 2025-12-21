// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"runtime"
	"testing"
)

func TestExpandProxyTargetValueUnix(t *testing.T) {
	tests := []struct {
		name             string
		target           string
		supportedSchemes []string
		defaultScheme    string
		want             string
		wantErr          bool
		skipOnWindows    bool
	}{
		{
			name:             "unix-socket-absolute-path",
			target:           "unix:/tmp/myservice.sock",
			supportedSchemes: []string{"http", "https", "unix"},
			defaultScheme:    "http",
			want:             "unix:/tmp/myservice.sock",
			skipOnWindows:    true,
		},
		{
			name:             "unix-socket-var-run",
			target:           "unix:/var/run/docker.sock",
			supportedSchemes: []string{"http", "https", "unix"},
			defaultScheme:    "http",
			want:             "unix:/var/run/docker.sock",
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
		},
		{
			name:             "unix-socket-not-in-supported-schemes",
			target:           "unix:/tmp/myservice.sock",
			supportedSchemes: []string{"http", "https"},
			defaultScheme:    "http",
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnWindows && runtime.GOOS == "windows" {
				t.Skip("skipping unix socket test on Windows")
			}

			// On Windows, unix sockets should always error
			if runtime.GOOS == "windows" && !tt.wantErr {
				tt.wantErr = true
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
