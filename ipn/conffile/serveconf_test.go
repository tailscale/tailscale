// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/tailcfg"
)

func TestTargetUnixSocketRoundtrip(t *testing.T) {
	tests := []struct {
		name       string
		serialized string
		want       Target
	}{
		{
			name:       "tcp_unix_socket",
			serialized: "tcp://unix:/var/run/app.sock",
			want: Target{
				Protocol:    ProtoTCP,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "tls_terminated_tcp_unix_socket",
			serialized: "tls-terminated-tcp://unix:/var/run/app.sock",
			want: Target{
				Protocol:    ProtoTLSTerminatedTCP,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "tcp_unix_socket_relative",
			serialized: "tcp://unix:relative.sock",
			want: Target{
				Protocol:    ProtoTCP,
				Destination: "unix:relative.sock",
			},
		},
		{
			name:       "http_unix_socket",
			serialized: "http://unix:/var/run/app.sock",
			want: Target{
				Protocol:    ProtoHTTP,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "https_unix_socket",
			serialized: "https://unix:/var/run/app.sock",
			want: Target{
				Protocol:    ProtoHTTPS,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "https_insecure_unix_socket",
			serialized: "https+insecure://unix:/var/run/app.sock",
			want: Target{
				Protocol:    ProtoHTTPSInsecure,
				Destination: "unix:/var/run/app.sock",
			},
		},
		{
			name:       "http_unix_socket_relative",
			serialized: "http://unix:relative.sock",
			want: Target{
				Protocol:    ProtoHTTP,
				Destination: "unix:relative.sock",
			},
		},
		{
			name:       "tcp_host_port",
			serialized: "tcp://localhost:5432",
			want: Target{
				Protocol:         ProtoTCP,
				Destination:      "localhost",
				DestinationPorts: tailcfg.PortRange{First: 5432, Last: 5432},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshal
			var got Target
			if err := got.UnmarshalJSON([]byte(`"` + tt.serialized + `"`)); err != nil {
				t.Fatalf("UnmarshalJSON(%q) failed: %v", tt.serialized, err)
			}
			if got != tt.want {
				t.Errorf("UnmarshalJSON(%q) = %+v, want %+v", tt.serialized, got, tt.want)
			}

			// Test marshal roundtrip
			marshaled, err := tt.want.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() failed: %v", err)
			}
			if string(marshaled) != tt.serialized {
				t.Errorf("MarshalText() = %q, want %q", marshaled, tt.serialized)
			}
		})
	}
}

func TestLoadServicesConfigNull(t *testing.T) {
	tests := []struct {
		name       string
		forService string
		config     string
		wantErr    string
	}{
		{
			name:    "null_service",
			config:  `{"version":"0.0.1","services":{"svc:a":null}}`,
			wantErr: `service "svc:a": must not be null`,
		},
		{
			name:    "null_endpoint",
			config:  `{"version":"0.0.1","services":{"svc:a":{"endpoints":{"tcp:443":null}}}}`,
			wantErr: `service "svc:a": endpoint "tcp:443": must not be null`,
		},
		{
			name:       "null_endpoint_for_service",
			forService: "svc:a",
			config:     `{"version":"0.0.1","endpoints":{"tcp:443":null}}`,
			wantErr:    `service "svc:a": endpoint "tcp:443": must not be null`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.config), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadServicesConfig(path, tt.forService)
			if err == nil {
				t.Fatalf("LoadServicesConfig succeeded; want error %q", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("LoadServicesConfig error = %q; want %q", err, tt.wantErr)
			}
		})
	}
}
