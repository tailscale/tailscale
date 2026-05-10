// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
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
			serialized: "tcp:///var/run/app.sock",
			want: Target{
				Protocol:    ProtoTCP,
				Destination: "/var/run/app.sock",
			},
		},
		{
			name:       "tls_terminated_tcp_unix_socket",
			serialized: "tls-terminated-tcp:///var/run/app.sock",
			want: Target{
				Protocol:    ProtoTLSTerminatedTCP,
				Destination: "/var/run/app.sock",
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
