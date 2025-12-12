// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package conffile

import (
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

// TestTarget_UnmarshalJSON tests Target JSON unmarshaling
func TestTarget_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		wantProtocol ServiceProtocol
		wantDest     string
		wantPorts    string
		wantErr      bool
	}{
		{
			name:         "tun_mode",
			json:         `"TUN"`,
			wantProtocol: ProtoTUN,
			wantDest:     "",
			wantPorts:    "*",
		},
		{
			name:         "http_with_host_port",
			json:         `"http://localhost:8080"`,
			wantProtocol: ProtoHTTP,
			wantDest:     "localhost",
			wantPorts:    "8080",
		},
		{
			name:         "https_with_host_port",
			json:         `"https://example.com:443"`,
			wantProtocol: ProtoHTTPS,
			wantDest:     "example.com",
			wantPorts:    "443",
		},
		{
			name:         "https_insecure",
			json:         `"https+insecure://localhost:9000"`,
			wantProtocol: ProtoHTTPSInsecure,
			wantDest:     "localhost",
			wantPorts:    "9000",
		},
		{
			name:         "tcp_with_host_port",
			json:         `"tcp://127.0.0.1:3000"`,
			wantProtocol: ProtoTCP,
			wantDest:     "127.0.0.1",
			wantPorts:    "3000",
		},
		{
			name:         "tls_terminated_tcp",
			json:         `"tls-terminated-tcp://backend:5000"`,
			wantProtocol: ProtoTLSTerminatedTCP,
			wantDest:     "backend",
			wantPorts:    "5000",
		},
		{
			name:         "file_protocol",
			json:         `"file:///var/www/html"`,
			wantProtocol: ProtoFile,
			wantDest:     "/var/www/html",
			wantPorts:    "",
		},
		{
			name:         "file_with_relative_path",
			json:         `"file://./public"`,
			wantProtocol: ProtoFile,
			wantDest:     "public",
			wantPorts:    "",
		},
		{
			name:    "invalid_no_protocol",
			json:    `"localhost:8080"`,
			wantErr: true,
		},
		{
			name:    "unsupported_protocol",
			json:    `"ftp://server:21"`,
			wantErr: true,
		},
		{
			name:    "invalid_json",
			json:    `not-a-json-string`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target Target
			err := target.UnmarshalJSON([]byte(tt.json))

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if target.Protocol != tt.wantProtocol {
				t.Errorf("Protocol = %q, want %q", target.Protocol, tt.wantProtocol)
			}
			if target.Destination != tt.wantDest {
				t.Errorf("Destination = %q, want %q", target.Destination, tt.wantDest)
			}

			if tt.wantPorts != "" {
				gotPorts := target.DestinationPorts.String()
				if tt.wantPorts == "*" {
					// PortRangeAny case
					if target.DestinationPorts != tailcfg.PortRangeAny {
						t.Errorf("DestinationPorts = %v, want PortRangeAny", target.DestinationPorts)
					}
				} else if gotPorts != tt.wantPorts {
					t.Errorf("DestinationPorts = %q, want %q", gotPorts, tt.wantPorts)
				}
			}
		})
	}
}

// TestTarget_MarshalText tests Target text marshaling
func TestTarget_MarshalText(t *testing.T) {
	tests := []struct {
		name    string
		target  Target
		want    string
		wantErr bool
	}{
		{
			name: "tun_mode",
			target: Target{
				Protocol:         ProtoTUN,
				Destination:      "",
				DestinationPorts: tailcfg.PortRangeAny,
			},
			want: "TUN",
		},
		{
			name: "http_target",
			target: Target{
				Protocol:    ProtoHTTP,
				Destination: "localhost",
				DestinationPorts: tailcfg.PortRange{
					First: 8080,
					Last:  8080,
				},
			},
			want: "http://localhost:8080",
		},
		{
			name: "https_target",
			target: Target{
				Protocol:    ProtoHTTPS,
				Destination: "example.com",
				DestinationPorts: tailcfg.PortRange{
					First: 443,
					Last:  443,
				},
			},
			want: "https://example.com:443",
		},
		{
			name: "tcp_target",
			target: Target{
				Protocol:    ProtoTCP,
				Destination: "10.0.0.1",
				DestinationPorts: tailcfg.PortRange{
					First: 3000,
					Last:  3000,
				},
			},
			want: "tcp://10.0.0.1:3000",
		},
		{
			name: "file_target",
			target: Target{
				Protocol:    ProtoFile,
				Destination: "/var/www",
			},
			want: "file:///var/www",
		},
		{
			name: "unsupported_protocol",
			target: Target{
				Protocol:    "unknown",
				Destination: "test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.target.MarshalText()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(got) != tt.want {
				t.Errorf("MarshalText() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

// TestTarget_RoundTrip tests unmarshal then marshal
func TestTarget_RoundTrip(t *testing.T) {
	tests := []string{
		`"TUN"`,
		`"http://localhost:8080"`,
		`"https://example.com:443"`,
		`"tcp://10.0.0.1:3000"`,
		`"file:///var/www/html"`,
		`"https+insecure://test:9999"`,
		`"tls-terminated-tcp://backend:5000"`,
	}

	for _, original := range tests {
		t.Run(original, func(t *testing.T) {
			var target Target
			if err := target.UnmarshalJSON([]byte(original)); err != nil {
				t.Fatalf("UnmarshalJSON failed: %v", err)
			}

			marshaled, err := target.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText failed: %v", err)
			}

			// Unmarshal again
			var target2 Target
			if err := target2.UnmarshalJSON(marshaled); err != nil {
				t.Fatalf("second UnmarshalJSON failed: %v", err)
			}

			// Compare
			if target.Protocol != target2.Protocol {
				t.Errorf("Protocol mismatch: %q != %q", target.Protocol, target2.Protocol)
			}
			if target.Destination != target2.Destination {
				t.Errorf("Destination mismatch: %q != %q", target.Destination, target2.Destination)
			}
			if target.DestinationPorts != target2.DestinationPorts {
				t.Errorf("DestinationPorts mismatch: %v != %v", target.DestinationPorts, target2.DestinationPorts)
			}
		})
	}
}

// TestServiceProtocol_Constants tests protocol constants
func TestServiceProtocol_Constants(t *testing.T) {
	tests := []struct {
		name     string
		protocol ServiceProtocol
		value    string
	}{
		{"http", ProtoHTTP, "http"},
		{"https", ProtoHTTPS, "https"},
		{"https_insecure", ProtoHTTPSInsecure, "https+insecure"},
		{"tcp", ProtoTCP, "tcp"},
		{"tls_terminated_tcp", ProtoTLSTerminatedTCP, "tls-terminated-tcp"},
		{"file", ProtoFile, "file"},
		{"tun", ProtoTUN, "TUN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.protocol) != tt.value {
				t.Errorf("protocol = %q, want %q", tt.protocol, tt.value)
			}
		})
	}
}

// TestTarget_PortRanges tests various port range formats
func TestTarget_PortRanges(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantFirst uint16
		wantLast  uint16
	}{
		{
			name:      "single_port",
			json:      `"tcp://localhost:8080"`,
			wantFirst: 8080,
			wantLast:  8080,
		},
		{
			name:      "port_range",
			json:      `"tcp://localhost:8000-8100"`,
			wantFirst: 8000,
			wantLast:  8100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target Target
			if err := target.UnmarshalJSON([]byte(tt.json)); err != nil {
				t.Fatalf("UnmarshalJSON failed: %v", err)
			}

			if target.DestinationPorts.First != tt.wantFirst {
				t.Errorf("DestinationPorts.First = %d, want %d", target.DestinationPorts.First, tt.wantFirst)
			}
			if target.DestinationPorts.Last != tt.wantLast {
				t.Errorf("DestinationPorts.Last = %d, want %d", target.DestinationPorts.Last, tt.wantLast)
			}
		})
	}
}

// TestFindOverlappingRange tests port range overlap detection
func TestFindOverlappingRange(t *testing.T) {
	tests := []struct {
		name      string
		haystack  []tailcfg.PortRange
		needle    tailcfg.PortRange
		wantFound bool
	}{
		{
			name: "no_overlap",
			haystack: []tailcfg.PortRange{
				{First: 80, Last: 80},
				{First: 443, Last: 443},
			},
			needle:    tailcfg.PortRange{First: 8080, Last: 8080},
			wantFound: false,
		},
		{
			name: "exact_match",
			haystack: []tailcfg.PortRange{
				{First: 80, Last: 80},
				{First: 443, Last: 443},
			},
			needle:    tailcfg.PortRange{First: 80, Last: 80},
			wantFound: true,
		},
		{
			name: "needle_contains_haystack",
			haystack: []tailcfg.PortRange{
				{First: 8080, Last: 8090},
			},
			needle:    tailcfg.PortRange{First: 8000, Last: 9000},
			wantFound: true,
		},
		{
			name: "haystack_contains_needle",
			haystack: []tailcfg.PortRange{
				{First: 8000, Last: 9000},
			},
			needle:    tailcfg.PortRange{First: 8080, Last: 8090},
			wantFound: true,
		},
		{
			name: "partial_overlap_start",
			haystack: []tailcfg.PortRange{
				{First: 8050, Last: 8100},
			},
			needle:    tailcfg.PortRange{First: 8000, Last: 8060},
			wantFound: true,
		},
		{
			name: "partial_overlap_end",
			haystack: []tailcfg.PortRange{
				{First: 8000, Last: 8050},
			},
			needle:    tailcfg.PortRange{First: 8040, Last: 8100},
			wantFound: true,
		},
		{
			name:      "empty_haystack",
			haystack:  []tailcfg.PortRange{},
			needle:    tailcfg.PortRange{First: 80, Last: 80},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findOverlappingRange(tt.haystack, tt.needle)
			found := result != nil

			if found != tt.wantFound {
				t.Errorf("findOverlappingRange() found = %v, want %v", found, tt.wantFound)
			}
		})
	}
}

// TestServicesConfigFile_Structure tests the config file structure
func TestServicesConfigFile_Structure(t *testing.T) {
	scf := ServicesConfigFile{
		Version: "0.0.1",
		Services: map[tailcfg.ServiceName]*ServiceDetailsFile{
			"test-service": {
				Version: "",
				Endpoints: map[*tailcfg.ProtoPortRange]*Target{
					{Proto: 6, Ports: tailcfg.PortRange{First: 443, Last: 443}}: {
						Protocol:    ProtoHTTPS,
						Destination: "localhost",
						DestinationPorts: tailcfg.PortRange{
							First: 8443,
							Last:  8443,
						},
					},
				},
				Advertised: opt.NewBool(true),
			},
		},
	}

	if scf.Version != "0.0.1" {
		t.Errorf("Version = %q, want 0.0.1", scf.Version)
	}

	if len(scf.Services) != 1 {
		t.Errorf("Services length = %d, want 1", len(scf.Services))
	}

	svc, ok := scf.Services["test-service"]
	if !ok {
		t.Fatal("test-service not found")
	}

	if svc.Advertised != opt.NewBool(true) {
		t.Error("Advertised should be true")
	}
}

// TestServiceDetailsFile_Advertised tests the Advertised field
func TestServiceDetailsFile_Advertised(t *testing.T) {
	tests := []struct {
		name       string
		advertised opt.Bool
		wantSet    bool
		wantValue  bool
	}{
		{
			name:       "advertised_true",
			advertised: opt.NewBool(true),
			wantSet:    true,
			wantValue:  true,
		},
		{
			name:       "advertised_false",
			advertised: opt.NewBool(false),
			wantSet:    true,
			wantValue:  false,
		},
		{
			name:       "advertised_unset",
			advertised: "",
			wantSet:    false,
			wantValue:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sdf := ServiceDetailsFile{
				Advertised: tt.advertised,
			}

			if tt.wantSet {
				val, ok := sdf.Advertised.Get()
				if !ok {
					t.Error("Advertised should be set")
				}
				if val != tt.wantValue {
					t.Errorf("Advertised value = %v, want %v", val, tt.wantValue)
				}
			} else {
				if _, ok := sdf.Advertised.Get(); ok {
					t.Error("Advertised should not be set")
				}
			}
		})
	}
}

// TestTarget_FilePathCleaning tests that file paths are cleaned
func TestTarget_FilePathCleaning(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wantPath string
	}{
		{
			name:     "absolute_path",
			json:     `"file:///var/www/html"`,
			wantPath: "/var/www/html",
		},
		{
			name:     "relative_path_with_dot",
			json:     `"file://./public"`,
			wantPath: "public",
		},
		{
			name:     "path_with_double_slash",
			json:     `"file://var//www//html"`,
			wantPath: "var/www/html",
		},
		{
			name:     "path_with_dot_dot",
			json:     `"file://var/www/../static"`,
			wantPath: "var/static",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target Target
			if err := target.UnmarshalJSON([]byte(tt.json)); err != nil {
				t.Fatalf("UnmarshalJSON failed: %v", err)
			}

			if target.Destination != tt.wantPath {
				t.Errorf("Destination = %q, want %q", target.Destination, tt.wantPath)
			}
		})
	}
}

// TestTarget_IPv6Addresses tests IPv6 address handling
func TestTarget_IPv6Addresses(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name:    "ipv6_with_port",
			json:    `"tcp://[::1]:8080"`,
			wantErr: false,
		},
		{
			name:    "ipv6_full_address",
			json:    `"https://[2001:db8::1]:443"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target Target
			err := target.UnmarshalJSON([]byte(tt.json))

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
