// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package local

import (
	"encoding/json"
	"testing"

	"tailscale.com/ipn"
)

func TestGetServeConfigFromJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantNil bool
		wantErr bool
	}{
		{
			name:    "empty_object",
			input:   []byte(`{}`),
			wantNil: false,
			wantErr: false,
		},
		{
			name:    "null",
			input:   []byte(`null`),
			wantNil: true,
			wantErr: false,
		},
		{
			name: "valid_config_with_web",
			input: []byte(`{
				"TCP": {},
				"Web": {
					"example.ts.net:443": {
						"Handlers": {
							"/": {"Proxy": "http://127.0.0.1:3000"}
						}
					}
				},
				"AllowFunnel": {}
			}`),
			wantNil: false,
			wantErr: false,
		},
		{
			name: "valid_config_with_tcp",
			input: []byte(`{
				"TCP": {
					"443": {
						"HTTPS": true
					}
				}
			}`),
			wantNil: false,
			wantErr: false,
		},
		{
			name:    "invalid_json",
			input:   []byte(`{invalid json`),
			wantNil: true,
			wantErr: true,
		},
		{
			name:    "empty_string",
			input:   []byte(``),
			wantNil: true,
			wantErr: true,
		},
		{
			name:    "array_instead_of_object",
			input:   []byte(`[]`),
			wantNil: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getServeConfigFromJSON(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if tt.wantNil && got != nil {
				t.Errorf("expected nil, got %+v", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

func TestGetServeConfigFromJSON_RoundTrip(t *testing.T) {
	// Create a serve config
	original := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			443: {HTTPS: true},
		},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"example.ts.net:443": {
				Handlers: map[string]*ipn.HTTPHandler{
					"/": {Proxy: "http://127.0.0.1:3000"},
				},
			},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Parse back
	parsed, err := getServeConfigFromJSON(data)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed == nil {
		t.Fatal("parsed config is nil")
	}

	// Verify TCP config
	if len(parsed.TCP) != 1 {
		t.Errorf("TCP length = %d, want 1", len(parsed.TCP))
	}
	if handler, ok := parsed.TCP[443]; !ok || !handler.HTTPS {
		t.Error("TCP[443] not configured correctly")
	}

	// Verify Web config
	if len(parsed.Web) != 1 {
		t.Errorf("Web length = %d, want 1", len(parsed.Web))
	}
}

func TestGetServeConfigFromJSON_NullVsEmptyObject(t *testing.T) {
	// Test that null JSON returns nil
	nullResult, err := getServeConfigFromJSON([]byte(`null`))
	if err != nil {
		t.Errorf("null JSON should not error: %v", err)
	}
	if nullResult != nil {
		t.Error("null JSON should return nil")
	}

	// Test that empty object returns non-nil
	emptyResult, err := getServeConfigFromJSON([]byte(`{}`))
	if err != nil {
		t.Errorf("empty object should not error: %v", err)
	}
	if emptyResult == nil {
		t.Error("empty object should return non-nil")
	}
}

func TestGetServeConfigFromJSON_ComplexConfig(t *testing.T) {
	complexJSON := []byte(`{
		"TCP": {
			"80": {"HTTPS": false, "TCPForward": "127.0.0.1:8080"},
			"443": {"HTTPS": true},
			"8080": {"TCPForward": "192.168.1.100:8080"}
		},
		"Web": {
			"site1.ts.net:443": {
				"Handlers": {
					"/": {"Proxy": "http://localhost:3000"},
					"/api": {"Proxy": "http://localhost:4000"},
					"/static": {"Path": "/var/www/static"}
				}
			},
			"site2.ts.net:443": {
				"Handlers": {
					"/": {"Proxy": "http://localhost:5000"}
				}
			}
		},
		"AllowFunnel": {
			"site1.ts.net:443": true
		}
	}`)

	config, err := getServeConfigFromJSON(complexJSON)
	if err != nil {
		t.Fatalf("failed to parse complex config: %v", err)
	}

	if config == nil {
		t.Fatal("config is nil")
	}

	// Verify TCP ports
	if len(config.TCP) != 3 {
		t.Errorf("TCP ports = %d, want 3", len(config.TCP))
	}

	// Verify Web hosts
	if len(config.Web) != 2 {
		t.Errorf("Web hosts = %d, want 2", len(config.Web))
	}

	// Verify AllowFunnel
	if len(config.AllowFunnel) != 1 {
		t.Errorf("AllowFunnel entries = %d, want 1", len(config.AllowFunnel))
	}
}

func TestGetServeConfigFromJSON_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "extra_fields",
			input:   []byte(`{"TCP": {}, "UnknownField": "value"}`),
			wantErr: false, // JSON unmarshaling ignores unknown fields by default
		},
		{
			name:    "numeric_string",
			input:   []byte(`"123"`),
			wantErr: true,
		},
		{
			name:    "boolean",
			input:   []byte(`true`),
			wantErr: true,
		},
		{
			name:    "nested_null",
			input:   []byte(`{"TCP": null, "Web": null}`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getServeConfigFromJSON(tt.input)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGetServeConfigFromJSON_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"leading_whitespace", []byte(`  {}`)},"trailing_whitespace", []byte(`{}  `)},
		{"newlines", []byte("{\n\t\"TCP\": {}\n}")},
		{"mixed_whitespace", []byte("  \n\t{\n  \"Web\": {}  \n}\t  ")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := getServeConfigFromJSON(tt.input)
			if err != nil {
				t.Errorf("whitespace should not cause error: %v", err)
			}
			if config == nil {
				t.Error("should return non-nil config")
			}
		})
	}
}
