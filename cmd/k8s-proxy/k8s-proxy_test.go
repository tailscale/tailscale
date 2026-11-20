// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import "testing"

func TestParsePort(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		want    uint16
		wantErr bool
	}{
		{
			name: "unset",
			port: "",
			want: 0,
		},
		{
			name: "valid",
			port: "12199",
			want: 12199,
		},
		{
			name: "max",
			port: "65535",
			want: 65535,
		},
		{
			name:    "out_of_range",
			port:    "65536",
			wantErr: true,
		},
		{
			name:    "negative",
			port:    "-1",
			wantErr: true,
		},
		{
			name:    "not_a_number",
			port:    "https",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePort(%q) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("parsePort(%q) = %d, want %d", tt.port, got, tt.want)
			}
		})
	}
}
