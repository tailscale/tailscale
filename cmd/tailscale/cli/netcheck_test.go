// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"testing"
)

func TestCreateBindStr(t *testing.T) {
	// Test all 8 combinations of CLI arg address, CLI arg port, and env var string
	// as an input to create netcheck bind string.
	tests := []struct {
		name        string
		cli_address string
		cli_port    int
		env_bind    string
		want        string
	}{
		{
			name:        "noAddr-noPort-noEnv",
			cli_address: "",
			cli_port:    -1,
			env_bind:    "",
			want:        ":0",
		},
		{
			name:        "yesAddr-noPort-noEnv",
			cli_address: "100.123.123.123",
			cli_port:    -1,
			env_bind:    "",
			want:        "100.123.123.123:0",
		},
		{
			name:        "yesAddr-yesPort-noEnv",
			cli_address: "100.123.123.123",
			cli_port:    456,
			env_bind:    "",
			want:        "100.123.123.123:456",
		},
		{
			name:        "yesAddr-yesPort-yesEnv",
			cli_address: "100.123.123.123",
			cli_port:    456,
			env_bind:    "55.55.55.55:789",
			want:        "100.123.123.123:456",
		},
		{
			name:        "noAddr-yesPort-noEnv",
			cli_address: "",
			cli_port:    456,
			env_bind:    "",
			want:        ":456",
		},
		{
			name:        "noAddr-yesPort-yesEnv",
			cli_address: "",
			cli_port:    456,
			env_bind:    "55.55.55.55:789",
			want:        ":456",
		},
		{
			name:        "noAddr-noPort-yesEnv",
			cli_address: "",
			cli_port:    -1,
			env_bind:    "55.55.55.55:789",
			want:        "55.55.55.55:789",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createNetcheckBindString(tt.cli_address, tt.cli_port, tt.env_bind)
			if got != tt.want {
				t.Errorf("error = got %q; want %q", got, tt.want)
			}
		})
	}
}
