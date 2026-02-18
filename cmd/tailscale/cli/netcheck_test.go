// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"testing"
)

func TestCreateBindStr(t *testing.T) {
	// Test all combinations of CLI arg address, CLI arg port, and env var string
	// as inputs to create netcheck bind string.
	tests := []struct {
		name            string
		CLIAddress      string
		CLIAddressIsSet bool
		CLIPort         int
		CLIPortIsSet    bool
		envBind         string
		want            string
		wantError       bool
	}{
		{
			name: "noAddr-noPort-noEnv",
			want: ":0",
		},
		{
			name:            "yesAddrv4-noPort-noEnv",
			CLIAddress:      "100.123.123.123",
			CLIAddressIsSet: true,
			want:            "100.123.123.123:0",
		},
		{
			name:            "yesAddrv6-noPort-noEnv",
			CLIAddress:      "dead::beef",
			CLIAddressIsSet: true,
			want:            "[dead::beef]:0",
		},
		{
			name:            "yesAddr-yesPort-noEnv",
			CLIAddress:      "100.123.123.123",
			CLIAddressIsSet: true,
			CLIPort:         456,
			CLIPortIsSet:    true,
			want:            "100.123.123.123:456",
		},
		{
			name:            "yesAddr-yesPort-yesEnv",
			CLIAddress:      "100.123.123.123",
			CLIAddressIsSet: true,
			CLIPort:         456,
			CLIPortIsSet:    true,
			envBind:         "55.55.55.55:789",
			want:            "100.123.123.123:456",
		},
		{
			name:         "noAddr-yesPort-noEnv",
			CLIPort:      456,
			CLIPortIsSet: true,
			want:         ":456",
		},
		{
			name:         "noAddr-yesPort-yesEnv",
			CLIPort:      456,
			CLIPortIsSet: true,
			envBind:      "55.55.55.55:789",
			want:         ":456",
		},
		{
			name:    "noAddr-noPort-yesEnv",
			envBind: "55.55.55.55:789",
			want:    "55.55.55.55:789",
		},
		{
			name:            "badAddr-noPort-noEnv",
			CLIAddress:      "678.678.678.678",
			CLIAddressIsSet: true,
			wantError:       true,
		},
		{
			name:         "noAddr-badPort-noEnv",
			CLIPort:      -1,
			CLIPortIsSet: true,
			wantError:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := createNetcheckBindString(tt.CLIAddress, tt.CLIAddressIsSet, tt.CLIPort, tt.CLIPortIsSet, tt.envBind)
			if tt.wantError {
				if gotErr == nil {
					t.Errorf("error = got successful %q; want error", got)
				}
			} else {
				if got != tt.want {
					t.Errorf("error = got %q; want %q", got, tt.want)
				}
			}
		})
	}
}
