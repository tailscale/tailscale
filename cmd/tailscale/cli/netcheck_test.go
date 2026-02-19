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
		cliAddress      string
		cliAddressIsSet bool
		cliPort         int
		cliPortIsSet    bool
		envBind         string
		want            string
		wantError       string
	}{
		{
			name: "noAddr-noPort-noEnv",
			want: ":0",
		},
		{
			name:            "yesAddrv4-noPort-noEnv",
			cliAddress:      "100.123.123.123",
			cliAddressIsSet: true,
			want:            "100.123.123.123:0",
		},
		{
			name:            "yesAddrv6-noPort-noEnv",
			cliAddress:      "dead::beef",
			cliAddressIsSet: true,
			want:            "[dead::beef]:0",
		},
		{
			name:            "yesAddr-yesPort-noEnv",
			cliAddress:      "100.123.123.123",
			cliAddressIsSet: true,
			cliPort:         456,
			cliPortIsSet:    true,
			want:            "100.123.123.123:456",
		},
		{
			name:            "yesAddr-yesPort-yesEnv",
			cliAddress:      "100.123.123.123",
			cliAddressIsSet: true,
			cliPort:         456,
			cliPortIsSet:    true,
			envBind:         "55.55.55.55:789",
			want:            "100.123.123.123:456",
		},
		{
			name:         "noAddr-yesPort-noEnv",
			cliPort:      456,
			cliPortIsSet: true,
			want:         ":456",
		},
		{
			name:         "noAddr-yesPort-yesEnv",
			cliPort:      456,
			cliPortIsSet: true,
			envBind:      "55.55.55.55:789",
			want:         ":456",
		},
		{
			name:    "noAddr-noPort-yesEnv",
			envBind: "55.55.55.55:789",
			want:    "55.55.55.55:789",
		},
		{
			name:            "badAddr-noPort-noEnv-1",
			cliAddress:      "678.678.678.678",
			cliAddressIsSet: true,
			wantError:       `invalid bind address: "678.678.678.678"`,
		},
		{
			name:            "badAddr-noPort-noEnv-2",
			cliAddress:      "lorem ipsum",
			cliAddressIsSet: true,
			wantError:       `invalid bind address: "lorem ipsum"`,
		},
		{
			name:         "noAddr-badPort-noEnv",
			cliPort:      -1,
			cliPortIsSet: true,
			wantError:    "invalid bind port number: -1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := createNetcheckBindString(tt.cliAddress, tt.cliAddressIsSet, tt.cliPort, tt.cliPortIsSet, tt.envBind)
			var gotErrStr string
			if gotErr != nil {
				gotErrStr = gotErr.Error()
			}
			if gotErrStr != tt.wantError {
				t.Errorf("got error %q; want error %q", gotErrStr, tt.wantError)
			}
			if got != tt.want {
				t.Errorf("got result %q; want result %q", got, tt.want)
			}
		})
	}
}
