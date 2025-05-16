// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derp

import "testing"

func TestCheckMeshKey(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "KeyOkay",
			input:   "f1ffafffffffffffffffffffffffffffffffffffffffffffffffff2ffffcfff6",
			want:    "f1ffafffffffffffffffffffffffffffffffffffffffffffffffff2ffffcfff6",
			wantErr: false,
		},
		{
			name:    "TrimKeyOkay",
			input:   "  f1ffafffffffffffffffffffffffffffffffffffffffffffffffff2ffffcfff6  ",
			want:    "f1ffafffffffffffffffffffffffffffffffffffffffffffffffff2ffffcfff6",
			wantErr: false,
		},
		{
			name:    "NotAKey",
			input:   "zzthisisnotakey",
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			k, err := CheckMeshKey(tt.input)
			if err != nil && !tt.wantErr {
				t.Errorf("unexpected error: %v", err)
			}
			if err == nil && tt.wantErr {
				t.Errorf("expected error but got none")
			}
			if k != tt.want {
				t.Errorf("got: %s doesn't match expected: %s", k, tt.want)
			}

		})
	}

}
