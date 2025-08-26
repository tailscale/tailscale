// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import "testing"

func TestHumanReadableBytes(t *testing.T) {
	type args struct {
		b      int64
		useIEC bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"SI_0", args{0, false}, "0 B"},
		{"SI_42", args{42, false}, "42 B"},
		{"SI_1K", args{1000, false}, "1.0 kB"},
		{"SI_1G", args{1000000000, false}, "1.0 GB"},
		{"SI_1E", args{1000000000000000000, false}, "1.0 EB"},
		{"IEC_0", args{0, true}, "0 B"},
		{"IEC_42", args{42, true}, "42 B"},
		{"IEC_1K", args{1024, true}, "1.0 KiB"},
		{"IEC_1G", args{1073741824, true}, "1.0 GiB"},
		{"IEC_1E", args{1152921504606846976, true}, "1.0 EiB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := humanReadableBytes(tt.args.b, tt.args.useIEC); got != tt.want {
				t.Errorf("humanReadableBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
