// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package strs

import "testing"

func TestCut(t *testing.T) {
	tests := []struct {
		fn       func(string, string) (string, bool)
		in1, in2 string
		want     string
		wantOK   bool
	}{
		{CutPrefix, "foo", "fo", "o", true},
		{CutPrefix, "bar", "fo", "bar", false},
		{CutSuffix, "foo", "o", "fo", true},
		{CutSuffix, "bar", "fo", "bar", false},
	}
	for i, tt := range tests {
		got, gotOK := tt.fn(tt.in1, tt.in2)
		if got != tt.want {
			t.Errorf("%d. got %q; want %q", i, got, tt.want)
		}
		if gotOK != tt.wantOK {
			t.Errorf("%d. got %v; want %v", i, gotOK, tt.wantOK)
		}
	}
}
