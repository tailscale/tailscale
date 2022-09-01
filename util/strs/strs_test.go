// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
