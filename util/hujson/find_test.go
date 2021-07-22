// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hujson

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFind(t *testing.T) {
	// Test case comes from RFC 6901, section 5.
	v, err := Parse([]byte(`
	{
		"foo": ["bar", "baz"],
		"": 0,
		"a/b": 1,
		"c%d": 2,
		"e^f": 3,
		"g|h": 4,
		"i\\j": 5,
		"k\"l": 6,
		" ": 7,
		"m~n": 8
	}`))
	v.Minimize()
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	tests := []struct {
		ptr  string
		want *Value
	}{
		{"", &v},
		{"/foo", &v.Value.(*Object).Members[0][1]},
		{"/foo/0", &v.Value.(*Object).Members[0][1].Value.(*Array).Elements[0]},
		{"/", &v.Value.(*Object).Members[1+0][1]},
		{"/a~1b", &v.Value.(*Object).Members[1+1][1]},
		{"/c%d", &v.Value.(*Object).Members[1+2][1]},
		{"/e^f", &v.Value.(*Object).Members[1+3][1]},
		{"/g|h", &v.Value.(*Object).Members[1+4][1]},
		{"/i\\j", &v.Value.(*Object).Members[1+5][1]},
		{"/k\"l", &v.Value.(*Object).Members[1+6][1]},
		{"/ ", &v.Value.(*Object).Members[1+7][1]},
		{"/m~0n", &v.Value.(*Object).Members[1+8][1]},
		{"foo", nil},
		{"/foo ", nil},
		{"/foo/00", nil},
	}
	for _, tt := range tests {
		got := v.Find(tt.ptr)
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("Find(%q) mismatch (-want +got):\n%s", tt.ptr, diff)
		}
	}
}
