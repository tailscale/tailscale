// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package bakedroots

import (
	"slices"
	"testing"
)

func TestBakedInRoots(t *testing.T) {
	ResetForTest(t, nil)
	p := Get()
	got := p.Subjects()
	if len(got) != 2 {
		t.Errorf("subjects = %v; want 2", len(got))
	}

	// TODO(bradfitz): is there a way to easily make this test prettier without
	// writing a DER decoder? I'm not seeing how.
	var name []string
	for _, der := range got {
		name = append(name, string(der))
	}
	want := []string{
		"0O1\v0\t\x06\x03U\x04\x06\x13\x02US1)0'\x06\x03U\x04\n\x13 Internet Security Research Group1\x150\x13\x06\x03U\x04\x03\x13\fISRG Root X1",
		"0O1\v0\t\x06\x03U\x04\x06\x13\x02US1)0'\x06\x03U\x04\n\x13 Internet Security Research Group1\x150\x13\x06\x03U\x04\x03\x13\fISRG Root X2",
	}
	if !slices.Equal(name, want) {
		t.Errorf("subjects = %q; want %q", name, want)
	}
}
