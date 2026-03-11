// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package preftype

import "testing"

func TestNetfilterMode(t *testing.T) {
	modes := []NetfilterMode{
		NetfilterOff,
		NetfilterOn,
		NetfilterNoDivert,
	}
	for _, m := range modes {
		s := m.String()
		if s == "" {
			t.Errorf("NetfilterMode(%d).String() is empty", m)
		}
	}
}
