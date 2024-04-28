// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import "testing"

func BenchmarkGetPACWindows(b *testing.B) {
	b.ReportAllocs()
	for i := range b.N {
		v := getPACWindows()
		if i == 0 {
			b.Logf("Got: %q", v)
		}
	}
}
