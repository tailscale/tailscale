// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package interfaces

import "testing"

func BenchmarkGetPACWindows(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v := getPACWindows()
		if i == 0 {
			b.Logf("Got: %q", v)
		}
	}
}
