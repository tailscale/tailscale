// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
