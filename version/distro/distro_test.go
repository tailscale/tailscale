// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package distro

import "testing"

func BenchmarkGet(b *testing.B) {
	b.ReportAllocs()
	var d Distro
	for range b.N {
		d = Get()
	}
	_ = d
}
