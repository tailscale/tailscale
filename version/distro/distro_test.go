// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package distro

import "testing"

func BenchmarkGet(b *testing.B) {
	b.ReportAllocs()
	var d Distro
	for i := 0; i < b.N; i++ {
		d = Get()
	}
	_ = d
}
