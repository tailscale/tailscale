// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import "testing"

// Verifies that the fast bit-twiddling implementation of Contains
// works the same as the easy-to-read implementation. Since we can't
// sensibly check it on 128 bits, the test runs over 4-bit
// "IPs". Bit-twiddling is the same at any width, so this adequately
// proves that the implementations are equivalent.
func TestOptimizedContains(t *testing.T) {
	for ipHi := 0; ipHi < 0xf; ipHi++ {
		for ipLo := 0; ipLo < 0xf; ipLo++ {
			for nIPHi := 0; nIPHi < 0xf; nIPHi++ {
				for nIPLo := 0; nIPLo < 0xf; nIPLo++ {
					for maskHi := 0; maskHi < 0xf; maskHi++ {
						for maskLo := 0; maskLo < 0xf; maskLo++ {

							a := (nIPHi ^ ipHi) & maskHi
							b := (nIPLo ^ ipLo) & maskLo
							got := (a | b) == 0

							want := ((nIPHi&maskHi) == (ipHi&maskHi) && (nIPLo&maskLo) == (ipLo&maskLo))

							if got != want {
								t.Errorf("mask %1x%1x/%1x%1x %1x%1x got=%v want=%v", nIPHi, nIPLo, maskHi, maskLo, ipHi, ipLo, got, want)
							}
						}
					}
				}
			}
		}
	}
}
