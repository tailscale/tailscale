// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netlog

import "testing"

func FuzzQuotedLen(f *testing.F) {
	for _, s := range quotedLenTestdata {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		testQuotedLen(t, s)
	})
}
