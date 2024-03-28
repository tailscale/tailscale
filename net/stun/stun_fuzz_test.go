// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package stun

import "testing"

func FuzzStun(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseResponse(data)

		_, _ = ParseBindingRequest(data)
	})
}
