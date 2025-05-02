// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import "testing"

func TestPropToString(t *testing.T) {
	for prop, want := range map[uint32]string{
		0:          "",
		0x4D534654: "MSFT",
		0x414D4400: "AMD",
		0x414D440D: "AMD",
	} {
		if got := propToString(prop); got != want {
			t.Errorf("propToString(0x%x): got %q, want %q", prop, got, want)
		}
	}
}
