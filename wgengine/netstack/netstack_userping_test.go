// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package netstack

import (
	"testing"
	"unsafe"
)

func TestWin32ICMPStructSizes(t *testing.T) {
	// Verify struct layouts match 64-bit Windows SDK expectations
	// to prevent memory misalignment when calling IcmpSendEcho / Icmp6SendEcho2.
	if sz := unsafe.Sizeof(icmpEchoReply{}); sz < 32 {
		t.Errorf("sizeof(icmpEchoReply) = %d; want >= 32", sz)
	}
	if sz := unsafe.Sizeof(icmpv6EchoReply{}); sz < 32 {
		t.Errorf("sizeof(icmpv6EchoReply) = %d; want >= 32", sz)
	}
	if sz := unsafe.Sizeof(sockaddrIn6{}); sz != 28 {
		t.Errorf("sizeof(sockaddrIn6) = %d; want 28", sz)
	}
}
