// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix && !windows

package netstack

import (
	"fmt"
	"net/netip"
)

// canBindLoopbackBeforeConnect reports whether this platform supports
// binding a not-yet-connected dial socket to learn its local address before
// the TCP handshake completes. Platforms without a bindLoopbackFD
// implementation (e.g. js/wasm, plan9) fall back to registering after the
// dial completes, the pre-#1616 behavior.
const canBindLoopbackBeforeConnect = false

func bindLoopbackFD(fd uintptr, ip netip.Addr) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("bindLoopbackFD: unsupported platform")
}
