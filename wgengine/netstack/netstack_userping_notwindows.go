// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !darwin && !ios

package netstack

import (
	"errors"
	"net/netip"
	"time"
)

func userPingViaAPI(dstIP netip.Addr, timeout time.Duration) error {
	return errors.New("Win32 ICMP API not available on this platform")
}
