// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package posture

import (
	"net/netip"
	"slices"

	"tailscale.com/net/netmon"
)

// GetHardwareAddrs returns the hardware addresses of all non-loopback
// network interfaces.
func GetHardwareAddrs() (hwaddrs []string, err error) {
	err = netmon.ForeachInterface(func(i netmon.Interface, _ []netip.Prefix) {
		if i.IsLoopback() {
			return
		}
		if a := i.HardwareAddr.String(); a != "" {
			hwaddrs = append(hwaddrs, a)
		}
	})
	slices.Sort(hwaddrs)
	return slices.Compact(hwaddrs), err
}
