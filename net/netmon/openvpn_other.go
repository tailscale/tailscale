// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package netmon

import "net"

// OpenVPN detection is only necessary for MacOS.
func isOpenVPNInterfaceDarwin(nif *net.Interface) bool {
	return false
}
