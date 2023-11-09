// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package netkernelconf

// CheckUDPGROForwarding is unimplemented for non-Linux platforms. Refer to the
// docstring in _linux.go.
func CheckUDPGROForwarding(tunInterface, defaultRouteInterface string) (warn, err error) {
	return nil, nil
}
