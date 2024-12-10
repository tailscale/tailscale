// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package prober

import (
	"fmt"
	"net/netip"
	"os/exec"

	"go4.org/netipx"
)

const tunName = "utun"

func configureTUN(addr netip.Prefix, tunname string) error {
	cmd := exec.Command("ifconfig", tunname, "inet", addr.String(), addr.Addr().String())
	res, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add address: %w (%s)", err, string(res))
	}

	net := netipx.PrefixIPNet(addr)
	nip := net.IP.Mask(net.Mask)
	nstr := fmt.Sprintf("%v/%d", nip, addr.Bits())
	cmd = exec.Command("route", "-q", "-n", "add", "-inet", nstr, "-iface", addr.Addr().String())
	res, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add route: %w (%s)", err, string(res))
	}

	return nil
}
