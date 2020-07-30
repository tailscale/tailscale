// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"fmt"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// For now this router only supports the userspace WireGuard implementations.
//
// Work is currently underway for an in-kernel FreeBSD implementation of wireguard
// https://svnweb.freebsd.org/base?view=revision&revision=357986

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tundev tun.Device) (Router, error) {
	return newUserspaceBSDRouter(logf, nil, tundev)
}

func upDNS(config DNSConfig, interfaceName string) error {
	if len(config.Nameservers) == 0 {
		return downDNS(interfaceName)
	}

	if resolvconfIsActive() {
		if err := dnsResolvconfUp(config, interfaceName); err != nil {
			return fmt.Errorf("resolvconf: %w")
		}
		return nil
	}

	if err := dnsDirectUp(config); err != nil {
		return fmt.Errorf("direct: %w")
	}
	return nil
}

func downDNS(interfaceName string) error {
	if resolvconfIsActive() {
		if err := dnsResolvconfDown(interfaceName); err != nil {
			return fmt.Errorf("resolvconf: %w")
		}
		return nil
	}

	if err := dnsDirectDown(); err != nil {
		return fmt.Errorf("direct: %w")
	}
	return nil
}

func cleanup(logf logger.Logf, interfaceName string) {
	if err := downDNS(interfaceName); err != nil {
		logf("dns down: %v", err)
	}
	// If the interface was left behind, ifconfig down will not remove it.
	// In fact, this will leave a system in a tainted state where starting tailscaled
	// will result in "interface tailscale0 already exists"
	// until the defunct interface is ifconfig-destroyed.
	ifup := []string{"ifconfig", interfaceName, "destroy"}
	if out, err := cmd(ifup...).CombinedOutput(); err != nil {
		logf("ifconfig destroy: %v\n%s", err, out)
	}
}
