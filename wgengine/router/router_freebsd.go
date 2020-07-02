// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"fmt"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

// For now this router only supports the userspace WireGuard implementations.
//
// Work is currently underway for an in-kernel FreeBSD implementation of wireguard
// https://svnweb.freebsd.org/base?view=revision&revision=357986

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tundev tun.Device) (Router, error) {
	return newUserspaceBSDRouter(logf, nil, tundev)
}

func upDNS(servers []netaddr.IP, domains []string) error {
	if len(servers) == 0 {
		return downDNS()
	}

	if resolvconfIsActive() {
		if err := dnsResolvconfUp(servers, domains); err != nil {
			return fmt.Errorf("resolvconf: %w")
		}
		return nil
	}

	if err := dnsManualUp(servers, domains); err != nil {
		return fmt.Errorf("manual: %w")
	}
	return nil
}

func downDNS() error {
	if resolvconfIsActive() {
		if err := dnsResolvconfDown(); err != nil {
			return fmt.Errorf("resolvconf: %w")
		}
		return nil
	}

	if err := dnsManualDown(); err != nil {
		return fmt.Errorf("manual: %w")
	}
	return nil
}

func cleanup() error {
	return downDNS()
}
