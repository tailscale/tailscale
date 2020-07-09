// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package router

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"tailscale.com/net/interfaces"
)

// resolvedStubPaths are the locations of resolved resolv.conf stubs.
//
// The official documentation mentions, in roughly descending order of goodness:
// 1. /usr/lib/systemd/resolv.conf
// 2. /var/run/systemd/resolve/stun-resolv.conf
// 3. /var/run/systemd/resolve/resolv.conf
// Our approach here does not support (3): that mode does not proxy requests
// through resolved, instead trying to figure out what the "best" global resolver is.
// This is probably not useful for us: a link can request priority with
//   SetLinkDomains([]{{"~.", true}, ...})
// but the interface with the default route does this too.
// At best, (3) ends up being a mix of our and their nameservers.
// This does not work for us, as there is a possibility of getting NXDOMAIN
// from their nameservers before we are asked or get a chance to respond.
// We consider this case as lacking resolved support and fall through to dnsDirect.
//
// As for (1) and (2), we include the stated paths and their variants
// to account for /lib possible being symlinked to /usr/lib and /var/run to /run.
var resolvedStubPaths = []string{
	"/lib/systemd/resolv.conf",
	"/usr/lib/systemd/resolv.conf",
	"/run/systemd/resolve/stub-resolv.conf",
	"/var/run/systemd/resolve/stub-resolv.conf",
}

var errNotReady = errors.New("interface not ready")

type resolvedLinkNameserver struct {
	Family  int
	Address []byte
}

type resolvedLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

// resolvedIsActive determines if resolved is currently managing system DNS settings.
func resolvedIsActive() bool {
	dst, err := os.Readlink("/etc/resolv.conf")
	if err != nil {
		return false
	}

	for _, path := range resolvedStubPaths {
		if dst == path {
			return true
		}
	}

	return false
}

// dnsResolvedUp sets the DNS parameters for the Tailscale interface
// to given nameservers and search domains using the resolved DBus API.
func dnsResolvedUp(config DNSConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connecting to system bus: %w", err)
	}

	resolved := conn.Object(
		"org.freedesktop.resolve1",
		dbus.ObjectPath("/org/freedesktop/resolve1"),
	)

	_, iface, err := interfaces.Tailscale()
	if err != nil {
		return fmt.Errorf("getting interface index: %w", err)
	}
	if iface == nil {
		return errNotReady
	}

	var linkNameservers = make([]resolvedLinkNameserver, len(config.Nameservers))
	for i, server := range config.Nameservers {
		ip := server.As16()
		if server.Is4() {
			linkNameservers[i] = resolvedLinkNameserver{
				Family:  unix.AF_INET,
				Address: ip[12:],
			}
		} else {
			linkNameservers[i] = resolvedLinkNameserver{
				Family:  unix.AF_INET6,
				Address: ip[:],
			}
		}
	}

	call := resolved.CallWithContext(
		ctx, "org.freedesktop.resolve1.Manager.SetLinkDNS", 0,
		iface.Index, linkNameservers,
	)
	if call.Err != nil {
		return fmt.Errorf("SetLinkDNS: %w", call.Err)
	}

	var linkDomains = make([]resolvedLinkDomain, len(config.Domains))
	for i, domain := range config.Domains {
		linkDomains[i] = resolvedLinkDomain{
			Domain:      domain,
			RoutingOnly: false,
		}
	}

	call = resolved.CallWithContext(
		ctx, "org.freedesktop.resolve1.Manager.SetLinkDomains", 0,
		iface.Index, linkDomains,
	)
	if call.Err != nil {
		return fmt.Errorf("SetLinkDomains: %w", call.Err)
	}

	return nil
}

// dnsResolvedDown undoes the changes made by dnsResolvedUp.
func dnsResolvedDown() error {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connecting to system bus: %w", err)
	}

	resolved := conn.Object(
		"org.freedesktop.resolve1",
		dbus.ObjectPath("/org/freedesktop/resolve1"),
	)

	_, iface, err := interfaces.Tailscale()
	if err != nil {
		return fmt.Errorf("getting interface index: %w", err)
	}
	if iface == nil {
		return errNotReady
	}

	call := resolved.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.RevertLink", 0, iface.Index)
	if call.Err != nil {
		return fmt.Errorf("RevertLink: %w", call.Err)
	}

	return nil
}
