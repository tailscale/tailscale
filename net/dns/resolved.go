// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

//lint:file-ignore U1000 refactoring, temporarily unused code.

package dns

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
)

// resolvedListenAddr is the listen address of the resolved stub resolver.
//
// We only consider resolved to be the system resolver if the stub resolver is;
// that is, if this address is the sole nameserver in /etc/resolved.conf.
// In other cases, resolved may be managing the system DNS configuration directly.
// Then the nameserver list will be a concatenation of those for all
// the interfaces that register their interest in being a default resolver with
//   SetLinkDomains([]{{"~.", true}, ...})
// which includes at least the interface with the default route, i.e. not us.
// This does not work for us: there is a possibility of getting NXDOMAIN
// from the other nameservers before we are asked or get a chance to respond.
// We consider this case as lacking resolved support and fall through to dnsDirect.
//
// While it may seem that we need to read a config option to get at this,
// this address is, in fact, hard-coded into resolved.
var resolvedListenAddr = netaddr.IPv4(127, 0, 0, 53)

var errNotReady = errors.New("interface not ready")

type resolvedLinkNameserver struct {
	Family  int32
	Address []byte
}

type resolvedLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

// isResolvedActive determines if resolved is currently managing system DNS settings.
func isResolvedActive() bool {
	// systemd-resolved is never installed without systemd.
	_, err := exec.LookPath("systemctl")
	if err != nil {
		return false
	}

	// is-active exits with code 3 if the service is not active.
	err = exec.Command("systemctl", "is-active", "systemd-resolved").Run()
	if err != nil {
		return false
	}

	config, err := readResolvConf()
	if err != nil {
		return false
	}

	// The sole nameserver must be the systemd-resolved stub.
	if len(config.Nameservers) == 1 && config.Nameservers[0] == resolvedListenAddr {
		return true
	}

	return false
}

// resolvedManager uses the systemd-resolved DBus API.
type resolvedManager struct{}

func newResolvedManager() resolvedManager {
	return resolvedManager{}
}

// Up implements managerImpl.
func (m resolvedManager) SetDNS(config OSConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()

	// conn is a shared connection whose lifecycle is managed by the dbus package.
	// We should not interfere with that by closing it.
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connecting to system bus: %w", err)
	}

	resolved := conn.Object(
		"org.freedesktop.resolve1",
		dbus.ObjectPath("/org/freedesktop/resolve1"),
	)

	// In principle, we could persist this in the manager struct
	// if we knew that interface indices are persistent. This does not seem to be the case.
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

	err = resolved.CallWithContext(
		ctx, "org.freedesktop.resolve1.Manager.SetLinkDNS", 0,
		iface.Index, linkNameservers,
	).Store()
	if err != nil {
		return fmt.Errorf("setLinkDNS: %w", err)
	}

	var linkDomains = make([]resolvedLinkDomain, len(config.Domains))
	for i, domain := range config.Domains {
		linkDomains[i] = resolvedLinkDomain{
			Domain:      domain,
			RoutingOnly: false,
		}
	}

	err = resolved.CallWithContext(
		ctx, "org.freedesktop.resolve1.Manager.SetLinkDomains", 0,
		iface.Index, linkDomains,
	).Store()
	if err != nil {
		return fmt.Errorf("setLinkDomains: %w", err)
	}

	return nil
}

func (m resolvedManager) SupportsSplitDNS() bool {
	return false
}

func (m resolvedManager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()

	// conn is a shared connection whose lifecycle is managed by the dbus package.
	// We should not interfere with that by closing it.
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

	err = resolved.CallWithContext(
		ctx, "org.freedesktop.resolve1.Manager.RevertLink", 0,
		iface.Index,
	).Store()
	if err != nil {
		return fmt.Errorf("RevertLink: %w", err)
	}

	return nil
}
