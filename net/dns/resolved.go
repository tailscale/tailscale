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

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
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
	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		// Probably no DBus on the system, or we're not allowed to use
		// it. Cannot control resolved.
		return false
	}

	rd := conn.Object("org.freedesktop.resolve1", dbus.ObjectPath("/org/freedesktop/resolve1"))
	call := rd.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0)
	if call.Err != nil {
		// Can't talk to resolved.
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
type resolvedManager struct {
	logf logger.Logf
}

func newResolvedManager(logf logger.Logf) (resolvedManager, error) {
	return resolvedManager{
		logf: logf,
	}, nil
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

	linkDomains := make([]resolvedLinkDomain, 0, len(config.SearchDomains)+len(config.MatchDomains))
	seenDomains := map[dnsname.FQDN]bool{}
	for _, domain := range config.SearchDomains {
		if seenDomains[domain] {
			continue
		}
		seenDomains[domain] = true
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      domain.WithTrailingDot(),
			RoutingOnly: false,
		})
	}
	for _, domain := range config.MatchDomains {
		if seenDomains[domain] {
			// Search domains act as both search and match in
			// resolved, so it's correct to skip.
			continue
		}
		seenDomains[domain] = true
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      domain.WithTrailingDot(),
			RoutingOnly: true,
		})
	}
	if len(config.MatchDomains) == 0 {
		// Caller requested full DNS interception, install a
		// routing-only root domain.
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      ".",
			RoutingOnly: true,
		})
	}

	err = resolved.CallWithContext(
		ctx, "org.freedesktop.resolve1.Manager.SetLinkDomains", 0,
		iface.Index, linkDomains,
	).Store()
	if err != nil {
		return fmt.Errorf("setLinkDomains: %w", err)
	}

	if call := resolved.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.SetLinkDefaultRoute", 0, iface.Index, len(config.MatchDomains) == 0); call.Err != nil {
		return fmt.Errorf("setLinkDefaultRoute: %w", err)
	}

	// Some best-effort setting of things, but resolved should do the
	// right thing if these fail (e.g. a really old resolved version
	// or something).

	// Disable LLMNR, we don't do multicast.
	if call := resolved.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.SetLinkLLMNR", 0, iface.Index, "no"); call.Err != nil {
		m.logf("[v1] failed to disable LLMNR: %v", call.Err)
	}

	// Disable mdns.
	if call := resolved.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.SetLinkMulticastDNS", 0, iface.Index, "no"); call.Err != nil {
		m.logf("[v1] failed to disable mdns: %v", call.Err)
	}

	// We don't support dnssec consistently right now, force it off to
	// avoid partial failures when we split DNS internally.
	if call := resolved.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.SetLinkDNSSEC", 0, iface.Index, "no"); call.Err != nil {
		m.logf("[v1] failed to disable DNSSEC: %v", call.Err)
	}

	if call := resolved.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.SetLinkDNSOverTLS", 0, iface.Index, "no"); call.Err != nil {
		m.logf("[v1] failed to disable DoT: %v", call.Err)
	}

	if call := resolved.CallWithContext(ctx, "org.freedesktop.resolve1.Manager.FlushCaches", 0); call.Err != nil {
		m.logf("failed to flush resolved DNS cache: %v", call.Err)
	}

	return nil
}

func (m resolvedManager) SupportsSplitDNS() bool {
	return true
}

func (m resolvedManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{}, ErrGetBaseConfigNotSupported
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
