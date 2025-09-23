// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && !ts_omit_networkmanager

package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/godbus/dbus/v5"
	"tailscale.com/net/tsaddr"
	"tailscale.com/util/cmpver"
	"tailscale.com/util/dnsname"
)

const (
	highestPriority = int32(-1 << 31)
	mediumPriority  = int32(1)   // Highest priority that doesn't hard-override
	lowerPriority   = int32(200) // lower than all builtin auto priorities
)

// nmManager uses the NetworkManager DBus API.
type nmManager struct {
	interfaceName string
	manager       dbus.BusObject
	dnsManager    dbus.BusObject
}

func init() {
	optNewNMManager.Set(newNMManager)
	optNMIsUsingResolved.Set(nmIsUsingResolved)
	optNMVersionBetween.Set(nmVersionBetween)
}

func newNMManager(interfaceName string) (OSConfigurator, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	return &nmManager{
		interfaceName: interfaceName,
		manager:       conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager")),
		dnsManager:    conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager")),
	}, nil
}

type nmConnectionSettings map[string]map[string]dbus.Variant

func (m *nmManager) SetDNS(config OSConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()

	// NetworkManager only lets you set DNS settings on "active"
	// connections, which requires an assigned IP address. This got
	// configured before the DNS manager was invoked, but it might
	// take a little time for the netlink notifications to propagate
	// up. So, keep retrying for the duration of the reconfigTimeout.
	var err error
	for ctx.Err() == nil {
		err = m.trySet(ctx, config)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return err
}

func (m *nmManager) trySet(ctx context.Context, config OSConfig) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connecting to system bus: %w", err)
	}

	// This is how we get at the DNS settings:
	//
	//               org.freedesktop.NetworkManager
	//                              |
	//                    [GetDeviceByIpIface]
	//                              |
	//                              v
	//           org.freedesktop.NetworkManager.Device <--------\
	//              (describes a network interface)             |
	//                              |                           |
	//                   [GetAppliedConnection]             [Reapply]
	//                              |                           |
	//                              v                           |
	//          org.freedesktop.NetworkManager.Connection       |
	//                   (connection settings)            ------/
	//          contains {dns, dns-priority, dns-search}
	//
	// Ref: https://developer.gnome.org/NetworkManager/stable/settings-ipv4.html.

	nm := conn.Object(
		"org.freedesktop.NetworkManager",
		dbus.ObjectPath("/org/freedesktop/NetworkManager"),
	)

	var devicePath dbus.ObjectPath
	err = nm.CallWithContext(
		ctx, "org.freedesktop.NetworkManager.GetDeviceByIpIface", 0,
		m.interfaceName,
	).Store(&devicePath)
	if err != nil {
		return fmt.Errorf("getDeviceByIpIface: %w", err)
	}
	device := conn.Object("org.freedesktop.NetworkManager", devicePath)

	var (
		settings nmConnectionSettings
		version  uint64
	)
	err = device.CallWithContext(
		ctx, "org.freedesktop.NetworkManager.Device.GetAppliedConnection", 0,
		uint32(0),
	).Store(&settings, &version)
	if err != nil {
		return fmt.Errorf("getAppliedConnection: %w", err)
	}

	// Frustratingly, NetworkManager represents IPv4 addresses as uint32s,
	// although IPv6 addresses are represented as byte arrays.
	// Perform the conversion here.
	var (
		dnsv4 []uint32
		dnsv6 [][]byte
	)
	for _, ip := range config.Nameservers {
		b := ip.As16()
		if ip.Is4() {
			dnsv4 = append(dnsv4, binary.NativeEndian.Uint32(b[12:]))
		} else {
			dnsv6 = append(dnsv6, b[:])
		}
	}

	// NetworkManager wipes out IPv6 address configuration unless we
	// tell it explicitly to keep it. Read out the current interface
	// settings and mirror them out to NetworkManager.
	var addrs6 []map[string]any
	if tsIf, err := net.InterfaceByName(m.interfaceName); err == nil {
		addrs, _ := tsIf.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				nip, ok := netip.AddrFromSlice(ipnet.IP)
				nip = nip.Unmap()
				if ok && tsaddr.IsTailscaleIP(nip) && nip.Is6() {
					addrs6 = append(addrs6, map[string]any{
						"address": nip.String(),
						"prefix":  uint32(128),
					})
				}
			}
		}
	}

	seen := map[dnsname.FQDN]bool{}
	var search []string
	for _, dom := range config.SearchDomains {
		if seen[dom] {
			continue
		}
		seen[dom] = true
		search = append(search, dom.WithTrailingDot())
	}
	for _, dom := range config.MatchDomains {
		if seen[dom] {
			continue
		}
		seen[dom] = true
		search = append(search, "~"+dom.WithTrailingDot())
	}
	if len(config.MatchDomains) == 0 {
		// Non-split routing requested, add an all-domains match.
		search = append(search, "~.")
	}

	// Ideally we would like to disable LLMNR and mdns on the
	// interface here, but older NetworkManagers don't understand
	// those settings and choke on them, so we don't. Both LLMNR and
	// mdns will fail since tailscale0 doesn't do multicast, so it's
	// effectively fine. We used to try and enforce LLMNR and mdns
	// settings here, but that led to #1870.

	ipv4Map := settings["ipv4"]
	ipv4Map["dns"] = dbus.MakeVariant(dnsv4)
	ipv4Map["dns-search"] = dbus.MakeVariant(search)
	// We should only request priority if we have nameservers to set.
	if len(dnsv4) == 0 {
		ipv4Map["dns-priority"] = dbus.MakeVariant(lowerPriority)
	} else if len(config.MatchDomains) > 0 {
		// Set a fairly high priority, but don't override all other
		// configs when in split-DNS mode.
		ipv4Map["dns-priority"] = dbus.MakeVariant(mediumPriority)
	} else {
		// Negative priority means only the settings from the most
		// negative connection get used. The way this mixes with
		// per-domain routing is unclear, but it _seems_ that the
		// priority applies after routing has found possible
		// candidates for a resolution.
		ipv4Map["dns-priority"] = dbus.MakeVariant(highestPriority)
	}

	ipv6Map := settings["ipv6"]
	// In IPv6 settings, you're only allowed to provide additional
	// static DNS settings in "auto" (SLAAC) or "manual" mode. In
	// "manual" mode you also have to specify IP addresses, so we use
	// "auto".
	//
	// NM actually documents that to set just DNS servers, you should
	// use "auto" mode and then set ignore auto routes and DNS, which
	// basically means "autoconfigure but ignore any autoconfiguration
	// results you might get". As a safety, we also say that
	// NetworkManager should never try to make us the default route
	// (none of its business anyway, we handle our own default
	// routing).
	ipv6Map["method"] = dbus.MakeVariant("auto")
	if len(addrs6) > 0 {
		ipv6Map["address-data"] = dbus.MakeVariant(addrs6)
	}
	ipv6Map["ignore-auto-routes"] = dbus.MakeVariant(true)
	ipv6Map["ignore-auto-dns"] = dbus.MakeVariant(true)
	ipv6Map["never-default"] = dbus.MakeVariant(true)

	ipv6Map["dns"] = dbus.MakeVariant(dnsv6)
	ipv6Map["dns-search"] = dbus.MakeVariant(search)
	if len(dnsv6) == 0 {
		ipv6Map["dns-priority"] = dbus.MakeVariant(lowerPriority)
	} else if len(config.MatchDomains) > 0 {
		// Set a fairly high priority, but don't override all other
		// configs when in split-DNS mode.
		ipv6Map["dns-priority"] = dbus.MakeVariant(mediumPriority)
	} else {
		ipv6Map["dns-priority"] = dbus.MakeVariant(highestPriority)
	}

	// deprecatedProperties are the properties in interface settings
	// that are deprecated by NetworkManager.
	//
	// In practice, this means that they are returned for reading,
	// but submitting a settings object with them present fails
	// with hard-to-diagnose errors. They must be removed.
	deprecatedProperties := []string{
		"addresses", "routes",
	}

	for _, property := range deprecatedProperties {
		delete(ipv4Map, property)
		delete(ipv6Map, property)
	}

	if call := device.CallWithContext(ctx, "org.freedesktop.NetworkManager.Device.Reapply", 0, settings, version, uint32(0)); call.Err != nil {
		return fmt.Errorf("reapply: %w", call.Err)
	}

	return nil
}

func (m *nmManager) SupportsSplitDNS() bool {
	var mode string
	v, err := m.dnsManager.GetProperty("org.freedesktop.NetworkManager.DnsManager.Mode")
	if err != nil {
		return false
	}
	mode, ok := v.Value().(string)
	if !ok {
		return false
	}

	// Per NM's documentation, it only does split-DNS when it's
	// programming dnsmasq or systemd-resolved. All other modes are
	// primary-only.
	return mode == "dnsmasq" || mode == "systemd-resolved"
}

func (m *nmManager) GetBaseConfig() (OSConfig, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return OSConfig{}, err
	}

	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager"))
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.DnsManager.Configuration")
	if err != nil {
		return OSConfig{}, err
	}
	cfgs, ok := v.Value().([]map[string]dbus.Variant)
	if !ok {
		return OSConfig{}, fmt.Errorf("unexpected NM config type %T", v.Value())
	}

	if len(cfgs) == 0 {
		return OSConfig{}, nil
	}

	type dnsPrio struct {
		resolvers []netip.Addr
		domains   []string
		priority  int32
	}
	order := make([]dnsPrio, 0, len(cfgs)-1)

	for _, cfg := range cfgs {
		if name, ok := cfg["interface"]; ok {
			if s, ok := name.Value().(string); ok && s == m.interfaceName {
				// Config for the tailscale interface, skip.
				continue
			}
		}

		var p dnsPrio

		if v, ok := cfg["nameservers"]; ok {
			if ips, ok := v.Value().([]string); ok {
				for _, s := range ips {
					ip, err := netip.ParseAddr(s)
					if err != nil {
						// hmm, what do? Shouldn't really happen.
						continue
					}
					p.resolvers = append(p.resolvers, ip)
				}
			}
		}
		if v, ok := cfg["domains"]; ok {
			if domains, ok := v.Value().([]string); ok {
				p.domains = domains
			}
		}
		if v, ok := cfg["priority"]; ok {
			if prio, ok := v.Value().(int32); ok {
				p.priority = prio
			}
		}

		order = append(order, p)
	}

	sort.Slice(order, func(i, j int) bool {
		return order[i].priority < order[j].priority
	})

	var (
		ret           OSConfig
		seenResolvers = map[netip.Addr]bool{}
		seenSearch    = map[string]bool{}
	)

	for _, cfg := range order {
		for _, resolver := range cfg.resolvers {
			if seenResolvers[resolver] {
				continue
			}
			ret.Nameservers = append(ret.Nameservers, resolver)
			seenResolvers[resolver] = true
		}
		for _, dom := range cfg.domains {
			if seenSearch[dom] {
				continue
			}
			fqdn, err := dnsname.ToFQDN(dom)
			if err != nil {
				continue
			}
			ret.SearchDomains = append(ret.SearchDomains, fqdn)
			seenSearch[dom] = true
		}
		if cfg.priority < 0 {
			// exclusive configurations preempt all other
			// configurations, so we're done.
			break
		}
	}

	return ret, nil
}

func (m *nmManager) Close() error {
	// No need to do anything on close, NetworkManager will delete our
	// settings when the tailscale interface goes away.
	return nil
}

func nmVersionBetween(first, last string) (bool, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return false, err
	}

	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager"))
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.Version")
	if err != nil {
		return false, err
	}

	version, ok := v.Value().(string)
	if !ok {
		return false, fmt.Errorf("unexpected type %T for NM version", v.Value())
	}

	outside := cmpver.Compare(version, first) < 0 || cmpver.Compare(version, last) > 0
	return !outside, nil
}

func nmIsUsingResolved() error {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return err
	}

	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager"))
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.DnsManager.Mode")
	if err != nil {
		return fmt.Errorf("getting NM mode: %w", err)
	}
	mode, ok := v.Value().(string)
	if !ok {
		return fmt.Errorf("unexpected type %T for NM DNS mode", v.Value())
	}
	if mode != "systemd-resolved" {
		return errors.New("NetworkManager is not using systemd-resolved for DNS")
	}
	return nil
}
