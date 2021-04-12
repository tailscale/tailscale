// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

//lint:file-ignore U1000 refactoring, temporarily unused code.

package dns

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/godbus/dbus/v5"
	"inet.af/netaddr"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/endian"
)

const (
	highestPriority = int32(-1 << 31)
	lowerPriority   = int32(200) // lower than all builtin auto priorities
)

// isNMActive determines if NetworkManager is currently managing system DNS settings.
func isNMActive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		// Probably no DBus on this system. Either way, we can't
		// control NM without DBus.
		return false
	}

	// Try to ping NetworkManager's DnsManager object. If it responds,
	// NM is running and we're allowed to touch it.
	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager"))
	call := nm.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0)
	if call.Err != nil {
		return false
	}

	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Look for the word "NetworkManager" until comments end.
		if len(line) > 0 && line[0] != '#' {
			return false
		}
		if bytes.Contains(line, []byte("NetworkManager")) {
			return true
		}
	}
	return false
}

// nmManager uses the NetworkManager DBus API.
type nmManager struct {
	interfaceName string
	canSplit      bool
}

func nmCanSplitDNS() bool {
	conn, err := dbus.SystemBus()
	if err != nil {
		return false
	}

	var mode string
	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager"))
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.DnsManager.Mode")
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

func newNMManager(interfaceName string) nmManager {
	return nmManager{
		interfaceName: interfaceName,
		canSplit:      nmCanSplitDNS(),
	}
}

type nmConnectionSettings map[string]map[string]dbus.Variant

func (m nmManager) SetDNS(config OSConfig) error {
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

func (m nmManager) trySet(ctx context.Context, config OSConfig) error {
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
			dnsv4 = append(dnsv4, endian.Native.Uint32(b[12:]))
		} else {
			dnsv6 = append(dnsv6, b[:])
		}
	}

	general := settings["connection"]
	general["llmnr"] = dbus.MakeVariant(0)
	general["mdns"] = dbus.MakeVariant(0)

	ipv4Map := settings["ipv4"]
	ipv4Map["dns"] = dbus.MakeVariant(dnsv4)
	ipv4Map["dns-search"] = dbus.MakeVariant(config.SearchDomains)
	// We should only request priority if we have nameservers to set.
	if len(dnsv4) == 0 {
		ipv4Map["dns-priority"] = dbus.MakeVariant(lowerPriority)
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
	ipv6Map["ignore-auto-routes"] = dbus.MakeVariant(true)
	ipv6Map["ignore-auto-dns"] = dbus.MakeVariant(true)
	ipv6Map["never-default"] = dbus.MakeVariant(true)

	ipv6Map["dns"] = dbus.MakeVariant(dnsv6)
	ipv6Map["dns-search"] = dbus.MakeVariant(config.SearchDomains)
	if len(dnsv6) == 0 {
		ipv6Map["dns-priority"] = dbus.MakeVariant(lowerPriority)
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
		return fmt.Errorf("reapply: %w", err)
	}

	return nil
}

func (m nmManager) SupportsSplitDNS() bool { return m.canSplit }

func (m nmManager) GetBaseConfig() (OSConfig, error) {
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

	type dnsPrio struct {
		resolvers []netaddr.IP
		domains   []string
		priority  int32
	}
	order := make([]dnsPrio, 0, len(cfgs)-1)

	for _, cfg := range cfgs {
		if name, ok := cfg["interface"]; ok {
			if s, ok := name.Value().(string); ok && s == m.interfaceName {
				// Config for the taislcale interface, skip.
				continue
			}
		}

		var p dnsPrio

		if v, ok := cfg["nameservers"]; ok {
			if ips, ok := v.Value().([]string); ok {
				for _, s := range ips {
					ip, err := netaddr.ParseIP(s)
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
		seenResolvers = map[netaddr.IP]bool{}
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

func (m nmManager) Close() error {
	// No need to do anything on close, NetworkManager will delete our
	// settings when the tailscale interface goes away.
	return nil
}
