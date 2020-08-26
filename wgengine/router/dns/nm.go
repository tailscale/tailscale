// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package dns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/godbus/dbus/v5"
)

var nativeEndian binary.ByteOrder

func init() {
	// TODO(dmytro): use DBus endianness flag when available.
	// A more elegant way to do this is by looking at the first byte of a raw DBus message.
	// However, that requires a change in godbus, which has slow maintainer response.
	i := uint32(1)
	p := unsafe.Pointer(&i)
	if *(*byte)(p) == 1 {
		nativeEndian = binary.LittleEndian
	} else {
		nativeEndian = binary.BigEndian
	}
}

// isNMActive determines if NetworkManager is currently managing system DNS settings.
func isNMActive() bool {
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

func nmDNSMode() string {
	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()

	// conn is a shared connection whose lifecycle is managed by the dbus package.
	// We should not interfere with that by closing it.
	conn, err := dbus.SystemBus()
	if err != nil {
		return ""
	}

	dnsManager := conn.Object(
		"org.freedesktop.NetworkManager",
		dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager"),
	)

	var dnsMode string
	err = dnsManager.CallWithContext(
		ctx, "org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.NetworkManager.DnsManager", "Mode",
	).Store(&dnsMode)
	if err != nil {
		return ""
	}

	return dnsMode
}

// nmManager uses the NetworkManager DBus API.
type nmManager struct {
	global        bool
	interfaceName string
	oldConfig     Config
	setUpstreams  func([]net.Addr)
}

func newNMManager(mconfig ManagerConfig) Manager {
	mode := nmDNSMode()
	mconfig.Logf("NetworkManager DNS mode is %q", mode)

	global := mode == "default"
	m := &nmManager{
		global:        global,
		interfaceName: mconfig.InterfaceName,
		setUpstreams:  mconfig.SetUpstreams,
	}

	if global {
		oldConfig, err := readResolvConf()
		if err != nil {
			mconfig.Logf("reading old config: %v", err)
		} else {
			m.oldConfig = oldConfig
		}
	}

	return m
}

type nmConnectionSettings map[string]map[string]dbus.Variant

// Set implements Manager.
func (m nmManager) Set(config Config) error {
	if m.global && !(len(config.Nameservers) == 0 && len(config.Domains) == 0) {
		config = prepareGlobalConfig(config, m.oldConfig, m.setUpstreams)
	}

	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()

	// conn is a shared connection whose lifecycle is managed by the dbus package.
	// We should not interfere with that by closing it.
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
			dnsv4 = append(dnsv4, nativeEndian.Uint32(b[12:]))
		} else {
			dnsv6 = append(dnsv6, b[:])
		}
	}

	ipv4Map := settings["ipv4"]
	ipv4Map["dns"] = dbus.MakeVariant(dnsv4)
	ipv4Map["dns-search"] = dbus.MakeVariant(config.Domains)
	// We should only request priority if we have nameservers to set.
	if len(dnsv4) == 0 {
		ipv4Map["dns-priority"] = dbus.MakeVariant(100)
	} else {
		// dns-priority = -1 ensures that we have priority
		// over other interfaces, except those exploiting this same trick.
		// Ref: https://bugs.launchpad.net/ubuntu/+source/network-manager/+bug/1211110/comments/92.
		ipv4Map["dns-priority"] = dbus.MakeVariant(-1)
	}
	// In principle, we should not need set this to true,
	// as our interface does not configure any automatic DNS settings (presumably via DHCP).
	// All the same, better to be safe.
	ipv4Map["ignore-auto-dns"] = dbus.MakeVariant(true)

	ipv6Map := settings["ipv6"]
	// This is a hack.
	// Methods "disabled", "ignore", "link-local" (IPv6 default) prevent us from setting DNS.
	// It seems that our only recourse is "manual" or "auto".
	// "manual" requires addresses, so we use "auto", which will assign us a random IPv6 /64.
	ipv6Map["method"] = dbus.MakeVariant("auto")
	// Our IPv6 config is a fake, so it should never become the default route.
	ipv6Map["never-default"] = dbus.MakeVariant(true)
	// Moreover, we should ignore all autoconfigured routes (hopefully none), as they are bogus.
	ipv6Map["ignore-auto-routes"] = dbus.MakeVariant(true)

	// Finally, set the actual DNS config.
	ipv6Map["dns"] = dbus.MakeVariant(dnsv6)
	ipv6Map["dns-search"] = dbus.MakeVariant(config.Domains)
	if len(dnsv6) == 0 {
		ipv6Map["dns-priority"] = dbus.MakeVariant(100)
	} else {
		ipv6Map["dns-priority"] = dbus.MakeVariant(-1)
	}
	ipv6Map["ignore-auto-dns"] = dbus.MakeVariant(true)

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

	err = device.CallWithContext(
		ctx, "org.freedesktop.NetworkManager.Device.Reapply", 0,
		settings, version, uint32(0),
	).Store()
	if err != nil {
		return fmt.Errorf("reapply: %w", err)
	}

	return nil
}

// Down implements Manager.
func (m nmManager) Down() error {
	return m.Set(Config{Nameservers: nil, Domains: nil})
}
