// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package router

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"

	"github.com/godbus/dbus/v5"
)

type nmSettings map[string]map[string]dbus.Variant

// nmIsActive determines if NetworkManager is currently managing system DNS settings.
func nmIsActive() bool {
	// This is somewhat tricky because NetworkManager supports a number
	// of DNS configuration modes. In all cases, we expect it to be installed
	// and /etc/resolv.conf to contain a mention of NetworkManager in the comments.
	_, err := exec.LookPath("NetworkManager")
	if err != nil {
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

// dnsNetworkManagerUp updates the DNS config for the Tailscale interface
// through the NetworkManager DBus API.
func dnsNetworkManagerUp(config DNSConfig, interfaceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dnsReconfigTimeout)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connecting to system bus: %w", err)
	}
	defer conn.Close()

	// This is how we get at the DNS settings:
	//               org.freedesktop.NetworkManager
	//                              ⇩
	//           org.freedesktop.NetworkManager.Device
	//              (describes a network interface)
	//                              ⇩
	//       org.freedesktop.NetworkManager.Connection.Active
	//  (active instance of a connection initialized from settings)
	//                              ⇩
	//         org.freedesktop.NetworkManager.Connection
	//                   (connection settings)
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
		interfaceName,
	).Store(&devicePath)
	if err != nil {
		return fmt.Errorf("GetDeviceByIpIface: %w", err)
	}
	device := conn.Object("org.freedesktop.NetworkManager", devicePath)

	var activeConnPath dbus.ObjectPath
	err = device.CallWithContext(
		ctx, "org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.NetworkManager.Device", "ActiveConnection",
	).Store(&activeConnPath)
	if err != nil {
		return fmt.Errorf("getting ActiveConnection: %w", err)
	}
	activeConn := conn.Object("org.freedesktop.NetworkManager", activeConnPath)

	var connPath dbus.ObjectPath
	err = activeConn.CallWithContext(
		ctx, "org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.NetworkManager.Connection.Active", "Connection",
	).Store(&connPath)
	if err != nil {
		return fmt.Errorf("getting Connection: %w", err)
	}
	connection := conn.Object("org.freedesktop.NetworkManager", connPath)

	// Note: strictly speaking, the following is not safe.
	//
	// It appears that the way to update connection settings
	// in NetworkManager is to get an entire connection settings object,
	// modify the fields we are interested in, then submit the modified object.
	//
	// This is unfortunate: if the network state changes in the meantime
	// (most relevantly to us, if routes change), we will overwrite those changes.
	//
	// That said, fortunately, this should have no real effect, as Tailscale routes
	// do not seem to show up in NetworkManager at all,
	// so they are presumably immune from being tampered with.

	var settings nmSettings
	err = connection.CallWithContext(
		ctx, "org.freedesktop.NetworkManager.Settings.Connection.GetSettings", 0,
	).Store(&settings)
	if err != nil {
		return fmt.Errorf("getting Settings: %w", err)
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
			dnsv4 = append(dnsv4, binary.LittleEndian.Uint32(b[12:]))
		} else {
			dnsv6 = append(dnsv6, b[:])
		}
	}

	ipv4Map := settings["ipv4"]
	ipv4Map["dns"] = dbus.MakeVariant(dnsv4)
	ipv4Map["dns-search"] = dbus.MakeVariant(config.Domains)
	// dns-priority = -1 ensures that we have priority
	// over other interfaces, except those exploiting this same trick.
	// Ref: https://bugs.launchpad.net/ubuntu/+source/network-manager/+bug/1211110/comments/92.
	ipv4Map["dns-priority"] = dbus.MakeVariant(-1)
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
	ipv6Map["dns-priority"] = dbus.MakeVariant(-1)
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

	err = connection.CallWithContext(
		ctx, "org.freedesktop.NetworkManager.Settings.Connection.UpdateUnsaved", 0, settings,
	).Store()
	if err != nil {
		return fmt.Errorf("setting Settings: %w", err)
	}

	return nil
}

// dnsNetworkManagerDown undoes the changes made by dnsNetworkManagerUp.
func dnsNetworkManagerDown(interfaceName string) error {
	return dnsNetworkManagerUp(DNSConfig{Nameservers: nil, Domains: nil}, interfaceName)
}
