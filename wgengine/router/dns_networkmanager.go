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

// deprecatedProperties are the properties in interface settings
// that are deprecated by NetworkManager.
//
// In practice, this means that they are returned for reading,
// but submitting a settings object with them present fails
// with hard-to-diagnose errors. They must be removed.
var nmDeprecatedProperties = []string{
	"addresses", "routes",
}

// nmIsActive determines if NetworkManager is currently managing system DNS settings.
func nmIsActive() bool {
	// This is somewhat tricky because NetworkManager supports a number
	// of DNS configuration modes. In all cases, we expect it to be installed
	// and /etc/resolv.conf to contain a mention of NetworkManager in the comments.
	err := exec.Command("which", "NetworkManager").Run()
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
		// Look for the word "resolvconf" until comments end.
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
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connecting to system bus: %w", err)
	}

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

	var activeConnPath dbus.ObjectPath
	device := conn.Object("org.freedesktop.NetworkManager", devicePath)
	err = device.CallWithContext(
		ctx, "org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.NetworkManager.Device", "ActiveConnection",
	).Store(&activeConnPath)
	if err != nil {
		return fmt.Errorf("getting ActiveConnection: %w", err)
	}

	var connPath dbus.ObjectPath
	activeConn := conn.Object("org.freedesktop.NetworkManager", activeConnPath)
	err = activeConn.CallWithContext(
		ctx, "org.freedesktop.DBus.Properties.Get", 0,
		"org.freedesktop.NetworkManager.Connection.Active", "Connection",
	).Store(&connPath)
	if err != nil {
		return fmt.Errorf("getting Connection: %w", err)
	}

	// Note: strictly speaking, the following is not safe.
	//
	// It appears that the way to update an interface's settings
	// in NetworkManager is by getting the entire settings object,
	// modifying the fields we are interested in,
	// then updating the interface's setting to the modified object.
	//
	// This is unfortunate: if the network state changes in the meantime
	// (most relevantly to us, if routes change), we will overwrite those changes.
	//
	// That said, fortunately, this should have no real effect, as Tailscale routes
	// do not seem to show up in NetworkManager at all,
	// so they are presumably immune from being tampered with.

	var settings nmSettings
	connection := conn.Object("org.freedesktop.NetworkManager", connPath)
	err = connection.CallWithContext(
		ctx, "org.freedesktop.NetworkManager.Settings.Connection.GetSettings", 0,
	).Store(&settings)
	if err != nil {
		return fmt.Errorf("getting Settings: %w", err)
	}

	// Unfortunately, NetworkManager represents IPv4 addresses as uint32s,
	// although IPv6 addresses are represented as byte arrays.
	// Perform the conversion here.
	dns := make([]uint32, len(config.Nameservers))
	for i, ip := range config.Nameservers {
		if ip.Is4() {
			b := ip.As4()
			dns[i] = binary.BigEndian.Uint32(b[:])
		}
	}

	ipv4Map := settings["ipv4"]
	ipv4Map["dns"] = dbus.MakeVariant(dns)
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

	for _, property := range nmDeprecatedProperties {
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
