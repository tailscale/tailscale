// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// Package androidbin makes Tailscale binaries work when run as raw
// (non-GUI app) executables on Android, such as under Termux, adb, or
// a rooted shell. Android denies app UIDs the NETLINK_ROUTE socket
// and /proc/net (Issue 2293, golang/go#40569), so net.Interfaces
// always fails and netmon cannot start. The Android app solves this
// from Java via netmon.RegisterInterfaceGetter, but a standalone
// binary has no Java to lean on.
//
// This package registers a netmon fallback that reports a single
// synthetic interface whose addresses are discovered by asking the
// kernel to route an outbound UDP socket (which sends no packets and
// is permitted). That's enough for magicsock to discover local
// endpoints, though it can't see the full multi-interface picture.
// The fallback runs only when nothing was registered with
// RegisterInterfaceGetter, net.Interfaces failed, and runtime
// detection says the process is on Android, so it's inert on regular
// Linux.
//
// It also pulls in the androiddns feature, which fixes name
// resolution with no /etc/resolv.conf, and points Go's CA root loader
// at Android's system certificate store in GOOS=linux builds (see
// cacerts.go), which otherwise find no roots and fail all TLS
// verification.
//
// Like androiddns, the package builds on GOOS=linux as well as
// GOOS=android, because static linux binaries are commonly run under
// Android kernels. This is an optional feature, included by default
// in tailscaled builds on Linux and Android; build with the
// ts_omit_androidbin tag to omit it. It is not linked into tsnet by
// default; tsnet apps and other programs opt in with a blank import
// of this package.
package androidbin

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"tailscale.com/net/netmon"

	_ "tailscale.com/feature/androiddns"
)

// fallbackInterfaces implements netmon.HookInterfacesFallback. It
// runs only after net.Interfaces has already failed.
func fallbackInterfaces() ([]netmon.Interface, error) {
	if !onAndroid() {
		return nil, errors.New("androidbin: not running on Android")
	}
	return buildSynthetic()
}

// buildSynthetic returns a single made-up interface carrying the
// process's outbound IPv4 and IPv6 source addresses.
func buildSynthetic() ([]netmon.Interface, error) {
	var addrs []net.Addr
	// The dial targets are never sent any packets; dialing a UDP
	// socket only makes the kernel pick a route and a source address.
	// Use Google Public DNS addresses rather than documentation range
	// (TEST-NET) addresses in case Android ever grows special routing
	// treatment of ranges that are never supposed to appear on a real
	// network.
	if ip, ok := outboundIP("udp4", "8.8.8.8:53"); ok {
		addrs = append(addrs, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(32, 32)})
	}
	if ip, ok := outboundIP("udp6", "[2001:4860:4860::8888]:53"); ok {
		addrs = append(addrs, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(128, 128)})
	}
	if len(addrs) == 0 {
		return nil, errors.New("androidbin: no outbound routes found")
	}
	return []netmon.Interface{{
		Interface: &net.Interface{
			MTU:   1500, // TODO: getsockopt IP_MTU_* to discover it if it ever matters
			Name:  "android",
			Flags: net.FlagUp | net.FlagRunning,
		},
		AltAddrs: addrs,
	}}, nil
}

// outboundIP reports the local source address the kernel picks for an
// outbound socket to addr. Dialing UDP performs no I/O, so this works
// under Android's app sandbox where interface enumeration does not.
func outboundIP(network, addr string) (netip.Addr, bool) {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial(network, addr)
	if err != nil {
		return netip.Addr{}, false
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return netip.Addr{}, false
	}
	return ip, true
}

// onAndroid reports whether the process is running on Android, even
// if it's a GOOS=linux binary running under an Android kernel. For
// that case it checks for /dev/__properties__, the bionic property
// service's backing store, which has existed on every Android version
// since 5.0, is stat-able by all processes because every app's libc
// reads properties, and is never present on regular Linux systems.
func onAndroid() bool {
	if runtime.GOOS == "android" {
		return true
	}
	_, err := os.Stat("/dev/__properties__")
	return err == nil
}
