// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

// Package icmplistener implements a net.ListenConfig interface that overrides
// the handling of "ip:icmp" and "ip6:icmp" networks to use datagram sockets
// instead of raw sockets.
//
// In the 2000s the prevalence of ICMP based internet attacks led to broad
// consensus that raw sockets must be highly priveleged, causing all ICMP to
// become unavailable to unprivileged processes. In more recent years, standing
// concerns about extending privelege to keep `ping` working have lead to a new
// emerging consensus that ICMP Echo specifically should be allowed, and the
// mechanism for doing so is to send ICMP Echo packets via a SOCK_DGRAM socket
// type.
//
// This behavior is implemented by macOS and Linux (in Linux this is contingent
// on `net.ipv4.ping_group_range` covering the users range, which it typically
// does).
//
// The Go net abstraction does not directly lend itself to this kind of
// reimplementation, as such some edge case behaviors may differ in deliberately
// undocumented ways. Those behaviors may later change to fit intended use cases
// (initially sending ICMP Echo from userspace).
package icmplistener

import (
	"context"
	"net"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
)

type ListenConfig struct {
	net.ListenConfig
}

func (lc *ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	switch network {
	case "ip:icmp", "ip6:icmp", "ip4:icmp", "ip6:icmp-ipv6":
		return lc.listenICMP(ctx, network, address)
	default:
		return lc.ListenConfig.ListenPacket(ctx, network, address)
	}
}

func (lc *ListenConfig) listenICMP(ctx context.Context, network, address string) (net.PacketConn, error) {
	// If running as root, just fall back to the default behavior as SOCK_RAW
	// should be available.
	if os.Geteuid() == 0 {
		return lc.ListenConfig.ListenPacket(ctx, network, address)
	}

	af := unix.AF_INET6
	pr := unix.IPPROTO_ICMPV6
	switch network {
	case "ip:icmp", "ip4:icmp":
		af = unix.AF_INET
		pr = unix.IPPROTO_ICMP
	case "ip6:icmp", "ip6:icmp-ipv6":
	default:
		// TODO: perhaps one day reimplement the full secret "favorite family"
		// behavior from the stdlib.

		// TODO: resolve, too
		addr, err := netip.ParseAddr(address)
		if err != nil {
			// TODO: appropriate error type
			return nil, err
		}
		if addr.Is4() {
			af = unix.AF_INET
			pr = unix.IPPROTO_ICMP
		}
	}

	// technically the dup'd fd will get upgraded to nonblock and cloexec, but
	// the behaviors and side effects are not entirely documented (and cloexec
	// correctness in concurrent runtimes is very very complicated, especially
	// if we're in a cgo program).
	fd, err := unix.Socket(af, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, pr)
	if err != nil {
		// TODO: convert to net error
		return nil, os.NewSyscallError("socket", err)
	}
	// close after the filepacketconn performs the dupfd
	defer unix.Close(fd)

	// TODO: handle configuration correctly:
	if af == unix.AF_INET6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
			// TODO: convert to net error
			return nil, err
		}
	}

	f := os.NewFile(uintptr(fd), address)
	if lc.Control != nil {
		rc, err := f.SyscallConn()
		// TODO: convert to net error
		if err != nil {
			return nil, err
		}
		lc.Control(network, address, rc)
	}

	if af == unix.AF_INET6 {
		err = unix.Bind(fd, &unix.SockaddrInet6{Port: 0})
	} else {
		err = unix.Bind(fd, &unix.SockaddrInet4{Port: 0})
	}
	if err != nil {
		// TODO: convert to net error
		return nil, err
	}

	return net.FilePacketConn(f)
}
