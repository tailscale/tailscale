// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"math/bits"
	"strings"
	"syscall"

	"golang.org/x/sys/cpu"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func interfaceIndex(iface *winipcfg.IPAdapterAddresses) uint32 {
	if iface == nil {
		// The zero ifidx means "unspecified". If we end up passing zero
		// to bindSocket*(), it unsets the binding and lets the socket
		// behave as normal again, which is what we want if there's no
		// default route we can use.
		return 0
	}
	return iface.IfIndex
}

func control(logger.Logf, *netmon.Monitor) func(network, address string, c syscall.RawConn) error {
	return controlC
}

// controlC binds c to the Windows interface that holds a default
// route, and is not the Tailscale WinTun interface.
func controlC(network, address string, c syscall.RawConn) error {
	if strings.HasPrefix(address, "127.") {
		// Don't bind to an interface for localhost connections,
		// otherwise we get:
		//   connectex: The requested address is not valid in its context
		// (The derphttp tests were failing)
		return nil
	}
	canV4, canV6 := false, false
	switch network {
	case "tcp", "udp":
		canV4, canV6 = true, true
	case "tcp4", "udp4":
		canV4 = true
	case "tcp6", "udp6":
		canV6 = true
	}

	if canV4 {
		iface, err := interfaces.GetWindowsDefault(windows.AF_INET)
		if err != nil {
			return err
		}
		if err := bindSocket4(c, interfaceIndex(iface)); err != nil {
			return err
		}
	}

	if canV6 {
		iface, err := interfaces.GetWindowsDefault(windows.AF_INET6)
		if err != nil {
			return err
		}
		if err := bindSocket6(c, interfaceIndex(iface)); err != nil {
			return err
		}
	}

	return nil
}

// sockoptBoundInterface is the value of IP_UNICAST_IF and IPV6_UNICAST_IF.
//
// See https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
// and https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
const sockoptBoundInterface = 31

// bindSocket4 binds the given RawConn to the network interface with
// index ifidx, for IPv4 traffic only.
func bindSocket4(c syscall.RawConn, ifidx uint32) error {
	// For IPv4 (but NOT IPv6) the interface index must be passed
	// as a big-endian integer (regardless of platform endianness)
	// because the underlying sockopt takes either an IPv4 address
	// or an index shoved into IPv4 address representation (an IP
	// in 0.0.0.0/8 means it's actually an index).
	//
	// See https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	// and IP_UNICAST_IF.
	indexAsAddr := nativeToBigEndian(ifidx)
	var controlErr error
	err := c.Control(func(fd uintptr) {
		controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, sockoptBoundInterface, int(indexAsAddr))
	})
	if err != nil {
		return err
	}
	return controlErr
}

// bindSocket6 binds the given RawConn to the network interface with
// index ifidx, for IPv6 traffic only.
func bindSocket6(c syscall.RawConn, ifidx uint32) error {
	var controlErr error
	err := c.Control(func(fd uintptr) {
		controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, sockoptBoundInterface, int(ifidx))
	})
	if err != nil {
		return err
	}
	return controlErr
}

// nativeToBigEndian returns i converted into big-endian
// representation, suitable for passing to Windows APIs that require a
// mangled uint32.
func nativeToBigEndian(i uint32) uint32 {
	if cpu.IsBigEndian {
		return i
	}
	return bits.ReverseBytes32(i)
}
