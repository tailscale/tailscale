// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/cpu"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/tsconst"
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

func defaultInterfaceIndex(family winipcfg.AddressFamily) (uint32, error) {
	iface, err := netmon.GetWindowsDefault(family)
	if err != nil {
		return 0, err
	}

	return interfaceIndex(iface), nil
}

func control(logf logger.Logf, _ *netmon.Monitor) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return controlC(logf, network, address, c)
	}
}

var bindToInterfaceByRouteEnv = envknob.RegisterBool("TS_BIND_TO_INTERFACE_BY_ROUTE")

// controlC binds c to the Windows interface that holds a default
// route, and is not the Tailscale WinTun interface.
func controlC(logf logger.Logf, network, address string, c syscall.RawConn) (err error) {
	if isLocalhost(address) {
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

	var defIfaceIdxV4, defIfaceIdxV6 uint32
	if canV4 {
		defIfaceIdxV4, err = defaultInterfaceIndex(windows.AF_INET)
		if err != nil {
			return fmt.Errorf("defaultInterfaceIndex(AF_INET): %w", err)
		}
	}

	if canV6 {
		defIfaceIdxV6, err = defaultInterfaceIndex(windows.AF_INET6)
		if err != nil {
			return fmt.Errorf("defaultInterfaceIndex(AF_INET6): %w", err)
		}
	}

	var ifaceIdxV4, ifaceIdxV6 uint32
	if useRoute := bindToInterfaceByRoute.Load() || bindToInterfaceByRouteEnv(); useRoute {
		addr, err := parseAddress(address)
		if err == nil {
			if canV4 && (addr.Is4() || addr.Is4In6()) {
				addrV4 := addr.Unmap()
				ifaceIdxV4, err = getInterfaceIndex(logf, addrV4, defIfaceIdxV4)
				if err != nil {
					return fmt.Errorf("getInterfaceIndex(%v): %w", addrV4, err)
				}
			}

			if canV6 && addr.Is6() {
				ifaceIdxV6, err = getInterfaceIndex(logf, addr, defIfaceIdxV6)
				if err != nil {
					return fmt.Errorf("getInterfaceIndex(%v): %w", addr, err)
				}
			}
		} else {
			if err != errUnspecifiedHost {
				logf("[unexpected] netns: error parsing address %q: %v", address, err)
			}
			ifaceIdxV4, ifaceIdxV6 = defIfaceIdxV4, defIfaceIdxV6
		}
	} else {
		ifaceIdxV4, ifaceIdxV6 = defIfaceIdxV4, defIfaceIdxV6
	}

	if canV4 {
		if err := bindSocket4(c, ifaceIdxV4); err != nil {
			return fmt.Errorf("bindSocket4(%d): %w", ifaceIdxV4, err)
		}
	}

	if canV6 {
		if err := bindSocket6(c, ifaceIdxV6); err != nil {
			return fmt.Errorf("bindSocket6(%d): %w", ifaceIdxV6, err)
		}
	}

	return nil
}

func getInterfaceIndex(logf logger.Logf, addr netip.Addr, defaultIdx uint32) (idx uint32, err error) {
	idx, err = interfaceIndexFor(addr)
	if err != nil {
		return defaultIdx, fmt.Errorf("interfaceIndexFor: %w", err)
	}

	isTS, err := isTailscaleInterface(idx)
	if err != nil {
		return defaultIdx, fmt.Errorf("isTailscaleInterface: %w", err)
	}
	if isTS {
		return defaultIdx, nil
	}
	return idx, nil
}

func isTailscaleInterface(ifaceIdx uint32) (bool, error) {
	ifaceLUID, err := winipcfg.LUIDFromIndex(ifaceIdx)
	if err != nil {
		return false, err
	}

	iface, err := ifaceLUID.Interface()
	if err != nil {
		return false, err
	}

	result := iface.Type == winipcfg.IfTypePropVirtual &&
		strings.Contains(iface.Description(), tsconst.WintunInterfaceDesc)
	return result, nil
}

func interfaceIndexFor(addr netip.Addr) (uint32, error) {
	var sockaddr winipcfg.RawSockaddrInet
	if err := sockaddr.SetAddr(addr); err != nil {
		return 0, err
	}

	var idx uint32
	if err := getBestInterfaceEx(&sockaddr, &idx); err != nil {
		return 0, err
	}

	return idx, nil
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
