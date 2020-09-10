// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netns

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"github.com/tailscale/winipcfg-go"
	"golang.org/x/sys/windows"
	"tailscale.com/net/interfaces"
)

// control binds c to the Windows interface that holds a default
// route, and is not the Tailscale WinTun interface.
func control(network, address string, c syscall.RawConn) error {
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
		if4, err := getDefaultInterface(winipcfg.AF_INET)
		if err != nil {
			return err
		}
		if err := bindSocket4(c, if4); err != nil {
			return err
		}
	}

	if canV6 {
		if6, err := getDefaultInterface(winipcfg.AF_INET6)
		if err != nil {
			return err
		}
		if err := bindSocket6(c, if6); err != nil {
			return err
		}
	}

	return nil
}

// getDefaultInterface returns the index of the interface that has the
// non-Tailscale default route for the given address family.
func getDefaultInterface(family winipcfg.AddressFamily) (ifidx uint32, err error) {
	ifs, err := interfaces.NonTailscaleMTUs()
	if err != nil {
		return 0, err
	}

	routes, err := winipcfg.GetRoutes(family)
	if err != nil {
		return 0, err
	}

	bestMetric := ^uint32(0)
	// The zero index means "unspecified". If we end up passing zero
	// to bindSocket*(), it unsets the binding and lets the socket
	// behave as normal again, which is what we want if there's no
	// default route we can use.
	var index uint32
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 || ifs[route.InterfaceLuid] == 0 {
			continue
		}
		if route.Metric < bestMetric {
			bestMetric = route.Metric
			index = route.InterfaceIndex
		}
	}

	return index, nil
}

const sockoptBoundInterface = 31

// bindSocket4 binds the given RawConn to the network interface with
// index ifidx, for IPv4 traffic only.
func bindSocket4(c syscall.RawConn, ifidx uint32) error {
	// For v4 the interface index must be passed as a big-endian
	// integer, regardless of platform endianness.
	index := nativeToBigEndian(ifidx)
	var controlErr error
	err := c.Control(func(fd uintptr) {
		controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, sockoptBoundInterface, int(index))
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
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}
