// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netns

import (
	"encoding/binary"
	"log"
	"syscall"
	"unsafe"

	"github.com/tailscale/winipcfg-go"
	"golang.org/x/sys/windows"
)

// control binds c to the Windows interface that holds a default
// route, and is not the Tailscale WinTun interface.
func control(network, address string, c syscall.RawConn) error {
	if4, err := getDefaultInterface(winipcfg.AF_INET)
	if err != nil {
		return err
	}
	if err := bindSocket4(c, if4); err != nil {
		return err
	}

	if6, err := getDefaultInterface(winipcfg.AF_INET6)
	if err != nil {
		return err
	}
	if err := bindSocket6(c, if6); err != nil {
		return err
	}

	log.Printf("WINDOWS DIAL %s %s, v4=%s v6=%s", network, address, if4, if6)

	return nil
}

// getDefaultInterface returns the index of the interface that has the
// non-Tailscale default route for the given address family.
func getDefaultInterface(family winipcfg.AddressFamily) (ifidx uint32, err error) {
	ifs, err := winipcfg.GetInterfaces()
	if err != nil {
		return 0, err
	}
	var tsLUIDs []uint64
	for _, iface := range ifs {
		if iface.Description == "Tailscale Tunnel" {
			tsLUIDs = append(tsLUIDs, iface.Luid)
		}
	}

	routes, err := winipcfg.GetRoutes(family)
	if err != nil {
		return 0, err
	}

	bestMetric := ^uint32(0)
	// Zero is "unspecified". If we end up passing zero to
	// bindSocket*(), it unsets the binding and lets the socket behave
	// as normal again, which is what we want if there's no default
	// route we can use.
	var index uint32
findDefaultRoute:
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		for _, ourLUID := range tsLUIDs {
			if ourLUID == route.InterfaceLuid {
				continue findDefaultRoute
			}
		}
		if route.Metric < bestMetric {
			bestMetric = route.Metric
			index = route.InterfaceIndex
		}
	}

	return index, nil
}

// bindSocket4 binds the given RawConn to the network interface with
// index ifidx, for IPv4 traffic only.
func bindSocket4(c syscall.RawConn, ifidx uint32) error {
	// For v4 the interface index must be passed as a big-endian
	// integer, regardless of platform endianness.
	index := nativeToBigEndian(ifidx)
	var controlErr error
	err := c.Control(func(fd uintptr) {
		controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(index))
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
		controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, int(ifidx))
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
