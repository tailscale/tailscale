// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

// rawSockaddr is a union that contains an IPv4, an IPv6 address, or an address family.
type rawSockaddr struct {
	windows.RawSockaddrInet
}

func rawSockaddrFromAddrPort(ap netip.AddrPort) (rsa rawSockaddr, err error) {
	switch addr := ap.Addr(); {
	case addr.Is4():
		pp := (*windows.RawSockaddrInet4)(unsafe.Pointer(&rsa))
		pp.Family = windows.AF_INET
		pp.Port = htons(ap.Port())
		pp.Addr = addr.As4()
	case addr.Is6():
		pp := (*windows.RawSockaddrInet6)(unsafe.Pointer(&rsa))
		pp.Family = windows.AF_INET6
		pp.Port = htons(ap.Port())
		pp.Addr = addr.As16()
		if zone := addr.Zone(); zone != "" {
			if pp.Scope_id, err = interfaceIndexFromZone(zone); err != nil {
				return rawSockaddr{}, err
			}
		}
	default:
		return rawSockaddr{}, fmt.Errorf("invalid IP address: %v", addr)
	}
	return rsa, nil
}

func interfaceIndexFromZone(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	iface, err := net.InterfaceByName(zone)
	if err == nil {
		return uint32(iface.Index), nil
	}
	if ifi, err := strconv.Atoi(zone); err == nil {
		return uint32(ifi), nil
	}
	return 0, fmt.Errorf("invalid IPv6 zone %q: %w", zone, err)
}

// Family returns the address family of the receiver.
func (rsa rawSockaddr) Family() uint16 {
	return rsa.RawSockaddrInet.Family
}

// Is4In6 reports whether the address is an IPv4-mapped IPv6 address.
func (rsa rawSockaddr) Is4In6() bool {
	if rsa.Family() != windows.AF_INET6 {
		return false
	}
	pp := (*windows.RawSockaddrInet6)(unsafe.Pointer(&rsa))
	hi := binary.BigEndian.Uint64(pp.Addr[0:8])
	lo := binary.BigEndian.Uint64(pp.Addr[8:16])
	return hi == 0 && lo>>32 == 0xffff
}

// Sockaddr returns a [windows.Sockaddr] representation of the receiver.
func (rsa rawSockaddr) Sockaddr() (windows.Sockaddr, error) {
	switch rsa.Family() {
	case windows.AF_INET:
		pp := (*windows.RawSockaddrInet4)(unsafe.Pointer(&rsa))
		return &windows.SockaddrInet4{
			Port: int(ntohs(pp.Port)),
			Addr: pp.Addr,
		}, nil
	case windows.AF_INET6:
		pp := (*windows.RawSockaddrInet6)(unsafe.Pointer(&rsa))
		return &windows.SockaddrInet6{
			Port:   int(ntohs(pp.Port)),
			ZoneId: pp.Scope_id,
			Addr:   pp.Addr,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported sockaddr family: %d", rsa.Family())
	}
}

// ToAddrPort returns a [netip.AddrPort] representation of the receiver.
func (rsa rawSockaddr) ToAddrPort() (netip.AddrPort, error) {
	switch rsa.Family() {
	case windows.AF_INET:
		pp := (*windows.RawSockaddrInet4)(unsafe.Pointer(&rsa))
		return netip.AddrPortFrom(netip.AddrFrom4(pp.Addr), ntohs(pp.Port)), nil
	case windows.AF_INET6:
		pp := (*windows.RawSockaddrInet6)(unsafe.Pointer(&rsa))
		addr := netip.AddrFrom16(pp.Addr)
		if pp.Scope_id != 0 {
			ifi, err := net.InterfaceByIndex(int(pp.Scope_id))
			if err != nil {
				return netip.AddrPort{}, fmt.Errorf("invalid IPv6 zone id %d: %w", pp.Scope_id, err)
			}
			addr = addr.WithZone(ifi.Name)
		}
		return netip.AddrPortFrom(addr, ntohs(pp.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("invalid sockaddr family: %v", rsa.Family())
	}
}

func addrPortFromSocket(socket windows.Handle) (netip.AddrPort, error) {
	sa, err := windows.Getsockname(socket)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return addrPortFromSockaddr(sa)
}

func addrPortFromSockaddr(sa windows.Sockaddr) (netip.AddrPort, error) {
	switch sa := sa.(type) {
	case *windows.SockaddrInet4:
		if sa.Port < 0 || sa.Port > 0xffff {
			return netip.AddrPort{}, fmt.Errorf("invalid port %d", sa.Port)
		}
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port)), nil
	case *windows.SockaddrInet6:
		if sa.Port < 0 || sa.Port > 0xffff {
			return netip.AddrPort{}, fmt.Errorf("invalid port %d", sa.Port)
		}
		addr := netip.AddrFrom16(sa.Addr)
		if sa.ZoneId != 0 {
			ifi, err := net.InterfaceByIndex(int(sa.ZoneId))
			if err != nil {
				return netip.AddrPort{}, fmt.Errorf("invalid IPv6 zone id %d: %w", sa.ZoneId, err)
			}
			addr = addr.WithZone(ifi.Name)
		}
		return netip.AddrPortFrom(addr, uint16(sa.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("invalid sockaddr type: %T", sa)
	}
}

func sockaddrFromAddrPort(addr netip.AddrPort) (sa windows.Sockaddr, family int32, err error) {
	rsa, err := rawSockaddrFromAddrPort(addr)
	if err != nil {
		return nil, 0, err
	}
	if sa, err = rsa.Sockaddr(); err != nil {
		return nil, 0, err
	}
	return sa, int32(rsa.Family()), nil
}

func netAddrFromAddrPort(addr netip.AddrPort, sotype int32) (net.Addr, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("invalid address: %v", addr)
	}
	switch sotype {
	case windows.SOCK_STREAM:
		return net.TCPAddrFromAddrPort(addr), nil
	case windows.SOCK_DGRAM:
		return net.UDPAddrFromAddrPort(addr), nil
	}
	return nil, fmt.Errorf("unsupported socket type: %d", sotype)
}

func networkName(sotype int32, proto int32, family int32, dualStack bool) (string, error) {
	net := ""
	switch {
	case sotype == windows.SOCK_DGRAM && proto == windows.IPPROTO_UDP:
		net = "udp"
	case sotype == windows.SOCK_STREAM && proto == windows.IPPROTO_TCP:
		net = "tcp"
	}
	if net != "" {
		switch {
		case family == windows.AF_INET:
			return net + "4", nil
		case family == windows.AF_INET6:
			if dualStack {
				return net, nil
			}
			return net + "6", nil
		}
	}
	return "", fmt.Errorf("unsupported socket options: family=%d, type=%d, proto=%d, dualStack=%v",
		family, sotype, proto, dualStack,
	)
}

// Windows is always little-endian.

func htons(p uint16) uint16 {
	return (p<<8)&0xff00 | p>>8
}

func ntohs(p uint16) uint16 {
	return (p<<8)&0xff00 | p>>8
}
