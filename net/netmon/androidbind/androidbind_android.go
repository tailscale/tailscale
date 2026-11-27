// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package androidbind

/*
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
*/
import "C"

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"tailscale.com/net/netmon"
)

func init() {
	netmon.RegisterInterfaceGetter(androidInterfaces)
}

// androidInterfaces returns the host's network interfaces. Tries Go
// stdlib first so older Androids (or non-untrusted_app contexts where
// netlink is permitted) take the faster path. On EACCES falls through
// to libc getifaddrs, which is SELinux-safe for untrusted_app.
func androidInterfaces() ([]netmon.Interface, error) {
	if ifs, err := net.Interfaces(); err == nil && len(ifs) > 0 {
		out := make([]netmon.Interface, len(ifs))
		for i := range ifs {
			out[i].Interface = &ifs[i]
			// Interface.Addrs() also uses netlink on Linux; source
			// the addresses from getifaddrs too so the returned
			// entries are complete regardless of stdlib behaviour.
			out[i].AltAddrs, _ = getifaddrsAddrs(ifs[i].Name)
		}
		return out, nil
	}
	return getifaddrsInterfaces()
}

// ifaceInfo groups getifaddrs entries by interface name. getifaddrs
// emits one struct per (interface, address) pair; we need one
// netmon.Interface per interface with its addresses collected.
type ifaceInfo struct {
	name  string
	flags net.Flags
	addrs []net.Addr
}

// getifaddrsInterfaces enumerates interfaces via libc getifaddrs(3).
// On Android bionic this is ioctl(SIOCGIFCONF) on a UDP socket — a
// syscall permitted for untrusted_app.
func getifaddrsInterfaces() ([]netmon.Interface, error) {
	var head *C.struct_ifaddrs
	if rc, err := C.getifaddrs(&head); rc != 0 {
		return nil, fmt.Errorf("getifaddrs: %w", err)
	}
	defer C.freeifaddrs(head)

	byName := map[string]*ifaceInfo{}
	for ifa := head; ifa != nil; ifa = ifa.ifa_next {
		name := C.GoString(ifa.ifa_name)
		info := byName[name]
		if info == nil {
			info = &ifaceInfo{
				name:  name,
				flags: translateFlags(uint32(ifa.ifa_flags)),
			}
			byName[name] = info
		}
		if addr := sockaddrToAddr(ifa.ifa_addr, ifa.ifa_netmask); addr != nil {
			info.addrs = append(info.addrs, addr)
		}
	}

	out := make([]netmon.Interface, 0, len(byName))
	for _, info := range byName {
		ni := &net.Interface{
			Name:  info.name,
			Flags: info.flags,
		}
		out = append(out, netmon.Interface{
			Interface: ni,
			AltAddrs:  info.addrs,
		})
	}
	return out, nil
}

// getifaddrsAddrs returns just the address list for a named interface,
// for use alongside a Go stdlib net.Interface whose Addrs() may itself
// go through netlink.
func getifaddrsAddrs(name string) ([]net.Addr, error) {
	var head *C.struct_ifaddrs
	if rc, err := C.getifaddrs(&head); rc != 0 {
		return nil, fmt.Errorf("getifaddrs: %w", err)
	}
	defer C.freeifaddrs(head)
	var addrs []net.Addr
	for ifa := head; ifa != nil; ifa = ifa.ifa_next {
		if C.GoString(ifa.ifa_name) != name {
			continue
		}
		if a := sockaddrToAddr(ifa.ifa_addr, ifa.ifa_netmask); a != nil {
			addrs = append(addrs, a)
		}
	}
	return addrs, nil
}

// translateFlags maps Linux IFF_* into Go's net.Flags, covering the
// bits [netmon.Interface] readers check.
func translateFlags(f uint32) net.Flags {
	var out net.Flags
	if f&C.IFF_UP != 0 {
		out |= net.FlagUp
	}
	if f&C.IFF_BROADCAST != 0 {
		out |= net.FlagBroadcast
	}
	if f&C.IFF_LOOPBACK != 0 {
		out |= net.FlagLoopback
	}
	if f&C.IFF_POINTOPOINT != 0 {
		out |= net.FlagPointToPoint
	}
	if f&C.IFF_MULTICAST != 0 {
		out |= net.FlagMulticast
	}
	if f&C.IFF_RUNNING != 0 {
		out |= net.FlagRunning
	}
	return out
}

// sockaddrToAddr converts a C sockaddr (IPv4 or IPv6) + netmask into
// a *net.IPNet. Returns nil for address families we don't care about
// (AF_PACKET link-layer addresses, etc).
func sockaddrToAddr(sa, nm *C.struct_sockaddr) net.Addr {
	if sa == nil {
		return nil
	}
	switch sa.sa_family {
	case C.AF_INET:
		sin := (*C.struct_sockaddr_in)(unsafe.Pointer(sa))
		addr := (*[4]byte)(unsafe.Pointer(&sin.sin_addr))[:]
		ip := netip.AddrFrom4(*(*[4]byte)(addr))
		prefix := 32
		if nm != nil && nm.sa_family == C.AF_INET {
			mask := (*C.struct_sockaddr_in)(unsafe.Pointer(nm))
			maskBytes := (*[4]byte)(unsafe.Pointer(&mask.sin_addr))[:]
			prefix = countLeadingOnes(maskBytes)
		}
		return &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(prefix, 32)}
	case C.AF_INET6:
		sin := (*C.struct_sockaddr_in6)(unsafe.Pointer(sa))
		addrBytes := (*[16]byte)(unsafe.Pointer(&sin.sin6_addr))[:]
		ip := netip.AddrFrom16(*(*[16]byte)(addrBytes))
		prefix := 128
		if nm != nil && nm.sa_family == C.AF_INET6 {
			mask := (*C.struct_sockaddr_in6)(unsafe.Pointer(nm))
			maskBytes := (*[16]byte)(unsafe.Pointer(&mask.sin6_addr))[:]
			prefix = countLeadingOnes(maskBytes)
		}
		return &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(prefix, 128)}
	}
	return nil
}

// countLeadingOnes returns the prefix length represented by a netmask
// byte slice. Valid netmasks are a run of 1-bits followed by 0-bits;
// the count stops at the first 0 in the first non-0xff byte.
func countLeadingOnes(mask []byte) int {
	ones := 0
	for _, b := range mask {
		if b == 0xff {
			ones += 8
			continue
		}
		for b&0x80 != 0 {
			ones++
			b <<= 1
		}
		break
	}
	return ones
}
