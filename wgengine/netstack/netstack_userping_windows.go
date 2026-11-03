// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package netstack

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows native ICMP relay via iphlpapi.dll — replaces the locale-dependent
// ping.exe output parsing (windowsPingOutputIsSuccess) that broke ICMP
// subnet-route relaying on non-English Windows systems.
//
// Upstream tracking:
//   - https://github.com/tailscale/tailscale/issues/18852
//   - https://github.com/tailscale/tailscale/pull/19013
//
// Implements upstream TODO in netstack.go:
//   // TODO(bradfitz,nickkhyl): delete this and use the proper Windows APIs.
//
// Struct layouts follow Cloudflare cloudflared ingress/icmp_windows.go
// (BSD-3-Clause) and Microsoft Windows SDK ipexport.h.

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	icmpCreateFileProc  = iphlpapi.NewProc("IcmpCreateFile")
	icmpCloseHandleProc = iphlpapi.NewProc("IcmpCloseHandle")
	icmpSendEchoProc    = iphlpapi.NewProc("IcmpSendEcho")
	icmp6CreateFileProc = iphlpapi.NewProc("Icmp6CreateFile")
	icmp6SendEcho2Proc  = iphlpapi.NewProc("Icmp6SendEcho2")
)

const (
	afInet6               = 23
	ipSuccess             = 0
	ipReqTimedOut         = 11010
	icmpRequestTimeoutMs  = 3000
	ioStatusBlockSize     = 2 * unsafe.Sizeof(uintptr(0))
	icmpv6ErrMessageSize  = 8
)

// icmpEchoReply maps ICMP_ECHO_REPLY (ipexport.h) on x64.
type icmpEchoReply struct {
	Address       uint32 // in_addr
	Status        uint32 // IPStatus
	RoundTripTime uint32 // ms
	DataSize      uint16
	Reserved      uint16
	DataPointer   uintptr // void* (8 bytes on x64)
	Options       icmpReplyOptions
}

type icmpReplyOptions struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// sockaddrIn6 mirrors sockaddr_in6 in ws2def.h.
type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	FlowInfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// ipv6AddrEx mirrors IPV6_ADDRESS_EX in ipexport.h.
type ipv6AddrEx struct {
	Port     uint16
	_        uint16 // 2 bytes padding for 4-byte alignment of FlowInfo
	FlowInfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// icmpv6EchoReply maps ICMPV6_ECHO_REPLY in ipexport.h.
type icmpv6EchoReply struct {
	Address       ipv6AddrEx
	Status        uint32
	RoundTripTime uint32
}

var (
	icmpMu    sync.Mutex
	icmp4Hnd  uintptr
	icmp4Init bool
	icmp6Hnd  uintptr
	icmp6Init bool
)

func getIcmp4Handle() (uintptr, error) {
	if icmp4Init {
		return icmp4Hnd, nil
	}
	h, _, err := icmpCreateFileProc.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, fmt.Errorf("IcmpCreateFile: %v", err)
	}
	icmp4Hnd, icmp4Init = h, true
	return h, nil
}

func getIcmp6Handle() (uintptr, error) {
	if icmp6Init {
		return icmp6Hnd, nil
	}
	h, _, err := icmp6CreateFileProc.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, fmt.Errorf("Icmp6CreateFile: %v", err)
	}
	icmp6Hnd, icmp6Init = h, true
	return h, nil
}

// userPingViaAPI sends an ICMP echo request to dstIP via Win32 API.
// Completely locale-independent (supports Chinese, English, etc.).
func userPingViaAPI(dstIP netip.Addr, timeout time.Duration) error {
	if dstIP.Is4() {
		return userPing4(dstIP, timeout)
	}
	if dstIP.Is6() {
		return userPing6(dstIP, timeout)
	}
	return fmt.Errorf("unsupported address: %v", dstIP)
}

func userPing4(dstIP netip.Addr, timeout time.Duration) error {
	icmpMu.Lock()
	defer icmpMu.Unlock()

	h, err := getIcmp4Handle()
	if err != nil {
		return err
	}

	// On little-endian Windows x86/x64, loading netip.Addr.As4() bytes
	// via LittleEndian produces the in_addr integer expected by IcmpSendEcho.
	v4 := dstIP.As4()
	dstAddr := binary.LittleEndian.Uint32(v4[:])

	data := []byte("tailscale-icmp4")
	replySize := int(unsafe.Sizeof(icmpEchoReply{})) + len(data) + 16
	replyBuf := make([]byte, replySize)

	timeoutMs := timeout.Milliseconds()
	if timeoutMs <= 0 {
		timeoutMs = icmpRequestTimeoutMs
	}

	ret, _, errSys := icmpSendEchoProc.Call(
		h,
		uintptr(dstAddr),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0, // pOptions = nil
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replySize),
		uintptr(timeoutMs),
	)
	if ret > 0 {
		return nil
	}

	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status == ipReqTimedOut {
		return fmt.Errorf("icmp echo to %v: request timed out", dstIP)
	}
	return fmt.Errorf("icmp echo to %v: status %d (%v)", dstIP, reply.Status, errSys)
}

func userPing6(dstIP netip.Addr, timeout time.Duration) error {
	icmpMu.Lock()
	defer icmpMu.Unlock()

	h, err := getIcmp6Handle()
	if err != nil {
		return err
	}

	var src sockaddrIn6
	src.Family = afInet6

	var dst sockaddrIn6
	dst.Family = afInet6
	v6 := dstIP.As16()
	copy(dst.Addr[:], v6[:])

	data := []byte("tailscale-icmp6")
	replySize := int(unsafe.Sizeof(icmpv6EchoReply{})) + len(data) + icmpv6ErrMessageSize + int(ioStatusBlockSize) + 32
	replyBuf := make([]byte, replySize)

	timeoutMs := timeout.Milliseconds()
	if timeoutMs <= 0 {
		timeoutMs = icmpRequestTimeoutMs
	}

	ret, _, errSys := icmp6SendEcho2Proc.Call(
		h,
		0, // Event = nil
		0, // ApcRoutine = nil
		0, // ApcContext = nil
		uintptr(unsafe.Pointer(&src)),
		uintptr(unsafe.Pointer(&dst)),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0, // RequestOptions = nil
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replySize),
		uintptr(timeoutMs),
	)
	if ret > 0 {
		return nil
	}

	reply := (*icmpv6EchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status == ipReqTimedOut {
		return fmt.Errorf("icmp6 echo to %v: request timed out", dstIP)
	}
	return fmt.Errorf("icmp6 echo to %v: status %d (%v)", dstIP, reply.Status, errSys)
}
