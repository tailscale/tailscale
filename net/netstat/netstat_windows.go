// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netstat returns the local machine's network connection table.
package netstat

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/net/netaddr"
	"tailscale.com/util/endian"
)

// See https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable

// TCP_TABLE_OWNER_PID_ALL means to include the PID info. The table type
// we get back from Windows depends on AF_INET vs AF_INET6:
// MIB_TCPTABLE_OWNER_PID for v4 or MIB_TCP6TABLE_OWNER_PID for v6.
const tcpTableOwnerPidAll = 5

var (
	iphlpapi    = syscall.NewLazyDLL("iphlpapi.dll")
	getTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	// TODO: GetExtendedUdpTable also? if/when needed.
)

type _MIB_TCPROW_OWNER_PID struct {
	state      uint32
	localAddr  uint32
	localPort  uint32
	remoteAddr uint32
	remotePort uint32
	pid        uint32
}

type _MIB_TCP6ROW_OWNER_PID struct {
	localAddr   [16]byte
	localScope  uint32
	localPort   uint32
	remoteAddr  [16]byte
	remoteScope uint32
	remotePort  uint32
	state       uint32
	pid         uint32
}

func get() (*Table, error) {
	t := new(Table)
	if err := t.addEntries(windows.AF_INET); err != nil {
		return nil, fmt.Errorf("failed to get IPv4 entries: %w", err)
	}
	if err := t.addEntries(windows.AF_INET6); err != nil {
		return nil, fmt.Errorf("failed to get IPv6 entries: %w", err)
	}
	return t, nil
}

func (t *Table) addEntries(fam int) error {
	var size uint32
	var addr unsafe.Pointer
	var buf []byte
	for {
		err, _, _ := getTCPTable.Call(
			uintptr(addr),
			uintptr(unsafe.Pointer(&size)),
			1, // sorted
			uintptr(fam),
			tcpTableOwnerPidAll,
			0, // reserved; "must be zero"
		)
		if err == 0 {
			break
		}
		if err == uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			const maxSize = 10 << 20
			if size > maxSize || size < 4 {
				return fmt.Errorf("unreasonable kernel-reported size %d", size)
			}
			buf = make([]byte, size)
			addr = unsafe.Pointer(&buf[0])
			continue
		}
		return syscall.Errno(err)
	}
	if len(buf) < int(size) {
		return errors.New("unexpected size growth from system call")
	}
	buf = buf[:size]

	numEntries := endian.Native.Uint32(buf[:4])
	buf = buf[4:]

	var recSize int
	switch fam {
	case windows.AF_INET:
		recSize = 6 * 4
	case windows.AF_INET6:
		recSize = 6*4 + 16*2
	}
	dataLen := numEntries * uint32(recSize)
	if uint32(len(buf)) > dataLen {
		buf = buf[:dataLen]
	}
	for len(buf) >= recSize {
		switch fam {
		case windows.AF_INET:
			row := (*_MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[0]))
			t.Entries = append(t.Entries, Entry{
				Local:  ipport4(row.localAddr, port(&row.localPort)),
				Remote: ipport4(row.remoteAddr, port(&row.remotePort)),
				Pid:    int(row.pid),
				State:  state(row.state),
			})
		case windows.AF_INET6:
			row := (*_MIB_TCP6ROW_OWNER_PID)(unsafe.Pointer(&buf[0]))
			t.Entries = append(t.Entries, Entry{
				Local:  ipport6(row.localAddr, row.localScope, port(&row.localPort)),
				Remote: ipport6(row.remoteAddr, row.remoteScope, port(&row.remotePort)),
				Pid:    int(row.pid),
				State:  state(row.state),
			})
		}
		buf = buf[recSize:]
	}
	return nil
}

var states = []string{
	"",
	"CLOSED",
	"LISTEN",
	"SYN-SENT",
	"SYN-RECEIVED",
	"ESTABLISHED",
	"FIN-WAIT-1",
	"FIN-WAIT-2",
	"CLOSE-WAIT",
	"CLOSING",
	"LAST-ACK",
	"DELETE-TCB",
}

func state(v uint32) string {
	if v < uint32(len(states)) {
		return states[v]
	}
	return fmt.Sprintf("unknown-state-%d", v)
}

func ipport4(addr uint32, port uint16) netip.AddrPort {
	if !endian.Big {
		addr = bits.ReverseBytes32(addr)
	}
	return netip.AddrPortFrom(
		netaddr.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)),
		port)
}

func ipport6(addr [16]byte, scope uint32, port uint16) netip.AddrPort {
	ip := netip.AddrFrom16(addr).Unmap()
	if scope != 0 {
		// TODO: something better here?
		ip = ip.WithZone(fmt.Sprint(scope))
	}
	return netip.AddrPortFrom(ip, port)
}

func port(v *uint32) uint16 {
	if !endian.Big {
		return uint16(bits.ReverseBytes32(*v) >> 16)
	}
	return uint16(*v >> 16)
}
