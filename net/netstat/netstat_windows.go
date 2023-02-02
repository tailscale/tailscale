// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netstat returns the local machine's network connection table.
package netstat

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/cpu"
	"golang.org/x/sys/windows"
	"tailscale.com/net/netaddr"
)

// OSMetadata includes any additional OS-specific information that may be
// obtained during the retrieval of a given Entry.
type OSMetadata interface {
	// GetModule returns the entry's module name.
	//
	// It returns ("", nil) if no entry is found. As of 2023-01-27, any returned
	// error is silently discarded by its sole caller in portlist_windows.go and
	// treated equivalently as returning ("", nil), but this may change in the
	// future. An error should only be returned in casees that are worthy of
	// being logged at least.
	GetModule() (string, error)
}

// See https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable

// TCP_TABLE_OWNER_MODULE_ALL means to include the PID and module. The table type
// we get back from Windows depends on AF_INET vs AF_INET6:
// MIB_TCPTABLE_OWNER_MODULE for v4 or MIB_TCP6TABLE_OWNER_MODULE for v6.
const tcpTableOwnerModuleAll = 8

// TCPIP_OWNER_MODULE_BASIC_INFO means to request "basic information" about the
// owner module.
const tcpipOwnerModuleBasicInfo = 0

var (
	iphlpapi                    = windows.NewLazySystemDLL("iphlpapi.dll")
	getTCPTable                 = iphlpapi.NewProc("GetExtendedTcpTable")
	getOwnerModuleFromTcpEntry  = iphlpapi.NewProc("GetOwnerModuleFromTcpEntry")
	getOwnerModuleFromTcp6Entry = iphlpapi.NewProc("GetOwnerModuleFromTcp6Entry")
	// TODO: GetExtendedUdpTable also? if/when needed.
)

// See https://web.archive.org/web/20221219211913/https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_module
type _MIB_TCPROW_OWNER_MODULE struct {
	state            uint32
	localAddr        uint32
	localPort        uint32
	remoteAddr       uint32
	remotePort       uint32
	pid              uint32
	createTimestamp  int64
	owningModuleInfo [16]uint64
}

func (row *_MIB_TCPROW_OWNER_MODULE) asEntry() Entry {
	return Entry{
		Local:      ipport4(row.localAddr, port(&row.localPort)),
		Remote:     ipport4(row.remoteAddr, port(&row.remotePort)),
		Pid:        int(row.pid),
		State:      state(row.state),
		OSMetadata: row,
	}
}

type _MIB_TCPTABLE_OWNER_MODULE struct {
	numEntries uint32
	table      _MIB_TCPROW_OWNER_MODULE
}

func (m *_MIB_TCPTABLE_OWNER_MODULE) getRows() []_MIB_TCPROW_OWNER_MODULE {
	return unsafe.Slice(&m.table, m.numEntries)
}

// See https://web.archive.org/web/20221219212442/https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcp6row_owner_module
type _MIB_TCP6ROW_OWNER_MODULE struct {
	localAddr        [16]byte
	localScope       uint32
	localPort        uint32
	remoteAddr       [16]byte
	remoteScope      uint32
	remotePort       uint32
	state            uint32
	pid              uint32
	createTimestamp  int64
	owningModuleInfo [16]uint64
}

func (row *_MIB_TCP6ROW_OWNER_MODULE) asEntry() Entry {
	return Entry{
		Local:      ipport6(row.localAddr, row.localScope, port(&row.localPort)),
		Remote:     ipport6(row.remoteAddr, row.remoteScope, port(&row.remotePort)),
		Pid:        int(row.pid),
		State:      state(row.state),
		OSMetadata: row,
	}
}

type _MIB_TCP6TABLE_OWNER_MODULE struct {
	numEntries uint32
	table      _MIB_TCP6ROW_OWNER_MODULE
}

func (m *_MIB_TCP6TABLE_OWNER_MODULE) getRows() []_MIB_TCP6ROW_OWNER_MODULE {
	return unsafe.Slice(&m.table, m.numEntries)
}

// See https://web.archive.org/web/20221219213143/https://learn.microsoft.com/en-us/windows/win32/api/iprtrmib/ns-iprtrmib-tcpip_owner_module_basic_info
type _TCPIP_OWNER_MODULE_BASIC_INFO struct {
	moduleName *uint16
	modulePath *uint16
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
			tcpTableOwnerModuleAll,
			0, // reserved; "must be zero"
		)
		if err == 0 {
			break
		}
		if err == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			const maxSize = 10 << 20
			if size > maxSize || size < 4 {
				return fmt.Errorf("unreasonable kernel-reported size %d", size)
			}
			buf = make([]byte, size)
			addr = unsafe.Pointer(&buf[0])
			continue
		}
		return windows.Errno(err)
	}
	if len(buf) < int(size) {
		return errors.New("unexpected size growth from system call")
	}
	buf = buf[:size]

	switch fam {
	case windows.AF_INET:
		info := (*_MIB_TCPTABLE_OWNER_MODULE)(unsafe.Pointer(&buf[0]))
		rows := info.getRows()
		for _, row := range rows {
			t.Entries = append(t.Entries, row.asEntry())
		}
	case windows.AF_INET6:
		info := (*_MIB_TCP6TABLE_OWNER_MODULE)(unsafe.Pointer(&buf[0]))
		rows := info.getRows()
		for _, row := range rows {
			t.Entries = append(t.Entries, row.asEntry())
		}
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
	if !cpu.IsBigEndian {
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
	if !cpu.IsBigEndian {
		return uint16(bits.ReverseBytes32(*v) >> 16)
	}
	return uint16(*v >> 16)
}

type moduleInfoConstraint interface {
	_MIB_TCPROW_OWNER_MODULE | _MIB_TCP6ROW_OWNER_MODULE
}

// moduleInfo implements OSMetadata.GetModule. It calls
// getOwnerModuleFromTcpEntry or getOwnerModuleFromTcp6Entry.
//
// See
// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getownermodulefromtcpentry
//
// It may return "", nil indicating a successful call but with empty data.
func moduleInfo[entryType moduleInfoConstraint](entry *entryType, proc *windows.LazyProc) (string, error) {
	var buf []byte
	var desiredLen uint32
	var addr unsafe.Pointer

	for {
		e, _, _ := proc.Call(
			uintptr(unsafe.Pointer(entry)),
			uintptr(tcpipOwnerModuleBasicInfo),
			uintptr(addr),
			uintptr(unsafe.Pointer(&desiredLen)),
		)
		err := windows.Errno(e)
		if err == windows.ERROR_SUCCESS {
			break
		}
		if err == windows.ERROR_NOT_FOUND {
			return "", nil
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return "", err
		}
		if desiredLen > 1<<20 {
			// Sanity check before allocating too much.
			return "", nil
		}
		buf = make([]byte, desiredLen)
		addr = unsafe.Pointer(&buf[0])
	}
	if addr == nil {
		// GetOwnerModuleFromTcp*Entry can apparently return ERROR_SUCCESS
		// (NO_ERROR) on the first call without the usual first
		// ERROR_INSUFFICIENT_BUFFER result. Windows said success, so interpret
		// that was sucessfully not having data.
		return "", nil
	}
	basicInfo := (*_TCPIP_OWNER_MODULE_BASIC_INFO)(addr)
	return windows.UTF16PtrToString(basicInfo.moduleName), nil
}

// GetModule implements OSMetadata.
func (m *_MIB_TCPROW_OWNER_MODULE) GetModule() (string, error) {
	return moduleInfo(m, getOwnerModuleFromTcpEntry)
}

// GetModule implements OSMetadata.
func (m *_MIB_TCP6ROW_OWNER_MODULE) GetModule() (string, error) {
	return moduleInfo(m, getOwnerModuleFromTcp6Entry)
}
