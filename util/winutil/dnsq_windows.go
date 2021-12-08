// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winutil

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type DNSAddr struct {
	maxSa            [32]byte /* DNS_ADDR_MAX_SOCKADDR_LENGTH */
	dnsAddrUserDword [8]uint32
}

func (a *DNSAddr) AsInet4() *windows.SockaddrInet4 {
	return (*windows.SockaddrInet4)(unsafe.Pointer(&a.maxSa[0]))
}

func (a *DNSAddr) AsInet6() *windows.SockaddrInet6 {
	return (*windows.SockaddrInet6)(unsafe.Pointer(&a.maxSa[0]))
}

type DNSAData struct {
	IPv4Address [4]byte
}

type DNSAddrArray struct {
	MaxCount  uint32
	AddrCount uint32
	tag       uint32
	Family    uint16
	wreserved uint16
	flags     uint32
	matchFlag uint32
	reserved1 uint32
	reserved2 uint32
	AddrArray [1]DNSAddr
}

// TODO: We can probably make this more efficient
func NewDNSAddrArray(family uint16, addrs []DNSAddr) *DNSAddrArray {
	numBytes := unsafe.Sizeof(DNSAddrArray{})
	count := len(addrs)
	if count > 1 {
		numBytes += (uintptr(count) - 1) * unsafe.Sizeof(DNSAddr{})
	}

	buf := make([]byte, numBytes)
	result := (*DNSAddrArray)(unsafe.Pointer(&buf[0]))
	result.MaxCount = uint32(count)
	result.AddrCount = uint32(count)
	result.Family = family

	dstAddrs := unsafe.Slice(&result.AddrArray[0], count)
	copy(dstAddrs, addrs)

	return result
}

const (
	DNS_QUERY_REQUEST_VERSION1 = 1
	DNS_QUERY_REQUEST_VERSION3 = 3
)

const (
	DNS_QUERY_RESULTS_VERSION1 = 1
)

const (
	DNS_QUERY_STANDARD                  = 0x00000000
	DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 0x00000001
	DNS_QUERY_USE_TCP_ONLY              = 0x00000002
	DNS_QUERY_NO_RECURSION              = 0x00000004
	DNS_QUERY_BYPASS_CACHE              = 0x00000008
	DNS_QUERY_NO_WIRE_QUERY             = 0x00000010
	DNS_QUERY_NO_LOCAL_NAME             = 0x00000020
	DNS_QUERY_NO_HOSTS_FILE             = 0x00000040
	DNS_QUERY_NO_NETBT                  = 0x00000080
	DNS_QUERY_WIRE_ONLY                 = 0x00000100
	DNS_QUERY_RETURN_MESSAGE            = 0x00000200
	DNS_QUERY_MULTICAST_ONLY            = 0x00000400
	DNS_QUERY_NO_MULTICAST              = 0x00000800
	DNS_QUERY_TREAT_AS_FQDN             = 0x00001000
	DNS_QUERY_ADDRCONFIG                = 0x00002000
	DNS_QUERY_DUAL_ADDR                 = 0x00004000
	DNS_QUERY_DONT_RESET_TTL_VALUES     = 0x00100000
	DNS_QUERY_DISABLE_IDN_ENCODING      = 0x00200000
	DNS_QUERY_APPEND_MULTILABEL         = 0x00800000
	DNS_QUERY_DNSSEC_OK                 = 0x01000000
	DNS_QUERY_DNSSEC_CHECKING_DISABLED  = 0x02000000
	DNS_QUERY_RESERVED                  = 0xf0000000
)

type DNSQueryRequest struct {
	Version                 uint32
	QueryName               *uint16
	QueryType               uint16
	QueryOptions            uint64
	DNSServerList           *DNSAddrArray
	InterfaceIndex          uint32
	QueryCompletionCallback uintptr
	QueryContext            uintptr
}

type DNSCustomServer struct {
	ServerType uint32
	Flags      uint64
	Template   *uint16
	MaxSa      [32]byte /* DNS_ADDR_MAX_SOCKADDR_LENGTH */
}

type DNSQueryRequest3 struct {
	DNSQueryRequest
	IsNetworkQueryRequired int32 /* BOOL */
	RequiredNetworkIndex   uint32
	CCustomServers         uint32
	PCustomServers         *DNSCustomServer
}

const (
	DNS_CUSTOM_SERVER_TYPE_UDP = 0x1
	DNS_CUSTOM_SERVER_TYPE_DOH = 0x2
)

const (
	DNS_CUSTOM_SERVER_UDP_FALLBACK = 0x1
)

var (
	DNS_REQUEST_PENDING windows.Errno = 0x00002522
)

type DNSStatus int32

type DNSQueryResult struct {
	Version      uint32
	QueryStatus  DNSStatus
	QueryOptions uint64
	QueryRecords *windows.DNSRecord
	reserved     uintptr
}

const (
	DNSFreeFlat                = 0
	DNSFreeRecordList          = 1
	DNSFreeParsedMessageFields = 2
)

func (qr *DNSQueryResult) Close() error {
	windows.DnsRecordListFree(qr.QueryRecords, DNSFreeRecordList)
	qr.QueryRecords = nil
	return nil
}

type DNSQueryCancel struct {
	// This is defined in C as 32 bytes, but it is also declared with 8 byte alignment
	reserved [4]uint64
}
