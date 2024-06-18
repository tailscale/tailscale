// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package xdp

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"tailscale.com/net/stun"
)

type xdpAction uint32

func (x xdpAction) String() string {
	switch x {
	case xdpActionAborted:
		return "XDP_ABORTED"
	case xdpActionDrop:
		return "XDP_DROP"
	case xdpActionPass:
		return "XDP_PASS"
	case xdpActionTX:
		return "XDP_TX"
	case xdpActionRedirect:
		return "XDP_REDIRECT"
	default:
		return fmt.Sprintf("unknown(%d)", x)
	}
}

const (
	xdpActionAborted xdpAction = iota
	xdpActionDrop
	xdpActionPass
	xdpActionTX
	xdpActionRedirect
)

const (
	ethHLen  = 14
	udpHLen  = 8
	ipv4HLen = 20
	ipv6HLen = 40
)

const (
	defaultSTUNPort = 3478
	defaultTTL      = 64
	reqSrcPort      = uint16(1025)
)

var (
	reqEthSrc  = tcpip.LinkAddress([]byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01})
	reqEthDst  = tcpip.LinkAddress([]byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x02})
	reqIPv4Src = netip.MustParseAddr("192.0.2.1")
	reqIPv4Dst = netip.MustParseAddr("192.0.2.2")
	reqIPv6Src = netip.MustParseAddr("2001:db8::1")
	reqIPv6Dst = netip.MustParseAddr("2001:db8::2")
)

var testTXID = stun.TxID([12]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b})

type ipv4Mutations struct {
	ipHeaderFn  func(header.IPv4)
	udpHeaderFn func(header.UDP)
	stunReqFn   func([]byte)
}

func getIPv4STUNBindingReq(mutations *ipv4Mutations) []byte {
	req := stun.Request(testTXID)
	if mutations != nil && mutations.stunReqFn != nil {
		mutations.stunReqFn(req)
	}
	payloadLen := len(req)
	totalLen := ipv4HLen + udpHLen + payloadLen
	b := make([]byte, ethHLen+totalLen)
	ipv4H := header.IPv4(b[ethHLen:])
	ethH := header.Ethernet(b)
	ethFields := header.EthernetFields{
		SrcAddr: reqEthSrc,
		DstAddr: reqEthDst,
		Type:    unix.ETH_P_IP,
	}
	ethH.Encode(&ethFields)
	ipFields := header.IPv4Fields{
		SrcAddr:     tcpip.AddrFrom4(reqIPv4Src.As4()),
		DstAddr:     tcpip.AddrFrom4(reqIPv4Dst.As4()),
		Protocol:    unix.IPPROTO_UDP,
		TTL:         defaultTTL,
		TotalLength: uint16(totalLen),
	}
	ipv4H.Encode(&ipFields)
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	if mutations != nil && mutations.ipHeaderFn != nil {
		mutations.ipHeaderFn(ipv4H)
	}
	udpH := header.UDP(b[ethHLen+ipv4HLen:])
	udpFields := header.UDPFields{
		SrcPort:  reqSrcPort,
		DstPort:  defaultSTUNPort,
		Length:   uint16(udpHLen + payloadLen),
		Checksum: 0,
	}
	udpH.Encode(&udpFields)
	copy(b[ethHLen+ipv4HLen+udpHLen:], req)
	cs := header.PseudoHeaderChecksum(
		unix.IPPROTO_UDP,
		ipv4H.SourceAddress(),
		ipv4H.DestinationAddress(),
		uint16(udpHLen+payloadLen),
	)
	cs = checksum.Checksum(req, cs)
	udpH.SetChecksum(^udpH.CalculateChecksum(cs))
	if mutations != nil && mutations.udpHeaderFn != nil {
		mutations.udpHeaderFn(udpH)
	}
	return b
}

type ipv6Mutations struct {
	ipHeaderFn  func(header.IPv6)
	udpHeaderFn func(header.UDP)
	stunReqFn   func([]byte)
}

func getIPv6STUNBindingReq(mutations *ipv6Mutations) []byte {
	req := stun.Request(testTXID)
	if mutations != nil && mutations.stunReqFn != nil {
		mutations.stunReqFn(req)
	}
	payloadLen := len(req)
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")
	b := make([]byte, ethHLen+ipv6HLen+udpHLen+payloadLen)
	ipv6H := header.IPv6(b[ethHLen:])
	ethH := header.Ethernet(b)
	ethFields := header.EthernetFields{
		SrcAddr: tcpip.LinkAddress([]byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}),
		DstAddr: tcpip.LinkAddress([]byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x02}),
		Type:    unix.ETH_P_IPV6,
	}
	ethH.Encode(&ethFields)
	ipFields := header.IPv6Fields{
		SrcAddr:           tcpip.AddrFrom16(src.As16()),
		DstAddr:           tcpip.AddrFrom16(dst.As16()),
		TransportProtocol: unix.IPPROTO_UDP,
		HopLimit:          64,
		PayloadLength:     uint16(udpHLen + payloadLen),
	}
	ipv6H.Encode(&ipFields)
	if mutations != nil && mutations.ipHeaderFn != nil {
		mutations.ipHeaderFn(ipv6H)
	}
	udpH := header.UDP(b[ethHLen+ipv6HLen:])
	udpFields := header.UDPFields{
		SrcPort:  1025,
		DstPort:  defaultSTUNPort,
		Length:   uint16(udpHLen + payloadLen),
		Checksum: 0,
	}
	udpH.Encode(&udpFields)
	copy(b[ethHLen+ipv6HLen+udpHLen:], req)
	cs := header.PseudoHeaderChecksum(
		unix.IPPROTO_UDP,
		ipv6H.SourceAddress(),
		ipv6H.DestinationAddress(),
		uint16(udpHLen+payloadLen),
	)
	cs = checksum.Checksum(req, cs)
	udpH.SetChecksum(^udpH.CalculateChecksum(cs))
	if mutations != nil && mutations.udpHeaderFn != nil {
		mutations.udpHeaderFn(udpH)
	}
	return b
}

func getIPv4STUNBindingResp() []byte {
	addrPort := netip.AddrPortFrom(reqIPv4Src, reqSrcPort)
	resp := stun.Response(testTXID, addrPort)
	payloadLen := len(resp)
	totalLen := ipv4HLen + udpHLen + payloadLen
	b := make([]byte, ethHLen+totalLen)
	ipv4H := header.IPv4(b[ethHLen:])
	ethH := header.Ethernet(b)
	ethFields := header.EthernetFields{
		SrcAddr: reqEthDst,
		DstAddr: reqEthSrc,
		Type:    unix.ETH_P_IP,
	}
	ethH.Encode(&ethFields)
	ipFields := header.IPv4Fields{
		SrcAddr:     tcpip.AddrFrom4(reqIPv4Dst.As4()),
		DstAddr:     tcpip.AddrFrom4(reqIPv4Src.As4()),
		Protocol:    unix.IPPROTO_UDP,
		TTL:         defaultTTL,
		TotalLength: uint16(totalLen),
	}
	ipv4H.Encode(&ipFields)
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	udpH := header.UDP(b[ethHLen+ipv4HLen:])
	udpFields := header.UDPFields{
		SrcPort:  defaultSTUNPort,
		DstPort:  reqSrcPort,
		Length:   uint16(udpHLen + payloadLen),
		Checksum: 0,
	}
	udpH.Encode(&udpFields)
	copy(b[ethHLen+ipv4HLen+udpHLen:], resp)
	cs := header.PseudoHeaderChecksum(
		unix.IPPROTO_UDP,
		ipv4H.SourceAddress(),
		ipv4H.DestinationAddress(),
		uint16(udpHLen+payloadLen),
	)
	cs = checksum.Checksum(resp, cs)
	udpH.SetChecksum(^udpH.CalculateChecksum(cs))
	return b
}

func getIPv6STUNBindingResp() []byte {
	addrPort := netip.AddrPortFrom(reqIPv6Src, reqSrcPort)
	resp := stun.Response(testTXID, addrPort)
	payloadLen := len(resp)
	totalLen := ipv6HLen + udpHLen + payloadLen
	b := make([]byte, ethHLen+totalLen)
	ipv6H := header.IPv6(b[ethHLen:])
	ethH := header.Ethernet(b)
	ethFields := header.EthernetFields{
		SrcAddr: reqEthDst,
		DstAddr: reqEthSrc,
		Type:    unix.ETH_P_IPV6,
	}
	ethH.Encode(&ethFields)
	ipFields := header.IPv6Fields{
		SrcAddr:           tcpip.AddrFrom16(reqIPv6Dst.As16()),
		DstAddr:           tcpip.AddrFrom16(reqIPv6Src.As16()),
		TransportProtocol: unix.IPPROTO_UDP,
		HopLimit:          defaultTTL,
		PayloadLength:     uint16(udpHLen + payloadLen),
	}
	ipv6H.Encode(&ipFields)
	udpH := header.UDP(b[ethHLen+ipv6HLen:])
	udpFields := header.UDPFields{
		SrcPort:  defaultSTUNPort,
		DstPort:  reqSrcPort,
		Length:   uint16(udpHLen + payloadLen),
		Checksum: 0,
	}
	udpH.Encode(&udpFields)
	copy(b[ethHLen+ipv6HLen+udpHLen:], resp)
	cs := header.PseudoHeaderChecksum(
		unix.IPPROTO_UDP,
		ipv6H.SourceAddress(),
		ipv6H.DestinationAddress(),
		uint16(udpHLen+payloadLen),
	)
	cs = checksum.Checksum(resp, cs)
	udpH.SetChecksum(^udpH.CalculateChecksum(cs))
	return b
}

func TestXDP(t *testing.T) {
	ipv4STUNBindingReqTX := getIPv4STUNBindingReq(nil)
	ipv6STUNBindingReqTX := getIPv6STUNBindingReq(nil)

	ipv4STUNBindingReqIPCsumPass := getIPv4STUNBindingReq(&ipv4Mutations{
		ipHeaderFn: func(ipv4H header.IPv4) {
			oldCS := ipv4H.Checksum()
			newCS := oldCS
			for newCS == 0 || newCS == oldCS {
				newCS++
			}
			ipv4H.SetChecksum(newCS)
		},
	})

	ipv4STUNBindingReqIHLPass := getIPv4STUNBindingReq(&ipv4Mutations{
		ipHeaderFn: func(ipv4H header.IPv4) {
			ipv4H[0] &= 0xF0
		},
	})

	ipv4STUNBindingReqIPVerPass := getIPv4STUNBindingReq(&ipv4Mutations{
		ipHeaderFn: func(ipv4H header.IPv4) {
			ipv4H[0] &= 0x0F
		},
	})

	ipv4STUNBindingReqIPProtoPass := getIPv4STUNBindingReq(&ipv4Mutations{
		ipHeaderFn: func(ipv4H header.IPv4) {
			ipv4H[9] = unix.IPPROTO_TCP
		},
	})

	ipv4STUNBindingReqFragOffsetPass := getIPv4STUNBindingReq(&ipv4Mutations{
		ipHeaderFn: func(ipv4H header.IPv4) {
			ipv4H.SetFlagsFragmentOffset(ipv4H.Flags(), 8)
		},
	})

	ipv4STUNBindingReqFlagsMFPass := getIPv4STUNBindingReq(&ipv4Mutations{
		ipHeaderFn: func(ipv4H header.IPv4) {
			ipv4H.SetFlagsFragmentOffset(header.IPv4FlagMoreFragments, 0)
		},
	})

	ipv4STUNBindingReqTotLenPass := getIPv4STUNBindingReq(&ipv4Mutations{
		ipHeaderFn: func(ipv4H header.IPv4) {
			ipv4H.SetTotalLength(ipv4H.TotalLength() + 1)
			ipv4H.SetChecksum(0)
			ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
		},
	})

	ipv6STUNBindingReqIPVerPass := getIPv6STUNBindingReq(&ipv6Mutations{
		ipHeaderFn: func(ipv6H header.IPv6) {
			ipv6H[0] &= 0x0F
		},
		udpHeaderFn: func(udp header.UDP) {},
	})

	ipv6STUNBindingReqNextHdrPass := getIPv6STUNBindingReq(&ipv6Mutations{
		ipHeaderFn: func(ipv6H header.IPv6) {
			ipv6H.SetNextHeader(unix.IPPROTO_TCP)
		},
		udpHeaderFn: func(udp header.UDP) {},
	})

	ipv6STUNBindingReqPayloadLenPass := getIPv6STUNBindingReq(&ipv6Mutations{
		ipHeaderFn: func(ipv6H header.IPv6) {
			ipv6H.SetPayloadLength(ipv6H.PayloadLength() + 1)
		},
		udpHeaderFn: func(udp header.UDP) {},
	})

	ipv4STUNBindingReqUDPCsumPass := getIPv4STUNBindingReq(&ipv4Mutations{
		udpHeaderFn: func(udpH header.UDP) {
			oldCS := udpH.Checksum()
			newCS := oldCS
			for newCS == 0 || newCS == oldCS {
				newCS++
			}
			udpH.SetChecksum(newCS)
		},
	})

	ipv6STUNBindingReqUDPCsumPass := getIPv6STUNBindingReq(&ipv6Mutations{
		udpHeaderFn: func(udpH header.UDP) {
			oldCS := udpH.Checksum()
			newCS := oldCS
			for newCS == 0 || newCS == oldCS {
				newCS++
			}
			udpH.SetChecksum(newCS)
		},
	})

	ipv4STUNBindingReqSTUNTypePass := getIPv4STUNBindingReq(&ipv4Mutations{
		stunReqFn: func(req []byte) {
			req[1] = ^req[1]
		},
	})

	ipv6STUNBindingReqSTUNTypePass := getIPv6STUNBindingReq(&ipv6Mutations{
		stunReqFn: func(req []byte) {
			req[1] = ^req[1]
		},
	})

	ipv4STUNBindingReqSTUNMagicPass := getIPv4STUNBindingReq(&ipv4Mutations{
		stunReqFn: func(req []byte) {
			req[4] = ^req[4]
		},
	})

	ipv6STUNBindingReqSTUNMagicPass := getIPv6STUNBindingReq(&ipv6Mutations{
		stunReqFn: func(req []byte) {
			req[4] = ^req[4]
		},
	})

	ipv4STUNBindingReqSTUNAttrsLenPass := getIPv4STUNBindingReq(&ipv4Mutations{
		stunReqFn: func(req []byte) {
			req[2] = ^req[2]
		},
	})

	ipv6STUNBindingReqSTUNAttrsLenPass := getIPv6STUNBindingReq(&ipv6Mutations{
		stunReqFn: func(req []byte) {
			req[2] = ^req[2]
		},
	})

	ipv4STUNBindingReqSTUNSWValPass := getIPv4STUNBindingReq(&ipv4Mutations{
		stunReqFn: func(req []byte) {
			req[24] = ^req[24]
		},
	})

	ipv6STUNBindingReqSTUNSWValPass := getIPv6STUNBindingReq(&ipv6Mutations{
		stunReqFn: func(req []byte) {
			req[24] = ^req[24]
		},
	})

	ipv4STUNBindingReqSTUNFirstAttrPass := getIPv4STUNBindingReq(&ipv4Mutations{
		stunReqFn: func(req []byte) {
			req[21] = ^req[21]
		},
	})

	ipv6STUNBindingReqSTUNFirstAttrPass := getIPv6STUNBindingReq(&ipv6Mutations{
		stunReqFn: func(req []byte) {
			req[21] = ^req[21]
		},
	})

	ipv4STUNBindingReqUDPZeroCsumTx := getIPv4STUNBindingReq(&ipv4Mutations{
		udpHeaderFn: func(udpH header.UDP) {
			udpH.SetChecksum(0)
		},
	})

	ipv6STUNBindingReqUDPZeroCsumPass := getIPv6STUNBindingReq(&ipv6Mutations{
		udpHeaderFn: func(udpH header.UDP) {
			udpH.SetChecksum(0)
		},
	})

	cases := []struct {
		name          string
		dropSTUN      bool
		packetIn      []byte
		wantCode      xdpAction
		wantPacketOut []byte
		wantMetrics   map[bpfCountersKey]uint64
	}{
		{
			name:          "ipv4 STUN Binding Request Drop STUN",
			dropSTUN:      true,
			packetIn:      ipv4STUNBindingReqTX,
			wantCode:      xdpActionDrop,
			wantPacketOut: ipv4STUNBindingReqTX,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_DROP_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_DROP_STUN),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_DROP_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_DROP_STUN),
				}: uint64(len(ipv4STUNBindingReqTX)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request Drop STUN",
			dropSTUN:      true,
			packetIn:      ipv6STUNBindingReqTX,
			wantCode:      xdpActionDrop,
			wantPacketOut: ipv6STUNBindingReqTX,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_DROP_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_DROP_STUN),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_DROP_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_DROP_STUN),
				}: uint64(len(ipv6STUNBindingReqTX)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request TX",
			packetIn:      ipv4STUNBindingReqTX,
			wantCode:      xdpActionTX,
			wantPacketOut: getIPv4STUNBindingResp(),
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_TX_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_TX_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(getIPv4STUNBindingResp())),
			},
		},
		{
			name:          "ipv6 STUN Binding Request TX",
			packetIn:      ipv6STUNBindingReqTX,
			wantCode:      xdpActionTX,
			wantPacketOut: getIPv6STUNBindingResp(),
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_TX_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_TX_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(getIPv6STUNBindingResp())),
			},
		},
		{
			name:          "ipv4 STUN Binding Request invalid ip csum PASS",
			packetIn:      ipv4STUNBindingReqIPCsumPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqIPCsumPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_IP_CSUM),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_IP_CSUM),
				}: uint64(len(ipv4STUNBindingReqIPCsumPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request ihl PASS",
			packetIn:      ipv4STUNBindingReqIHLPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqIHLPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqIHLPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request ip version PASS",
			packetIn:      ipv4STUNBindingReqIPVerPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqIPVerPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqIPVerPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request ip proto PASS",
			packetIn:      ipv4STUNBindingReqIPProtoPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqIPProtoPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqIPProtoPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request frag offset PASS",
			packetIn:      ipv4STUNBindingReqFragOffsetPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqFragOffsetPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqFragOffsetPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request flags mf PASS",
			packetIn:      ipv4STUNBindingReqFlagsMFPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqFlagsMFPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqFlagsMFPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request tot len PASS",
			packetIn:      ipv4STUNBindingReqTotLenPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqTotLenPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqTotLenPass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request ip version PASS",
			packetIn:      ipv6STUNBindingReqIPVerPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqIPVerPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv6STUNBindingReqIPVerPass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request next hdr PASS",
			packetIn:      ipv6STUNBindingReqNextHdrPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqNextHdrPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv6STUNBindingReqNextHdrPass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request payload len PASS",
			packetIn:      ipv6STUNBindingReqPayloadLenPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqPayloadLenPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv6STUNBindingReqPayloadLenPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request UDP csum PASS",
			packetIn:      ipv4STUNBindingReqUDPCsumPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqUDPCsumPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_UDP_CSUM),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_UDP_CSUM),
				}: uint64(len(ipv4STUNBindingReqUDPCsumPass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request UDP csum PASS",
			packetIn:      ipv6STUNBindingReqUDPCsumPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqUDPCsumPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_UDP_CSUM),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_UDP_CSUM),
				}: uint64(len(ipv6STUNBindingReqUDPCsumPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request STUN type PASS",
			packetIn:      ipv4STUNBindingReqSTUNTypePass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqSTUNTypePass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqSTUNTypePass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request STUN type PASS",
			packetIn:      ipv6STUNBindingReqSTUNTypePass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqSTUNTypePass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv6STUNBindingReqSTUNTypePass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request STUN magic PASS",
			packetIn:      ipv4STUNBindingReqSTUNMagicPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqSTUNMagicPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqSTUNMagicPass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request STUN magic PASS",
			packetIn:      ipv6STUNBindingReqSTUNMagicPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqSTUNMagicPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv6STUNBindingReqSTUNMagicPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request STUN attrs len PASS",
			packetIn:      ipv4STUNBindingReqSTUNAttrsLenPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqSTUNAttrsLenPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv4STUNBindingReqSTUNAttrsLenPass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request STUN attrs len PASS",
			packetIn:      ipv6STUNBindingReqSTUNAttrsLenPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqSTUNAttrsLenPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(ipv6STUNBindingReqSTUNAttrsLenPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request STUN SW val PASS",
			packetIn:      ipv4STUNBindingReqSTUNSWValPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqSTUNSWValPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_SW_ATTR_VAL),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_SW_ATTR_VAL),
				}: uint64(len(ipv4STUNBindingReqSTUNSWValPass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request STUN SW val PASS",
			packetIn:      ipv6STUNBindingReqSTUNSWValPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqSTUNSWValPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_SW_ATTR_VAL),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_SW_ATTR_VAL),
				}: uint64(len(ipv6STUNBindingReqSTUNSWValPass)),
			},
		},
		{
			name:          "ipv4 STUN Binding Request STUN first attr PASS",
			packetIn:      ipv4STUNBindingReqSTUNFirstAttrPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv4STUNBindingReqSTUNFirstAttrPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNEXPECTED_FIRST_STUN_ATTR),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNEXPECTED_FIRST_STUN_ATTR),
				}: uint64(len(ipv4STUNBindingReqSTUNFirstAttrPass)),
			},
		},
		{
			name:          "ipv6 STUN Binding Request STUN first attr PASS",
			packetIn:      ipv6STUNBindingReqSTUNFirstAttrPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqSTUNFirstAttrPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNEXPECTED_FIRST_STUN_ATTR),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNEXPECTED_FIRST_STUN_ATTR),
				}: uint64(len(ipv6STUNBindingReqSTUNFirstAttrPass)),
			},
		},
		{
			name:          "ipv4 UDP zero csum TX",
			packetIn:      ipv4STUNBindingReqUDPZeroCsumTx,
			wantCode:      xdpActionTX,
			wantPacketOut: getIPv4STUNBindingResp(),
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_TX_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV4),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_TX_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_UNSPECIFIED),
				}: uint64(len(getIPv4STUNBindingResp())),
			},
		},
		{
			name:          "ipv6 UDP zero csum PASS",
			packetIn:      ipv6STUNBindingReqUDPZeroCsumPass,
			wantCode:      xdpActionPass,
			wantPacketOut: ipv6STUNBindingReqUDPZeroCsumPass,
			wantMetrics: map[bpfCountersKey]uint64{
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_UDP_CSUM),
				}: 1,
				{
					Af:      uint8(bpfCounterKeyAfCOUNTER_KEY_AF_IPV6),
					Pba:     uint8(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_BYTES_PASS_TOTAL),
					ProgEnd: uint8(bpfCounterKeyProgEndCOUNTER_KEY_END_INVALID_UDP_CSUM),
				}: uint64(len(ipv6STUNBindingReqUDPZeroCsumPass)),
			},
		},
	}

	server, err := NewSTUNServer(&STUNServerConfig{DeviceName: "fake", DstPort: defaultSTUNPort},
		&noAttachOption{})
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			// TODO(jwhited): get this running
			t.Skip("skipping due to EPERM error; test requires elevated privileges")
		}
		t.Fatalf("error constructing STUN server: %v", err)
	}
	defer server.Close()

	clearCounters := func() error {
		server.metrics.last = make(map[bpfCountersKey]uint64)
		var cur, next bpfCountersKey
		keys := make([]bpfCountersKey, 0)
		for err = server.objs.CountersMap.NextKey(nil, &next); ; err = server.objs.CountersMap.NextKey(cur, &next) {
			if err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					break
				}
				return err
			}
			keys = append(keys, next)
			cur = next
		}
		for _, key := range keys {
			err = server.objs.CountersMap.Delete(&key)
			if err != nil {
				return err
			}
		}
		err = server.objs.CountersMap.NextKey(nil, &next)
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return errors.New("counters map is not empty")
		}
		return nil
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err = clearCounters()
			if err != nil {
				t.Fatalf("error clearing counters: %v", err)
			}
			opts := ebpf.RunOptions{
				Data:    c.packetIn,
				DataOut: make([]byte, 1514),
			}
			err = server.SetDropSTUN(c.dropSTUN)
			if err != nil {
				t.Fatalf("error setting drop STUN: %v", err)
			}
			got, err := server.objs.XdpProgFunc.Run(&opts)
			if err != nil {
				t.Fatalf("error running program: %v", err)
			}
			if xdpAction(got) != c.wantCode {
				t.Fatalf("got code: %s != %s", xdpAction(got), c.wantCode)
			}
			if !bytes.Equal(opts.DataOut, c.wantPacketOut) {
				t.Fatal("packets not equal")
			}
			err = server.updateMetrics()
			if err != nil {
				t.Fatalf("error updating metrics: %v", err)
			}
			if c.wantMetrics != nil {
				for k, v := range c.wantMetrics {
					gotCounter, ok := server.metrics.last[k]
					if !ok {
						t.Errorf("expected counter at key %+v not found", k)
					}
					if gotCounter != v {
						t.Errorf("key: %+v gotCounter: %d != %d", k, gotCounter, v)
					}
				}
				for k := range server.metrics.last {
					_, ok := c.wantMetrics[k]
					if !ok {
						t.Errorf("counter at key: %+v incremented unexpectedly", k)
					}
				}
			}
		})
	}
}

func TestCountersMapKey(t *testing.T) {
	if bpfCounterKeyAfCOUNTER_KEY_AF_LEN > 256 {
		t.Error("COUNTER_KEY_AF_LEN no longer fits within uint8")
	}
	if bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_BYTES_ACTION_LEN > 256 {
		t.Error("COUNTER_KEY_PACKETS_BYTES_ACTION no longer fits within uint8")
	}
	if bpfCounterKeyProgEndCOUNTER_KEY_END_LEN > 256 {
		t.Error("COUNTER_KEY_END_LEN no longer fits within uint8")
	}
	if len(pbaToOutcomeLV) != int(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_BYTES_ACTION_LEN) {
		t.Error("pbaToOutcomeLV is not in sync with xdp.c")
	}
	if len(progEndLV) != int(bpfCounterKeyProgEndCOUNTER_KEY_END_LEN) {
		t.Error("progEndLV is not in sync with xdp.c")
	}
	if len(packetCounterKeys)+len(bytesCounterKeys) != int(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_BYTES_ACTION_LEN) {
		t.Error("packetCounterKeys and/or bytesCounterKeys is not in sync with xdp.c")
	}
	if len(pbaToOutcomeLV) != int(bpfCounterKeyPacketsBytesActionCOUNTER_KEY_PACKETS_BYTES_ACTION_LEN) {
		t.Error("pbaToOutcomeLV is not in sync with xdp.c")
	}
}
