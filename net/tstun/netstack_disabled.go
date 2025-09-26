// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_netstack

package tstun

type netstack_PacketBuffer struct {
	GSOOptions netstack_GSO
}

func (*netstack_PacketBuffer) DecRef()   { panic("unreachable") }
func (*netstack_PacketBuffer) Size() int { panic("unreachable") }

type netstack_GSOType int

const (
	netstack_GSONone netstack_GSOType = iota
	netstack_GSOTCPv4
	netstack_GSOTCPv6
	netstack_GSOGvisor
)

type netstack_GSO struct {
	// Type is one of GSONone, GSOTCPv4, etc.
	Type netstack_GSOType
	// NeedsCsum is set if the checksum offload is enabled.
	NeedsCsum bool
	// CsumOffset is offset after that to place checksum.
	CsumOffset uint16

	// Mss is maximum segment size.
	MSS uint16
	// L3Len is L3 (IP) header length.
	L3HdrLen uint16

	// MaxSize is maximum GSO packet size.
	MaxSize uint32
}

func (p *netstack_PacketBuffer) NetworkHeader() slicer {
	panic("unreachable")
}

func (p *netstack_PacketBuffer) TransportHeader() slicer {
	panic("unreachable")
}

func (p *netstack_PacketBuffer) ToBuffer() netstack_Buffer { panic("unreachable") }

func (p *netstack_PacketBuffer) Data() asRanger {
	panic("unreachable")
}

type asRanger struct{}

func (asRanger) AsRange() toSlicer { panic("unreachable") }

type toSlicer struct{}

func (toSlicer) ToSlice() []byte { panic("unreachable") }

type slicer struct{}

func (s slicer) Slice() []byte { panic("unreachable") }

type netstack_Buffer struct{}

func (netstack_Buffer) Flatten() []byte { panic("unreachable") }
