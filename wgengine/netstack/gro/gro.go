// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package gro implements GRO for the receive (write) path into gVisor.
package gro

import (
	"bytes"
	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
)

// RXChecksumOffload validates IPv4, TCP, and UDP header checksums in p,
// returning an equivalent *stack.PacketBuffer if they are valid, otherwise nil.
// The set of headers validated covers where gVisor would perform validation if
// !stack.PacketBuffer.RXChecksumValidated, i.e. it satisfies
// stack.CapabilityRXChecksumOffload. Other protocols with checksum fields,
// e.g. ICMP{v6}, are still validated by gVisor regardless of rx checksum
// offloading capabilities.
func RXChecksumOffload(p *packet.Parsed) *stack.PacketBuffer {
	var (
		pn        tcpip.NetworkProtocolNumber
		csumStart int
	)
	buf := p.Buffer()

	switch p.IPVersion {
	case 4:
		if len(buf) < header.IPv4MinimumSize {
			return nil
		}
		csumStart = int((buf[0] & 0x0F) * 4)
		if csumStart < header.IPv4MinimumSize || csumStart > header.IPv4MaximumHeaderSize || len(buf) < csumStart {
			return nil
		}
		if ^tun.Checksum(buf[:csumStart], 0) != 0 {
			return nil
		}
		pn = header.IPv4ProtocolNumber
	case 6:
		if len(buf) < header.IPv6FixedHeaderSize {
			return nil
		}
		csumStart = header.IPv6FixedHeaderSize
		pn = header.IPv6ProtocolNumber
		if p.IPProto != ipproto.ICMPv6 && p.IPProto != ipproto.TCP && p.IPProto != ipproto.UDP {
			// buf could have extension headers before a UDP or TCP header, but
			// packet.Parsed.IPProto will be set to the ext header type, so we
			// have to look deeper. We are still responsible for validating the
			// L4 checksum in this case. So, make use of gVisor's existing
			// extension header parsing via parse.IPv6() in order to unpack the
			// L4 csumStart index. This is not particularly efficient as we have
			// to allocate a short-lived stack.PacketBuffer that cannot be
			// re-used. parse.IPv6() "consumes" the IPv6 headers, so we can't
			// inject this stack.PacketBuffer into the stack at a later point.
			packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(bytes.Clone(buf)),
			})
			defer packetBuf.DecRef()
			// The rightmost bool returns false only if packetBuf is too short,
			// which we've already accounted for above.
			transportProto, _, _, _, _ := parse.IPv6(packetBuf)
			if transportProto == header.TCPProtocolNumber || transportProto == header.UDPProtocolNumber {
				csumLen := packetBuf.Data().Size()
				if len(buf) < csumLen {
					return nil
				}
				csumStart = len(buf) - csumLen
				p.IPProto = ipproto.Proto(transportProto)
			}
		}
	}

	if p.IPProto == ipproto.TCP || p.IPProto == ipproto.UDP {
		lenForPseudo := len(buf) - csumStart
		csum := tun.PseudoHeaderChecksum(
			uint8(p.IPProto),
			p.Src.Addr().AsSlice(),
			p.Dst.Addr().AsSlice(),
			uint16(lenForPseudo))
		csum = tun.Checksum(buf[csumStart:], csum)
		if ^csum != 0 {
			return nil
		}
	}

	packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(bytes.Clone(buf)),
	})
	packetBuf.NetworkProtocolNumber = pn
	// Setting this is not technically required. gVisor overrides where
	// stack.CapabilityRXChecksumOffload is advertised from Capabilities().
	// https://github.com/google/gvisor/blob/64c016c92987cc04dfd4c7b091ddd21bdad875f8/pkg/tcpip/stack/nic.go#L763
	// This is also why we offload for all packets since we cannot signal this
	// per-packet.
	packetBuf.RXChecksumValidated = true
	return packetBuf
}
