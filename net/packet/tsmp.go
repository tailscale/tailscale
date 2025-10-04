// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TSMP is our ICMP-like "Tailscale Message Protocol" for signaling
// Tailscale-specific messages between nodes. It uses IP protocol 99
// (reserved for "any private encryption scheme") within
// WireGuard's normal encryption between peers and never hits the host
// network stack.

package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"tailscale.com/types/ipproto"
)

const minTSMPSize = 7 // the rejected body is 7 bytes

// TailscaleRejectedHeader is a TSMP message that says that one
// Tailscale node has rejected the connection from another. Unlike a
// TCP RST, this includes a reason.
//
// On the wire, after the IP header, it's currently 7 or 8 bytes:
//   - '!'
//   - IPProto byte (IANA protocol number: TCP or UDP)
//   - 'A' or 'S' (RejectedDueToACLs, RejectedDueToShieldsUp)
//   - srcPort big endian uint16
//   - dstPort big endian uint16
//   - [optional] byte of flag bits:
//     lowest bit (0x1): MaybeBroken
//
// In the future it might also accept 16 byte IP flow src/dst IPs
// after the header, if they're different than the IP-level ones.
type TailscaleRejectedHeader struct {
	IPSrc  netip.Addr            // IPv4 or IPv6 header's src IP
	IPDst  netip.Addr            // IPv4 or IPv6 header's dst IP
	Src    netip.AddrPort        // rejected flow's src
	Dst    netip.AddrPort        // rejected flow's dst
	Proto  ipproto.Proto         // proto that was rejected (TCP or UDP)
	Reason TailscaleRejectReason // why the connection was rejected

	// MaybeBroken is whether the rejection is non-terminal (the
	// client should not fail immediately). This is sent by a
	// target when it's not sure whether it's totally broken, but
	// it might be. For example, the target tailscaled might think
	// its host firewall or IP forwarding aren't configured
	// properly, but tailscaled might be wrong (not having enough
	// visibility into what the OS is doing). When true, the
	// message is simply an FYI as a potential reason to use for
	// later when the pendopen connection tracking timer expires.
	MaybeBroken bool
}

const rejectFlagBitMaybeBroken = 0x1

func (rh TailscaleRejectedHeader) String() string {
	return fmt.Sprintf("TSMP-reject-flow{%s %s > %s}: %s", rh.Proto, rh.Src, rh.Dst, rh.Reason)
}

type TSMPType uint8

const (
	// TSMPTypeRejectedConn is the type byte for a TailscaleRejectedHeader.
	TSMPTypeRejectedConn TSMPType = '!'

	// TSMPTypePing is the type byte for a TailscalePingRequest.
	TSMPTypePing TSMPType = 'p'

	// TSMPTypePong is the type byte for a TailscalePongResponse.
	TSMPTypePong TSMPType = 'o'
)

type TailscaleRejectReason byte

// IsZero reports whether r is the zero value, representing no rejection.
func (r TailscaleRejectReason) IsZero() bool { return r == TailscaleRejectReasonNone }

const (
	// TailscaleRejectReasonNone is the TailscaleRejectReason zero value.
	TailscaleRejectReasonNone TailscaleRejectReason = 0

	// RejectedDueToACLs means that the host rejected the connection due to ACLs.
	RejectedDueToACLs TailscaleRejectReason = 'A'

	// RejectedDueToShieldsUp means that the host rejected the connection due to shields being up.
	RejectedDueToShieldsUp TailscaleRejectReason = 'S'

	// RejectedDueToIPForwarding means that the relay node's IP
	// forwarding is disabled.
	RejectedDueToIPForwarding TailscaleRejectReason = 'F'

	// RejectedDueToHostFirewall means that the target host's
	// firewall is blocking the traffic.
	RejectedDueToHostFirewall TailscaleRejectReason = 'W'
)

func (r TailscaleRejectReason) String() string {
	switch r {
	case RejectedDueToACLs:
		return "acl"
	case RejectedDueToShieldsUp:
		return "shields"
	case RejectedDueToIPForwarding:
		return "host-ip-forwarding-unavailable"
	case RejectedDueToHostFirewall:
		return "host-firewall"
	}
	return fmt.Sprintf("0x%02x", byte(r))
}

func (h TailscaleRejectedHeader) hasFlags() bool {
	return h.MaybeBroken // the only one currently
}

func (h TailscaleRejectedHeader) Len() int {
	v := 1 + // TSMPType byte
		1 + // IPProto byte
		1 + // TailscaleRejectReason byte
		2*2 // 2 uint16 ports
	if h.IPSrc.Is4() {
		v += ip4HeaderLength
	} else if h.IPSrc.Is6() {
		v += ip6HeaderLength
	}
	if h.hasFlags() {
		v++
	}
	return v
}

func (h TailscaleRejectedHeader) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	if h.Src.Addr().Is4() {
		iph := IP4Header{
			IPProto: ipproto.TSMP,
			Src:     h.IPSrc,
			Dst:     h.IPDst,
		}
		iph.Marshal(buf)
		buf = buf[ip4HeaderLength:]
	} else if h.Src.Addr().Is6() {
		iph := IP6Header{
			IPProto: ipproto.TSMP,
			Src:     h.IPSrc,
			Dst:     h.IPDst,
		}
		iph.Marshal(buf)
		buf = buf[ip6HeaderLength:]
	} else {
		return errors.New("bogus src IP")
	}
	buf[0] = byte(TSMPTypeRejectedConn)
	buf[1] = byte(h.Proto)
	buf[2] = byte(h.Reason)
	binary.BigEndian.PutUint16(buf[3:5], h.Src.Port())
	binary.BigEndian.PutUint16(buf[5:7], h.Dst.Port())

	if h.hasFlags() {
		var flags byte
		if h.MaybeBroken {
			flags |= rejectFlagBitMaybeBroken
		}
		buf[7] = flags
	}
	return nil
}

// AsTailscaleRejectedHeader parses pp as an incoming rejection
// connection TSMP message.
//
// ok reports whether pp was a valid TSMP rejection packet.
func (pp *Parsed) AsTailscaleRejectedHeader() (h TailscaleRejectedHeader, ok bool) {
	p := pp.Payload()
	if len(p) < 7 || p[0] != byte(TSMPTypeRejectedConn) {
		return
	}
	h = TailscaleRejectedHeader{
		Proto:  ipproto.Proto(p[1]),
		Reason: TailscaleRejectReason(p[2]),
		IPSrc:  pp.Src.Addr(),
		IPDst:  pp.Dst.Addr(),
		Src:    netip.AddrPortFrom(pp.Dst.Addr(), binary.BigEndian.Uint16(p[3:5])),
		Dst:    netip.AddrPortFrom(pp.Src.Addr(), binary.BigEndian.Uint16(p[5:7])),
	}
	if len(p) > 7 {
		flags := p[7]
		h.MaybeBroken = (flags & rejectFlagBitMaybeBroken) != 0
	}
	return h, true
}

// TSMPPingRequest is a TSMP message that's like an ICMP ping request.
//
// On the wire, after the IP header, it's currently 9 bytes:
//   - 'p' (TSMPTypePing)
//   - 8 opaque ping bytes to copy back in the response
type TSMPPingRequest struct {
	Data [8]byte
}

func (pp *Parsed) AsTSMPPing() (h TSMPPingRequest, ok bool) {
	if pp.IPProto != ipproto.TSMP {
		return
	}
	p := pp.Payload()
	if len(p) < 9 || p[0] != byte(TSMPTypePing) {
		return
	}
	copy(h.Data[:], p[1:])
	return h, true
}

type TSMPPongReply struct {
	IPHeader    Header
	Data        [8]byte
	PeerAPIPort uint16
}

// AsTSMPPong returns pp as a TSMPPongReply and whether it is one.
// The pong.IPHeader field is not populated.
func (pp *Parsed) AsTSMPPong() (pong TSMPPongReply, ok bool) {
	if pp.IPProto != ipproto.TSMP {
		return
	}
	p := pp.Payload()
	if len(p) < 9 || p[0] != byte(TSMPTypePong) {
		return
	}
	copy(pong.Data[:], p[1:])
	if len(p) >= 11 {
		pong.PeerAPIPort = binary.BigEndian.Uint16(p[9:])
	}
	return pong, true
}

func (h TSMPPongReply) Len() int {
	return h.IPHeader.Len() + 11
}

func (h TSMPPongReply) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if err := h.IPHeader.Marshal(buf); err != nil {
		return err
	}
	buf = buf[h.IPHeader.Len():]
	buf[0] = byte(TSMPTypePong)
	copy(buf[1:], h.Data[:])
	binary.BigEndian.PutUint16(buf[9:11], h.PeerAPIPort)
	return nil
}
