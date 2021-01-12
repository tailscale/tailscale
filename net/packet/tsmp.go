// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TSMP is our ICMP-like "Tailscale Message Protocol" for signaling
// Tailscale-specific messages between nodes. It uses IP protocol 99
// (reserved for "any private encryption scheme") within
// Wireguard's normal encryption between peers and never hits the host
// network stack.

package packet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"inet.af/netaddr"
	"tailscale.com/net/flowtrack"
)

// TailscaleRejectedHeader is a TSMP message that says that one
// Tailscale node has rejected the connection from another. Unlike a
// TCP RST, this includes a reason.
//
// On the wire, after the IP header, it's currently 7 bytes:
//     * '!'
//     * IPProto byte (IANA protocol number: TCP or UDP)
//     * 'A' or 'S' (RejectedDueToACLs, RejectedDueToShieldsUp)
//     * srcPort big endian uint16
//     * dstPort big endian uint16
//
// In the future it might also accept 16 byte IP flow src/dst IPs
// after the header, if they're different than the IP-level ones.
type TailscaleRejectedHeader struct {
	IPSrc  netaddr.IP            // IPv4 or IPv6 header's src IP
	IPDst  netaddr.IP            // IPv4 or IPv6 header's dst IP
	Src    netaddr.IPPort        // rejected flow's src
	Dst    netaddr.IPPort        // rejected flow's dst
	Proto  IPProto               // proto that was rejected (TCP or UDP)
	Reason TailscaleRejectReason // why the connection was rejected
}

func (rh TailscaleRejectedHeader) Flow() flowtrack.Tuple {
	return flowtrack.Tuple{Src: rh.Src, Dst: rh.Dst}
}

func (rh TailscaleRejectedHeader) String() string {
	return fmt.Sprintf("TSMP-reject-flow{%s %s > %s}: %s", rh.Proto, rh.Src, rh.Dst, rh.Reason)
}

type TSMPType uint8

const (
	TSMPTypeRejectedConn TSMPType = '!'
)

type TailscaleRejectReason byte

const (
	RejectedDueToACLs      TailscaleRejectReason = 'A'
	RejectedDueToShieldsUp TailscaleRejectReason = 'S'
)

func (r TailscaleRejectReason) String() string {
	switch r {
	case RejectedDueToACLs:
		return "acl"
	case RejectedDueToShieldsUp:
		return "shields"
	}
	return fmt.Sprintf("0x%02x", byte(r))
}

func (h TailscaleRejectedHeader) Len() int {
	var ipHeaderLen int
	if h.IPSrc.Is4() {
		ipHeaderLen = ip4HeaderLength
	} else if h.IPSrc.Is6() {
		ipHeaderLen = ip6HeaderLength
	}
	return ipHeaderLen +
		1 + // TSMPType byte
		1 + // IPProto byte
		1 + // TailscaleRejectReason byte
		2*2 // 2 uint16 ports
}

func (h TailscaleRejectedHeader) Marshal(buf []byte) error {
	if len(buf) < h.Len() {
		return errSmallBuffer
	}
	if len(buf) > maxPacketLength {
		return errLargePacket
	}
	if h.Src.IP.Is4() {
		iph := IP4Header{
			IPProto: TSMP,
			Src:     h.IPSrc,
			Dst:     h.IPDst,
		}
		iph.Marshal(buf)
		buf = buf[ip4HeaderLength:]
	} else if h.Src.IP.Is6() {
		iph := IP6Header{
			IPProto: TSMP,
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
	binary.BigEndian.PutUint16(buf[3:5], h.Src.Port)
	binary.BigEndian.PutUint16(buf[5:7], h.Dst.Port)
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
	return TailscaleRejectedHeader{
		Proto:  IPProto(p[1]),
		Reason: TailscaleRejectReason(p[2]),
		IPSrc:  pp.Src.IP,
		IPDst:  pp.Dst.IP,
		Src:    netaddr.IPPort{IP: pp.Dst.IP, Port: binary.BigEndian.Uint16(p[3:5])},
		Dst:    netaddr.IPPort{IP: pp.Src.IP, Port: binary.BigEndian.Uint16(p[5:7])},
	}, true
}
