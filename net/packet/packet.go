// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/strbuilder"
)

const unknown = ipproto.Unknown

// RFC1858: prevent overlapping fragment attacks.
const minFrag = 60 + 20 // max IPv4 header + basic TCP header

type TCPFlag uint8

const (
	TCPFin    TCPFlag = 0x01
	TCPSyn    TCPFlag = 0x02
	TCPRst    TCPFlag = 0x04
	TCPPsh    TCPFlag = 0x08
	TCPAck    TCPFlag = 0x10
	TCPSynAck TCPFlag = TCPSyn | TCPAck
)

// Parsed is a minimal decoding of a packet suitable for use in filters.
type Parsed struct {
	// b is the byte buffer that this decodes.
	b []byte
	// subofs is the offset of IP subprotocol.
	subofs int
	// dataofs is the offset of IP subprotocol payload.
	dataofs int
	// length is the total length of the packet.
	// This is not the same as len(b) because b can have trailing zeros.
	length int

	// IPVersion is the IP protocol version of the packet (4 or
	// 6), or 0 if the packet doesn't look like IPv4 or IPv6.
	IPVersion uint8
	// IPProto is the IP subprotocol (UDP, TCP, etc.). Valid iff IPVersion != 0.
	IPProto ipproto.Proto
	// SrcIP4 is the source address. Family matches IPVersion. Port is
	// valid iff IPProto == TCP || IPProto == UDP.
	Src netaddr.IPPort
	// DstIP4 is the destination address. Family matches IPVersion.
	Dst netaddr.IPPort
	// TCPFlags is the packet's TCP flag bigs. Valid iff IPProto == TCP.
	TCPFlags TCPFlag
}

func (p *Parsed) String() string {
	if p.IPVersion != 4 && p.IPVersion != 6 {
		return "Unknown{???}"
	}

	sb := strbuilder.Get()
	sb.WriteString(p.IPProto.String())
	sb.WriteByte('{')
	writeIPPort(sb, p.Src)
	sb.WriteString(" > ")
	writeIPPort(sb, p.Dst)
	sb.WriteByte('}')
	return sb.String()
}

// writeIPPort writes ipp.String() into sb, with fewer allocations.
//
// TODO: make netaddr more efficient in this area, and retire this func.
func writeIPPort(sb *strbuilder.Builder, ipp netaddr.IPPort) {
	if ipp.IP.Is4() {
		raw := ipp.IP.As4()
		sb.WriteUint(uint64(raw[0]))
		sb.WriteByte('.')
		sb.WriteUint(uint64(raw[1]))
		sb.WriteByte('.')
		sb.WriteUint(uint64(raw[2]))
		sb.WriteByte('.')
		sb.WriteUint(uint64(raw[3]))
		sb.WriteByte(':')
	} else {
		sb.WriteByte('[')
		sb.WriteString(ipp.IP.String()) // TODO: faster?
		sb.WriteString("]:")
	}
	sb.WriteUint(uint64(ipp.Port))
}

// Decode extracts data from the packet in b into q.
// It performs extremely simple packet decoding for basic IPv4 packet types.
// It extracts only the subprotocol id, IP addresses, and (if any) ports,
// and shouldn't need any memory allocation.
func (q *Parsed) Decode(b []byte) {
	q.b = b

	if len(b) < 1 {
		q.IPVersion = 0
		q.IPProto = unknown
		return
	}

	q.IPVersion = b[0] >> 4
	switch q.IPVersion {
	case 4:
		q.decode4(b)
	case 6:
		q.decode6(b)
	default:
		q.IPVersion = 0
		q.IPProto = unknown
	}
}

// StuffForTesting makes Parsed contain a len-bytes buffer. Used in
// tests to build up a synthetic parse result with a non-zero buffer.
func (q *Parsed) StuffForTesting(len int) {
	q.b = make([]byte, len)
}

func (q *Parsed) decode4(b []byte) {
	if len(b) < ip4HeaderLength {
		q.IPVersion = 0
		q.IPProto = unknown
		return
	}

	// Check that it's IPv4.
	q.IPProto = ipproto.Proto(b[9])
	q.length = int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) < q.length {
		// Packet was cut off before full IPv4 length.
		q.IPProto = unknown
		return
	}

	// If it's valid IPv4, then the IP addresses are valid
	q.Src.IP = netaddr.IPv4(b[12], b[13], b[14], b[15])
	q.Dst.IP = netaddr.IPv4(b[16], b[17], b[18], b[19])

	q.subofs = int((b[0] & 0x0F) << 2)
	if q.subofs > q.length {
		// next-proto starts beyond end of packet.
		q.IPProto = unknown
		return
	}
	sub := b[q.subofs:]
	sub = sub[:len(sub):len(sub)] // help the compiler do bounds check elimination

	// We don't care much about IP fragmentation, except insofar as it's
	// used for firewall bypass attacks. The trick is make the first
	// fragment of a TCP or UDP packet so short that it doesn't fit
	// the TCP or UDP header, so we can't read the port, in hope that
	// it'll sneak past. Then subsequent fragments fill it in, but we're
	// missing the first part of the header, so we can't read that either.
	//
	// A "perfectly correct" implementation would have to reassemble
	// fragments before deciding what to do. But the truth is there's
	// zero reason to send such a short first fragment, so we can treat
	// it as Unknown. We can also treat any subsequent fragment that starts
	// at such a low offset as Unknown.
	fragFlags := binary.BigEndian.Uint16(b[6:8])
	moreFrags := (fragFlags & 0x20) != 0
	fragOfs := fragFlags & 0x1FFF
	if fragOfs == 0 {
		// This is the first fragment
		if moreFrags && len(sub) < minFrag {
			// Suspiciously short first fragment, dump it.
			q.IPProto = unknown
			return
		}
		// otherwise, this is either non-fragmented (the usual case)
		// or a big enough initial fragment that we can read the
		// whole subprotocol header.
		switch q.IPProto {
		case ipproto.ICMPv4:
			if len(sub) < icmp4HeaderLength {
				q.IPProto = unknown
				return
			}
			q.Src.Port = 0
			q.Dst.Port = 0
			q.dataofs = q.subofs + icmp4HeaderLength
			return
		case ipproto.IGMP:
			// Keep IPProto, but don't parse anything else
			// out.
			return
		case ipproto.TCP:
			if len(sub) < tcpHeaderLength {
				q.IPProto = unknown
				return
			}
			q.Src.Port = binary.BigEndian.Uint16(sub[0:2])
			q.Dst.Port = binary.BigEndian.Uint16(sub[2:4])
			q.TCPFlags = TCPFlag(sub[13]) & 0x3F
			headerLength := (sub[12] & 0xF0) >> 2
			q.dataofs = q.subofs + int(headerLength)
			return
		case ipproto.UDP:
			if len(sub) < udpHeaderLength {
				q.IPProto = unknown
				return
			}
			q.Src.Port = binary.BigEndian.Uint16(sub[0:2])
			q.Dst.Port = binary.BigEndian.Uint16(sub[2:4])
			q.dataofs = q.subofs + udpHeaderLength
			return
		case ipproto.SCTP:
			if len(sub) < sctpHeaderLength {
				q.IPProto = unknown
				return
			}
			q.Src.Port = binary.BigEndian.Uint16(sub[0:2])
			q.Dst.Port = binary.BigEndian.Uint16(sub[2:4])
			return
		case ipproto.TSMP:
			// Inter-tailscale messages.
			q.dataofs = q.subofs
			return
		default:
			q.IPProto = unknown
			return
		}
	} else {
		// This is a fragment other than the first one.
		if fragOfs < minFrag {
			// First frag was suspiciously short, so we can't
			// trust the followup either.
			q.IPProto = unknown
			return
		}
		// otherwise, we have to permit the fragment to slide through.
		// Second and later fragments don't have sub-headers.
		// Ideally, we would drop fragments that we can't identify,
		// but that would require statefulness. Anyway, receivers'
		// kernels know to drop fragments where the initial fragment
		// doesn't arrive.
		q.IPProto = ipproto.Fragment
		return
	}
}

func (q *Parsed) decode6(b []byte) {
	if len(b) < ip6HeaderLength {
		q.IPVersion = 0
		q.IPProto = unknown
		return
	}

	q.IPProto = ipproto.Proto(b[6])
	q.length = int(binary.BigEndian.Uint16(b[4:6])) + ip6HeaderLength
	if len(b) < q.length {
		// Packet was cut off before the full IPv6 length.
		q.IPProto = unknown
		return
	}

	// okay to ignore `ok` here, because IPs pulled from packets are
	// always well-formed stdlib IPs.
	q.Src.IP, _ = netaddr.FromStdIP(net.IP(b[8:24]))
	q.Dst.IP, _ = netaddr.FromStdIP(net.IP(b[24:40]))

	// We don't support any IPv6 extension headers. Don't try to
	// be clever. Therefore, the IP subprotocol always starts at
	// byte 40.
	//
	// Note that this means we don't support fragmentation in
	// IPv6. This is fine, because IPv6 strongly mandates that you
	// should not fragment, which makes fragmentation on the open
	// internet extremely uncommon.
	//
	// This also means we don't support IPSec headers (AH/ESP), or
	// IPv6 jumbo frames. Those will get marked Unknown and
	// dropped.
	q.subofs = 40
	sub := b[q.subofs:]
	sub = sub[:len(sub):len(sub)] // help the compiler do bounds check elimination

	switch q.IPProto {
	case ipproto.ICMPv6:
		if len(sub) < icmp6HeaderLength {
			q.IPProto = unknown
			return
		}
		q.Src.Port = 0
		q.Dst.Port = 0
		q.dataofs = q.subofs + icmp6HeaderLength
	case ipproto.TCP:
		if len(sub) < tcpHeaderLength {
			q.IPProto = unknown
			return
		}
		q.Src.Port = binary.BigEndian.Uint16(sub[0:2])
		q.Dst.Port = binary.BigEndian.Uint16(sub[2:4])
		q.TCPFlags = TCPFlag(sub[13]) & 0x3F
		headerLength := (sub[12] & 0xF0) >> 2
		q.dataofs = q.subofs + int(headerLength)
		return
	case ipproto.UDP:
		if len(sub) < udpHeaderLength {
			q.IPProto = unknown
			return
		}
		q.Src.Port = binary.BigEndian.Uint16(sub[0:2])
		q.Dst.Port = binary.BigEndian.Uint16(sub[2:4])
		q.dataofs = q.subofs + udpHeaderLength
	case ipproto.SCTP:
		if len(sub) < sctpHeaderLength {
			q.IPProto = unknown
			return
		}
		q.Src.Port = binary.BigEndian.Uint16(sub[0:2])
		q.Dst.Port = binary.BigEndian.Uint16(sub[2:4])
		return
	case ipproto.TSMP:
		// Inter-tailscale messages.
		q.dataofs = q.subofs
		return
	default:
		q.IPProto = unknown
		return
	}
}

func (q *Parsed) IP4Header() IP4Header {
	if q.IPVersion != 4 {
		panic("IP4Header called on non-IPv4 Parsed")
	}
	ipid := binary.BigEndian.Uint16(q.b[4:6])
	return IP4Header{
		IPID:    ipid,
		IPProto: q.IPProto,
		Src:     q.Src.IP,
		Dst:     q.Dst.IP,
	}
}

func (q *Parsed) IP6Header() IP6Header {
	if q.IPVersion != 6 {
		panic("IP6Header called on non-IPv6 Parsed")
	}
	ipid := (binary.BigEndian.Uint32(q.b[:4]) << 12) >> 12
	return IP6Header{
		IPID:    ipid,
		IPProto: q.IPProto,
		Src:     q.Src.IP,
		Dst:     q.Dst.IP,
	}
}

func (q *Parsed) ICMP4Header() ICMP4Header {
	if q.IPVersion != 4 {
		panic("IP4Header called on non-IPv4 Parsed")
	}
	return ICMP4Header{
		IP4Header: q.IP4Header(),
		Type:      ICMP4Type(q.b[q.subofs+0]),
		Code:      ICMP4Code(q.b[q.subofs+1]),
	}
}

func (q *Parsed) UDP4Header() UDP4Header {
	if q.IPVersion != 4 {
		panic("IP4Header called on non-IPv4 Parsed")
	}
	return UDP4Header{
		IP4Header: q.IP4Header(),
		SrcPort:   q.Src.Port,
		DstPort:   q.Dst.Port,
	}
}

// Buffer returns the entire packet buffer.
// This is a read-only view; that is, q retains the ownership of the buffer.
func (q *Parsed) Buffer() []byte {
	return q.b
}

// Payload returns the payload of the IP subprotocol section.
// This is a read-only view; that is, q retains the ownership of the buffer.
func (q *Parsed) Payload() []byte {
	return q.b[q.dataofs:q.length]
}

// IsTCPSyn reports whether q is a TCP SYN packet
// (i.e. the first packet in a new connection).
func (q *Parsed) IsTCPSyn() bool {
	return (q.TCPFlags & TCPSynAck) == TCPSyn
}

// IsError reports whether q is an ICMP "Error" packet.
func (q *Parsed) IsError() bool {
	switch q.IPProto {
	case ipproto.ICMPv4:
		if len(q.b) < q.subofs+8 {
			return false
		}
		t := ICMP4Type(q.b[q.subofs])
		return t == ICMP4Unreachable || t == ICMP4TimeExceeded
	case ipproto.ICMPv6:
		if len(q.b) < q.subofs+8 {
			return false
		}
		t := ICMP6Type(q.b[q.subofs])
		return t == ICMP6Unreachable || t == ICMP6TimeExceeded
	default:
		return false
	}
}

// IsEchoRequest reports whether q is an ICMP Echo Request.
func (q *Parsed) IsEchoRequest() bool {
	switch q.IPProto {
	case ipproto.ICMPv4:
		return len(q.b) >= q.subofs+8 && ICMP4Type(q.b[q.subofs]) == ICMP4EchoRequest && ICMP4Code(q.b[q.subofs+1]) == ICMP4NoCode
	case ipproto.ICMPv6:
		return len(q.b) >= q.subofs+8 && ICMP6Type(q.b[q.subofs]) == ICMP6EchoRequest && ICMP6Code(q.b[q.subofs+1]) == ICMP6NoCode
	default:
		return false
	}
}

// IsEchoRequest reports whether q is an IPv4 ICMP Echo Response.
func (q *Parsed) IsEchoResponse() bool {
	switch q.IPProto {
	case ipproto.ICMPv4:
		return len(q.b) >= q.subofs+8 && ICMP4Type(q.b[q.subofs]) == ICMP4EchoReply && ICMP4Code(q.b[q.subofs+1]) == ICMP4NoCode
	case ipproto.ICMPv6:
		return len(q.b) >= q.subofs+8 && ICMP6Type(q.b[q.subofs]) == ICMP6EchoReply && ICMP6Code(q.b[q.subofs+1]) == ICMP6NoCode
	default:
		return false
	}
}

func Hexdump(b []byte) string {
	out := new(strings.Builder)
	for i := 0; i < len(b); i += 16 {
		if i > 0 {
			fmt.Fprintf(out, "\n")
		}
		fmt.Fprintf(out, "  %04x  ", i)
		j := 0
		for ; j < 16 && i+j < len(b); j++ {
			if j == 8 {
				fmt.Fprintf(out, " ")
			}
			fmt.Fprintf(out, "%02x ", b[i+j])
		}
		for ; j < 16; j++ {
			if j == 8 {
				fmt.Fprintf(out, " ")
			}
			fmt.Fprintf(out, "   ")
		}
		fmt.Fprintf(out, " ")
		for j = 0; j < 16 && i+j < len(b); j++ {
			if b[i+j] >= 32 && b[i+j] < 128 {
				fmt.Fprintf(out, "%c", b[i+j])
			} else {
				fmt.Fprintf(out, ".")
			}
		}
	}
	return out.String()
}
