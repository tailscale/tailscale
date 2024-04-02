// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"tailscale.com/net/netaddr"
	"tailscale.com/types/ipproto"
)

const unknown = ipproto.Unknown

// RFC1858: prevent overlapping fragment attacks.
const minFragBlks = (60 + 20) / 8 // max IPv4 header + basic TCP header in fragment blocks (8 bytes each)

type TCPFlag uint8

const (
	TCPFin     TCPFlag = 0x01
	TCPSyn     TCPFlag = 0x02
	TCPRst     TCPFlag = 0x04
	TCPPsh     TCPFlag = 0x08
	TCPAck     TCPFlag = 0x10
	TCPUrg     TCPFlag = 0x20
	TCPECNEcho TCPFlag = 0x40
	TCPCWR     TCPFlag = 0x80
	TCPSynAck  TCPFlag = TCPSyn | TCPAck
	TCPECNBits TCPFlag = TCPECNEcho | TCPCWR
)

// CaptureMeta contains metadata that is used when debugging.
type CaptureMeta struct {
	DidSNAT     bool           // SNAT was performed & the address was updated.
	OriginalSrc netip.AddrPort // The source address before SNAT was performed.
	DidDNAT     bool           // DNAT was performed & the address was updated.
	OriginalDst netip.AddrPort // The destination address before DNAT was performed.
}

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
	Src netip.AddrPort
	// DstIP4 is the destination address. Family matches IPVersion.
	Dst netip.AddrPort
	// TCPFlags is the packet's TCP flag bits. Valid iff IPProto == TCP.
	TCPFlags TCPFlag

	// CaptureMeta contains metadata that is used when debugging.
	CaptureMeta CaptureMeta
}

func (p *Parsed) String() string {
	if p.IPVersion != 4 && p.IPVersion != 6 {
		return "Unknown{???}"
	}

	// max is the maximum reasonable length of the string we are constructing.
	// It's OK to overshoot, as the temp buffer is allocated on the stack.
	const max = len("ICMPv6{[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%enp5s0]:65535 > [ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%enp5s0]:65535}")
	b := make([]byte, 0, max)
	b = append(b, p.IPProto.String()...)
	b = append(b, '{')
	b = p.Src.AppendTo(b)
	b = append(b, ' ', '>', ' ')
	b = p.Dst.AppendTo(b)
	b = append(b, '}')
	return string(b)
}

// Decode extracts data from the packet in b into q.
// It performs extremely simple packet decoding for basic IPv4 and IPv6 packet types.
// It extracts only the subprotocol id, IP addresses, and (if any) ports,
// and shouldn't need any memory allocation.
func (q *Parsed) Decode(b []byte) {
	q.b = b
	q.CaptureMeta = CaptureMeta{} // Clear any capture metadata if it exists.

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
	q.Src = withIP(q.Src, netaddr.IPv4(b[12], b[13], b[14], b[15]))
	q.Dst = withIP(q.Dst, netaddr.IPv4(b[16], b[17], b[18], b[19]))

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
	moreFrags := (fragFlags & 0x2000) != 0
	fragOfs := fragFlags & 0x1FFF

	if fragOfs == 0 {
		// This is the first fragment
		if moreFrags && len(sub) < minFragBlks {
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
			q.Src = withPort(q.Src, 0)
			q.Dst = withPort(q.Dst, 0)
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
			q.Src = withPort(q.Src, binary.BigEndian.Uint16(sub[0:2]))
			q.Dst = withPort(q.Dst, binary.BigEndian.Uint16(sub[2:4]))
			q.TCPFlags = TCPFlag(sub[13])
			headerLength := (sub[12] & 0xF0) >> 2
			q.dataofs = q.subofs + int(headerLength)
			return
		case ipproto.UDP:
			if len(sub) < udpHeaderLength {
				q.IPProto = unknown
				return
			}
			q.Src = withPort(q.Src, binary.BigEndian.Uint16(sub[0:2]))
			q.Dst = withPort(q.Dst, binary.BigEndian.Uint16(sub[2:4]))
			q.dataofs = q.subofs + udpHeaderLength
			return
		case ipproto.SCTP:
			if len(sub) < sctpHeaderLength {
				q.IPProto = unknown
				return
			}
			q.Src = withPort(q.Src, binary.BigEndian.Uint16(sub[0:2]))
			q.Dst = withPort(q.Dst, binary.BigEndian.Uint16(sub[2:4]))
			return
		case ipproto.TSMP:
			// Inter-tailscale messages.
			q.dataofs = q.subofs
			return
		case ipproto.Fragment:
			// An IPProto value of 0xff (our Fragment constant for internal use)
			// should never actually be used in the wild; if we see it,
			// something's suspicious and we map it back to zero (unknown).
			q.IPProto = unknown
		}
	} else {
		// This is a fragment other than the first one.
		if fragOfs < minFragBlks {
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
	srcIP, _ := netip.AddrFromSlice(net.IP(b[8:24]))
	dstIP, _ := netip.AddrFromSlice(net.IP(b[24:40]))
	q.Src = withIP(q.Src, srcIP)
	q.Dst = withIP(q.Dst, dstIP)

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
		q.Src = withPort(q.Src, 0)
		q.Dst = withPort(q.Dst, 0)
		q.dataofs = q.subofs + icmp6HeaderLength
	case ipproto.TCP:
		if len(sub) < tcpHeaderLength {
			q.IPProto = unknown
			return
		}
		q.Src = withPort(q.Src, binary.BigEndian.Uint16(sub[0:2]))
		q.Dst = withPort(q.Dst, binary.BigEndian.Uint16(sub[2:4]))
		q.TCPFlags = TCPFlag(sub[13])
		headerLength := (sub[12] & 0xF0) >> 2
		q.dataofs = q.subofs + int(headerLength)
		return
	case ipproto.UDP:
		if len(sub) < udpHeaderLength {
			q.IPProto = unknown
			return
		}
		q.Src = withPort(q.Src, binary.BigEndian.Uint16(sub[0:2]))
		q.Dst = withPort(q.Dst, binary.BigEndian.Uint16(sub[2:4]))
		q.dataofs = q.subofs + udpHeaderLength
	case ipproto.SCTP:
		if len(sub) < sctpHeaderLength {
			q.IPProto = unknown
			return
		}
		q.Src = withPort(q.Src, binary.BigEndian.Uint16(sub[0:2]))
		q.Dst = withPort(q.Dst, binary.BigEndian.Uint16(sub[2:4]))
		return
	case ipproto.TSMP:
		// Inter-tailscale messages.
		q.dataofs = q.subofs
		return
	case ipproto.Fragment:
		// An IPProto value of 0xff (our Fragment constant for internal use)
		// should never actually be used in the wild; if we see it,
		// something's suspicious and we map it back to zero (unknown).
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
		Src:     q.Src.Addr(),
		Dst:     q.Dst.Addr(),
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
		Src:     q.Src.Addr(),
		Dst:     q.Dst.Addr(),
	}
}

func (q *Parsed) ICMP4Header() ICMP4Header {
	return ICMP4Header{
		IP4Header: q.IP4Header(),
		Type:      ICMP4Type(q.b[q.subofs+0]),
		Code:      ICMP4Code(q.b[q.subofs+1]),
	}
}

func (q *Parsed) ICMP6Header() ICMP6Header {
	return ICMP6Header{
		IP6Header: q.IP6Header(),
		Type:      ICMP6Type(q.b[q.subofs+0]),
		Code:      ICMP6Code(q.b[q.subofs+1]),
	}
}

func (q *Parsed) UDP4Header() UDP4Header {
	return UDP4Header{
		IP4Header: q.IP4Header(),
		SrcPort:   q.Src.Port(),
		DstPort:   q.Dst.Port(),
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

// Transport returns the transport header and payload (IP subprotocol, such as TCP or UDP).
// This is a read-only view; that is, p retains the ownership of the buffer.
func (p *Parsed) Transport() []byte {
	return p.b[p.subofs:]
}

// IsTCPSyn reports whether q is a TCP SYN packet,
// without ACK set. (i.e. the first packet in a new connection)
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
		return t == ICMP4Unreachable || t == ICMP4TimeExceeded || t == ICMP4ParamProblem
	case ipproto.ICMPv6:
		if len(q.b) < q.subofs+8 {
			return false
		}
		t := ICMP6Type(q.b[q.subofs])
		return t == ICMP6Unreachable || t == ICMP6PacketTooBig || t == ICMP6TimeExceeded || t == ICMP6ParamProblem
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

// IsEchoResponse reports whether q is an IPv4 ICMP Echo Response.
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

// EchoIDSeq extracts the identifier/sequence bytes from an ICMP Echo response,
// and returns them as a uint32, used to lookup internally routed ICMP echo
// responses. This function is intentionally lightweight as it is called on
// every incoming ICMP packet.
func (q *Parsed) EchoIDSeq() uint32 {
	switch q.IPProto {
	case ipproto.ICMPv4:
		offset := ip4HeaderLength + icmp4HeaderLength
		if len(q.b) < offset+4 {
			return 0
		}
		return binary.LittleEndian.Uint32(q.b[offset:])
	case ipproto.ICMPv6:
		offset := ip6HeaderLength + icmp6HeaderLength
		if len(q.b) < offset+4 {
			return 0
		}
		return binary.LittleEndian.Uint32(q.b[offset:])
	default:
		return 0
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

func withIP(ap netip.AddrPort, ip netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(ip, ap.Port())
}

func withPort(ap netip.AddrPort, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr(), port)
}
