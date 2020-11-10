// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"fmt"
	"strings"

	"tailscale.com/types/strbuilder"
)

// RFC1858: prevent overlapping fragment attacks.
const minFrag = 60 + 20 // max IPv4 header + basic TCP header

const (
	TCPSyn    = 0x02
	TCPAck    = 0x10
	TCPSynAck = TCPSyn | TCPAck
)

var (
	get16 = binary.BigEndian.Uint16
	get32 = binary.BigEndian.Uint32

	put16 = binary.BigEndian.PutUint16
	put32 = binary.BigEndian.PutUint32
)

// Parsed is a minimal decoding of a packet suitable for use in filters.
//
// In general, it only supports IPv4. The IPv6 parsing is very minimal.
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

	IPVersion uint8    // 4, 6, or 0
	IPProto   IP4Proto // IP subprotocol (UDP, TCP, etc); the NextHeader field for IPv6
	SrcIP4    IP4      // IPv4 source address (not used for IPv6)
	DstIP4    IP4      // IPv4 destination address (not used for IPv6)
	SrcIP6    IP6      // IPv6 source address (not used for IPv4)
	DstIP6    IP6      // IPv6 destination address (not used for IPv4)
	SrcPort   uint16   // TCP/UDP source port
	DstPort   uint16   // TCP/UDP destination port
	TCPFlags  uint8    // TCP flags (SYN, ACK, etc)
}

// NextHeader
type NextHeader uint8

func (p *Parsed) String() string {
	if p.IPVersion == 6 {
		return fmt.Sprintf("IPv6{Proto=%d}", p.IPProto)
	}
	switch p.IPProto {
	case Unknown:
		return "Unknown{???}"
	}
	sb := strbuilder.Get()
	sb.WriteString(p.IPProto.String())
	sb.WriteByte('{')
	writeIPPort(sb, p.SrcIP4, p.SrcPort)
	sb.WriteString(" > ")
	writeIPPort(sb, p.DstIP4, p.DstPort)
	sb.WriteByte('}')
	return sb.String()
}

func writeIPPort(sb *strbuilder.Builder, ip IP4, port uint16) {
	sb.WriteUint(uint64(byte(ip >> 24)))
	sb.WriteByte('.')
	sb.WriteUint(uint64(byte(ip >> 16)))
	sb.WriteByte('.')
	sb.WriteUint(uint64(byte(ip >> 8)))
	sb.WriteByte('.')
	sb.WriteUint(uint64(byte(ip)))
	sb.WriteByte(':')
	sb.WriteUint(uint64(port))
}

// based on https://tools.ietf.org/html/rfc1071
func ipChecksum(b []byte) uint16 {
	var ac uint32
	i := 0
	n := len(b)
	for n >= 2 {
		ac += uint32(get16(b[i : i+2]))
		n -= 2
		i += 2
	}
	if n == 1 {
		ac += uint32(b[i]) << 8
	}
	for (ac >> 16) > 0 {
		ac = (ac >> 16) + (ac & 0xffff)
	}
	return uint16(^ac)
}

// Decode extracts data from the packet in b into q.
// It performs extremely simple packet decoding for basic IPv4 packet types.
// It extracts only the subprotocol id, IP addresses, and (if any) ports,
// and shouldn't need any memory allocation.
func (q *Parsed) Decode(b []byte) {
	q.b = b

	if len(b) < ipHeaderLength {
		q.IPVersion = 0
		q.IPProto = Unknown
		return
	}

	// Check that it's IPv4.
	// TODO(apenwarr): consider IPv6 support
	q.IPVersion = (b[0] & 0xF0) >> 4
	switch q.IPVersion {
	case 4:
		q.IPProto = IP4Proto(b[9])
	case 6:
		q.IPProto = IP4Proto(b[6]) // "Next Header" field
		return
	default:
		q.IPVersion = 0
		q.IPProto = Unknown
		return
	}

	q.length = int(get16(b[2:4]))
	if len(b) < q.length {
		// Packet was cut off before full IPv4 length.
		q.IPProto = Unknown
		return
	}

	// If it's valid IPv4, then the IP addresses are valid
	q.SrcIP4 = IP4(get32(b[12:16]))
	q.DstIP4 = IP4(get32(b[16:20]))

	q.subofs = int((b[0] & 0x0F) << 2)
	sub := b[q.subofs:]

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
	fragFlags := get16(b[6:8])
	moreFrags := (fragFlags & 0x20) != 0
	fragOfs := fragFlags & 0x1FFF
	if fragOfs == 0 {
		// This is the first fragment
		if moreFrags && len(sub) < minFrag {
			// Suspiciously short first fragment, dump it.
			q.IPProto = Unknown
			return
		}
		// otherwise, this is either non-fragmented (the usual case)
		// or a big enough initial fragment that we can read the
		// whole subprotocol header.
		switch q.IPProto {
		case ICMP:
			if len(sub) < icmpHeaderLength {
				q.IPProto = Unknown
				return
			}
			q.SrcPort = 0
			q.DstPort = 0
			q.dataofs = q.subofs + icmpHeaderLength
			return
		case TCP:
			if len(sub) < tcpHeaderLength {
				q.IPProto = Unknown
				return
			}
			q.SrcPort = get16(sub[0:2])
			q.DstPort = get16(sub[2:4])
			q.TCPFlags = sub[13] & 0x3F
			headerLength := (sub[12] & 0xF0) >> 2
			q.dataofs = q.subofs + int(headerLength)
			return
		case UDP:
			if len(sub) < udpHeaderLength {
				q.IPProto = Unknown
				return
			}
			q.SrcPort = get16(sub[0:2])
			q.DstPort = get16(sub[2:4])
			q.dataofs = q.subofs + udpHeaderLength
			return
		default:
			q.IPProto = Unknown
			return
		}
	} else {
		// This is a fragment other than the first one.
		if fragOfs < minFrag {
			// First frag was suspiciously short, so we can't
			// trust the followup either.
			q.IPProto = Unknown
			return
		}
		// otherwise, we have to permit the fragment to slide through.
		// Second and later fragments don't have sub-headers.
		// Ideally, we would drop fragments that we can't identify,
		// but that would require statefulness. Anyway, receivers'
		// kernels know to drop fragments where the initial fragment
		// doesn't arrive.
		q.IPProto = Fragment
		return
	}
}

func (q *Parsed) IPHeader() IP4Header {
	ipid := get16(q.b[4:6])
	return IP4Header{
		IPID:    ipid,
		IPProto: q.IPProto,
		SrcIP:   q.SrcIP4,
		DstIP:   q.DstIP4,
	}
}

func (q *Parsed) ICMPHeader() ICMP4Header {
	return ICMP4Header{
		IP4Header: q.IPHeader(),
		Type:      ICMP4Type(q.b[q.subofs+0]),
		Code:      ICMP4Code(q.b[q.subofs+1]),
	}
}

func (q *Parsed) UDPHeader() UDP4Header {
	return UDP4Header{
		IP4Header: q.IPHeader(),
		SrcPort:   q.SrcPort,
		DstPort:   q.DstPort,
	}
}

// Buffer returns the entire packet buffer.
// This is a read-only view; that is, q retains the ownership of the buffer.
func (q *Parsed) Buffer() []byte {
	return q.b
}

// Sub returns the IP subprotocol section.
// This is a read-only view; that is, q retains the ownership of the buffer.
func (q *Parsed) Sub(begin, n int) []byte {
	return q.b[q.subofs+begin : q.subofs+begin+n]
}

// Payload returns the payload of the IP subprotocol section.
// This is a read-only view; that is, q retains the ownership of the buffer.
func (q *Parsed) Payload() []byte {
	return q.b[q.dataofs:q.length]
}

// Trim trims the buffer to its IPv4 length.
// Sometimes packets arrive from an interface with extra bytes on the end.
// This removes them.
func (q *Parsed) Trim() []byte {
	return q.b[:q.length]
}

// IsTCPSyn reports whether q is a TCP SYN packet
// (i.e. the first packet in a new connection).
func (q *Parsed) IsTCPSyn() bool {
	return (q.TCPFlags & TCPSynAck) == TCPSyn
}

// IsError reports whether q is an IPv4 ICMP "Error" packet.
func (q *Parsed) IsError() bool {
	if q.IPProto == ICMP && len(q.b) >= q.subofs+8 {
		switch ICMP4Type(q.b[q.subofs]) {
		case ICMP4Unreachable, ICMP4TimeExceeded:
			return true
		}
	}
	return false
}

// IsEchoRequest reports whether q is an IPv4 ICMP Echo Request.
func (q *Parsed) IsEchoRequest() bool {
	if q.IPProto == ICMP && len(q.b) >= q.subofs+8 {
		return ICMP4Type(q.b[q.subofs]) == ICMP4EchoRequest &&
			ICMP4Code(q.b[q.subofs+1]) == ICMP4NoCode
	}
	return false
}

// IsEchoRequest reports whether q is an IPv4 ICMP Echo Response.
func (q *Parsed) IsEchoResponse() bool {
	if q.IPProto == ICMP && len(q.b) >= q.subofs+8 {
		return ICMP4Type(q.b[q.subofs]) == ICMP4EchoReply &&
			ICMP4Code(q.b[q.subofs+1]) == ICMP4NoCode
	}
	return false
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
