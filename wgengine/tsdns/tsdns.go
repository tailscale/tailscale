package tsdns

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"

	"github.com/miekg/dns"
	"github.com/tailscale/wireguard-go/device"
	"tailscale.com/wgengine/packet"
)

const (
	// MaxQuerySize is the maximal size of a Magic DNS query.
	MaxQuerySize = 512
	// MaxResponseSize is the maximal size of a Magic DNS response.
	MaxResponseSize = 512
)

const (
	ipOffset      = device.MessageTransportHeaderSize
	dnsDataOffset = ipOffset + packet.UDPDataOffset

	bufferSize = dnsDataOffset + MaxResponseSize
)

type Resolver struct {
	ip   packet.IP
	port uint16

	responseBuffer [bufferSize]byte
}

func NewResolver() *Resolver {
	return &Resolver{
		ip:   packet.IP(binary.BigEndian.Uint32([]byte{100, 100, 100, 100})),
		port: uint16(53),
	}
}

var (
	ErrNotOurName = errors.New("not an *.ipn.dev domain")
	ErrNotQuery   = errors.New("not a DNS query")
	ErrNoTypeA    = errors.New("query has no quetion of type A")
)

// AcceptsPacket determines if the given packet is a DNS request
// directed to this resolver (by ip and port).
// We also require that UDP be used to simplify parsing for now.
func (r *Resolver) AcceptsPacket(q *packet.QDecode) bool {
	return q.DstIP == r.ip && q.DstPort == r.port && q.IPProto == packet.UDP
}

// Respond generates a response to the given packet.
func (r *Resolver) Respond(q *packet.QDecode) ([]byte, error) {
	var msg, reply dns.Msg
	msg.Unpack(q.Sub(packet.UDPHeaderSize, MaxQuerySize)) // Does not allocate.

	if msg.Opcode != dns.OpcodeQuery {
		return nil, ErrNotQuery
	}

	var question *dns.Question
	for i := range msg.Question {
		if msg.Question[i].Qtype == dns.TypeA {
			question = &msg.Question[i]
			break
		}
	}
	if question == nil {
		return nil, ErrNoTypeA
	}

	// ###.ipn.dev.
	if len(question.Name) != 12 || question.Name[3:] != ".ipn.dev." {
		return nil, ErrNotOurName
	}
	lastOctet, err := strconv.Atoi(question.Name[:3])
	if err != nil || lastOctet < 0 || lastOctet > 255 {
		return nil, ErrNotOurName
	}

	answer := dns.A{
		Hdr: dns.RR_Header{
			Name:     question.Name,
			Rrtype:   dns.TypeA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 4,
		},
		A: net.IPv4(100, 64, 0, byte(lastOctet)),
	}

	reply.SetReply(&msg)
	reply.Answer = append(reply.Answer, &answer)
	// Pretend we are the desired kind of resolver.
	if msg.RecursionDesired {
		reply.RecursionAvailable = true
	}

	newbuf, err := reply.PackBuffer(r.responseBuffer[dnsDataOffset:])
	if err != nil {
		return nil, err
	}
	if &newbuf[0] != &r.responseBuffer[dnsDataOffset] {
		// Reallocation happened :(
	}
	end := dnsDataOffset + len(newbuf)

	ipID := binary.BigEndian.Uint16(q.Sub(2, 4))
	// Error is impossible: r.responseBuffer has static size
	packet.WriteUDPHeader(
		q.DstIP, q.SrcIP, ipID, q.DstPort, q.SrcPort,
		r.responseBuffer[ipOffset:end],
	)

	return r.responseBuffer[:end], nil
}
