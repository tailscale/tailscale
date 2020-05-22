// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsdns provides a Resolver struct capable of resolving
// domains on a Tailscale network.
package tsdns

import (
	"encoding/binary"
	"errors"

	"github.com/tailscale/wireguard-go/device"
	"golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
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

var (
	errNotOurName = errors.New("not an *.ipn.dev domain")
	errNotQuery   = errors.New("not a DNS query")
)

var (
	// The default IP for a new resolver.
	DefaultIP = packet.IP(binary.BigEndian.Uint32([]byte{100, 100, 100, 100}))
	// The default port for a new resolver.
	DefaultPort = uint16(53)
)

// Resolver is a DNS resolver for domain names of the form ###.ipn.dev
type Resolver struct {
	logf logger.Logf

	// ip is the IP on which the resolver is listening.
	ip packet.IP
	// port is the port on which the resolver is listening.
	port uint16

	parser dnsmessage.Parser
	// responseBuffer to avoid graticious allocations.
	responseBuffer [bufferSize]byte
}

// NewResolver constructs a resolver with default parameters.
func NewResolver(logf logger.Logf) *Resolver {
	return &Resolver{
		logf: logf,
		ip:   DefaultIP,
		port: DefaultPort,
	}
}

// AcceptsPacket determines if the given packet is
// directed to this resolver (by ip and port).
// We also require that UDP be used to simplify things for now.
func (r *Resolver) AcceptsPacket(in *packet.QDecode) bool {
	return in.DstIP == r.ip && in.DstPort == r.port && in.IPProto == packet.UDP
}

// digitsToNumber converts a string of decimal digits to the number it represents.
// This differs from Atoi in that it does not allow leading signs, for example.
func digitsToNumber(in string) (int, bool) {
	var out int
	for _, c := range in {
		if '0' <= c && c <= '9' {
			out = out*10 + int(c-'0')
		} else {
			return 0, false
		}
	}
	return out, true
}

// Resolve maps a given domain name to the IP address of the host that owns it.
func (r *Resolver) Resolve(domain string) (netaddr.IP, error) {
	// ###.ipn.dev
	if len(domain) != 11 || domain[3:] != ".ipn.dev" {
		return netaddr.IP{}, errNotOurName
	}
	lastOctet, ok := digitsToNumber(domain[:3])
	// lastOctet >= 0 is guaranteed as digitsToNumber does not accept minus signs.
	if !ok || lastOctet > 255 {
		return netaddr.IP{}, errNotOurName
	}

	return netaddr.IPv4(100, 64, 0, byte(lastOctet)), nil
}

// Respond generates a response to the given packet.
// It is assumed that r.AcceptsPacket(query) is true.
func (r *Resolver) Respond(query *packet.QDecode) ([]byte, error) {
	// Extract the UDP payload.
	in := query.Sub(packet.UDPHeaderSize, MaxQuerySize)

	header, err := r.parser.Start(in)
	if err != nil {
		return nil, err
	}
	if header.Response {
		return nil, errNotQuery
	}
	question, err := r.parser.Question()
	if err != nil {
		return nil, err
	}

	name := question.Name.String()
	ip, err := r.Resolve(name[:len(name)-1])
	if err != nil {
		return nil, err
	}

	header.Response = true
	answerHeader := dnsmessage.ResourceHeader{
		Name:  question.Name,
		Class: dnsmessage.ClassINET,
		TTL:   3600,
	}

	builder := dnsmessage.NewBuilder(r.responseBuffer[dnsDataOffset:dnsDataOffset], header)
	err = builder.StartQuestions()
	if err != nil {
		return nil, err
	}
	err = builder.Question(question)
	if err != nil {
		return nil, err
	}
	err = builder.StartAnswers()
	if err != nil {
		return nil, err
	}
	if ip.Is4() {
		var answer dnsmessage.AResource
		copy(answer.A[:], ip.IPAddr().IP)
		answerHeader.Type = dnsmessage.TypeA
		err = builder.AResource(answerHeader, answer)
	} else {
		var answer dnsmessage.AAAAResource
		copy(answer.AAAA[:], ip.IPAddr().IP)
		answerHeader.Type = dnsmessage.TypeAAAA
		err = builder.AAAAResource(answerHeader, answer)
	}
	if err != nil {
		return nil, err
	}
	resp, err := builder.Finish()
	if err != nil {
		return nil, err
	}

	end := dnsDataOffset + len(resp)
	// Flip the bits in the ipID.
	// If incoming ipIDs are distinct, then so are these.
	ipID := ^binary.BigEndian.Uint16(query.Sub(4, 2))
	// Failure is impossible: r.responseBuffer has statically sufficient size.
	packet.WriteUDPHeader(
		query.DstIP, query.SrcIP, ipID, query.DstPort, query.SrcPort,
		r.responseBuffer[ipOffset:end],
	)

	return r.responseBuffer[:end], nil
}
