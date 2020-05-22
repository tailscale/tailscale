// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsdns provides a Resolver struct capable of resolving
// domains on a Tailscale network.
package tsdns

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/tailscale/wireguard-go/device"
	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/packet"
)

// MaxResponseSize is the maximal size of a Tailscale DNS response.
const MaxResponseSize = 512

const (
	// ipOffset is the space before the IP header. It is reserved for wireguard-go.
	ipOffset = device.MessageTransportHeaderSize
	// dnsDataOffset is the space before DNS data. It includes the IP and UDP headers.
	dnsDataOffset = ipOffset + packet.UDPDataOffset

	// The response buffer must have space for all the headers and the response body.
	bufferSize = dnsDataOffset + MaxResponseSize
)

var (
	errNoSuchDomain   = errors.New("domain does not exist")
	errNotImplemented = errors.New("query type not implemented")
	errNotOurName     = errors.New("not an *.ipn.dev domain")
	errNotQuery       = errors.New("not a DNS query")
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

	parser dns.Parser
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
func (r *Resolver) Resolve(domain string) (netaddr.IP, dns.RCode, error) {
	// If not a subdomain of ipn.dev, then we must refuse this query.
	if !strings.HasSuffix(domain, ".ipn.dev") {
		return netaddr.IP{}, dns.RCodeRefused, errNotOurName
	}
	// If not ###.ipn.dev, then NXDOMAIN.
	if len(domain) != len("123.ipn.dev") {
		return netaddr.IP{}, dns.RCodeNameError, errNoSuchDomain
	}
	lastOctet, ok := digitsToNumber(domain[:3])
	// lastOctet >= 0 is guaranteed as digitsToNumber does not accept minus signs.
	if !ok || lastOctet > 255 {
		return netaddr.IP{}, dns.RCodeNameError, errNoSuchDomain
	}

	return netaddr.IPv4(100, 64, 0, byte(lastOctet)), dns.RCodeSuccess, nil
}

type response struct {
	Header         dns.Header
	ResourceHeader dns.ResourceHeader
	Question       dns.Question
	IP             netaddr.IP
}

func (r *Resolver) parseQuery(query *packet.QDecode, resp *response) error {
	var err error

	// Extract the UDP payload.
	in := query.Trim()

	resp.Header, err = r.parser.Start(in[packet.UDPDataOffset:])
	if err != nil {
		resp.Header.RCode = dns.RCodeFormatError
		return err
	}

	if resp.Header.Response {
		resp.Header.RCode = dns.RCodeFormatError
		return errNotQuery
	}

	resp.Question, err = r.parser.Question()
	if err != nil {
		resp.Header.RCode = dns.RCodeFormatError
		return err
	}

	return nil
}

func (r *Resolver) makeResponse(resp *response) error {
	var err error

	switch resp.Question.Type {
	case dns.TypeA, dns.TypeALL:
		// Remove final dot from name: *.ipn.dev. -> *.ipn.dev
		name := resp.Question.Name.String()
		name = name[:len(name)-1]
		resp.IP, resp.Header.RCode, err = r.Resolve(name)
	default:
		resp.Header.RCode = dns.RCodeNotImplemented
		err = errNotImplemented
	}

	return err
}

func writeAnswer(builder *dns.Builder, resp *response, out []byte) error {
	var answer dns.AResource
	var err error

	resp.Header.Authoritative = true
	if resp.Header.RecursionDesired {
		resp.Header.RecursionAvailable = true
	}

	err = builder.StartAnswers()
	if err != nil {
		return err
	}

	answerHeader := dns.ResourceHeader{
		Name:  resp.Question.Name,
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		TTL:   3600,
	}
	copy(answer.A[:], resp.IP.IPAddr().IP)
	return builder.AResource(answerHeader, answer)
}

func writeResponse(resp *response, out []byte) ([]byte, error) {
	builder := dns.NewBuilder(out, resp.Header)
	resp.Header.Response = true

	err := builder.StartQuestions()
	if err != nil {
		return nil, err
	}

	err = builder.Question(resp.Question)
	if err != nil {
		return nil, err
	}

	if resp.Header.RCode == dns.RCodeSuccess {
		err = writeAnswer(&builder, resp, out)
		if err != nil {
			return nil, err
		}
	}

	return builder.Finish()
}

// Respond generates a response to the given packet.
// It is assumed that r.AcceptsPacket(query) is true.
func (r *Resolver) Respond(query *packet.QDecode) ([]byte, error) {
	var resp response

	// 1. Parse query packet.
	err := r.parseQuery(query, &resp)
	// We will not return this error: it is the sender's fault.
	if err != nil {
		r.logf("tsdns: error during query parsing: %v", err)
		goto respond
	}

	// 2. Service the query.
	err = r.makeResponse(&resp)
	// We will not return this error: it is the sender's fault.
	if err != nil {
		r.logf("tsdns: error during name resolution: %v", err)
		goto respond
	}
	// For now, we require IPv4 in all cases.
	// If we somehow came up with a non-IPv4 address, it's our fault.
	if !resp.IP.Is4() {
		resp.Header.RCode = dns.RCodeServerFailure
		r.logf("tsdns: error during name resolution: %v", err)
	}

	// 3. Serialize the response.
respond:
	// dns.Builder appends to the passed buffer (without reallocation when possible),
	// so we pass in a zero-length slice starting at the point it should start writing.
	// rbuf is the response slice with the correct length starting at the same point.
	rbuf, err := writeResponse(&resp, r.responseBuffer[dnsDataOffset:dnsDataOffset])
	if err != nil {
		// This error cannot be reported to the sender:
		// it happened during the generation of a response packet.
		return nil, err
	}

	// 4. Serialize the response.
	end := dnsDataOffset + len(rbuf)
	udpHeader := packet.UDPHeader{
		IPHeader: query.ResponseIPHeader(),
		DstPort:  query.SrcPort,
		SrcPort:  query.DstPort,
	}
	// Failure is impossible: r.responseBuffer has statically sufficient size.
	packet.WriteUDPHeader(udpHeader, r.responseBuffer[ipOffset:end])

	return r.responseBuffer[:end], nil
}
