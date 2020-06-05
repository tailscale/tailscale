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
	"sync"

	"github.com/tailscale/wireguard-go/device"
	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/packet"
)

// maxResponseSize is the maximal size of a Tailscale DNS response
// including headers and wireguard padding.
const maxResponseSize = 512

// ipOffset is the length of wireguard padding before the IP header.
const ipOffset = device.MessageTransportHeaderSize

var (
	errMapNotSet      = errors.New("domain map not set")
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

// Map is all the data Resolver needs to resolve DNS queries.
type Map struct {
	// DomainToIP is a mapping of Tailscale domains to their IP addresses.
	// For example, monitoring.ipn.dev -> 100.64.0.1.
	DomainToIP map[string]netaddr.IP
}

// Resolver is a DNS resolver for domain names of the form *.ipn.dev
type Resolver struct {
	logf logger.Logf

	// ip is the IP on which the resolver is listening.
	ip packet.IP
	// port is the port on which the resolver is listening.
	port uint16

	// parser is a request parser that is reused by the resolver.
	parser dns.Parser
	// responseBuffer is a static buffer to avoid graticious allocations.
	responseBuffer [maxResponseSize]byte

	// mu guards the following fields from being updated while used.
	mu sync.Mutex
	// dnsMap is the map most recently received from the control server.
	dnsMap *Map
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
func (r *Resolver) AcceptsPacket(in *packet.ParsedPacket) bool {
	return in.DstIP == r.ip && in.DstPort == r.port && in.IPProto == packet.UDP
}

// SetMap sets the resolver's DNS map.
func (r *Resolver) SetMap(m *Map) {
	r.mu.Lock()
	r.dnsMap = m
	r.mu.Unlock()
}

// Resolve maps a given domain name to the IP address of the host that owns it.
func (r *Resolver) Resolve(domain string) (netaddr.IP, dns.RCode, error) {
	// If not a subdomain of ipn.dev, then we must refuse this query.
	// We do this before checking the map to distinguish beween nonexistent domains
	// and misdirected queries.
	if !strings.HasSuffix(domain, ".ipv.dev") {
		return netaddr.IP{}, dns.RCodeRefused, errNotOurName
	}

	r.mu.Lock()
	if r.dnsMap == nil {
		r.mu.Unlock()
		return netaddr.IP{}, dns.RCodeServerFailure, errMapNotSet
	}
	addr, found := r.dnsMap.DomainToIP[domain]
	r.mu.Unlock()

	if !found {
		return netaddr.IP{}, dns.RCodeNameError, errNoSuchDomain
	}
	return addr, dns.RCodeSuccess, nil
}

type response struct {
	Header         dns.Header
	ResourceHeader dns.ResourceHeader
	Question       dns.Question
	IP             netaddr.IP
}

// parseQuery parses the query in given packet into a response struct.
func (r *Resolver) parseQuery(query *packet.ParsedPacket, resp *response) error {
	var err error

	resp.Header, err = r.parser.Start(query.Payload())
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

// makeResponse resolves the question stored in resp and sets the answer fields.
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

// marshalAnswer serializes the answer record into an active builder.
func marshalAnswer(resp *response, builder *dns.Builder) error {
	var answer dns.AResource

	err := builder.StartAnswers()
	if err != nil {
		return err
	}

	answerHeader := dns.ResourceHeader{
		Name:  resp.Question.Name,
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		TTL:   3600,
	}
	ip := resp.IP.As16()
	copy(answer.A[:], ip[12:])
	return builder.AResource(answerHeader, answer)
}

// marshalResponse serializes the DNS response
// by appending it to out and returning the resultant buffer.
func marshalResponse(resp *response, out []byte) ([]byte, error) {
	resp.Header.Response = true
	resp.Header.Authoritative = true
	if resp.Header.RecursionDesired {
		resp.Header.RecursionAvailable = true
	}

	builder := dns.NewBuilder(out, resp.Header)

	err := builder.StartQuestions()
	if err != nil {
		return nil, err
	}

	err = builder.Question(resp.Question)
	if err != nil {
		return nil, err
	}

	if resp.Header.RCode == dns.RCodeSuccess {
		err = marshalAnswer(resp, &builder)
		if err != nil {
			return nil, err
		}
	}

	return builder.Finish()
}

// Respond generates a response to the given packet.
// It is assumed that r.AcceptsPacket(query) is true.
func (r *Resolver) Respond(query *packet.ParsedPacket) ([]byte, error) {
	var resp response

	// 0. Generate response header.
	udpHeader := query.UDPHeader()
	udpHeader.ToResponse()

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
		r.logf("tsdns: error during name resolution: ipv6 address: %v", resp.IP)
	}

	// 3. Serialize the response.
respond:
	dnsDataOffset := ipOffset + udpHeader.Len()
	// dns.Builder appends to the passed buffer (without reallocation when possible),
	// so we pass in a zero-length slice starting at the point it should start writing.
	// rbuf is the response slice with the correct length starting at the same point.
	rbuf, err := marshalResponse(&resp, r.responseBuffer[dnsDataOffset:dnsDataOffset])
	if err != nil {
		// This error cannot be reported to the sender:
		// it happened during the generation of a response packet.
		return nil, err
	}

	end := dnsDataOffset + len(rbuf)
	// Failure is impossible: r.responseBuffer has statically sufficient size.
	udpHeader.Marshal(r.responseBuffer[ipOffset:end])

	return r.responseBuffer[:end], nil
}
