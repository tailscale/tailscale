// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsdns provides a Resolver capable of resolving
// domains on a Tailscale network.
package tsdns

import (
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/packet"
)

// defaultTTL is the TTL of all responses from Resolver.
const defaultTTL = 600 * time.Second

var (
	errMapNotSet      = errors.New("domain map not set")
	errNoSuchDomain   = errors.New("domain does not exist")
	errNotImplemented = errors.New("query type not implemented")
	errNotOurName     = errors.New("not an *.ipn.dev domain")
	errNotOurQuery    = errors.New("query not for this resolver")
	errNotQuery       = errors.New("not a DNS query")
	errSmallBuffer    = errors.New("response buffer too small")
)

var (
	defaultIP   = packet.IP(binary.BigEndian.Uint32([]byte{100, 100, 100, 100}))
	defaultPort = uint16(53)
)

// Map is all the data Resolver needs to resolve DNS queries.
type Map struct {
	// domainToIP is a mapping of Tailscale domains to their IP addresses.
	// For example, monitoring.ipn.dev -> 100.64.0.1.
	domainToIP map[string]netaddr.IP
}

// NewMap returns a new Map with domain to address mapping given by domainToIP.
// It takes ownership of the provided map.
func NewMap(domainToIP map[string]netaddr.IP) *Map {
	return &Map{
		domainToIP: domainToIP,
	}
}

// Resolver is a DNS resolver for domain names of the form *.ipn.dev.
type Resolver struct {
	logf logger.Logf

	// ip is the IP on which the resolver is listening.
	ip packet.IP
	// port is the port on which the resolver is listening.
	port uint16

	// mu guards the following fields from being updated while used.
	mu sync.Mutex
	// dnsMap is the map most recently received from the control server.
	dnsMap *Map
}

// NewResolver constructs a resolver with default parameters.
func NewResolver(logf logger.Logf) *Resolver {
	r := &Resolver{
		logf: logf,
		ip:   defaultIP,
		port: defaultPort,
	}

	return r
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
	if !strings.HasSuffix(domain, ".ipn.dev") {
		return netaddr.IP{}, dns.RCodeRefused, errNotOurName
	}

	r.mu.Lock()
	if r.dnsMap == nil {
		r.mu.Unlock()
		return netaddr.IP{}, dns.RCodeServerFailure, errMapNotSet
	}
	addr, found := r.dnsMap.domainToIP[domain]
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
	// TODO(dmytro): support IPv6.
	IP netaddr.IP
}

// parseQuery parses the query in given packet into a response struct.
func (r *Resolver) parseQuery(query *packet.ParsedPacket, resp *response) error {
	var parser dns.Parser
	var err error

	resp.Header, err = parser.Start(query.Payload())
	if err != nil {
		return err
	}

	if resp.Header.Response {
		return errNotQuery
	}

	resp.Question, err = parser.Question()
	if err != nil {
		return err
	}

	return nil
}

// makeResponse resolves the question stored in resp and sets the answer fields.
func (r *Resolver) makeResponse(resp *response) error {
	var err error

	name := resp.Question.Name.String()
	if len(name) > 0 {
		name = name[:len(name)-1]
	}

	if resp.Question.Type == dns.TypeA {
		// Remove final dot from name: *.ipn.dev. -> *.ipn.dev
		resp.IP, resp.Header.RCode, err = r.Resolve(name)
	} else {
		resp.Header.RCode = dns.RCodeNotImplemented
		err = errNotImplemented
	}

	return err
}

// marshalAnswer serializes the answer record into an active builder.
// The caller may continue using the builder following the call.
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
		TTL:   uint32(defaultTTL / time.Second),
	}
	ip := resp.IP.As16()
	copy(answer.A[:], ip[12:])
	return builder.AResource(answerHeader, answer)
}

// marshalResponse serializes the DNS response into an active builder.
// The caller may continue using the builder following the call.
func marshalResponse(resp *response, builder *dns.Builder) error {
	err := builder.StartQuestions()
	if err != nil {
		return err
	}

	err = builder.Question(resp.Question)
	if err != nil {
		return err
	}

	if resp.Header.RCode == dns.RCodeSuccess {
		err = marshalAnswer(resp, builder)
		if err != nil {
			return err
		}
	}

	return nil
}

// marshalReponsePacket marshals a full DNS packet (including headers)
// representing resp, which is a response to query, into buf.
// It returns buf trimmed to the length of the response packet.
func marshalResponsePacket(query *packet.ParsedPacket, resp *response, buf []byte) ([]byte, error) {
	udpHeader := query.UDPHeader()
	udpHeader.ToResponse()
	offset := udpHeader.Len()

	resp.Header.Response = true
	resp.Header.Authoritative = true
	if resp.Header.RecursionDesired {
		resp.Header.RecursionAvailable = true
	}

	// dns.Builder appends to the passed buffer (without reallocation when possible),
	// so we pass in a zero-length slice starting at the point it should start writing.
	builder := dns.NewBuilder(buf[offset:offset], resp.Header)

	err := marshalResponse(resp, &builder)
	if err != nil {
		return nil, err
	}

	// rbuf is the response slice with the correct length starting at offset.
	rbuf, err := builder.Finish()
	if err != nil {
		return nil, err
	}

	end := offset + len(rbuf)
	err = udpHeader.Marshal(buf[:end])
	if err != nil {
		return nil, err
	}

	return buf[:end], nil
}

// Respond writes a response to query into buf and returns buf trimmed to the response length.
// It is assumed that r.AcceptsPacket(query) is true.
func (r *Resolver) Respond(query *packet.ParsedPacket, buf []byte) ([]byte, error) {
	var resp response
	var err error

	// 0. Verify that contract is upheld.
	if !r.AcceptsPacket(query) {
		return nil, errNotOurQuery
	}
	// A DNS response is at least as long as the query
	if len(buf) < len(query.Buffer()) {
		return nil, errSmallBuffer
	}

	// 1. Parse query packet.
	err = r.parseQuery(query, &resp)
	// We will not return this error: it is the sender's fault.
	if err != nil {
		r.logf("tsdns: error during query parsing: %v", err)
		resp.Header.RCode = dns.RCodeFormatError
		return marshalResponsePacket(query, &resp, buf)
	}

	// 2. Service the query.
	err = r.makeResponse(&resp)
	// We will not return this error: it is the sender's fault.
	if err != nil {
		r.logf("tsdns: error during name resolution: %v", err)
		return marshalResponsePacket(query, &resp, buf)
	}
	// For now, we require IPv4 in all cases.
	// If we somehow came up with a non-IPv4 address, it's our fault.
	if !resp.IP.Is4() {
		resp.Header.RCode = dns.RCodeServerFailure
		r.logf("tsdns: error during name resolution: IPv6 address: %v", resp.IP)
	}

	// 3. Serialize the response.
	return marshalResponsePacket(query, &resp, buf)
}
