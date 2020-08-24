// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsdns provides a Resolver capable of resolving
// domains on a Tailscale network.
package tsdns

import (
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

// maxResponseBytes is the maximum size of a response from a Resolver.
const maxResponseBytes = 512

// pendingQueueSize is the maximal number of DNS requests that can await polling.
// If EnqueueRequest is called when this many requests are already pending,
// the request will be dropped to avoid blocking the caller.
const pendingQueueSize = 64

// defaultTTL is the TTL of all responses from Resolver.
const defaultTTL = 600 * time.Second

// ErrClosed indicates that the resolver has been closed and readers should exit.
var ErrClosed = errors.New("closed")

var (
	errFullQueue      = errors.New("request queue full")
	errMapNotSet      = errors.New("domain map not set")
	errNotForwarding  = errors.New("forwarding disabled")
	errNotImplemented = errors.New("query type not implemented")
	errNotQuery       = errors.New("not a DNS query")
	errNotOurName     = errors.New("not a Tailscale DNS name")
)

// Packet represents a DNS payload together with the address of its origin.
type Packet struct {
	// Payload is the application layer DNS payload.
	// Resolver assumes ownership of the request payload when it is enqueued
	// and cedes ownership of the response payload when it is returned from NextResponse.
	Payload []byte
	// Addr is the source address for a request and the destination address for a response.
	Addr netaddr.IPPort
}

// Resolver is a DNS resolver for nodes on the Tailscale network,
// associating them with domain names of the form <mynode>.<mydomain>.<root>.
// If it is asked to resolve a domain that is not of that form,
// it delegates to upstream nameservers if any are set.
type Resolver struct {
	logf logger.Logf
	// forwarder forwards requests to upstream nameservers.
	forwarder *forwarder

	// queue is a buffered channel holding DNS requests queued for resolution.
	queue chan Packet
	// responses is an unbuffered channel to which responses are returned.
	responses chan Packet
	// errors is an unbuffered channel to which errors are returned.
	errors chan error
	// closed signals all goroutines to stop.
	closed chan struct{}
	// wg signals when all goroutines have stopped.
	wg sync.WaitGroup

	// mu guards the following fields from being updated while used.
	mu sync.Mutex
	// dnsMap is the map most recently received from the control server.
	dnsMap *Map
}

// ResolverConfig is the set of configuration options for a Resolver.
type ResolverConfig struct {
	// Logf is the logger to use throughout the Resolver.
	Logf logger.Logf
	// RootDomain is the domain whose subdomains will be resolved locally as Tailscale nodes.
	RootDomain string
	// Forward determines whether the resolver will forward packets to
	// nameservers set with SetUpstreams if the domain name is not of a Tailscale node.
	Forward bool
}

// NewResolver constructs a resolver associated with the given root domain.
// The root domain must be in canonical form (with a trailing period).
func NewResolver(config ResolverConfig) *Resolver {
	r := &Resolver{
		logf:      logger.WithPrefix(config.Logf, "tsdns: "),
		queue:     make(chan Packet, pendingQueueSize),
		responses: make(chan Packet),
		errors:    make(chan error),
		closed:    make(chan struct{}),
	}

	if config.Forward {
		r.forwarder = newForwarder(r.logf, r.responses)
	}

	return r
}

func (r *Resolver) Start() error {
	if r.forwarder != nil {
		if err := r.forwarder.Start(); err != nil {
			return err
		}
	}

	r.wg.Add(1)
	go r.poll()

	return nil
}

// Close shuts down the resolver and ensures poll goroutines have exited.
// The Resolver cannot be used again after Close is called.
func (r *Resolver) Close() {
	select {
	case <-r.closed:
		return
	default:
		// continue
	}
	close(r.closed)

	if r.forwarder != nil {
		r.forwarder.Close()
	}

	r.wg.Wait()
}

// SetMap sets the resolver's DNS map, taking ownership of it.
func (r *Resolver) SetMap(m *Map) {
	r.mu.Lock()
	oldMap := r.dnsMap
	r.dnsMap = m
	r.mu.Unlock()
	r.logf("map diff:\n%s", m.PrettyDiffFrom(oldMap))
}

// SetUpstreams sets the addresses of the resolver's
// upstream nameservers, taking ownership of the argument.
func (r *Resolver) SetUpstreams(upstreams []net.Addr) {
	if r.forwarder != nil {
		r.forwarder.setUpstreams(upstreams)
	}
}

// EnqueueRequest places the given DNS request in the resolver's queue.
// It takes ownership of the payload and does not block.
// If the queue is full, the request will be dropped and an error will be returned.
func (r *Resolver) EnqueueRequest(request Packet) error {
	select {
	case <-r.closed:
		return ErrClosed
	case r.queue <- request:
		return nil
	default:
		return errFullQueue
	}
}

// NextResponse returns a DNS response to a previously enqueued request.
// It blocks until a response is available and gives up ownership of the response payload.
func (r *Resolver) NextResponse() (Packet, error) {
	select {
	case <-r.closed:
		return Packet{}, ErrClosed
	case resp := <-r.responses:
		return resp, nil
	case err := <-r.errors:
		return Packet{}, err
	}
}

// Resolve maps a given domain name to the IP address of the host that owns it.
// The domain name must be in canonical form (with a trailing period).
func (r *Resolver) Resolve(domain string) (netaddr.IP, dns.RCode, error) {
	r.mu.Lock()
	dnsMap := r.dnsMap
	r.mu.Unlock()

	if dnsMap == nil {
		return netaddr.IP{}, dns.RCodeServerFailure, errMapNotSet
	}

	anyHasSuffix := false
	for _, rootDomain := range dnsMap.rootDomains {
		if strings.HasSuffix(domain, rootDomain) {
			anyHasSuffix = true
			break
		}
	}
	if !anyHasSuffix {
		return netaddr.IP{}, dns.RCodeRefused, nil
	}

	addr, found := dnsMap.nameToIP[domain]
	if !found {
		return netaddr.IP{}, dns.RCodeNameError, nil
	}
	return addr, dns.RCodeSuccess, nil
}

// ResolveReverse returns the unique domain name that maps to the given address.
// The returned domain name is in canonical form (with a trailing period).
func (r *Resolver) ResolveReverse(ip netaddr.IP) (string, dns.RCode, error) {
	r.mu.Lock()
	dnsMap := r.dnsMap
	r.mu.Unlock()

	if dnsMap == nil {
		return "", dns.RCodeServerFailure, errMapNotSet
	}
	name, found := dnsMap.ipToName[ip]
	if !found {
		return "", dns.RCodeNameError, nil
	}
	return name, dns.RCodeSuccess, nil
}

func (r *Resolver) poll() {
	defer r.wg.Done()

	var packet Packet
	for {
		select {
		case <-r.closed:
			return
		case packet = <-r.queue:
			// continue
		}

		out, err := r.respond(packet.Payload)

		if err == errNotOurName {
			if r.forwarder != nil {
				err = r.forwarder.forward(packet)
				if err == nil {
					// forward will send response into r.responses, nothing to do.
					continue
				}
			} else {
				err = errNotForwarding
			}
		}

		if err != nil {
			select {
			case <-r.closed:
				return
			case r.errors <- err:
				// continue
			}
		} else {
			packet.Payload = out
			select {
			case <-r.closed:
				return
			case r.responses <- packet:
				// continue
			}
		}
	}
}

type response struct {
	Header   dns.Header
	Question dns.Question
	// Name is the response to a PTR query.
	Name string
	// IP is the response to an A, AAAA, or ANY query.
	IP netaddr.IP
}

// parseQuery parses the query in given packet into a response struct.
func (r *Resolver) parseQuery(query []byte, resp *response) error {
	var parser dns.Parser
	var err error

	resp.Header, err = parser.Start(query)
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

// marshalARecord serializes an A record into an active builder.
// The caller may continue using the builder following the call.
func marshalARecord(name dns.Name, ip netaddr.IP, builder *dns.Builder) error {
	var answer dns.AResource

	answerHeader := dns.ResourceHeader{
		Name:  name,
		Type:  dns.TypeA,
		Class: dns.ClassINET,
		TTL:   uint32(defaultTTL / time.Second),
	}
	ipbytes := ip.As4()
	copy(answer.A[:], ipbytes[:])
	return builder.AResource(answerHeader, answer)
}

// marshalAAAARecord serializes an AAAA record into an active builder.
// The caller may continue using the builder following the call.
func marshalAAAARecord(name dns.Name, ip netaddr.IP, builder *dns.Builder) error {
	var answer dns.AAAAResource

	answerHeader := dns.ResourceHeader{
		Name:  name,
		Type:  dns.TypeAAAA,
		Class: dns.ClassINET,
		TTL:   uint32(defaultTTL / time.Second),
	}
	ipbytes := ip.As16()
	copy(answer.AAAA[:], ipbytes[:])
	return builder.AAAAResource(answerHeader, answer)
}

// marshalPTRRecord serializes a PTR record into an active builder.
// The caller may continue using the builder following the call.
func marshalPTRRecord(queryName dns.Name, name string, builder *dns.Builder) error {
	var answer dns.PTRResource
	var err error

	answerHeader := dns.ResourceHeader{
		Name:  queryName,
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
		TTL:   uint32(defaultTTL / time.Second),
	}
	answer.PTR, err = dns.NewName(name)
	if err != nil {
		return err
	}
	return builder.PTRResource(answerHeader, answer)
}

// marshalResponse serializes the DNS response into a new buffer.
func marshalResponse(resp *response) ([]byte, error) {
	resp.Header.Response = true
	resp.Header.Authoritative = true
	if resp.Header.RecursionDesired {
		resp.Header.RecursionAvailable = true
	}

	builder := dns.NewBuilder(nil, resp.Header)

	err := builder.StartQuestions()
	if err != nil {
		return nil, err
	}

	err = builder.Question(resp.Question)
	if err != nil {
		return nil, err
	}

	// Only successful responses contain answers.
	if resp.Header.RCode != dns.RCodeSuccess {
		return builder.Finish()
	}

	err = builder.StartAnswers()
	if err != nil {
		return nil, err
	}

	switch resp.Question.Type {
	case dns.TypeA, dns.TypeAAAA, dns.TypeALL:
		if resp.IP.Is4() {
			err = marshalARecord(resp.Question.Name, resp.IP, &builder)
		} else {
			err = marshalAAAARecord(resp.Question.Name, resp.IP, &builder)
		}
	case dns.TypePTR:
		err = marshalPTRRecord(resp.Question.Name, resp.Name, &builder)
	}
	if err != nil {
		return nil, err
	}

	return builder.Finish()
}

const (
	rdnsv4Suffix = ".in-addr.arpa."
	rdnsv6Suffix = ".ip6.arpa."
)

// rawNameToLower converts a raw DNS name to a string, lowercasing it.
func rawNameToLower(name []byte) string {
	var sb strings.Builder
	sb.Grow(len(name))

	for _, b := range name {
		if 'A' <= b && b <= 'Z' {
			b = b - 'A' + 'a'
		}
		sb.WriteByte(b)
	}

	return sb.String()
}

// ptrNameToIPv4 transforms a PTR name representing an IPv4 address to said address.
// Such names are IPv4 labels in reverse order followed by .in-addr.arpa.
// For example,
//   4.3.2.1.in-addr.arpa
// is transformed to
//   1.2.3.4
func rdnsNameToIPv4(name string) (ip netaddr.IP, ok bool) {
	name = strings.TrimSuffix(name, rdnsv4Suffix)
	ip, err := netaddr.ParseIP(string(name))
	if err != nil {
		return netaddr.IP{}, false
	}
	if !ip.Is4() {
		return netaddr.IP{}, false
	}
	b := ip.As4()
	return netaddr.IPv4(b[3], b[2], b[1], b[0]), true
}

// ptrNameToIPv6 transforms a PTR name representing an IPv6 address to said address.
// Such names are dot-separated nibbles in reverse order followed by .ip6.arpa.
// For example,
//   b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
// is transformed to
//   2001:db8::567:89ab
func rdnsNameToIPv6(name string) (ip netaddr.IP, ok bool) {
	var b [32]byte
	var ipb [16]byte

	name = strings.TrimSuffix(name, rdnsv6Suffix)
	// 32 nibbles and 31 dots between them.
	if len(name) != 63 {
		return netaddr.IP{}, false
	}

	// Dots and hex digits alternate.
	prevDot := true
	// i ranges over name backward; j ranges over b forward.
	for i, j := len(name)-1, 0; i >= 0; i-- {
		thisDot := (name[i] == '.')
		if prevDot == thisDot {
			return netaddr.IP{}, false
		}
		prevDot = thisDot

		if !thisDot {
			// This is safe assuming alternation.
			// We do not check that non-dots are hex digits: hex.Decode below will do that.
			b[j] = name[i]
			j++
		}
	}

	_, err := hex.Decode(ipb[:], b[:])
	if err != nil {
		return netaddr.IP{}, false
	}

	return netaddr.IPFrom16(ipb), true
}

// respondReverse returns a DNS response to a PTR query.
// It is assumed that resp.Question is populated by respond before this is called.
func (r *Resolver) respondReverse(query []byte, name string, resp *response) ([]byte, error) {
	var ip netaddr.IP
	var ok bool
	var err error
	switch {
	case strings.HasSuffix(name, rdnsv4Suffix):
		ip, ok = rdnsNameToIPv4(name)
	case strings.HasSuffix(name, rdnsv6Suffix):
		ip, ok = rdnsNameToIPv6(name)
	default:
		return nil, errNotOurName
	}

	// It is more likely that we failed in parsing the name than that it is actually malformed.
	// To avoid frustrating users, just log and delegate.
	if !ok {
		// Without this conversion, escape analysis rules that resp escapes.
		r.logf("parsing rdns: malformed name: %s", name)
		return nil, errNotOurName
	}

	resp.Name, resp.Header.RCode, err = r.ResolveReverse(ip)
	if err != nil {
		r.logf("resolving rdns: %v", ip, err)
	}
	if resp.Header.RCode == dns.RCodeNameError {
		return nil, errNotOurName
	}

	return marshalResponse(resp)
}

// respond returns a DNS response to query if it can be resolved locally.
// Otherwise, it returns errNotOurName.
func (r *Resolver) respond(query []byte) ([]byte, error) {
	resp := new(response)

	// ParseQuery is sufficiently fast to run on every DNS packet.
	// This is considerably simpler than extracting the name by hand
	// to shave off microseconds in case of delegation.
	err := r.parseQuery(query, resp)
	// We will not return this error: it is the sender's fault.
	if err != nil {
		r.logf("parsing query: %v", err)
		resp.Header.RCode = dns.RCodeFormatError
		return marshalResponse(resp)
	}
	rawName := resp.Question.Name.Data[:resp.Question.Name.Length]
	name := rawNameToLower(rawName)

	// Always try to handle reverse lookups; delegate inside when not found.
	// This way, queries for exitent nodes do not leak,
	// but we behave gracefully if non-Tailscale nodes exist in CGNATRange.
	if resp.Question.Type == dns.TypePTR {
		return r.respondReverse(query, name, resp)
	}

	switch resp.Question.Type {
	case dns.TypeA, dns.TypeAAAA, dns.TypeALL:
		resp.IP, resp.Header.RCode, err = r.Resolve(name)
		// This return code is special: it requests forwarding.
		if resp.Header.RCode == dns.RCodeRefused {
			return nil, errNotOurName
		}
	default:
		resp.Header.RCode = dns.RCodeNotImplemented
		err = errNotImplemented
	}
	// We will not return this error: it is the sender's fault.
	if err != nil {
		r.logf("resolving: %v", err)
	}

	return marshalResponse(resp)
}
