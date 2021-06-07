// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package resolver implements a stub DNS resolver that can also serve
// records out of an internal local zone.
package resolver

import (
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/monitor"
)

// maxResponseBytes is the maximum size of a response from a Resolver. The
// actual buffer size will be one larger than this so that we can detect
// truncation in a platform-agnostic way.
const maxResponseBytes = 4095

// queueSize is the maximal number of DNS requests that can await polling.
// If EnqueueRequest is called when this many requests are already pending,
// the request will be dropped to avoid blocking the caller.
const queueSize = 64

// defaultTTL is the TTL of all responses from Resolver.
const defaultTTL = 600 * time.Second

// ErrClosed indicates that the resolver has been closed and readers should exit.
var ErrClosed = errors.New("closed")

var (
	errFullQueue  = errors.New("request queue full")
	errNotQuery   = errors.New("not a DNS query")
	errNotOurName = errors.New("not a Tailscale DNS name")
)

type packet struct {
	bs   []byte
	addr netaddr.IPPort // src for a request, dst for a response
}

// Config is a resolver configuration.
// Given a Config, queries are resolved in the following order:
// If the query is an exact match for an entry in LocalHosts, return that.
// Else if the query suffix matches an entry in LocalDomains, return NXDOMAIN.
// Else forward the query to the most specific matching entry in Routes.
// Else return SERVFAIL.
type Config struct {
	// Routes is a map of DNS name suffix to the resolvers to use for
	// queries within that suffix.
	// Queries only match the most specific suffix.
	// To register a "default route", add an entry for ".".
	Routes map[dnsname.FQDN][]netaddr.IPPort
	// LocalHosts is a map of FQDNs to corresponding IPs.
	Hosts map[dnsname.FQDN][]netaddr.IP
	// LocalDomains is a list of DNS name suffixes that should not be
	// routed to upstream resolvers.
	LocalDomains []dnsname.FQDN
}

// Resolver is a DNS resolver for nodes on the Tailscale network,
// associating them with domain names of the form <mynode>.<mydomain>.<root>.
// If it is asked to resolve a domain that is not of that form,
// it delegates to upstream nameservers if any are set.
type Resolver struct {
	logf               logger.Logf
	linkMon            *monitor.Mon     // or nil
	unregLinkMon       func()           // or nil
	saveConfigForTests func(cfg Config) // used in tests to capture resolver config
	// forwarder forwards requests to upstream nameservers.
	forwarder *forwarder

	// queue is a buffered channel holding DNS requests queued for resolution.
	queue chan packet
	// responses is an unbuffered channel to which responses are returned.
	responses chan packet
	// errors is an unbuffered channel to which errors are returned.
	errors chan error
	// closed signals all goroutines to stop.
	closed chan struct{}
	// wg signals when all goroutines have stopped.
	wg sync.WaitGroup

	// mu guards the following fields from being updated while used.
	mu           sync.Mutex
	localDomains []dnsname.FQDN
	hostToIP     map[dnsname.FQDN][]netaddr.IP
	ipToHost     map[netaddr.IP]dnsname.FQDN
}

// New returns a new resolver.
// linkMon optionally specifies a link monitor to use for socket rebinding.
func New(logf logger.Logf, linkMon *monitor.Mon) *Resolver {
	r := &Resolver{
		logf:      logger.WithPrefix(logf, "dns: "),
		linkMon:   linkMon,
		queue:     make(chan packet, queueSize),
		responses: make(chan packet),
		errors:    make(chan error),
		closed:    make(chan struct{}),
		hostToIP:  map[dnsname.FQDN][]netaddr.IP{},
		ipToHost:  map[netaddr.IP]dnsname.FQDN{},
	}
	r.forwarder = newForwarder(r.logf, r.responses)
	if r.linkMon != nil {
		r.unregLinkMon = r.linkMon.RegisterChangeCallback(r.onLinkMonitorChange)
	}

	r.wg.Add(1)
	go r.poll()

	return r
}

func (r *Resolver) TestOnlySetHook(hook func(Config)) { r.saveConfigForTests = hook }

func (r *Resolver) SetConfig(cfg Config) error {
	if r.saveConfigForTests != nil {
		r.saveConfigForTests(cfg)
	}

	routes := make([]route, 0, len(cfg.Routes))
	reverse := make(map[netaddr.IP]dnsname.FQDN, len(cfg.Hosts))

	for host, ips := range cfg.Hosts {
		for _, ip := range ips {
			reverse[ip] = host
		}
	}

	for suffix, ips := range cfg.Routes {
		routes = append(routes, route{
			suffix:    suffix,
			resolvers: ips,
		})
	}
	// Sort from longest prefix to shortest.
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].suffix.NumLabels() > routes[j].suffix.NumLabels()
	})

	r.forwarder.setRoutes(routes)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.localDomains = cfg.LocalDomains
	r.hostToIP = cfg.Hosts
	r.ipToHost = reverse
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

	if r.unregLinkMon != nil {
		r.unregLinkMon()
	}

	r.forwarder.Close()
	r.wg.Wait()
}

func (r *Resolver) onLinkMonitorChange(changed bool, state *interfaces.State) {
	if !changed {
		return
	}
	r.forwarder.rebindFromNetworkChange()
}

// EnqueueRequest places the given DNS request in the resolver's queue.
// It takes ownership of the payload and does not block.
// If the queue is full, the request will be dropped and an error will be returned.
func (r *Resolver) EnqueueRequest(bs []byte, from netaddr.IPPort) error {
	select {
	case <-r.closed:
		return ErrClosed
	case r.queue <- packet{bs, from}:
		return nil
	default:
		return errFullQueue
	}
}

// NextResponse returns a DNS response to a previously enqueued request.
// It blocks until a response is available and gives up ownership of the response payload.
func (r *Resolver) NextResponse() (packet []byte, to netaddr.IPPort, err error) {
	select {
	case <-r.closed:
		return nil, netaddr.IPPort{}, ErrClosed
	case resp := <-r.responses:
		return resp.bs, resp.addr, nil
	case err := <-r.errors:
		return nil, netaddr.IPPort{}, err
	}
}

// resolveLocal returns an IP for the given domain, if domain is in
// the local hosts map and has an IP corresponding to the requested
// typ (A, AAAA, ALL).
// Returns dns.RCodeRefused to indicate that the local map is not
// authoritative for domain.
func (r *Resolver) resolveLocal(domain dnsname.FQDN, typ dns.Type) (netaddr.IP, dns.RCode) {
	// Reject .onion domains per RFC 7686.
	if dnsname.HasSuffix(domain.WithoutTrailingDot(), ".onion") {
		return netaddr.IP{}, dns.RCodeNameError
	}

	r.mu.Lock()
	hosts := r.hostToIP
	localDomains := r.localDomains
	r.mu.Unlock()

	addrs, found := hosts[domain]
	if !found {
		for _, suffix := range localDomains {
			if suffix.Contains(domain) {
				// We are authoritative for the queried domain.
				return netaddr.IP{}, dns.RCodeNameError
			}
		}
		// Not authoritative, signal that forwarding is advisable.
		return netaddr.IP{}, dns.RCodeRefused
	}

	// Refactoring note: this must happen after we check suffixes,
	// otherwise we will respond with NOTIMP to requests that should be forwarded.
	//
	// DNS semantics subtlety: when a DNS name exists, but no records
	// are available for the requested record type, we must return
	// RCodeSuccess with no data, not NXDOMAIN.
	switch typ {
	case dns.TypeA:
		for _, ip := range addrs {
			if ip.Is4() {
				return ip, dns.RCodeSuccess
			}
		}
		return netaddr.IP{}, dns.RCodeSuccess
	case dns.TypeAAAA:
		for _, ip := range addrs {
			if ip.Is6() {
				return ip, dns.RCodeSuccess
			}
		}
		return netaddr.IP{}, dns.RCodeSuccess
	case dns.TypeALL:
		// Answer with whatever we've got.
		// It could be IPv4, IPv6, or a zero addr.
		// TODO: Return all available resolutions (A and AAAA, if we have them).
		if len(addrs) == 0 {
			return netaddr.IP{}, dns.RCodeSuccess
		}
		return addrs[0], dns.RCodeSuccess

	// Leave some some record types explicitly unimplemented.
	// These types relate to recursive resolution or special
	// DNS semantics and might be implemented in the future.
	case dns.TypeNS, dns.TypeSOA, dns.TypeAXFR, dns.TypeHINFO:
		return netaddr.IP{}, dns.RCodeNotImplemented

	// For everything except for the few types above that are explictly not implemented, return no records.
	// This is what other DNS systems do: always return NOERROR
	// without any records whenever the requested record type is unknown.
	// You can try this with:
	//   dig -t TYPE9824 example.com
	// and note that NOERROR is returned, despite that record type being made up.
	default:
		// The name exists, but no records exist of the requested type.
		return netaddr.IP{}, dns.RCodeSuccess
	}
}

// resolveReverse returns the unique domain name that maps to the given address.
func (r *Resolver) resolveLocalReverse(ip netaddr.IP) (dnsname.FQDN, dns.RCode) {
	r.mu.Lock()
	ips := r.ipToHost
	r.mu.Unlock()

	name, found := ips[ip]
	if !found {
		return "", dns.RCodeNameError
	}
	return name, dns.RCodeSuccess
}

func (r *Resolver) poll() {
	defer r.wg.Done()

	var pkt packet
	for {
		select {
		case <-r.closed:
			return
		case pkt = <-r.queue:
			// continue
		}

		out, err := r.respond(pkt.bs)

		if err == errNotOurName {
			err = r.forwarder.forward(pkt)
			if err == nil {
				// forward will send response into r.responses, nothing to do.
				continue
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
			pkt.bs = out
			select {
			case <-r.closed:
				return
			case r.responses <- pkt:
				// continue
			}
		}
	}
}

type response struct {
	Header   dns.Header
	Question dns.Question
	// Name is the response to a PTR query.
	Name dnsname.FQDN
	// IP is the response to an A, AAAA, or ALL query.
	IP netaddr.IP
}

// parseQuery parses the query in given packet into a response struct.
// if the parse is successful, resp.Name contains the normalized name being queried.
// TODO: stuffing the query name in resp.Name temporarily is a hack. Clean it up.
func parseQuery(query []byte, resp *response) error {
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
func marshalPTRRecord(queryName dns.Name, name dnsname.FQDN, builder *dns.Builder) error {
	var answer dns.PTRResource
	var err error

	answerHeader := dns.ResourceHeader{
		Name:  queryName,
		Type:  dns.TypePTR,
		Class: dns.ClassINET,
		TTL:   uint32(defaultTTL / time.Second),
	}
	answer.PTR, err = dns.NewName(name.WithTrailingDot())
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

	isSuccess := resp.Header.RCode == dns.RCodeSuccess

	if resp.Question.Type != 0 || isSuccess {
		err := builder.StartQuestions()
		if err != nil {
			return nil, err
		}

		err = builder.Question(resp.Question)
		if err != nil {
			return nil, err
		}
	}

	// Only successful responses contain answers.
	if !isSuccess {
		return builder.Finish()
	}

	err := builder.StartAnswers()
	if err != nil {
		return nil, err
	}

	switch resp.Question.Type {
	case dns.TypeA, dns.TypeAAAA, dns.TypeALL:
		if resp.IP.Is4() {
			err = marshalARecord(resp.Question.Name, resp.IP, &builder)
		} else if resp.IP.Is6() {
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

// hasRDNSBonjourPrefix reports whether name has a Bonjour Service Prefix..
//
// https://tools.ietf.org/html/rfc6763 lists
// "five special RR names" for Bonjour service discovery:
//
//   b._dns-sd._udp.<domain>.
//  db._dns-sd._udp.<domain>.
//   r._dns-sd._udp.<domain>.
//  dr._dns-sd._udp.<domain>.
//  lb._dns-sd._udp.<domain>.
func hasRDNSBonjourPrefix(name dnsname.FQDN) bool {
	// Even the shortest name containing a Bonjour prefix is long,
	// so check length (cheap) and bail early if possible.
	if len(name) < len("*._dns-sd._udp.0.0.0.0.in-addr.arpa.") {
		return false
	}
	s := name.WithTrailingDot()
	dot := strings.IndexByte(s, '.')
	if dot == -1 {
		return false // shouldn't happen
	}
	switch s[:dot] {
	case "b", "db", "r", "dr", "lb":
	default:
		return false
	}

	return strings.HasPrefix(s[dot:], "._dns-sd._udp.")
}

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
func rdnsNameToIPv4(name dnsname.FQDN) (ip netaddr.IP, ok bool) {
	s := strings.TrimSuffix(name.WithTrailingDot(), rdnsv4Suffix)
	ip, err := netaddr.ParseIP(s)
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
func rdnsNameToIPv6(name dnsname.FQDN) (ip netaddr.IP, ok bool) {
	var b [32]byte
	var ipb [16]byte

	s := strings.TrimSuffix(name.WithTrailingDot(), rdnsv6Suffix)
	// 32 nibbles and 31 dots between them.
	if len(s) != 63 {
		return netaddr.IP{}, false
	}

	// Dots and hex digits alternate.
	prevDot := true
	// i ranges over name backward; j ranges over b forward.
	for i, j := len(s)-1, 0; i >= 0; i-- {
		thisDot := (s[i] == '.')
		if prevDot == thisDot {
			return netaddr.IP{}, false
		}
		prevDot = thisDot

		if !thisDot {
			// This is safe assuming alternation.
			// We do not check that non-dots are hex digits: hex.Decode below will do that.
			b[j] = s[i]
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
func (r *Resolver) respondReverse(query []byte, name dnsname.FQDN, resp *response) ([]byte, error) {
	if hasRDNSBonjourPrefix(name) {
		return nil, errNotOurName
	}

	var ip netaddr.IP
	var ok bool
	switch {
	case strings.HasSuffix(name.WithTrailingDot(), rdnsv4Suffix):
		ip, ok = rdnsNameToIPv4(name)
	case strings.HasSuffix(name.WithTrailingDot(), rdnsv6Suffix):
		ip, ok = rdnsNameToIPv6(name)
	default:
		return nil, errNotOurName
	}

	// It is more likely that we failed in parsing the name than that it is actually malformed.
	// To avoid frustrating users, just log and delegate.
	if !ok {
		r.logf("parsing rdns: malformed name: %s", name)
		return nil, errNotOurName
	}

	resp.Name, resp.Header.RCode = r.resolveLocalReverse(ip)
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
	err := parseQuery(query, resp)
	// We will not return this error: it is the sender's fault.
	if err != nil {
		if errors.Is(err, dns.ErrSectionDone) {
			r.logf("parseQuery(%02x): no DNS questions", query)
		} else {
			r.logf("parseQuery(%02x): %v", query, err)
		}
		resp.Header.RCode = dns.RCodeFormatError
		return marshalResponse(resp)
	}
	rawName := resp.Question.Name.Data[:resp.Question.Name.Length]
	name, err := dnsname.ToFQDN(rawNameToLower(rawName))
	if err != nil {
		// DNS packet unexpectedly contains an invalid FQDN.
		resp.Header.RCode = dns.RCodeFormatError
		return marshalResponse(resp)
	}

	// Always try to handle reverse lookups; delegate inside when not found.
	// This way, queries for existent nodes do not leak,
	// but we behave gracefully if non-Tailscale nodes exist in CGNATRange.
	if resp.Question.Type == dns.TypePTR {
		return r.respondReverse(query, name, resp)
	}

	resp.IP, resp.Header.RCode = r.resolveLocal(name, resp.Question.Type)
	// This return code is special: it requests forwarding.
	if resp.Header.RCode == dns.RCodeRefused {
		return nil, errNotOurName
	}

	return marshalResponse(resp)
}
