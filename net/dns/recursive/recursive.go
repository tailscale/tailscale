// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package recursive implements a simple recursive DNS resolver.
package recursive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/envknob"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
	"tailscale.com/util/slicesx"
)

const (
	// maxDepth is how deep from the root nameservers we'll recurse when
	// resolving; passing this limit will instead return an error.
	//
	// maxDepth must be at least 20 to resolve "console.aws.amazon.com",
	// which is a domain with a moderately complicated DNS setup. The
	// current value of 30 was chosen semi-arbitrarily to ensure that we
	// have about 50% headroom.
	maxDepth = 30
	// numStartingServers is the number of root nameservers that we use as
	// initial candidates for our recursion.
	numStartingServers = 3
	// udpQueryTimeout is the amount of time we wait for a UDP response
	// from a nameserver before falling back to a TCP connection.
	udpQueryTimeout = 5 * time.Second

	// These constants aren't typed in the DNS package, so we create typed
	// versions here to avoid having to do repeated type casts.
	qtypeA    dns.Type = dns.Type(dns.TypeA)
	qtypeAAAA dns.Type = dns.Type(dns.TypeAAAA)
)

var (
	// ErrMaxDepth is returned when recursive resolving exceeds the maximum
	// depth limit for this package.
	ErrMaxDepth = fmt.Errorf("exceeded max depth %d when resolving", maxDepth)

	// ErrAuthoritativeNoResponses is the error returned when an
	// authoritative nameserver indicates that there are no responses to
	// the given query.
	ErrAuthoritativeNoResponses = errors.New("authoritative server returned no responses")

	// ErrNoResponses is returned when our resolution process completes
	// with no valid responses from any nameserver, but no authoritative
	// server explicitly returned NXDOMAIN.
	ErrNoResponses = errors.New("no responses to query")
)

var rootServersV4 = []netip.Addr{
	netip.MustParseAddr("198.41.0.4"),     // a.root-servers.net
	netip.MustParseAddr("170.247.170.2"),  // b.root-servers.net
	netip.MustParseAddr("192.33.4.12"),    // c.root-servers.net
	netip.MustParseAddr("199.7.91.13"),    // d.root-servers.net
	netip.MustParseAddr("192.203.230.10"), // e.root-servers.net
	netip.MustParseAddr("192.5.5.241"),    // f.root-servers.net
	netip.MustParseAddr("192.112.36.4"),   // g.root-servers.net
	netip.MustParseAddr("198.97.190.53"),  // h.root-servers.net
	netip.MustParseAddr("192.36.148.17"),  // i.root-servers.net
	netip.MustParseAddr("192.58.128.30"),  // j.root-servers.net
	netip.MustParseAddr("193.0.14.129"),   // k.root-servers.net
	netip.MustParseAddr("199.7.83.42"),    // l.root-servers.net
	netip.MustParseAddr("202.12.27.33"),   // m.root-servers.net
}

var rootServersV6 = []netip.Addr{
	netip.MustParseAddr("2001:503:ba3e::2:30"), // a.root-servers.net
	netip.MustParseAddr("2801:1b8:10::b"),      // b.root-servers.net
	netip.MustParseAddr("2001:500:2::c"),       // c.root-servers.net
	netip.MustParseAddr("2001:500:2d::d"),      // d.root-servers.net
	netip.MustParseAddr("2001:500:a8::e"),      // e.root-servers.net
	netip.MustParseAddr("2001:500:2f::f"),      // f.root-servers.net
	netip.MustParseAddr("2001:500:12::d0d"),    // g.root-servers.net
	netip.MustParseAddr("2001:500:1::53"),      // h.root-servers.net
	netip.MustParseAddr("2001:7fe::53"),        // i.root-servers.net
	netip.MustParseAddr("2001:503:c27::2:30"),  // j.root-servers.net
	netip.MustParseAddr("2001:7fd::1"),         // k.root-servers.net
	netip.MustParseAddr("2001:500:9f::42"),     // l.root-servers.net
	netip.MustParseAddr("2001:dc3::35"),        // m.root-servers.net
}

var debug = envknob.RegisterBool("TS_DEBUG_RECURSIVE_DNS")

// Resolver is a recursive DNS resolver that is designed for looking up A and AAAA records.
type Resolver struct {
	// Dialer is used to create outbound connections. If nil, a zero
	// net.Dialer will be used instead.
	Dialer netns.Dialer

	// Logf is the logging function to use; if none is specified, then logs
	// will be dropped.
	Logf logger.Logf

	// NoIPv6, if set, will prevent this package from querying for AAAA
	// records and will avoid contacting nameservers over IPv6.
	NoIPv6 bool

	// Test mocks
	testQueryHook    func(name dnsname.FQDN, nameserver netip.Addr, protocol string, qtype dns.Type) (*dns.Msg, error)
	testExchangeHook func(nameserver netip.Addr, network string, msg *dns.Msg) (*dns.Msg, error)
	rootServers      []netip.Addr
	timeNow          func() time.Time

	// Caching
	// NOTE(andrew): if we make resolution parallel, this needs a mutex
	queryCache map[dnsQuery]dnsMsgWithExpiry

	// Possible future additions:
	//    - Additional nameservers? From the system maybe?
	//    - NoIPv4 for IPv4
	//    - DNS-over-HTTPS or DNS-over-TLS support
}

// queryState stores all state during the course of a single query
type queryState struct {
	// rootServers are the root nameservers to start from
	rootServers []netip.Addr

	// TODO: metrics?
}

type dnsQuery struct {
	nameserver netip.Addr
	name       dnsname.FQDN
	qtype      dns.Type
}

func (q dnsQuery) String() string {
	return fmt.Sprintf("dnsQuery{nameserver:%q,name:%q,qtype:%v}", q.nameserver.String(), q.name, q.qtype)
}

type dnsMsgWithExpiry struct {
	*dns.Msg
	expiresAt time.Time
}

func (r *Resolver) now() time.Time {
	if r.timeNow != nil {
		return r.timeNow()
	}
	return time.Now()
}

func (r *Resolver) logf(format string, args ...any) {
	if r.Logf == nil {
		return
	}
	r.Logf(format, args...)
}

func (r *Resolver) depthlogf(depth int, format string, args ...any) {
	if r.Logf == nil || !debug() {
		return
	}
	prefix := fmt.Sprintf("[%d] %s", depth, strings.Repeat("  ", depth))
	r.Logf(prefix+format, args...)
}

var defaultDialer net.Dialer

func (r *Resolver) dialer() netns.Dialer {
	if r.Dialer != nil {
		return r.Dialer
	}

	return &defaultDialer
}

func (r *Resolver) newState() *queryState {
	var rootServers []netip.Addr
	if len(r.rootServers) > 0 {
		rootServers = r.rootServers
	} else {
		// Select a random subset of root nameservers to start from, since if
		// we don't get responses from those, something else has probably gone
		// horribly wrong.
		roots4 := slices.Clone(rootServersV4)
		slicesx.Shuffle(roots4)
		roots4 = roots4[:numStartingServers]

		var roots6 []netip.Addr
		if !r.NoIPv6 {
			roots6 = slices.Clone(rootServersV6)
			slicesx.Shuffle(roots6)
			roots6 = roots6[:numStartingServers]
		}

		// Interleave the root servers so that we try to contact them over
		// IPv4, then IPv6, IPv4, IPv6, etc.
		rootServers = slicesx.Interleave(roots4, roots6)
	}

	return &queryState{
		rootServers: rootServers,
	}
}

// Resolve will perform a recursive DNS resolution for the provided name,
// starting at a randomly-chosen root DNS server, and return the A and AAAA
// responses as a slice of netip.Addrs along with the minimum TTL for the
// returned records.
func (r *Resolver) Resolve(ctx context.Context, name string) (addrs []netip.Addr, minTTL time.Duration, err error) {
	dnsName, err := dnsname.ToFQDN(name)
	if err != nil {
		return nil, 0, err
	}

	qstate := r.newState()

	r.logf("querying IPv4 addresses for: %q", name)
	addrs4, minTTL4, err4 := r.resolveRecursiveFromRoot(ctx, qstate, 0, dnsName, qtypeA)

	var (
		addrs6  []netip.Addr
		minTTL6 time.Duration
		err6    error
	)
	if !r.NoIPv6 {
		r.logf("querying IPv6 addresses for: %q", name)
		addrs6, minTTL6, err6 = r.resolveRecursiveFromRoot(ctx, qstate, 0, dnsName, qtypeAAAA)
	}

	if err4 != nil && err6 != nil {
		if err4 == err6 {
			return nil, 0, err4
		}

		return nil, 0, multierr.New(err4, err6)
	}
	if err4 != nil {
		return addrs6, minTTL6, nil
	} else if err6 != nil {
		return addrs4, minTTL4, nil
	}

	minTTL = minTTL4
	if minTTL6 < minTTL {
		minTTL = minTTL6
	}

	addrs = append(addrs4, addrs6...)
	if len(addrs) == 0 {
		return nil, 0, ErrNoResponses
	}

	slicesx.Shuffle(addrs)
	return addrs, minTTL, nil
}

func (r *Resolver) resolveRecursiveFromRoot(
	ctx context.Context,
	qstate *queryState,
	depth int,
	name dnsname.FQDN, // what we're querying
	qtype dns.Type,
) ([]netip.Addr, time.Duration, error) {
	r.depthlogf(depth, "resolving %q from root (type: %v)", name, qtype)

	var depthError bool
	for _, server := range qstate.rootServers {
		addrs, minTTL, err := r.resolveRecursive(ctx, qstate, depth, name, server, qtype)
		if err == nil {
			return addrs, minTTL, err
		} else if errors.Is(err, ErrAuthoritativeNoResponses) {
			return nil, 0, ErrAuthoritativeNoResponses
		} else if errors.Is(err, ErrMaxDepth) {
			depthError = true
		}
	}

	if depthError {
		return nil, 0, ErrMaxDepth
	}
	return nil, 0, ErrNoResponses
}

func (r *Resolver) resolveRecursive(
	ctx context.Context,
	qstate *queryState,
	depth int,
	name dnsname.FQDN, // what we're querying
	nameserver netip.Addr,
	qtype dns.Type,
) ([]netip.Addr, time.Duration, error) {
	if depth == maxDepth {
		r.depthlogf(depth, "not recursing past maximum depth")
		return nil, 0, ErrMaxDepth
	}

	// Ask this nameserver for an answer.
	resp, err := r.queryNameserver(ctx, depth, name, nameserver, qtype)
	if err != nil {
		return nil, 0, err
	}

	// If we get an actual answer from the nameserver, then return it.
	var (
		answers []netip.Addr
		cnames  []dnsname.FQDN
		minTTL  = 24 * 60 * 60 // 24 hours in seconds
	)
	for _, answer := range resp.Answer {
		if crec, ok := answer.(*dns.CNAME); ok {
			cnameFQDN, err := dnsname.ToFQDN(crec.Target)
			if err != nil {
				r.logf("bad CNAME %q returned: %v", crec.Target, err)
				continue
			}

			cnames = append(cnames, cnameFQDN)
			continue
		}

		addr := addrFromRecord(answer)
		if !addr.IsValid() {
			r.logf("[unexpected] invalid record in %T answer", answer)
		} else if addr.Is4() && qtype != qtypeA {
			r.logf("[unexpected] got IPv4 answer but qtype=%v", qtype)
		} else if addr.Is6() && qtype != qtypeAAAA {
			r.logf("[unexpected] got IPv6 answer but qtype=%v", qtype)
		} else {
			answers = append(answers, addr)
			minTTL = min(minTTL, int(answer.Header().Ttl))
		}
	}

	if len(answers) > 0 {
		r.depthlogf(depth, "got answers for %q: %v", name, answers)
		return answers, time.Duration(minTTL) * time.Second, nil
	}

	r.depthlogf(depth, "no answers for %q", name)

	// If we have a non-zero number of CNAMEs, then try resolving those
	// (from the root again) and return the first one that succeeds.
	//
	// TODO: return the union of all responses?
	// TODO: parallelism?
	if len(cnames) > 0 {
		r.depthlogf(depth, "got CNAME responses for %q: %v", name, cnames)
	}
	var cnameDepthError bool
	for _, cname := range cnames {
		answers, minTTL, err := r.resolveRecursiveFromRoot(ctx, qstate, depth+1, cname, qtype)
		if err == nil {
			return answers, minTTL, nil
		} else if errors.Is(err, ErrAuthoritativeNoResponses) {
			return nil, 0, ErrAuthoritativeNoResponses
		} else if errors.Is(err, ErrMaxDepth) {
			cnameDepthError = true
		}
	}

	// If this is an authoritative response, then we know that continuing
	// to look further is not going to result in any answers and we should
	// bail out.
	if resp.MsgHdr.Authoritative {
		// If we failed to recurse into a CNAME due to a depth limit,
		// propagate that here.
		if cnameDepthError {
			return nil, 0, ErrMaxDepth
		}

		r.depthlogf(depth, "got authoritative response with no answers; stopping")
		return nil, 0, ErrAuthoritativeNoResponses
	}

	r.depthlogf(depth, "got %d NS responses and %d ADDITIONAL responses for %q", len(resp.Ns), len(resp.Extra), name)

	// No CNAMEs and no answers; see if we got any AUTHORITY responses,
	// which indicate which nameservers to query next.
	var authorities []dnsname.FQDN
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}

		nsName, err := dnsname.ToFQDN(ns.Ns)
		if err != nil {
			r.logf("unexpected bad NS name %q: %v", ns.Ns, err)
			continue
		}

		authorities = append(authorities, nsName)
	}

	// Also check for "glue" records, which are IP addresses provided by
	// the DNS server for authority responses; these are required when the
	// authority server is a subdomain of what's being resolved.
	glueRecords := make(map[dnsname.FQDN][]netip.Addr)
	for _, rr := range resp.Extra {
		name, err := dnsname.ToFQDN(rr.Header().Name)
		if err != nil {
			r.logf("unexpected bad Name %q in Extra addr: %v", rr.Header().Name, err)
			continue
		}

		if addr := addrFromRecord(rr); addr.IsValid() {
			glueRecords[name] = append(glueRecords[name], addr)
		} else {
			r.logf("unexpected bad Extra %T addr", rr)
		}
	}

	// Try authorities with glue records first, to minimize the number of
	// additional DNS queries that we need to make.
	authoritiesGlue, authoritiesNoGlue := slicesx.Partition(authorities, func(aa dnsname.FQDN) bool {
		return len(glueRecords[aa]) > 0
	})

	authorityDepthError := false

	r.depthlogf(depth, "authorities with glue records for recursion: %v", authoritiesGlue)
	for _, authority := range authoritiesGlue {
		for _, nameserver := range glueRecords[authority] {
			answers, minTTL, err := r.resolveRecursive(ctx, qstate, depth+1, name, nameserver, qtype)
			if err == nil {
				return answers, minTTL, nil
			} else if errors.Is(err, ErrAuthoritativeNoResponses) {
				return nil, 0, ErrAuthoritativeNoResponses
			} else if errors.Is(err, ErrMaxDepth) {
				authorityDepthError = true
			}
		}
	}

	r.depthlogf(depth, "authorities with no glue records for recursion: %v", authoritiesNoGlue)
	for _, authority := range authoritiesNoGlue {
		// First, resolve the IP for the authority server from the
		// root, querying for both IPv4 and IPv6 addresses regardless
		// of what the current question type is.
		//
		// TODO: check for infinite recursion; it'll get caught by our
		// recursion depth, but we want to bail early.
		for _, authorityQtype := range []dns.Type{qtypeAAAA, qtypeA} {
			answers, _, err := r.resolveRecursiveFromRoot(ctx, qstate, depth+1, authority, authorityQtype)
			if err != nil {
				r.depthlogf(depth, "error querying authority %q: %v", authority, err)
				continue
			}
			r.depthlogf(depth, "resolved authority %q (type %v) to: %v", authority, authorityQtype, answers)

			// Now, query this authority for the final address.
			for _, nameserver := range answers {
				answers, minTTL, err := r.resolveRecursive(ctx, qstate, depth+1, name, nameserver, qtype)
				if err == nil {
					return answers, minTTL, nil
				} else if errors.Is(err, ErrAuthoritativeNoResponses) {
					return nil, 0, ErrAuthoritativeNoResponses
				} else if errors.Is(err, ErrMaxDepth) {
					authorityDepthError = true
				}
			}
		}
	}

	if authorityDepthError {
		return nil, 0, ErrMaxDepth
	}
	return nil, 0, ErrNoResponses
}

// queryNameserver sends a query for "name" to the nameserver "nameserver" for
// records of type "qtype", trying both UDP and TCP connections as
// appropriate.
func (r *Resolver) queryNameserver(
	ctx context.Context,
	depth int,
	name dnsname.FQDN, // what we're querying
	nameserver netip.Addr, // destination of query
	qtype dns.Type,
) (*dns.Msg, error) {
	// TODO(andrew): we should QNAME minimisation here to avoid sending the
	// full name to intermediate/root nameservers. See:
	//    https://www.rfc-editor.org/rfc/rfc7816

	// Handle the case where UDP is blocked by adding an explicit timeout
	// for the UDP portion of this query.
	udpCtx, udpCtxCancel := context.WithTimeout(ctx, udpQueryTimeout)
	defer udpCtxCancel()

	msg, err := r.queryNameserverProto(udpCtx, depth, name, nameserver, "udp", qtype)
	if err == nil {
		return msg, nil
	}

	msg, err2 := r.queryNameserverProto(ctx, depth, name, nameserver, "tcp", qtype)
	if err2 == nil {
		return msg, nil
	}

	return nil, multierr.New(err, err2)
}

// queryNameserverProto sends a query for "name" to the nameserver "nameserver"
// for records of type "qtype" over the provided protocol (either "udp"
// or "tcp"), and returns the DNS response or an error.
func (r *Resolver) queryNameserverProto(
	ctx context.Context,
	depth int,
	name dnsname.FQDN, // what we're querying
	nameserver netip.Addr, // destination of query
	protocol string,
	qtype dns.Type,
) (resp *dns.Msg, err error) {
	if r.testQueryHook != nil {
		return r.testQueryHook(name, nameserver, protocol, qtype)
	}

	now := r.now()
	nameserverStr := nameserver.String()

	cacheKey := dnsQuery{
		nameserver: nameserver,
		name:       name,
		qtype:      qtype,
	}
	cacheEntry, ok := r.queryCache[cacheKey]
	if ok && cacheEntry.expiresAt.Before(now) {
		r.depthlogf(depth, "using cached response from %s about %q (type: %v)", nameserverStr, name, qtype)
		return cacheEntry.Msg, nil
	}

	var network string
	if nameserver.Is4() {
		network = protocol + "4"
	} else {
		network = protocol + "6"
	}

	// Prepare a message asking for an appropriately-typed record
	// for the name we're querying.
	m := new(dns.Msg)
	m.SetQuestion(name.WithTrailingDot(), uint16(qtype))

	// Allow mocking out the network components with our exchange hook.
	if r.testExchangeHook != nil {
		resp, err = r.testExchangeHook(nameserver, network, m)
	} else {
		// Dial the current nameserver using our dialer.
		var nconn net.Conn
		nconn, err = r.dialer().DialContext(ctx, network, net.JoinHostPort(nameserverStr, "53"))
		if err != nil {
			return nil, err
		}

		var c dns.Client // TODO: share?
		conn := &dns.Conn{
			Conn:    nconn,
			UDPSize: c.UDPSize,
		}

		// Send the DNS request to the current nameserver.
		r.depthlogf(depth, "asking %s over %s about %q (type: %v)", nameserverStr, protocol, name, qtype)
		resp, _, err = c.ExchangeWithConnContext(ctx, m, conn)
	}
	if err != nil {
		return nil, err
	}

	// If the message was truncated and we're using UDP, re-run with TCP.
	if resp.MsgHdr.Truncated && protocol == "udp" {
		r.depthlogf(depth, "response message truncated; re-running query with TCP")
		resp, err = r.queryNameserverProto(ctx, depth, name, nameserver, "tcp", qtype)
		if err != nil {
			return nil, err
		}
	}

	// Find minimum expiry for all records in this message.
	var minTTL int
	for _, rr := range resp.Answer {
		minTTL = min(minTTL, int(rr.Header().Ttl))
	}
	for _, rr := range resp.Ns {
		minTTL = min(minTTL, int(rr.Header().Ttl))
	}
	for _, rr := range resp.Extra {
		minTTL = min(minTTL, int(rr.Header().Ttl))
	}

	mak.Set(&r.queryCache, cacheKey, dnsMsgWithExpiry{
		Msg:       resp,
		expiresAt: now.Add(time.Duration(minTTL) * time.Second),
	})
	return resp, nil
}

func addrFromRecord(rr dns.RR) netip.Addr {
	switch v := rr.(type) {
	case *dns.A:
		ip, ok := netip.AddrFromSlice(v.A)
		if !ok || !ip.Is4() {
			return netip.Addr{}
		}
		return ip
	case *dns.AAAA:
		ip, ok := netip.AddrFromSlice(v.AAAA)
		if !ok || !ip.Is6() {
			return netip.Addr{}
		}
		return ip
	}
	return netip.Addr{}
}
