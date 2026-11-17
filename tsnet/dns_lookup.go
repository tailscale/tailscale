// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	dnsmessage "golang.org/x/net/dns/dnsmessage"

	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

// dnsResolver resolves addresses under the server's current tailnet DNS policy.
// Its callbacks require a running backend and must be safe for concurrent use.
type dnsResolver struct {
	// queryDNS uses the internal resolver's TCP query path. routed reports
	// whether tailnet policy routes the name to an upstream. Routed queries
	// never fall back to the host resolver, even on error.
	queryDNS func(context.Context, dnsname.FQDN, dnsmessage.Type) (response []byte, routed bool, err error)

	// searchDomains returns the current tailnet search domains in order.
	searchDomains func() []dnsname.FQDN
}

// lookupIP resolves host according to [Server.LookupIP].
// It returns the first candidate with addresses, or the last candidate's error.
func (c *dnsResolver) lookupIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, &net.DNSError{Err: "empty host name", Name: host, IsNotFound: true}
	}

	switch {
	case strings.HasSuffix(network, "4"):
		network = "ip4"
	case strings.HasSuffix(network, "6"):
		network = "ip6"
	default:
		network = "ip"
	}

	if ip, err := netip.ParseAddr(strings.TrimSuffix(host, ".")); err == nil {
		ip = ip.Unmap()
		if (network == "ip4" && ip.Is6()) || (network == "ip6" && ip.Is4()) {
			return nil, &net.DNSError{Err: "address does not match the requested address family", Name: host, IsNotFound: true}
		}
		return []netip.Addr{ip}, nil
	}

	var search []dnsname.FQDN
	if c.searchDomains != nil {
		search = c.searchDomains()
	}
	names, err := searchCandidates(host, search)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: host, IsNotFound: true}
	}

	var last candidateResult
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, ctxError(err, host)
		}
		res := c.lookupCandidate(ctx, network, name, hostFallbackName(name, host))
		if len(res.ips) > 0 {
			return res.ips, nil
		}
		last = res
	}
	return nil, last.asError(host)
}

// ctxError annotates err with host and preserves errors.Is matching.
func ctxError(err error, host string) error {
	return fmt.Errorf("dns lookup %s: %w", host, err)
}

// hostFallbackName returns candidate as an absolute name, except that a
// relative single-label host retains its form for host search expansion.
func hostFallbackName(candidate dnsname.FQDN, host string) string {
	trimmed := strings.TrimSuffix(host, ".")
	bare := !strings.Contains(trimmed, ".") && !strings.HasSuffix(host, ".")
	if bare {
		if fqdn, err := dnsname.ToFQDN(host); err == nil && fqdn == candidate {
			return host
		}
	}
	return candidate.WithTrailingDot()
}

// searchDomainsFromNetmap returns nm's search domains in order, followed by
// the MagicDNS suffix if enabled and not already present. It returns nil for nil nm.
func searchDomainsFromNetmap(nm *netmap.NetworkMap) []dnsname.FQDN {
	if nm == nil {
		return nil
	}
	var out []dnsname.FQDN
	for _, dom := range nm.DNS.Domains {
		if fqdn, err := dnsname.ToFQDN(dom); err == nil && fqdn != "." {
			addSearchDomain(&out, fqdn)
		}
	}
	if nm.DNS.Proxied { // MagicDNS enabled
		if sfx := nm.MagicDNSSuffix(); sfx != "" {
			if fqdn, err := dnsname.ToFQDN(sfx); err == nil && fqdn != "." {
				addSearchDomain(&out, fqdn)
			}
		}
	}
	return out
}

// addSearchDomain appends the lowercase fqdn to dst if not already present.
func addSearchDomain(dst *[]dnsname.FQDN, fqdn dnsname.FQDN) {
	fqdn = dnsname.FQDN(strings.ToLower(string(fqdn)))
	if !slices.Contains(*dst, fqdn) {
		*dst = append(*dst, fqdn)
	}
}

type candidateResult struct {
	ips      []netip.Addr // non-empty on success
	notFound bool         // authoritative NXDOMAIN or no records
	servfail bool         // SERVFAIL from upstream or policy
	err      error        // transport or other error
}

func (res candidateResult) asError(host string) error {
	switch {
	case res.err != nil:
		var dnsErr *net.DNSError
		if errors.As(res.err, &dnsErr) {
			return dnsErr
		}
		return fmt.Errorf("dns lookup %s: %w", host, res.err)
	case res.notFound:
		return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	case res.servfail:
		return &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
	default:
		return &net.DNSError{Err: "DNS lookup returned no results", Name: host, IsNotFound: true}
	}
}

// lookupCandidate resolves name for the address families selected by network.
// Host fallback requires no configured route and SERVFAIL or transport errors
// from every queried family.
func (c *dnsResolver) lookupCandidate(ctx context.Context, network string, name dnsname.FQDN, hostFB string) candidateResult {
	var (
		wg               sync.WaitGroup
		res4, res6       *queryResult
		routed4, routed6 bool
	)
	query := func(qtype dnsmessage.Type) {
		q, routed := c.query(ctx, name, qtype)
		if qtype == dnsmessage.TypeA {
			res4, routed4 = &q, routed
		} else {
			res6, routed6 = &q, routed
		}
	}
	switch network {
	case "ip4":
		wg.Add(1)
		go func() { defer wg.Done(); query(dnsmessage.TypeA) }()
	case "ip6":
		wg.Add(1)
		go func() { defer wg.Done(); query(dnsmessage.TypeAAAA) }()
	default:
		wg.Add(2)
		go func() { defer wg.Done(); query(dnsmessage.TypeA) }()
		go func() { defer wg.Done(); query(dnsmessage.TypeAAAA) }()
	}
	wg.Wait()

	var ips []netip.Addr
	if res4 != nil {
		ips = append(ips, res4.ips...)
	}
	if res6 != nil {
		ips = append(ips, res6.ips...)
	}
	if len(ips) > 0 {
		return candidateResult{ips: ips}
	}

	attempted := 0
	allNotFound := true
	allServfail := true
	var firstErr error
	for _, qr := range []*queryResult{res4, res6} {
		if qr == nil {
			continue
		}
		attempted++
		allNotFound = allNotFound && qr.notFound
		allServfail = allServfail && (qr.servfail || qr.err != nil)
		if qr.err != nil && firstErr == nil {
			firstErr = qr.err
		}
	}
	if attempted == 0 {
		return candidateResult{err: errors.New("no address families to query")}
	}

	// A configured route for either family disables host fallback.
	routed := routed4 || routed6
	if !routed && allServfail {
		return c.hostLookup(ctx, network, hostFB)
	}
	switch {
	case allNotFound:
		return candidateResult{notFound: true}
	case allServfail:
		return candidateResult{servfail: true, err: firstErr}
	default:
		// A query failure takes precedence over another family's denial.
		return candidateResult{servfail: true, err: firstErr}
	}
}

// hostLookup resolves name using net.DefaultResolver.
func (c *dnsResolver) hostLookup(ctx context.Context, network string, name string) candidateResult {
	stdIPs, err := net.DefaultResolver.LookupIP(ctx, network, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return candidateResult{notFound: true, err: err}
		}
		return candidateResult{err: err}
	}
	var ips []netip.Addr
	for _, ip := range stdIPs {
		if a, ok := netip.AddrFromSlice(ip); ok {
			ips = append(ips, a.Unmap())
		}
	}
	if len(ips) == 0 {
		return candidateResult{notFound: true}
	}
	return candidateResult{ips: ips}
}

type queryResult struct {
	ips      []netip.Addr
	notFound bool
	servfail bool
	err      error
}

func (c *dnsResolver) query(ctx context.Context, name dnsname.FQDN, qtype dnsmessage.Type) (res queryResult, routed bool) {
	bs, routed, err := c.queryDNS(ctx, name, qtype)
	if err != nil {
		return queryResult{err: err}, routed
	}
	return parseResponse(bs, name, qtype), routed
}

// parseResponse reads a wire-format DNS response for name and qtype.
// The response question must match. Records of other types, including
// CNAMEs, are ignored. Successful responses without records of the
// requested type are treated as not found.
func parseResponse(payload []byte, name dnsname.FQDN, qtype dnsmessage.Type) queryResult {
	var p dnsmessage.Parser
	hdr, err := p.Start(payload)
	if err != nil {
		return queryResult{err: fmt.Errorf("parsing DNS response: %w", err)}
	}
	q, err := p.Question()
	if err != nil {
		return queryResult{err: fmt.Errorf("parsing DNS response: %w", err)}
	}
	if !strings.EqualFold(q.Name.String(), name.WithTrailingDot()) ||
		q.Type != qtype || q.Class != dnsmessage.ClassINET {
		return queryResult{err: errors.New("response question does not match the query")}
	}
	if err := p.SkipAllQuestions(); err != nil {
		return queryResult{err: fmt.Errorf("parsing DNS response: %w", err)}
	}
	if hdr.Truncated {
		return queryResult{err: errors.New("truncated DNS response")}
	}
	switch hdr.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return queryResult{notFound: true}
	case dnsmessage.RCodeServerFailure:
		return queryResult{servfail: true}
	default:
		// Treat other DNS failure codes as SERVFAIL.
		return queryResult{servfail: true}
	}
	var res queryResult
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return queryResult{err: fmt.Errorf("parsing DNS response: %w", err)}
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			rec, err := p.AResource()
			if err != nil {
				return queryResult{err: fmt.Errorf("parsing DNS response: %w", err)}
			}
			if qtype == dnsmessage.TypeA {
				res.ips = append(res.ips, netip.AddrFrom4(rec.A))
			}
		case dnsmessage.TypeAAAA:
			rec, err := p.AAAAResource()
			if err != nil {
				return queryResult{err: fmt.Errorf("parsing DNS response: %w", err)}
			}
			if qtype != dnsmessage.TypeAAAA {
				continue
			}
			ip := netip.AddrFrom16(rec.AAAA)
			if ip.Is4In6() {
				continue
			}
			res.ips = append(res.ips, ip)
		default:
			if err := p.SkipAnswer(); err != nil {
				return queryResult{err: fmt.Errorf("parsing DNS response: %w", err)}
			}
		}
	}
	if len(res.ips) == 0 {
		res.notFound = true
	}
	return res
}

// searchCandidates returns host's query candidates in ndots=1 search
// order. See [Server.LookupIP].
func searchCandidates(host string, searchDomains []dnsname.FQDN) ([]dnsname.FQDN, error) {
	absolute := strings.HasSuffix(host, ".")
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, errors.New("empty name")
	}
	self, err := dnsname.ToFQDN(host)
	if err != nil {
		return nil, err
	}
	if absolute {
		return []dnsname.FQDN{self}, nil
	}
	var qualified []dnsname.FQDN
	for _, sd := range searchDomains {
		if fqdn, err := dnsname.ToFQDN(host + "." + sd.WithTrailingDot()); err == nil {
			qualified = append(qualified, fqdn)
		}
	}
	if strings.Count(host, ".") >= 1 {
		return append([]dnsname.FQDN{self}, qualified...), nil
	}
	return append(qualified, self), nil
}
