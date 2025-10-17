package resolver

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/dnsname"
)

// SubResolver is used by resolvers to recursively resolve the DNS server.
type SubResolver struct {
	parentForwarder *forwarder
	parentResolver  resolverAndDelay
}

// NewSubResolver creates a new SubResolver
//
// f: the parent forwarder
// rr: is the resolverAndDelay of the parent forwarder that this SubResolver is held by
func NewSubResolver(f *forwarder, rr resolverAndDelay) SubResolver {
	return SubResolver{
		parentForwarder: f,
		parentResolver:  rr,
	}
}

// queryRRs resolves from given resolverAndDelays
func (r SubResolver) queryRRs(ctx context.Context, fqdn dnsname.FQDN, queryType dnsmessage.Type, rr ...resolverAndDelay) ([]netip.Addr, error) {
	n, err := dnsmessage.NewName(fqdn.WithTrailingDot())
	db := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		OpCode:           0,
		RecursionDesired: true,
		ID:               1,
	})
	db.StartQuestions()
	db.Question(dnsmessage.Question{
		Name:  n,
		Type:  queryType,
		Class: dnsmessage.ClassINET,
	})
	queryPkt, err := db.Finish()
	if err != nil {
		return nil, err
	}

	from := netip.MustParseAddrPort("127.0.0.1:0")
	responses := make(chan packet, 1)
	ctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
	defer close(responses)
	defer cancel()
	err = r.parentForwarder.forwardWithDestChan(ctx, packet{queryPkt, "tcp", from}, responses, rr...)
	if err != nil {
		return nil, err
	}
	resPkt := (<-responses).bs

	var parser dnsmessage.Parser
	header, err := parser.Start(resPkt)
	if err != nil {
		return nil, err
	}

	_ = parser.SkipAllQuestions()
	var ips []netip.Addr

	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, nil
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return nil, err
	}
	for _, ans := range answers {
		switch rdata := ans.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, netip.AddrFrom4(rdata.A))
		case *dnsmessage.AAAAResource:
			ips = append(ips, netip.AddrFrom16(rdata.AAAA))
		default:
			// ignore other record types
		}
	}

	return ips, nil
}

// LookupNetIP implements the net.Resolver.LookupNetIP method.
func (r SubResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	// Use original forwarder to lookup DoH domain IPs
	r.parentForwarder.logf("SubResolver: LookupNetIP network=%v host=%v", network, host)
	fqdn, err := dnsname.ToFQDN(strings.ToLower(host))
	resolvers := r.parentForwarder.resolvers(fqdn)

	if err != nil || len(resolvers) == 0 {
		return nil, err
	}

	// Filter the resolvers: we don't want ourselves to handle our request recursively
	var filteredResolvers []resolverAndDelay
	for _, resolver := range resolvers {
		if resolver.name.Addr == r.parentResolver.name.Addr {
			continue
		}
		filteredResolvers = append(filteredResolvers, resolver)
	}
	if len(filteredResolvers) == 0 {
		r.parentForwarder.logf("SubResolver: no resolvers for custom DoH server resolving available")
		// HACK: maybe use original system resolvers for this?
		return nil, err
	}
	resolvers = filteredResolvers

	switch network {
	case "ip4":
		return r.queryRRs(ctx, fqdn, dnsmessage.TypeA, resolvers...)
	case "ip6":
		return r.queryRRs(ctx, fqdn, dnsmessage.TypeAAAA, resolvers...)
	case "ip":
		// Query over dual stack
		var ips []netip.Addr
		ips4, err := r.queryRRs(ctx, fqdn, dnsmessage.TypeA, resolvers...)
		ips6, err2 := r.queryRRs(ctx, fqdn, dnsmessage.TypeAAAA, resolvers...)
		if err != nil && err2 != nil {
			return nil, err
		}
		// Best effort to report addresses
		if err == nil {
			ips = append(ips, ips4...)
		}
		if err2 == nil {
			ips = append(ips, ips6...)
		}
		return ips, nil
	default:
		return nil, net.UnknownNetworkError(network)
	}

}
