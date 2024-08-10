// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package resolver implements a stub DNS resolver that can also serve
// records out of an internal local zone.
package resolver

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/syncs"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/cloudenv"
	"tailscale.com/util/dnsname"
)

const dnsSymbolicFQDN = "magicdns.localhost-tailscale-daemon."

// maxResponseBytes is the maximum size of a response from a Resolver. The
// actual buffer size will be one larger than this so that we can detect
// truncation in a platform-agnostic way.
const maxResponseBytes = 4095

// defaultTTL is the TTL of all responses from Resolver.
const defaultTTL = 600 * time.Second

var (
	errNotQuery   = errors.New("not a DNS query")
	errNotOurName = errors.New("not a Tailscale DNS name")
)

type packet struct {
	bs     []byte
	family string         // either "tcp" or "udp"
	addr   netip.AddrPort // src for a request, dst for a response
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
	Routes map[dnsname.FQDN][]*dnstype.Resolver
	// LocalHosts is a map of FQDNs to corresponding IPs.
	Hosts map[dnsname.FQDN][]netip.Addr
	// LocalDomains is a list of DNS name suffixes that should not be
	// routed to upstream resolvers.
	LocalDomains []dnsname.FQDN
}

// WriteToBufioWriter write a debug version of c for logs to w, omitting
// spammy stuff like *.arpa entries and replacing it with a total count.
func (c *Config) WriteToBufioWriter(w *bufio.Writer) {
	w.WriteString("{Routes:")
	WriteRoutes(w, c.Routes)
	fmt.Fprintf(w, " Hosts:%v LocalDomains:[", len(c.Hosts))
	space := false
	arpa := 0
	for _, d := range c.LocalDomains {
		if strings.HasSuffix(string(d), ".arpa.") {
			arpa++
			continue
		}
		if space {
			w.WriteByte(' ')
		}
		w.WriteString(string(d))
		space = true
	}
	w.WriteString("]")
	if arpa > 0 {
		fmt.Fprintf(w, "+%darpa", arpa)
	}
	if c := cloudenv.Get(); c != "" {
		fmt.Fprintf(w, ", cloud=%q", string(c))
	}
	w.WriteString("}")
}

// WriteIPPorts writes vv to w.
func WriteIPPorts(w *bufio.Writer, vv []netip.AddrPort) {
	w.WriteByte('[')
	var b []byte
	for i, v := range vv {
		if i > 0 {
			w.WriteByte(' ')
		}
		b = v.AppendTo(b[:0])
		w.Write(b)
	}
	w.WriteByte(']')
}

// WriteDNSResolver writes r to w.
func WriteDNSResolver(w *bufio.Writer, r *dnstype.Resolver) {
	io.WriteString(w, r.Addr)
	if len(r.BootstrapResolution) > 0 {
		w.WriteByte('(')
		var b []byte
		for _, ip := range r.BootstrapResolution {
			ip.AppendTo(b[:0])
			w.Write(b)
		}
		w.WriteByte(')')
	}
}

// WriteDNSResolvers writes resolvers to w.
func WriteDNSResolvers(w *bufio.Writer, resolvers []*dnstype.Resolver) {
	w.WriteByte('[')
	for i, r := range resolvers {
		if i > 0 {
			w.WriteByte(' ')
		}
		WriteDNSResolver(w, r)
	}
	w.WriteByte(']')
}

// WriteRoutes writes routes to w, omitting *.arpa routes and instead
// summarizing how many of them there were.
func WriteRoutes(w *bufio.Writer, routes map[dnsname.FQDN][]*dnstype.Resolver) {
	var kk []dnsname.FQDN
	arpa := 0
	for k := range routes {
		if strings.HasSuffix(string(k), ".arpa.") {
			arpa++
			continue
		}
		kk = append(kk, k)
	}
	sort.Slice(kk, func(i, j int) bool { return kk[i] < kk[j] })
	w.WriteByte('{')
	for i, k := range kk {
		if i > 0 {
			w.WriteByte(' ')
		}
		w.WriteString(string(k))
		w.WriteByte(':')
		WriteDNSResolvers(w, routes[k])
	}
	w.WriteByte('}')
	if arpa > 0 {
		fmt.Fprintf(w, "+%darpa", arpa)
	}
}

// RoutesRequireNoCustomResolvers returns true if this resolver.Config only contains routes
// that do not specify a set of custom resolver(s), i.e. they can be resolved by the local
// upstream DNS resolver.
func (c *Config) RoutesRequireNoCustomResolvers() bool {
	for route, resolvers := range c.Routes {
		if route.WithoutTrailingDot() == "ts.net" {
			// Ignore the "ts.net" route here. It always specifies the corp resolvers but
			// its presence is not an issue, as ts.net will be a search domain.
			continue
		}
		if len(resolvers) != 0 {
			// Found a route with custom resolvers.
			return false
		}
	}
	// No routes other than ts.net have specified one or more resolvers.
	return true
}

// Resolver is a DNS resolver for nodes on the Tailscale network,
// associating them with domain names of the form <mynode>.<mydomain>.<root>.
// If it is asked to resolve a domain that is not of that form,
// it delegates to upstream nameservers if any are set.
type Resolver struct {
	logf               logger.Logf
	netMon             *netmon.Monitor  // non-nil
	dialer             *tsdial.Dialer   // non-nil
	health             *health.Tracker  // non-nil
	saveConfigForTests func(cfg Config) // used in tests to capture resolver config
	// forwarder forwards requests to upstream nameservers.
	forwarder *forwarder

	// closed signals all goroutines to stop.
	closed chan struct{}

	// mu guards the following fields from being updated while used.
	mu           sync.Mutex
	localDomains []dnsname.FQDN
	hostToIP     map[dnsname.FQDN][]netip.Addr
	ipToHost     map[netip.Addr]dnsname.FQDN
}

type ForwardLinkSelector interface {
	// PickLink returns which network device should be used to query
	// the DNS server at the given IP.
	// The empty string means to use an unspecified default.
	PickLink(netip.Addr) (linkName string)
}

// New returns a new resolver.
// dialer and health must be non-nil.
func New(logf logger.Logf, linkSel ForwardLinkSelector, dialer *tsdial.Dialer, health *health.Tracker, knobs *controlknobs.Knobs) *Resolver {
	if dialer == nil {
		panic("nil Dialer")
	}
	if health == nil {
		panic("nil health")
	}
	netMon := dialer.NetMon()
	if netMon == nil {
		logf("nil netMon")
	}
	r := &Resolver{
		logf:     logger.WithPrefix(logf, "resolver: "),
		netMon:   netMon,
		closed:   make(chan struct{}),
		hostToIP: map[dnsname.FQDN][]netip.Addr{},
		ipToHost: map[netip.Addr]dnsname.FQDN{},
		dialer:   dialer,
		health:   health,
	}
	r.forwarder = newForwarder(r.logf, netMon, linkSel, dialer, health, knobs)
	return r
}

// SetMissingUpstreamRecovery sets a callback to be called upon encountering
// a SERVFAIL due to missing upstream resolvers.
//
// This call should only happen before the resolver is used. It is not safe
// for concurrent use.
func (r *Resolver) SetMissingUpstreamRecovery(f func()) {
	r.forwarder.missingUpstreamRecovery = f
}

func (r *Resolver) TestOnlySetHook(hook func(Config)) { r.saveConfigForTests = hook }

func (r *Resolver) SetConfig(cfg Config) error {
	if r.saveConfigForTests != nil {
		r.saveConfigForTests(cfg)
	}

	reverse := make(map[netip.Addr]dnsname.FQDN, len(cfg.Hosts))

	for host, ips := range cfg.Hosts {
		for _, ip := range ips {
			reverse[ip] = host
		}
	}

	r.forwarder.setRoutes(cfg.Routes)

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

	r.forwarder.Close()
}

// dnsQueryTimeout is not intended to be user-visible (the users
// DNS resolver will retry well before that), just put an upper
// bound on per-query resource usage.
const dnsQueryTimeout = 10 * time.Second

func (r *Resolver) Query(ctx context.Context, bs []byte, family string, from netip.AddrPort) ([]byte, error) {
	metricDNSQueryLocal.Add(1)
	select {
	case <-r.closed:
		metricDNSQueryErrorClosed.Add(1)
		return nil, net.ErrClosed
	default:
	}

	out, err := r.respond(bs)
	if err == errNotOurName {
		responses := make(chan packet, 1)
		ctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
		defer close(responses)
		defer cancel()
		err = r.forwarder.forwardWithDestChan(ctx, packet{bs, family, from}, responses)
		if err != nil {
			select {
			// Best effort: use any error response sent by forwardWithDestChan.
			// This is present in some errors paths, such as when all upstream
			// DNS servers replied with an error.
			case resp := <-responses:
				return resp.bs, err
			default:
				return nil, err
			}
		}
		return (<-responses).bs, nil
	}

	return out, err
}

// parseExitNodeQuery parses a DNS request packet.
// It returns nil if it's malformed or lacking a question.
func parseExitNodeQuery(q []byte) *response {
	p := dnsParserPool.Get().(*dnsParser)
	defer dnsParserPool.Put(p)
	p.zeroParser()
	defer p.zeroParser()
	if err := p.parseQuery(q); err != nil {
		return nil
	}
	return p.response()
}

// HandlePeerDNSQuery handles a DNS query that arrived from a peer
// via the peerapi's DoH server. This is used when the local
// node is being an exit node or an app connector.
//
// The provided allowName callback is whether a DNS query for a name
// (as found by parsing q) is allowed.
//
// In most (all?) cases, err will be nil. A bogus DNS query q will
// still result in a response DNS packet (saying there's a failure)
// and a nil error.
// TODO: figure out if we even need an error result.
func (r *Resolver) HandlePeerDNSQuery(ctx context.Context, q []byte, from netip.AddrPort, allowName func(name string) bool) (res []byte, err error) {
	metricDNSExitProxyQuery.Add(1)
	ch := make(chan packet, 1)

	resp := parseExitNodeQuery(q)
	if resp == nil {
		return nil, errors.New("bad query")
	}
	name := resp.Question.Name.String()
	if !allowName(name) {
		metricDNSExitProxyErrorName.Add(1)
		resp.Header.RCode = dns.RCodeRefused
		return marshalResponse(resp)
	}

	switch runtime.GOOS {
	default:
		return nil, errors.New("unsupported exit node OS")
	case "windows", "android":
		return handleExitNodeDNSQueryWithNetPkg(ctx, r.logf, nil, resp)
	case "darwin":
		// /etc/resolv.conf is a lie and only says one upstream DNS
		// but for now that's probably good enough. Later we'll
		// want to blend in everything from scutil --dns.
		fallthrough
	case "linux", "freebsd", "openbsd", "illumos", "ios":
		nameserver, err := stubResolverForOS()
		if err != nil {
			r.logf("stubResolverForOS: %v", err)
			metricDNSExitProxyErrorResolvConf.Add(1)
			return nil, err
		}
		// TODO: more than 1 resolver from /etc/resolv.conf?

		var resolvers []resolverAndDelay
		switch nameserver {
		case tsaddr.TailscaleServiceIP(), tsaddr.TailscaleServiceIPv6():
			// If resolv.conf says 100.100.100.100, it's coming right back to us anyway
			// so avoid the loop through the kernel and just do what we
			// would've done anyway. By not passing any resolvers, the forwarder
			// will use its default ones from our DNS config.
		case netip.Addr{}:
			// Likewise, if the platform has no resolv.conf, just use our defaults.
		default:
			resolvers = []resolverAndDelay{{
				name: &dnstype.Resolver{Addr: net.JoinHostPort(nameserver.String(), "53")},
			}}
		}

		err = r.forwarder.forwardWithDestChan(ctx, packet{q, "tcp", from}, ch, resolvers...)
		if err != nil {
			metricDNSExitProxyErrorForward.Add(1)
			return nil, err
		}
	}
	select {
	case p, ok := <-ch:
		if ok {
			return p.bs, nil
		}
		panic("unexpected close chan")
	default:
		panic("unexpected unreadable chan")
	}
}

var debugExitNodeDNSNetPkg = envknob.RegisterBool("TS_DEBUG_EXIT_NODE_DNS_NET_PKG")

// handleExitNodeDNSQueryWithNetPkg takes a DNS query message in q and
// return a reply (for the ExitDNS DoH service) using the net package's
// native APIs.
//
// If resolver is nil, the net.Resolver zero value is used.
//
// response contains the pre-serialized response, which notably
// includes the original question and its header.
func handleExitNodeDNSQueryWithNetPkg(ctx context.Context, logf logger.Logf, resolver *net.Resolver, resp *response) (res []byte, err error) {
	logf = logger.WithPrefix(logf, "exitNodeDNSQueryWithNetPkg: ")
	if resp.Question.Class != dns.ClassINET {
		return nil, errors.New("unsupported class")
	}

	r := resolver
	if r == nil {
		r = new(net.Resolver)
	}
	name := resp.Question.Name.String()

	handleError := func(err error) (res []byte, _ error) {
		if isGoNoSuchHostError(err) {
			if debugExitNodeDNSNetPkg() {
				logf(`converting Go "no such host" error to a NXDOMAIN: %v`, err)
			}
			resp.Header.RCode = dns.RCodeNameError
			return marshalResponse(resp)
		}

		if debugExitNodeDNSNetPkg() {
			logf("returning error: %v", err)
		}
		// TODO: map other errors to RCodeServerFailure?
		// Or I guess our caller should do that?
		return nil, err
	}

	resp.Header.RCode = dns.RCodeSuccess // unless changed below

	switch resp.Question.Type {
	case dns.TypeA, dns.TypeAAAA:
		network := "ip4"
		if resp.Question.Type == dns.TypeAAAA {
			network = "ip6"
		}
		if debugExitNodeDNSNetPkg() {
			logf("resolving %s %q", network, name)
		}
		ips, err := r.LookupIP(ctx, network, name)
		if err != nil {
			return handleError(err)
		}
		for _, stdIP := range ips {
			if ip, ok := netip.AddrFromSlice(stdIP); ok {
				resp.IPs = append(resp.IPs, ip.Unmap())
			}
		}
	case dns.TypeTXT:
		if debugExitNodeDNSNetPkg() {
			logf("resolving TXT %q", name)
		}
		strs, err := r.LookupTXT(ctx, name)
		if err != nil {
			return handleError(err)
		}
		resp.TXT = strs
	case dns.TypePTR:
		ipStr, ok := unARPA(name)
		if !ok {
			// TODO: is this RCodeFormatError?
			return nil, errors.New("bogus PTR name")
		}
		if debugExitNodeDNSNetPkg() {
			logf("resolving PTR %q", ipStr)
		}
		addrs, err := r.LookupAddr(ctx, ipStr)
		if err != nil {
			return handleError(err)
		}
		if len(addrs) > 0 {
			resp.Name, _ = dnsname.ToFQDN(addrs[0])
		}
	case dns.TypeCNAME:
		if debugExitNodeDNSNetPkg() {
			logf("resolving CNAME %q", name)
		}
		cname, err := r.LookupCNAME(ctx, name)
		if err != nil {
			return handleError(err)
		}
		resp.CNAME = cname
	case dns.TypeSRV:
		if debugExitNodeDNSNetPkg() {
			logf("resolving SRV %q", name)
		}
		// Thanks, Go: "To accommodate services publishing SRV
		// records under non-standard names, if both service
		// and proto are empty strings, LookupSRV looks up
		// name directly."
		_, srvs, err := r.LookupSRV(ctx, "", "", name)
		if err != nil {
			return handleError(err)
		}
		resp.SRVs = srvs
	case dns.TypeNS:
		if debugExitNodeDNSNetPkg() {
			logf("resolving NS %q", name)
		}
		nss, err := r.LookupNS(ctx, name)
		if err != nil {
			return handleError(err)
		}
		resp.NSs = nss
	default:
		return nil, fmt.Errorf("unsupported record type %v", resp.Question.Type)
	}
	return marshalResponse(resp)
}

func isGoNoSuchHostError(err error) bool {
	if de, ok := err.(*net.DNSError); ok {
		return de.IsNotFound
	}
	return false
}

type resolvConfCache struct {
	mod  time.Time
	size int64
	ip   netip.Addr
	// TODO: inode/dev?
}

// resolvConfCacheValue contains the most recent stat metadata and parsed
// version of /etc/resolv.conf.
var resolvConfCacheValue syncs.AtomicValue[resolvConfCache]

var errEmptyResolvConf = errors.New("resolv.conf has no nameservers")

// stubResolverForOS returns the IP address of the first nameserver in
// /etc/resolv.conf.
//
// It may also return the netip.Addr zero value and a nil error to mean
// that the platform has no resolv.conf.
func stubResolverForOS() (ip netip.Addr, err error) {
	if runtime.GOOS == "ios" {
		return netip.Addr{}, nil // no resolv.conf on iOS
	}
	fi, err := os.Stat(resolvconffile.Path)
	if err != nil {
		return netip.Addr{}, err
	}
	cur := resolvConfCache{
		mod:  fi.ModTime(),
		size: fi.Size(),
	}
	if c, ok := resolvConfCacheValue.LoadOk(); ok && c.mod == cur.mod && c.size == cur.size {
		return c.ip, nil
	}
	conf, err := resolvconffile.ParseFile(resolvconffile.Path)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(conf.Nameservers) == 0 {
		return netip.Addr{}, errEmptyResolvConf
	}
	ip = conf.Nameservers[0]
	cur.ip = ip
	resolvConfCacheValue.Store(cur)
	return ip, nil
}

// resolveLocal returns an IP for the given domain, if domain is in
// the local hosts map and has an IP corresponding to the requested
// typ (A, AAAA, ALL).
// Returns dns.RCodeRefused to indicate that the local map is not
// authoritative for domain.
func (r *Resolver) resolveLocal(domain dnsname.FQDN, typ dns.Type) (netip.Addr, dns.RCode) {
	metricDNSResolveLocal.Add(1)
	// Reject .onion domains per RFC 7686.
	if dnsname.HasSuffix(domain.WithoutTrailingDot(), ".onion") {
		metricDNSResolveLocalErrorOnion.Add(1)
		return netip.Addr{}, dns.RCodeNameError
	}

	// We return a symbolic domain if someone does a reverse lookup on the
	// DNS endpoint. To round out this special case, we also do the inverse
	// (returning the endpoint IP if someone looks up the symbolic domain).
	if domain == dnsSymbolicFQDN {
		switch typ {
		case dns.TypeA:
			return tsaddr.TailscaleServiceIP(), dns.RCodeSuccess
		case dns.TypeAAAA:
			return tsaddr.TailscaleServiceIPv6(), dns.RCodeSuccess
		}
	}
	// Special-case: 4via6 DNS names.
	if ip, ok := r.resolveViaDomain(domain, typ); ok {
		return ip, dns.RCodeSuccess
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
				metricDNSResolveLocalErrorMissing.Add(1)
				return netip.Addr{}, dns.RCodeNameError
			}
		}
		// Not authoritative, signal that forwarding is advisable.
		metricDNSResolveLocalErrorRefused.Add(1)
		return netip.Addr{}, dns.RCodeRefused
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
				metricDNSResolveLocalOKA.Add(1)
				return ip, dns.RCodeSuccess
			}
		}
		metricDNSResolveLocalNoA.Add(1)
		return netip.Addr{}, dns.RCodeSuccess
	case dns.TypeAAAA:
		for _, ip := range addrs {
			if ip.Is6() {
				metricDNSResolveLocalOKAAAA.Add(1)
				return ip, dns.RCodeSuccess
			}
		}
		metricDNSResolveLocalNoAAAA.Add(1)
		return netip.Addr{}, dns.RCodeSuccess
	case dns.TypeALL:
		// Answer with whatever we've got.
		// It could be IPv4, IPv6, or a zero addr.
		// TODO: Return all available resolutions (A and AAAA, if we have them).
		if len(addrs) == 0 {
			metricDNSResolveLocalNoAll.Add(1)
			return netip.Addr{}, dns.RCodeSuccess
		}
		metricDNSResolveLocalOKAll.Add(1)
		return addrs[0], dns.RCodeSuccess

	// Leave some record types explicitly unimplemented.
	// These types relate to recursive resolution or special
	// DNS semantics and might be implemented in the future.
	case dns.TypeNS, dns.TypeSOA, dns.TypeAXFR, dns.TypeHINFO:
		metricDNSResolveNotImplType.Add(1)
		return netip.Addr{}, dns.RCodeNotImplemented

	// For everything except for the few types above that are explicitly not implemented, return no records.
	// This is what other DNS systems do: always return NOERROR
	// without any records whenever the requested record type is unknown.
	// You can try this with:
	//   dig -t TYPE9824 example.com
	// and note that NOERROR is returned, despite that record type being made up.
	default:
		metricDNSResolveNoRecordType.Add(1)
		// The name exists, but no records exist of the requested type.
		return netip.Addr{}, dns.RCodeSuccess
	}
}

// resolveViaDomain synthesizes an IP address for quad-A DNS requests of the form
// `<IPv4-address-with-hypens-instead-of-dots>-via-<siteid>[.*]`. Two prior formats that
// didn't pan out (due to a Chrome issue and DNS search ndots issues) were
// `<IPv4-address>.via-<X>` and the older `via-<X>.<IPv4-address>`,
// where X is a decimal, or hex-encoded number with a '0x' prefix.
//
// This exists as a convenient mapping into Tailscales 'Via Range'.
//
// It returns a zero netip.Addr and true to indicate a successful response with
// an empty answers section if the specified domain is a valid Tailscale 4via6
// domain, but the request type is neither quad-A nor ALL.
//
// TODO(maisem/bradfitz/tom): `<IPv4-address>.via-<X>` was introduced
// (2022-06-02) to work around an issue in Chrome where it would treat
// "http://via-1.1.2.3.4" as a search string instead of a URL. We should rip out
// the old format in early 2023.
func (r *Resolver) resolveViaDomain(domain dnsname.FQDN, typ dns.Type) (netip.Addr, bool) {
	fqdn := string(domain.WithoutTrailingDot())
	switch typ {
	case dns.TypeA, dns.TypeAAAA, dns.TypeALL:
		// For Type A requests, we should return a successful response
		// with an empty answer section rather than an NXDomain
		// if the specified domain is a valid Tailscale 4via6 domain.
		//
		// Therefore, we should continue and parse the domain name first
		// before deciding whether to return an IPv6 address,
		// a zero (invalid) netip.Addr and true to indicate a successful empty response,
		// or a zero netip.Addr and false to indicate that it is not a Tailscale 4via6 domain.
	default:
		return netip.Addr{}, false
	}
	if len(fqdn) < len("via-X.0.0.0.0") {
		return netip.Addr{}, false // too short to be valid
	}

	var siteID string
	var ip4Str string
	switch {
	case strings.Contains(fqdn, "-via-"):
		// Format number 3: "192-168-1-2-via-7" or "192-168-1-2-via-7.foo.ts.net."
		// Third time's a charm. The earlier two formats follow after this block.
		firstLabel, domain, _ := strings.Cut(fqdn, ".") // "192-168-1-2-via-7"
		if !(domain == "" || dnsname.HasSuffix(domain, "ts.net") || dnsname.HasSuffix(domain, "tailscale.net")) {
			return netip.Addr{}, false
		}
		v4hyphens, suffix, ok := strings.Cut(firstLabel, "-via-")
		if !ok {
			return netip.Addr{}, false
		}
		siteID = suffix
		ip4Str = strings.ReplaceAll(v4hyphens, "-", ".")
	case strings.HasPrefix(fqdn, "via-"):
		firstDot := strings.Index(fqdn, ".")
		if firstDot < 0 {
			return netip.Addr{}, false // missing dot delimiters
		}
		siteID = fqdn[len("via-"):firstDot]
		ip4Str = fqdn[firstDot+1:]
	default:
		lastDot := strings.LastIndex(fqdn, ".")
		if lastDot < 0 {
			return netip.Addr{}, false // missing dot delimiters
		}
		suffix := fqdn[lastDot+1:]
		if !strings.HasPrefix(suffix, "via-") {
			return netip.Addr{}, false
		}
		siteID = suffix[len("via-"):]
		ip4Str = fqdn[:lastDot]
	}

	ip4, err := netip.ParseAddr(ip4Str)
	if err != nil {
		return netip.Addr{}, false // badly formed, don't respond
	}

	prefix, err := strconv.ParseUint(siteID, 0, 32)
	if err != nil {
		return netip.Addr{}, false // badly formed, don't respond
	}

	if typ == dns.TypeA {
		return netip.Addr{}, true // the name exists, but cannot be resolved to an IPv4 address
	}

	// MapVia will never error when given an IPv4 netip.Prefix.
	out, _ := tsaddr.MapVia(uint32(prefix), netip.PrefixFrom(ip4, ip4.BitLen()))
	return out.Addr(), true
}

// resolveReverse returns the unique domain name that maps to the given address.
func (r *Resolver) resolveLocalReverse(name dnsname.FQDN) (dnsname.FQDN, dns.RCode) {
	var ip netip.Addr
	var ok bool
	switch {
	case strings.HasSuffix(name.WithTrailingDot(), rdnsv4Suffix):
		ip, ok = rdnsNameToIPv4(name)
	case strings.HasSuffix(name.WithTrailingDot(), rdnsv6Suffix):
		ip, ok = rdnsNameToIPv6(name)
	}
	if !ok {
		// This isn't a well-formed in-addr.arpa or ip6.arpa name, but
		// who knows what upstreams might do, try kicking it up to
		// them. We definitely won't handle it.
		return "", dns.RCodeRefused
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// If the requested IP is part of the IPv6 4-to-6 range, it might
	// correspond to an IPv4 address (assuming IPv4 is enabled).
	if ip4, ok := tsaddr.Tailscale6to4(ip); ok {
		fqdn, code := r.fqdnForIPLocked(ip4, name)
		if code == dns.RCodeSuccess {
			return fqdn, code
		}
	}
	return r.fqdnForIPLocked(ip, name)
}

// r.mu must be held.
func (r *Resolver) fqdnForIPLocked(ip netip.Addr, name dnsname.FQDN) (dnsname.FQDN, dns.RCode) {
	// If someone curiously does a reverse lookup on the DNS IP, we
	// return a domain that helps indicate that Tailscale is using
	// this IP for a special purpose and it is not a node on their
	// tailnet.
	if ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6() {
		return dnsSymbolicFQDN, dns.RCodeSuccess
	}

	ret, ok := r.ipToHost[ip]
	if !ok {
		for _, suffix := range r.localDomains {
			if suffix.Contains(name) {
				// We are authoritative for this chunk of IP space.
				return "", dns.RCodeNameError
			}
		}
		// Not authoritative, signal that forwarding is advisable.
		return "", dns.RCodeRefused
	}
	return ret, dns.RCodeSuccess
}

type response struct {
	Header   dns.Header
	Question dns.Question

	// Name is the response to a PTR query.
	Name dnsname.FQDN

	// IP and IPs are the responses to an A, AAAA, or ALL query.
	// Either/both/neither can be populated.
	IP  netip.Addr
	IPs []netip.Addr

	// TXT is the response to a TXT query.
	// Each one is its own RR with one string.
	TXT []string

	// CNAME is the response to a CNAME query.
	CNAME string

	// SRVs are the responses to a SRV query.
	SRVs []*net.SRV

	// NSs are the responses to an NS query.
	NSs []*net.NS
}

var dnsParserPool = &sync.Pool{
	New: func() any {
		return new(dnsParser)
	},
}

// dnsParser parses DNS queries using x/net/dns/dnsmessage.
// These structs are pooled with dnsParserPool.
type dnsParser struct {
	Header   dns.Header
	Question dns.Question

	parser dns.Parser
}

func (p *dnsParser) response() *response {
	return &response{Header: p.Header, Question: p.Question}
}

// zeroParser clears parser so it doesn't retain its most recently
// parsed DNS query's []byte while it's sitting in a sync.Pool.
// It's not useful to keep anyway: the next Start will do the same.
func (p *dnsParser) zeroParser() { p.parser = dns.Parser{} }

// parseQuery parses the query in given packet into p.Header and
// p.Question.
func (p *dnsParser) parseQuery(query []byte) error {
	defer p.zeroParser()
	p.zeroParser()
	var err error
	p.Header, err = p.parser.Start(query)
	if err != nil {
		return err
	}
	if p.Header.Response {
		return errNotQuery
	}
	p.Question, err = p.parser.Question()
	return err
}

// marshalARecord serializes an A record into an active builder.
// The caller may continue using the builder following the call.
func marshalARecord(name dns.Name, ip netip.Addr, builder *dns.Builder) error {
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
func marshalAAAARecord(name dns.Name, ip netip.Addr, builder *dns.Builder) error {
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

func marshalIP(name dns.Name, ip netip.Addr, builder *dns.Builder) error {
	if ip.Is4() {
		return marshalARecord(name, ip, builder)
	}
	if ip.Is6() {
		return marshalAAAARecord(name, ip, builder)
	}
	return nil
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

func marshalTXT(queryName dns.Name, txts []string, builder *dns.Builder) error {
	for _, txt := range txts {
		if err := builder.TXTResource(dns.ResourceHeader{
			Name:  queryName,
			Type:  dns.TypeTXT,
			Class: dns.ClassINET,
			TTL:   uint32(defaultTTL / time.Second),
		}, dns.TXTResource{
			TXT: []string{txt},
		}); err != nil {
			return err
		}
	}
	return nil
}

func marshalCNAME(queryName dns.Name, cname string, builder *dns.Builder) error {
	if cname == "" {
		return nil
	}
	name, err := dns.NewName(cname)
	if err != nil {
		return err
	}
	return builder.CNAMEResource(dns.ResourceHeader{
		Name:  queryName,
		Type:  dns.TypeCNAME,
		Class: dns.ClassINET,
		TTL:   uint32(defaultTTL / time.Second),
	}, dns.CNAMEResource{
		CNAME: name,
	})
}

func marshalNS(queryName dns.Name, nss []*net.NS, builder *dns.Builder) error {
	for _, ns := range nss {
		name, err := dns.NewName(ns.Host)
		if err != nil {
			return err
		}
		err = builder.NSResource(dns.ResourceHeader{
			Name:  queryName,
			Type:  dns.TypeNS,
			Class: dns.ClassINET,
			TTL:   uint32(defaultTTL / time.Second),
		}, dns.NSResource{NS: name})
		if err != nil {
			return err
		}
	}
	return nil
}

func marshalSRV(queryName dns.Name, srvs []*net.SRV, builder *dns.Builder) error {
	for _, s := range srvs {
		srvName, err := dns.NewName(s.Target)
		if err != nil {
			return err
		}
		err = builder.SRVResource(dns.ResourceHeader{
			Name:  queryName,
			Type:  dns.TypeSRV,
			Class: dns.ClassINET,
			TTL:   uint32(defaultTTL / time.Second),
		}, dns.SRVResource{
			Target:   srvName,
			Priority: s.Priority,
			Port:     s.Port,
			Weight:   s.Weight,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// marshalResponse serializes the DNS response into a new buffer.
func marshalResponse(resp *response) ([]byte, error) {
	resp.Header.Response = true
	resp.Header.Authoritative = true
	if resp.Header.RecursionDesired {
		resp.Header.RecursionAvailable = true
	}

	builder := dns.NewBuilder(nil, resp.Header)

	// TODO(bradfitz): I'm not sure why this wasn't enabled
	// before, but for now (2021-12-09) enable it at least when
	// there's more than 1 record (which was never the case
	// before), where it really helps.
	if len(resp.IPs) > 1 {
		builder.EnableCompression()
	}

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
		if err := marshalIP(resp.Question.Name, resp.IP, &builder); err != nil {
			return nil, err
		}
		for _, ip := range resp.IPs {
			if err := marshalIP(resp.Question.Name, ip, &builder); err != nil {
				return nil, err
			}
		}
	case dns.TypePTR:
		err = marshalPTRRecord(resp.Question.Name, resp.Name, &builder)
	case dns.TypeTXT:
		err = marshalTXT(resp.Question.Name, resp.TXT, &builder)
	case dns.TypeCNAME:
		err = marshalCNAME(resp.Question.Name, resp.CNAME, &builder)
	case dns.TypeSRV:
		err = marshalSRV(resp.Question.Name, resp.SRVs, &builder)
	case dns.TypeNS:
		err = marshalNS(resp.Question.Name, resp.NSs, &builder)
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
//	 b._dns-sd._udp.<domain>.
//	db._dns-sd._udp.<domain>.
//	 r._dns-sd._udp.<domain>.
//	dr._dns-sd._udp.<domain>.
//	lb._dns-sd._udp.<domain>.
func hasRDNSBonjourPrefix(name dnsname.FQDN) bool {
	s := name.WithTrailingDot()
	base, rest, ok := strings.Cut(s, ".")
	if !ok {
		return false // shouldn't happen
	}
	switch base {
	case "b", "db", "r", "dr", "lb":
	default:
		return false
	}

	return strings.HasPrefix(rest, "_dns-sd._udp.")
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
//
//	4.3.2.1.in-addr.arpa
//
// is transformed to
//
//	1.2.3.4
func rdnsNameToIPv4(name dnsname.FQDN) (ip netip.Addr, ok bool) {
	s := strings.TrimSuffix(name.WithTrailingDot(), rdnsv4Suffix)
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	if !ip.Is4() {
		return netip.Addr{}, false
	}
	b := ip.As4()
	return netaddr.IPv4(b[3], b[2], b[1], b[0]), true
}

// ptrNameToIPv6 transforms a PTR name representing an IPv6 address to said address.
// Such names are dot-separated nibbles in reverse order followed by .ip6.arpa.
// For example,
//
//	b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
//
// is transformed to
//
//	2001:db8::567:89ab
func rdnsNameToIPv6(name dnsname.FQDN) (ip netip.Addr, ok bool) {
	var b [32]byte
	var ipb [16]byte

	s := strings.TrimSuffix(name.WithTrailingDot(), rdnsv6Suffix)
	// 32 nibbles and 31 dots between them.
	if len(s) != 63 {
		return netip.Addr{}, false
	}

	// Dots and hex digits alternate.
	prevDot := true
	// i ranges over name backward; j ranges over b forward.
	for i, j := len(s)-1, 0; i >= 0; i-- {
		thisDot := (s[i] == '.')
		if prevDot == thisDot {
			return netip.Addr{}, false
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
		return netip.Addr{}, false
	}

	return netip.AddrFrom16(ipb), true
}

// respondReverse returns a DNS response to a PTR query.
// It is assumed that resp.Question is populated by respond before this is called.
func (r *Resolver) respondReverse(query []byte, name dnsname.FQDN, resp *response) ([]byte, error) {
	if hasRDNSBonjourPrefix(name) {
		metricDNSReverseMissBonjour.Add(1)
		return nil, errNotOurName
	}

	resp.Name, resp.Header.RCode = r.resolveLocalReverse(name)
	if resp.Header.RCode == dns.RCodeRefused {
		metricDNSReverseMissOther.Add(1)
		return nil, errNotOurName
	}

	metricDNSMagicDNSSuccessReverse.Add(1)
	return marshalResponse(resp)
}

// respond returns a DNS response to query if it can be resolved locally.
// Otherwise, it returns errNotOurName.
func (r *Resolver) respond(query []byte) ([]byte, error) {
	parser := dnsParserPool.Get().(*dnsParser)
	defer dnsParserPool.Put(parser)

	// ParseQuery is sufficiently fast to run on every DNS packet.
	// This is considerably simpler than extracting the name by hand
	// to shave off microseconds in case of delegation.
	err := parser.parseQuery(query)
	// We will not return this error: it is the sender's fault.
	if err != nil {
		if errors.Is(err, dns.ErrSectionDone) {
			metricDNSErrorParseNoQ.Add(1)
			r.logf("parseQuery(%02x): no DNS questions", query)
		} else {
			metricDNSErrorParseQuery.Add(1)
			r.logf("parseQuery(%02x): %v", query, err)
		}
		resp := parser.response()
		resp.Header.RCode = dns.RCodeFormatError
		return marshalResponse(resp)
	}
	rawName := parser.Question.Name.Data[:parser.Question.Name.Length]
	name, err := dnsname.ToFQDN(rawNameToLower(rawName))
	if err != nil {
		metricDNSErrorNotFQDN.Add(1)
		// DNS packet unexpectedly contains an invalid FQDN.
		resp := parser.response()
		resp.Header.RCode = dns.RCodeFormatError
		return marshalResponse(resp)
	}

	// Always try to handle reverse lookups; delegate inside when not found.
	// This way, queries for existent nodes do not leak,
	// but we behave gracefully if non-Tailscale nodes exist in CGNATRange.
	if parser.Question.Type == dns.TypePTR {
		return r.respondReverse(query, name, parser.response())
	}

	ip, rcode := r.resolveLocal(name, parser.Question.Type)
	if rcode == dns.RCodeRefused {
		return nil, errNotOurName // sentinel error return value: it requests forwarding
	}

	resp := parser.response()
	resp.Header.RCode = rcode
	resp.IP = ip
	metricDNSMagicDNSSuccessName.Add(1)
	return marshalResponse(resp)
}

// unARPA maps from "4.4.8.8.in-addr.arpa." to "8.8.4.4", etc.
func unARPA(a string) (ipStr string, ok bool) {
	const suf4 = ".in-addr.arpa."
	if s, ok := strings.CutSuffix(a, suf4); ok {
		// Parse and reverse octets.
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			return "", false
		}
		a4 := ip.As4()
		return netaddr.IPv4(a4[3], a4[2], a4[1], a4[0]).String(), true
	}
	const suf6 = ".ip6.arpa."
	if len(a) == len("e.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.b.0.8.0.a.0.0.4.0.b.8.f.7.0.6.2.ip6.arpa.") &&
		strings.HasSuffix(a, suf6) {
		var hx [32]byte
		var a16 [16]byte
		for i := range hx {
			hx[31-i] = a[i*2]
			if a[i*2+1] != '.' {
				return "", false
			}
		}
		hex.Decode(a16[:], hx[:])
		return netip.AddrFrom16(a16).Unmap().String(), true
	}
	return "", false

}

var (
	metricDNSQueryLocal       = clientmetric.NewCounter("dns_query_local")
	metricDNSQueryErrorClosed = clientmetric.NewCounter("dns_query_local_error_closed")

	metricDNSErrorParseNoQ   = clientmetric.NewCounter("dns_query_respond_error_no_question")
	metricDNSErrorParseQuery = clientmetric.NewCounter("dns_query_respond_error_parse")
	metricDNSErrorNotFQDN    = clientmetric.NewCounter("dns_query_respond_error_not_fqdn")

	metricDNSMagicDNSSuccessName    = clientmetric.NewCounter("dns_query_magic_success_name")
	metricDNSMagicDNSSuccessReverse = clientmetric.NewCounter("dns_query_magic_success_reverse")

	metricDNSExitProxyQuery           = clientmetric.NewCounter("dns_exit_node_query")
	metricDNSExitProxyErrorName       = clientmetric.NewCounter("dns_exit_node_error_name")
	metricDNSExitProxyErrorForward    = clientmetric.NewCounter("dns_exit_node_error_forward")
	metricDNSExitProxyErrorResolvConf = clientmetric.NewCounter("dns_exit_node_error_resolvconf")

	metricDNSFwd                     = clientmetric.NewCounter("dns_query_fwd")
	metricDNSFwdDropBonjour          = clientmetric.NewCounter("dns_query_fwd_drop_bonjour")
	metricDNSFwdErrorName            = clientmetric.NewCounter("dns_query_fwd_error_name")
	metricDNSFwdErrorNoUpstream      = clientmetric.NewCounter("dns_query_fwd_error_no_upstream")
	metricDNSFwdSuccess              = clientmetric.NewCounter("dns_query_fwd_success")
	metricDNSFwdErrorContext         = clientmetric.NewCounter("dns_query_fwd_error_context")
	metricDNSFwdErrorContextGotError = clientmetric.NewCounter("dns_query_fwd_error_context_got_error")

	metricDNSFwdErrorType = clientmetric.NewCounter("dns_query_fwd_error_type")
	metricDNSFwdTruncated = clientmetric.NewCounter("dns_query_fwd_truncated")

	metricDNSFwdUDP            = clientmetric.NewCounter("dns_query_fwd_udp")       // on entry
	metricDNSFwdUDPWrote       = clientmetric.NewCounter("dns_query_fwd_udp_wrote") // sent UDP packet
	metricDNSFwdUDPErrorWrite  = clientmetric.NewCounter("dns_query_fwd_udp_error_write")
	metricDNSFwdUDPErrorServer = clientmetric.NewCounter("dns_query_fwd_udp_error_server")
	metricDNSFwdUDPErrorTxID   = clientmetric.NewCounter("dns_query_fwd_udp_error_txid")
	metricDNSFwdUDPErrorRead   = clientmetric.NewCounter("dns_query_fwd_udp_error_read")
	metricDNSFwdUDPSuccess     = clientmetric.NewCounter("dns_query_fwd_udp_success")

	metricDNSFwdTCP            = clientmetric.NewCounter("dns_query_fwd_tcp")       // on entry
	metricDNSFwdTCPWrote       = clientmetric.NewCounter("dns_query_fwd_tcp_wrote") // sent TCP packet
	metricDNSFwdTCPErrorWrite  = clientmetric.NewCounter("dns_query_fwd_tcp_error_write")
	metricDNSFwdTCPErrorServer = clientmetric.NewCounter("dns_query_fwd_tcp_error_server")
	metricDNSFwdTCPErrorTxID   = clientmetric.NewCounter("dns_query_fwd_tcp_error_txid")
	metricDNSFwdTCPErrorRead   = clientmetric.NewCounter("dns_query_fwd_tcp_error_read")
	metricDNSFwdTCPSuccess     = clientmetric.NewCounter("dns_query_fwd_tcp_success")

	metricDNSFwdDoH               = clientmetric.NewCounter("dns_query_fwd_doh")
	metricDNSFwdDoHErrorStatus    = clientmetric.NewCounter("dns_query_fwd_doh_error_status")
	metricDNSFwdDoHErrorCT        = clientmetric.NewCounter("dns_query_fwd_doh_error_content_type")
	metricDNSFwdDoHErrorTransport = clientmetric.NewCounter("dns_query_fwd_doh_error_transport")
	metricDNSFwdDoHErrorBody      = clientmetric.NewCounter("dns_query_fwd_doh_error_body")

	metricDNSResolveLocal             = clientmetric.NewCounter("dns_resolve_local")
	metricDNSResolveLocalErrorOnion   = clientmetric.NewCounter("dns_resolve_local_error_onion")
	metricDNSResolveLocalErrorMissing = clientmetric.NewCounter("dns_resolve_local_error_missing")
	metricDNSResolveLocalErrorRefused = clientmetric.NewCounter("dns_resolve_local_error_refused")
	metricDNSResolveLocalOKA          = clientmetric.NewCounter("dns_resolve_local_ok_a")
	metricDNSResolveLocalOKAAAA       = clientmetric.NewCounter("dns_resolve_local_ok_aaaa")
	metricDNSResolveLocalOKAll        = clientmetric.NewCounter("dns_resolve_local_ok_all")
	metricDNSResolveLocalNoA          = clientmetric.NewCounter("dns_resolve_local_no_a")
	metricDNSResolveLocalNoAAAA       = clientmetric.NewCounter("dns_resolve_local_no_aaaa")
	metricDNSResolveLocalNoAll        = clientmetric.NewCounter("dns_resolve_local_no_all")
	metricDNSResolveNotImplType       = clientmetric.NewCounter("dns_resolve_local_not_impl_type")
	metricDNSResolveNoRecordType      = clientmetric.NewCounter("dns_resolve_local_no_record_type")

	metricDNSReverseMissBonjour = clientmetric.NewCounter("dns_reverse_miss_bonjour")
	metricDNSReverseMissOther   = clientmetric.NewCounter("dns_reverse_miss_other")
)
