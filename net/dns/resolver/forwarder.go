// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"inet.af/netaddr"
	"tailscale.com/hostinfo"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/neterror"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/monitor"
)

// headerBytes is the number of bytes in a DNS message header.
const headerBytes = 12

const (
	// responseTimeout is the maximal amount of time to wait for a DNS response.
	responseTimeout = 5 * time.Second

	// dohTransportTimeout is how long to keep idle HTTP
	// connections open to DNS-over-HTTPs servers. This is pretty
	// arbitrary.
	dohTransportTimeout = 30 * time.Second

	// wellKnownHostBackupDelay is how long to artificially delay upstream
	// DNS queries to the "fallback" DNS server IP for a known provider
	// (e.g. how long to wait to query Google's 8.8.4.4 after 8.8.8.8).
	wellKnownHostBackupDelay = 200 * time.Millisecond
)

var errNoUpstreams = errors.New("upstream nameservers not set")

// txid identifies a DNS transaction.
//
// As the standard DNS Request ID is only 16 bits, we extend it:
// the lower 32 bits are the zero-extended bits of the DNS Request ID;
// the upper 32 bits are the CRC32 checksum of the first question in the request.
// This makes probability of txid collision negligible.
type txid uint64

// getTxID computes the txid of the given DNS packet.
func getTxID(packet []byte) txid {
	if len(packet) < headerBytes {
		return 0
	}

	dnsid := binary.BigEndian.Uint16(packet[0:2])
	// Previously, we hashed the question and combined it with the original txid
	// which was useful when concurrent queries were multiplexed on a single
	// local source port. We encountered some situations where the DNS server
	// canonicalizes the question in the response (uppercase converted to
	// lowercase in this case), which resulted in responses that we couldn't
	// match to the original request due to hash mismatches.
	return txid(dnsid)
}

func getRCode(packet []byte) dns.RCode {
	if len(packet) < headerBytes {
		// treat invalid packets as a refusal
		return dns.RCode(5)
	}
	// get bottom 4 bits of 3rd byte
	return dns.RCode(packet[3] & 0x0F)
}

// clampEDNSSize attempts to limit the maximum EDNS response size. This is not
// an exhaustive solution, instead only easy cases are currently handled in the
// interest of speed and reduced complexity. Only OPT records at the very end of
// the message with no option codes are addressed.
// TODO: handle more situations if we discover that they happen often
func clampEDNSSize(packet []byte, maxSize uint16) {
	// optFixedBytes is the size of an OPT record with no option codes.
	const optFixedBytes = 11
	const edns0Version = 0

	if len(packet) < headerBytes+optFixedBytes {
		return
	}

	arCount := binary.BigEndian.Uint16(packet[10:12])
	if arCount == 0 {
		// OPT shows up in an AR, so there must be no OPT
		return
	}

	// https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2
	opt := packet[len(packet)-optFixedBytes:]

	if opt[0] != 0 {
		// OPT NAME must be 0 (root domain)
		return
	}
	if dns.Type(binary.BigEndian.Uint16(opt[1:3])) != dns.TypeOPT {
		// Not an OPT record
		return
	}
	requestedSize := binary.BigEndian.Uint16(opt[3:5])
	// Ignore extended RCODE in opt[5]
	if opt[6] != edns0Version {
		// Be conservative and don't touch unknown versions.
		return
	}
	// Ignore flags in opt[6:9]
	if binary.BigEndian.Uint16(opt[9:11]) != 0 {
		// RDLEN must be 0 (no variable length data). We're at the end of the
		// packet so this should be 0 anyway)..
		return
	}

	if requestedSize <= maxSize {
		return
	}

	// Clamp the maximum size
	binary.BigEndian.PutUint16(opt[3:5], maxSize)
}

type route struct {
	Suffix    dnsname.FQDN
	Resolvers []resolverAndDelay
}

// resolverAndDelay is an upstream DNS resolver and a delay for how
// long to wait before querying it.
type resolverAndDelay struct {
	// name is the upstream resolver.
	name dnstype.Resolver

	// startDelay is an amount to delay this resolver at
	// start. It's used when, say, there are four Google or
	// Cloudflare DNS IPs (two IPv4 + two IPv6) and we don't want
	// to race all four at once.
	startDelay time.Duration
}

// forwarder forwards DNS packets to a number of upstream nameservers.
type forwarder struct {
	logf    logger.Logf
	linkMon *monitor.Mon
	linkSel ForwardLinkSelector // TODO(bradfitz): remove this when tsdial.Dialer absords it
	dialer  *tsdial.Dialer
	dohSem  chan struct{}

	ctx       context.Context    // good until Close
	ctxCancel context.CancelFunc // closes ctx

	// responses is a channel by which responses are returned.
	responses chan packet

	mu sync.Mutex // guards following

	dohClient map[string]*http.Client // urlBase -> client

	// routes are per-suffix resolvers to use, with
	// the most specific routes first.
	routes []route
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func maxDoHInFlight(goos string) int {
	if goos != "ios" {
		return 1000 // effectively unlimited
	}
	// iOS <  15 limits the memory to 15MB for NetworkExtensions.
	// iOS >= 15 gives us 50MB.
	// See: https://tailscale.com/blog/go-linker/
	ver := hostinfo.GetOSVersion()
	if ver == "" {
		// Unknown iOS version, be cautious.
		return 10
	}
	major, _, ok := strings.Cut(ver, ".")
	if !ok {
		// Unknown iOS version, be cautious.
		return 10
	}
	if m, err := strconv.Atoi(major); err != nil || m < 15 {
		return 10
	}
	return 1000
}

func newForwarder(logf logger.Logf, responses chan packet, linkMon *monitor.Mon, linkSel ForwardLinkSelector, dialer *tsdial.Dialer) *forwarder {
	f := &forwarder{
		logf:      logger.WithPrefix(logf, "forward: "),
		linkMon:   linkMon,
		linkSel:   linkSel,
		dialer:    dialer,
		responses: responses,
		dohSem:    make(chan struct{}, maxDoHInFlight(runtime.GOOS)),
	}
	f.ctx, f.ctxCancel = context.WithCancel(context.Background())
	return f
}

func (f *forwarder) Close() error {
	f.ctxCancel()
	return nil
}

// resolversWithDelays maps from a set of DNS server names to a slice of
// a type that included a startDelay. So if resolvers contains e.g. four
// Google DNS IPs (two IPv4 + twoIPv6), this function partition adds
// delays to some.
func resolversWithDelays(resolvers []dnstype.Resolver) []resolverAndDelay {
	type hostAndFam struct {
		host string // some arbitrary string representing DNS host (currently the DoH base)
		bits uint8  // either 32 or 128 for IPv4 vs IPv6s address family
	}

	// Track how many of each known resolver host are in the list,
	// per address family.
	total := map[hostAndFam]int{}

	rr := make([]resolverAndDelay, len(resolvers))
	for _, r := range resolvers {
		if ip, err := netaddr.ParseIP(r.Addr); err == nil {
			if host, ok := publicdns.KnownDoH()[ip]; ok {
				total[hostAndFam{host, ip.BitLen()}]++
			}
		}
	}

	done := map[hostAndFam]int{}
	for i, r := range resolvers {
		var startDelay time.Duration
		if ip, err := netaddr.ParseIP(r.Addr); err == nil {
			if host, ok := publicdns.KnownDoH()[ip]; ok {
				key4 := hostAndFam{host, 32}
				key6 := hostAndFam{host, 128}
				switch {
				case ip.Is4():
					if done[key4] > 0 {
						startDelay += wellKnownHostBackupDelay
					}
				case ip.Is6():
					total4 := total[key4]
					if total4 >= 2 {
						// If we have two IPv4 IPs of the same provider
						// already in the set, delay the IPv6 queries
						// until halfway through the timeout (so wait
						// 2.5 seconds). Even the network is IPv6-only,
						// the DoH dialer will fallback to IPv6
						// immediately anyway.
						startDelay = responseTimeout / 2
					} else if total4 == 1 {
						startDelay += wellKnownHostBackupDelay
					}
					if done[key6] > 0 {
						startDelay += wellKnownHostBackupDelay
					}
				}
				done[hostAndFam{host, ip.BitLen()}]++
			}
		}
		rr[i] = resolverAndDelay{
			name:       r,
			startDelay: startDelay,
		}
	}
	return rr
}

// setRoutes sets the routes to use for DNS forwarding. It's called by
// Resolver.SetConfig on reconfig.
//
// The memory referenced by routesBySuffix should not be modified.
func (f *forwarder) setRoutes(routesBySuffix map[dnsname.FQDN][]dnstype.Resolver) {
	routes := make([]route, 0, len(routesBySuffix))
	for suffix, rs := range routesBySuffix {
		routes = append(routes, route{
			Suffix:    suffix,
			Resolvers: resolversWithDelays(rs),
		})
	}
	// Sort from longest prefix to shortest.
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Suffix.NumLabels() > routes[j].Suffix.NumLabels()
	})

	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = routes
}

var stdNetPacketListener packetListener = new(net.ListenConfig)

type packetListener interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

func (f *forwarder) packetListener(ip netaddr.IP) (packetListener, error) {
	if f.linkSel == nil || initListenConfig == nil {
		return stdNetPacketListener, nil
	}
	linkName := f.linkSel.PickLink(ip)
	if linkName == "" {
		return stdNetPacketListener, nil
	}
	lc := new(net.ListenConfig)
	if err := initListenConfig(lc, f.linkMon, linkName); err != nil {
		return nil, err
	}
	return lc, nil
}

// getKnownDoHClient returns an HTTP client for a DoH provider (such as Google
// or Cloudflare DNS), as a function of one of its (usually four) IPs.
//
// The provided IP is only used to determine the DoH provider; it is not
// prioritized among the set of IPs that are used by the provider.
func (f *forwarder) getKnownDoHClient(ip netaddr.IP) (urlBase string, c *http.Client, ok bool) {
	urlBase, ok = publicdns.KnownDoH()[ip]
	if !ok {
		return "", nil, false
	}
	c, ok = f.getKnownDoHClientForProvider(urlBase)
	if !ok {
		return "", nil, false
	}
	return urlBase, c, true
}

// getKnownDoHClientForProvider returns an HTTP client for a specific DoH
// provider named by its DoH base URL (like "https://dns.google/dns-query").
//
// The returned client race/Happy Eyeballs dials all IPs for urlBase (usually
// 4), as statically known by the publicdns package.
func (f *forwarder) getKnownDoHClientForProvider(urlBase string) (c *http.Client, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.dohClient[urlBase]; ok {
		return c, true
	}
	allIPs := publicdns.DoHIPsOfBase()[urlBase]
	if len(allIPs) == 0 {
		return nil, false
	}
	dohURL, err := url.Parse(urlBase)
	if err != nil {
		return nil, false
	}
	nsDialer := netns.NewDialer(f.logf)
	dialer := dnscache.Dialer(nsDialer.DialContext, &dnscache.Resolver{
		SingleHost:             dohURL.Hostname(),
		SingleHostStaticResult: allIPs,
	})
	c = &http.Client{
		Transport: &http.Transport{
			IdleConnTimeout: dohTransportTimeout,
			DialContext: func(ctx context.Context, netw, addr string) (net.Conn, error) {
				if !strings.HasPrefix(netw, "tcp") {
					return nil, fmt.Errorf("unexpected network %q", netw)
				}
				return dialer(ctx, netw, addr)
			},
		},
	}
	if f.dohClient == nil {
		f.dohClient = map[string]*http.Client{}
	}
	f.dohClient[urlBase] = c
	return c, true
}

const dohType = "application/dns-message"

func (f *forwarder) releaseDoHSem() { <-f.dohSem }

func (f *forwarder) sendDoH(ctx context.Context, urlBase string, c *http.Client, packet []byte) ([]byte, error) {
	// Bound the number of HTTP requests in flight. This primarily
	// matters for iOS where we're very memory constrained and
	// HTTP requests are heavier on iOS where we don't include
	// HTTP/2 for binary size reasons (as binaries on iOS linked
	// with Go code cost memory proportional to the binary size,
	// for reasons not fully understood).
	select {
	case f.dohSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer f.releaseDoHSem()

	metricDNSFwdDoH.Add(1)
	req, err := http.NewRequestWithContext(ctx, "POST", urlBase, bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohType)
	// Note: we don't currently set the Accept header (which is
	// only a SHOULD in the spec) as iOS doesn't use HTTP/2 and
	// we'd rather save a few bytes on outgoing requests when
	// empirically no provider cares about the Accept header's
	// absence.

	hres, err := c.Do(req)
	if err != nil {
		metricDNSFwdDoHErrorTransport.Add(1)
		return nil, err
	}
	defer hres.Body.Close()
	if hres.StatusCode != 200 {
		metricDNSFwdDoHErrorStatus.Add(1)
		return nil, errors.New(hres.Status)
	}
	if ct := hres.Header.Get("Content-Type"); ct != dohType {
		metricDNSFwdDoHErrorCT.Add(1)
		return nil, fmt.Errorf("unexpected response Content-Type %q", ct)
	}
	res, err := ioutil.ReadAll(hres.Body)
	if err != nil {
		metricDNSFwdDoHErrorBody.Add(1)
	}
	return res, err
}

// send sends packet to dst. It is best effort.
//
// send expects the reply to have the same txid as txidOut.
func (f *forwarder) send(ctx context.Context, fq *forwardQuery, rr resolverAndDelay) ([]byte, error) {
	if strings.HasPrefix(rr.name.Addr, "http://") {
		return f.sendDoH(ctx, rr.name.Addr, f.dialer.PeerAPIHTTPClient(), fq.packet)
	}
	if strings.HasPrefix(rr.name.Addr, "https://") {
		metricDNSFwdErrorType.Add(1)
		return nil, fmt.Errorf("https:// resolvers not supported yet")
	}
	if strings.HasPrefix(rr.name.Addr, "tls://") {
		metricDNSFwdErrorType.Add(1)
		return nil, fmt.Errorf("tls:// resolvers not supported yet")
	}
	ipp, err := netaddr.ParseIPPort(rr.name.Addr)
	if err != nil {
		return nil, err
	}

	// Upgrade known DNS IPs to DoH (DNS-over-HTTPs).
	// All known DoH is over port 53.
	if urlBase, dc, ok := f.getKnownDoHClient(ipp.IP()); ok {
		res, err := f.sendDoH(ctx, urlBase, dc, fq.packet)
		if err == nil || ctx.Err() != nil {
			return res, err
		}
		f.logf("DoH error from %v: %v", ipp.IP(), err)
	}

	metricDNSFwdUDP.Add(1)
	ln, err := f.packetListener(ipp.IP())
	if err != nil {
		return nil, err
	}
	conn, err := ln.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		f.logf("ListenPacket failed: %v", err)
		return nil, err
	}
	defer conn.Close()

	fq.closeOnCtxDone.Add(conn)
	defer fq.closeOnCtxDone.Remove(conn)

	if _, err := conn.WriteTo(fq.packet, ipp.UDPAddr()); err != nil {
		metricDNSFwdUDPErrorWrite.Add(1)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, err
	}
	metricDNSFwdUDPWrote.Add(1)

	// The 1 extra byte is to detect packet truncation.
	out := make([]byte, maxResponseBytes+1)
	n, _, err := conn.ReadFrom(out)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if neterror.PacketWasTruncated(err) {
			err = nil
		} else {
			metricDNSFwdUDPErrorRead.Add(1)
			return nil, err
		}
	}
	truncated := n > maxResponseBytes
	if truncated {
		n = maxResponseBytes
	}
	if n < headerBytes {
		f.logf("recv: packet too small (%d bytes)", n)
	}
	out = out[:n]
	txid := getTxID(out)
	if txid != fq.txid {
		metricDNSFwdUDPErrorTxID.Add(1)
		return nil, errors.New("txid doesn't match")
	}
	rcode := getRCode(out)
	// don't forward transient errors back to the client when the server fails
	if rcode == dns.RCodeServerFailure {
		f.logf("recv: response code indicating server failure: %d", rcode)
		metricDNSFwdUDPErrorServer.Add(1)
		return nil, errors.New("response code indicates server issue")
	}

	if truncated {
		const dnsFlagTruncated = 0x200
		flags := binary.BigEndian.Uint16(out[2:4])
		flags |= dnsFlagTruncated
		binary.BigEndian.PutUint16(out[2:4], flags)

		// TODO(#2067): Remove any incomplete records? RFC 1035 section 6.2
		// states that truncation should head drop so that the authority
		// section can be preserved if possible. However, the UDP read with
		// a too-small buffer has already dropped the end, so that's the
		// best we can do.
	}

	clampEDNSSize(out, maxResponseBytes)
	metricDNSFwdUDPSuccess.Add(1)
	return out, nil
}

// resolvers returns the resolvers to use for domain.
func (f *forwarder) resolvers(domain dnsname.FQDN) []resolverAndDelay {
	f.mu.Lock()
	routes := f.routes
	f.mu.Unlock()
	for _, route := range routes {
		if route.Suffix == "." || route.Suffix.Contains(domain) {
			return route.Resolvers
		}
	}
	return nil
}

// forwardQuery is information and state about a forwarded DNS query that's
// being sent to 1 or more upstreams.
//
// In the case of racing against multiple equivalent upstreams
// (e.g. Google or CloudFlare's 4 DNS IPs: 2 IPv4 + 2 IPv6), this type
// handles racing them more intelligently than just blasting away 4
// queries at once.
type forwardQuery struct {
	txid   txid
	packet []byte

	// closeOnCtxDone lets send register values to Close if the
	// caller's ctx expires. This avoids send from allocating its
	// own waiting goroutine to interrupt the ReadFrom, as memory
	// is tight on iOS and we want the number of pending DNS
	// lookups to be bursty without too much associated
	// goroutine/memory cost.
	closeOnCtxDone *closePool

	// TODO(bradfitz): add race delay state:
	// mu sync.Mutex
	// ...
}

// forward forwards the query to all upstream nameservers and waits for
// the first response.
//
// It either sends to f.responses and returns nil, or returns a
// non-nil error (without sending to the channel).
func (f *forwarder) forward(query packet) error {
	ctx, cancel := context.WithTimeout(f.ctx, responseTimeout)
	defer cancel()
	return f.forwardWithDestChan(ctx, query, f.responses)
}

// forwardWithDestChan forwards the query to all upstream nameservers
// and waits for the first response.
//
// It either sends to responseChan and returns nil, or returns a
// non-nil error (without sending to the channel).
//
// If resolvers is non-empty, it's used explicitly (notably, for exit
// node DNS proxy queries), otherwise f.resolvers is used.
func (f *forwarder) forwardWithDestChan(ctx context.Context, query packet, responseChan chan<- packet, resolvers ...resolverAndDelay) error {
	metricDNSFwd.Add(1)
	domain, err := nameFromQuery(query.bs)
	if err != nil {
		metricDNSFwdErrorName.Add(1)
		return err
	}

	// Drop DNS service discovery spam, primarily for battery life
	// on mobile.  Things like Spotify on iOS generate this traffic,
	// when browsing for LAN devices.  But even when filtering this
	// out, playing on Sonos still works.
	if hasRDNSBonjourPrefix(domain) {
		metricDNSFwdDropBonjour.Add(1)
		res, err := nxDomainResponse(query)
		if err != nil {
			f.logf("error parsing bonjour query: %v", err)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case responseChan <- res:
			return nil
		}
	}

	if fl, ok := fwdLogAtomic.Load().(*fwdLog); ok {
		fl.addName(string(domain))
	}

	clampEDNSSize(query.bs, maxResponseBytes)

	if len(resolvers) == 0 {
		resolvers = f.resolvers(domain)
		if len(resolvers) == 0 {
			metricDNSFwdErrorNoUpstream.Add(1)
			return errNoUpstreams
		}
	}

	fq := &forwardQuery{
		txid:           getTxID(query.bs),
		packet:         query.bs,
		closeOnCtxDone: new(closePool),
	}
	defer fq.closeOnCtxDone.Close()

	resc := make(chan []byte, 1)
	var (
		mu       sync.Mutex
		firstErr error
	)

	for i := range resolvers {
		go func(rr *resolverAndDelay) {
			if rr.startDelay > 0 {
				timer := time.NewTimer(rr.startDelay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
			resb, err := f.send(ctx, fq, *rr)
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			select {
			case resc <- resb:
			default:
			}
		}(&resolvers[i])
	}

	select {
	case v := <-resc:
		select {
		case <-ctx.Done():
			metricDNSFwdErrorContext.Add(1)
			return ctx.Err()
		case responseChan <- packet{v, query.addr}:
			metricDNSFwdSuccess.Add(1)
			return nil
		}
	case <-ctx.Done():
		mu.Lock()
		defer mu.Unlock()
		metricDNSFwdErrorContext.Add(1)
		if firstErr != nil {
			metricDNSFwdErrorContextGotError.Add(1)
			return firstErr
		}
		return ctx.Err()
	}
}

var initListenConfig func(_ *net.ListenConfig, _ *monitor.Mon, tunName string) error

// nameFromQuery extracts the normalized query name from bs.
func nameFromQuery(bs []byte) (dnsname.FQDN, error) {
	var parser dns.Parser

	hdr, err := parser.Start(bs)
	if err != nil {
		return "", err
	}
	if hdr.Response {
		return "", errNotQuery
	}

	q, err := parser.Question()
	if err != nil {
		return "", err
	}

	n := q.Name.Data[:q.Name.Length]
	return dnsname.ToFQDN(rawNameToLower(n))
}

// nxDomainResponse returns an NXDomain DNS reply for the provided request.
func nxDomainResponse(req packet) (res packet, err error) {
	p := dnsParserPool.Get().(*dnsParser)
	defer dnsParserPool.Put(p)

	if err := p.parseQuery(req.bs); err != nil {
		return packet{}, err
	}

	h := p.Header
	h.Response = true
	h.RecursionAvailable = h.RecursionDesired
	h.RCode = dns.RCodeNameError
	b := dns.NewBuilder(nil, h)
	// TODO(bradfitz): should we add an SOA record in the Authority
	// section too? (for the nxdomain negative caching TTL)
	// For which zone? Does iOS care?
	res.bs, err = b.Finish()
	res.addr = req.addr
	return res, err
}

// closePool is a dynamic set of io.Closers to close as a group.
// It's intended to be Closed at most once.
//
// The zero value is ready for use.
type closePool struct {
	mu     sync.Mutex
	m      map[io.Closer]bool
	closed bool
}

func (p *closePool) Add(c io.Closer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		c.Close()
		return
	}
	if p.m == nil {
		p.m = map[io.Closer]bool{}
	}
	p.m[c] = true
}

func (p *closePool) Remove(c io.Closer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	delete(p.m, c)
}

func (p *closePool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	for c := range p.m {
		c.Close()
	}
	return nil
}
