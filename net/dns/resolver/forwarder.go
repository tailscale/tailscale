// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/control/controlknobs"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/neterror"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netx"
	"tailscale.com/net/sockstats"
	"tailscale.com/net/tsdial"
	"tailscale.com/syncs"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/util/cloudenv"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/race"
	"tailscale.com/version"
)

// headerBytes is the number of bytes in a DNS message header.
const headerBytes = 12

// dnsFlagTruncated is set in the flags word when the packet is truncated.
const dnsFlagTruncated = 0x200

// truncatedFlagSet returns true if the DNS packet signals that it has
// been truncated. False is also returned if the packet was too small
// to be valid.
func truncatedFlagSet(pkt []byte) bool {
	if len(pkt) < headerBytes {
		return false
	}
	return (binary.BigEndian.Uint16(pkt[2:4]) & dnsFlagTruncated) != 0
}

const (
	// dohIdleConnTimeout is how long to keep idle HTTP connections
	// open to DNS-over-HTTPS servers. 10 seconds is a sensible
	// default, as it's long enough to handle a burst of queries
	// coming in a row, but short enough to not keep idle connections
	// open for too long. In theory, idle connections could be kept
	// open for a long time without any battery impact as no traffic
	// is supposed to be flowing on them.
	// However, in practice, DoH servers will send TCP keepalives (e.g.
	// NextDNS sends them every ~10s). Handling these keepalives
	// wakes up the modem, and that uses battery. Therefore, we keep
	// the idle timeout low enough to allow idle connections to be
	// closed during an extended period with no DNS queries, killing
	// keepalive network activity.
	dohIdleConnTimeout = 10 * time.Second

	// dohTransportTimeout is how much of a head start to give a DoH query
	// that was upgraded from a well-known public DNS provider's IP before
	// normal UDP mode is attempted as a fallback.
	dohHeadStart = 500 * time.Millisecond

	// wellKnownHostBackupDelay is how long to artificially delay upstream
	// DNS queries to the "fallback" DNS server IP for a known provider
	// (e.g. how long to wait to query Google's 8.8.4.4 after 8.8.8.8).
	wellKnownHostBackupDelay = 200 * time.Millisecond

	// udpRaceTimeout is the timeout after which we will start a DNS query
	// over TCP while waiting for the UDP query to complete.
	udpRaceTimeout = 2 * time.Second

	// tcpQueryTimeout is the timeout for a DNS query performed over TCP.
	// It matches the default 5sec timeout of the 'dig' utility.
	tcpQueryTimeout = 5 * time.Second
)

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

// dnsForwarderFailing should be raised when the forwarder is unable to reach the
// upstream resolvers. This is a high severity warning as it results in "no internet".
// This warning must be cleared when the forwarder is working again.
//
// We allow for 5 second grace period to ensure this is not raised for spurious errors
// under the assumption that DNS queries are relatively frequent and a subsequent
// successful query will clear any one-off errors.
var dnsForwarderFailing = health.Register(&health.Warnable{
	Code:                "dns-forward-failing",
	Title:               "DNS unavailable",
	Severity:            health.SeverityMedium,
	DependsOn:           []*health.Warnable{health.NetworkStatusWarnable},
	Text:                health.StaticMessage("Tailscale can't reach the configured DNS servers. Internet connectivity may be affected."),
	ImpactsConnectivity: true,
	TimeToVisible:       15 * time.Second,
})

type route struct {
	Suffix    dnsname.FQDN
	Resolvers []resolverAndDelay
}

// resolverAndDelay is an upstream DNS resolver and a delay for how
// long to wait before querying it.
type resolverAndDelay struct {
	// name is the upstream resolver.
	name *dnstype.Resolver

	// startDelay is an amount to delay this resolver at
	// start. It's used when, say, there are four Google or
	// Cloudflare DNS IPs (two IPv4 + two IPv6) and we don't want
	// to race all four at once.
	startDelay time.Duration
}

// forwarder forwards DNS packets to a number of upstream nameservers.
type forwarder struct {
	logf       logger.Logf
	netMon     *netmon.Monitor     // always non-nil
	linkSel    ForwardLinkSelector // TODO(bradfitz): remove this when tsdial.Dialer absorbs it
	dialer     *tsdial.Dialer
	health     *health.Tracker // always non-nil
	verboseFwd bool            // if true, log all DNS forwarding

	controlKnobs *controlknobs.Knobs // or nil

	ctx       context.Context    // good until Close
	ctxCancel context.CancelFunc // closes ctx

	mu syncs.Mutex // guards following

	dohClient map[string]*http.Client // urlBase -> client

	// routes are per-suffix resolvers to use, with
	// the most specific routes first.
	routes []route
	// cloudHostFallback are last resort resolvers to use if no per-suffix
	// resolver matches. These are only populated on cloud hosts where the
	// platform provides a well-known recursive resolver.
	//
	// That is, if we're running on GCP or AWS where there's always a well-known
	// IP of a recursive resolver, return that rather than having callers return
	// SERVFAIL. This fixes both normal 100.100.100.100 resolution when
	// /etc/resolv.conf is missing/corrupt, and the peerapi ExitDNS stub
	// resolver lookup.
	cloudHostFallback []resolverAndDelay
}

func newForwarder(logf logger.Logf, netMon *netmon.Monitor, linkSel ForwardLinkSelector, dialer *tsdial.Dialer, health *health.Tracker, knobs *controlknobs.Knobs) *forwarder {
	if !buildfeatures.HasDNS {
		return nil
	}
	if netMon == nil {
		panic("nil netMon")
	}
	f := &forwarder{
		logf:         logger.WithPrefix(logf, "forward: "),
		netMon:       netMon,
		linkSel:      linkSel,
		dialer:       dialer,
		health:       health,
		controlKnobs: knobs,
		verboseFwd:   verboseDNSForward(),
	}
	f.ctx, f.ctxCancel = context.WithCancel(context.Background())
	return f
}

func (f *forwarder) Close() error {
	f.ctxCancel()
	return nil
}

// resolversWithDelays maps from a set of DNS server names to a slice of a type
// that included a startDelay, upgrading any well-known DoH (DNS-over-HTTP)
// servers in the process, insert a DoH lookup first before UDP fallbacks.
func resolversWithDelays(resolvers []*dnstype.Resolver) []resolverAndDelay {
	rr := make([]resolverAndDelay, 0, len(resolvers)+2)

	type dohState uint8
	const addedDoH = dohState(1)
	const addedDoHAndDontAddUDP = dohState(2)

	// Add the known DoH ones first, starting immediately.
	didDoH := map[string]dohState{}
	for _, r := range resolvers {
		ipp, ok := r.IPPort()
		if !ok {
			continue
		}
		dohBase, dohOnly, ok := publicdns.DoHEndpointFromIP(ipp.Addr())
		if !ok || didDoH[dohBase] != 0 {
			continue
		}
		if dohOnly {
			didDoH[dohBase] = addedDoHAndDontAddUDP
		} else {
			didDoH[dohBase] = addedDoH
		}
		rr = append(rr, resolverAndDelay{name: &dnstype.Resolver{Addr: dohBase}})
	}

	type hostAndFam struct {
		host string // some arbitrary string representing DNS host (currently the DoH base)
		bits uint8  // either 32 or 128 for IPv4 vs IPv6s address family
	}
	done := map[hostAndFam]int{}
	for _, r := range resolvers {
		ipp, ok := r.IPPort()
		if !ok {
			// Pass non-IP ones through unchanged, without delay.
			// (e.g. DNS-over-ExitDNS when using an exit node)
			rr = append(rr, resolverAndDelay{name: r})
			continue
		}
		ip := ipp.Addr()
		var startDelay time.Duration
		if host, _, ok := publicdns.DoHEndpointFromIP(ip); ok {
			if didDoH[host] == addedDoHAndDontAddUDP {
				continue
			}
			// We already did the DoH query early. These
			// are for normal dns53 UDP queries.
			startDelay = dohHeadStart
			key := hostAndFam{host, uint8(ip.BitLen())}
			if done[key] > 0 {
				startDelay += wellKnownHostBackupDelay
			}
			done[key]++
		}
		rr = append(rr, resolverAndDelay{
			name:       r,
			startDelay: startDelay,
		})
	}
	return rr
}

var (
	cloudResolversOnce sync.Once
	cloudResolversLazy []resolverAndDelay
)

func cloudResolvers() []resolverAndDelay {
	cloudResolversOnce.Do(func() {
		if ip := cloudenv.Get().ResolverIP(); ip != "" {
			cloudResolver := []*dnstype.Resolver{{Addr: ip}}
			cloudResolversLazy = resolversWithDelays(cloudResolver)
		}
	})
	return cloudResolversLazy
}

// setRoutes sets the routes to use for DNS forwarding. It's called by
// Resolver.SetConfig on reconfig.
//
// The memory referenced by routesBySuffix should not be modified.
func (f *forwarder) setRoutes(routesBySuffix map[dnsname.FQDN][]*dnstype.Resolver) {
	routes := make([]route, 0, len(routesBySuffix))

	cloudHostFallback := cloudResolvers()
	for suffix, rs := range routesBySuffix {
		if suffix == "." && len(rs) == 0 && len(cloudHostFallback) > 0 {
			routes = append(routes, route{
				Suffix:    suffix,
				Resolvers: cloudHostFallback,
			})
		} else {
			routes = append(routes, route{
				Suffix:    suffix,
				Resolvers: resolversWithDelays(rs),
			})
		}
	}

	if cloudenv.Get().HasInternalTLD() && len(cloudHostFallback) > 0 {
		if _, ok := routesBySuffix["internal."]; !ok {
			routes = append(routes, route{
				Suffix:    "internal.",
				Resolvers: cloudHostFallback,
			})
		}
	}

	// Sort from longest prefix to shortest.
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Suffix.NumLabels() > routes[j].Suffix.NumLabels()
	})

	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes = routes
	f.cloudHostFallback = cloudHostFallback
}

var stdNetPacketListener nettype.PacketListenerWithNetIP = nettype.MakePacketListenerWithNetIP(new(net.ListenConfig))

func (f *forwarder) packetListener(ip netip.Addr) (nettype.PacketListenerWithNetIP, error) {
	if f.linkSel == nil || initListenConfig == nil {
		return stdNetPacketListener, nil
	}
	linkName := f.linkSel.PickLink(ip)
	if linkName == "" {
		return stdNetPacketListener, nil
	}
	lc := new(net.ListenConfig)
	if err := initListenConfig(lc, f.netMon, linkName); err != nil {
		return nil, err
	}
	return nettype.MakePacketListenerWithNetIP(lc), nil
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
	allIPs := publicdns.DoHIPsOfBase(urlBase)
	if len(allIPs) == 0 {
		return nil, false
	}
	dohURL, err := url.Parse(urlBase)
	if err != nil {
		return nil, false
	}

	dialer := dnscache.Dialer(f.getDialerType(), &dnscache.Resolver{
		SingleHost:             dohURL.Hostname(),
		SingleHostStaticResult: allIPs,
		Logf:                   f.logf,
	})
	tlsConfig := &tls.Config{
		// Enforce TLS 1.3, as all of our supported DNS-over-HTTPS servers are compatible with it
		// (see tailscale.com/net/dns/publicdns/publicdns.go).
		MinVersion: tls.VersionTLS13,
	}
	c = &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			IdleConnTimeout:   dohIdleConnTimeout,
			// On mobile platforms TCP KeepAlive is disabled in the dialer,
			// ensure that we timeout if the connection appears to be hung.
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConnsPerHost:   1,
			DialContext: func(ctx context.Context, netw, addr string) (net.Conn, error) {
				if !strings.HasPrefix(netw, "tcp") {
					return nil, fmt.Errorf("unexpected network %q", netw)
				}
				return dialer(ctx, netw, addr)
			},
			TLSClientConfig: tlsConfig,
		},
	}
	if f.dohClient == nil {
		f.dohClient = map[string]*http.Client{}
	}
	f.dohClient[urlBase] = c
	return c, true
}

const dohType = "application/dns-message"

func (f *forwarder) sendDoH(ctx context.Context, urlBase string, c *http.Client, packet []byte) ([]byte, error) {
	ctx = sockstats.WithSockStats(ctx, sockstats.LabelDNSForwarderDoH, f.logf)
	metricDNSFwdDoH.Add(1)
	req, err := http.NewRequestWithContext(ctx, "POST", urlBase, bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohType)
	req.Header.Set("Accept", dohType)
	req.Header.Set("User-Agent", "tailscaled/"+version.Long())

	hres, err := c.Do(req)
	if err != nil {
		metricDNSFwdDoHErrorTransport.Add(1)
		return nil, err
	}
	defer hres.Body.Close()
	if hres.StatusCode != 200 {
		metricDNSFwdDoHErrorStatus.Add(1)
		if hres.StatusCode/100 == 5 {
			// Translate 5xx HTTP server errors into SERVFAIL DNS responses.
			return nil, fmt.Errorf("%w: %s", errServerFailure, hres.Status)
		}
		return nil, errors.New(hres.Status)
	}
	if ct := hres.Header.Get("Content-Type"); ct != dohType {
		metricDNSFwdDoHErrorCT.Add(1)
		return nil, fmt.Errorf("unexpected response Content-Type %q", ct)
	}
	res, err := io.ReadAll(hres.Body)
	if err != nil {
		metricDNSFwdDoHErrorBody.Add(1)
	}
	if truncatedFlagSet(res) {
		metricDNSFwdTruncated.Add(1)
	}
	return res, err
}

var (
	verboseDNSForward = envknob.RegisterBool("TS_DEBUG_DNS_FORWARD_SEND")
	skipTCPRetry      = envknob.RegisterBool("TS_DNS_FORWARD_SKIP_TCP_RETRY")

	// For correlating log messages in the send() function; only used when
	// verboseDNSForward() is true.
	forwarderCount atomic.Uint64
)

// send sends packet to dst. It is best effort.
//
// send expects the reply to have the same txid as txidOut.
func (f *forwarder) send(ctx context.Context, fq *forwardQuery, rr resolverAndDelay) (ret []byte, err error) {
	if f.verboseFwd {
		id := forwarderCount.Add(1)
		domain, typ, _ := nameFromQuery(fq.packet)
		f.logf("forwarder.send(%q, %d, %v, %d) [%d] ...", rr.name.Addr, fq.txid, typ, len(domain), id)
		defer func() {
			f.logf("forwarder.send(%q, %d, %v, %d) [%d] = %v, %v", rr.name.Addr, fq.txid, typ, len(domain), id, len(ret), err)
		}()
	}
	if strings.HasPrefix(rr.name.Addr, "http://") {
		if !buildfeatures.HasPeerAPIClient {
			return nil, feature.ErrUnavailable
		}
		return f.sendDoH(ctx, rr.name.Addr, f.dialer.PeerAPIHTTPClient(), fq.packet)
	}
	if strings.HasPrefix(rr.name.Addr, "https://") {
		// Only known DoH providers are supported currently. Specifically, we
		// only support DoH providers where we can TCP connect to them on port
		// 443 at the same IP address they serve normal UDP DNS from (1.1.1.1,
		// 8.8.8.8, 9.9.9.9, etc.) That's why OpenDNS and custom DoH providers
		// aren't currently supported. There's no backup DNS resolution path for
		// them.
		urlBase := rr.name.Addr
		if hc, ok := f.getKnownDoHClientForProvider(urlBase); ok {
			return f.sendDoH(ctx, urlBase, hc, fq.packet)
		}
		metricDNSFwdErrorType.Add(1)
		return nil, fmt.Errorf("arbitrary https:// resolvers not supported yet")
	}
	if strings.HasPrefix(rr.name.Addr, "tls://") {
		metricDNSFwdErrorType.Add(1)
		return nil, fmt.Errorf("tls:// resolvers not supported yet")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	isUDPQuery := fq.family == "udp"
	skipTCP := skipTCPRetry() || (f.controlKnobs != nil && f.controlKnobs.DisableDNSForwarderTCPRetries.Load())

	// Print logs about retries if this was because of a truncated response.
	var explicitRetry atomic.Bool // true if truncated UDP response retried
	defer func() {
		if !explicitRetry.Load() {
			return
		}
		if err == nil {
			f.logf("forwarder.send(%q): successfully retried via TCP", rr.name.Addr)
		} else {
			f.logf("forwarder.send(%q): could not retry via TCP: %v", rr.name.Addr, err)
		}
	}()

	firstUDP := func(ctx context.Context) ([]byte, error) {
		resp, err := f.sendUDP(ctx, fq, rr)
		if err != nil {
			return nil, err
		}
		if !truncatedFlagSet(resp) {
			// Successful, non-truncated response; no retry.
			return resp, nil
		}

		// If this is a UDP query, return it regardless of whether the
		// response is truncated or not; the client can retry
		// communicating with tailscaled over TCP. There's no point
		// falling back to TCP for a truncated query if we can't return
		// the results to the client.
		if isUDPQuery {
			return resp, nil
		}

		if skipTCP {
			// Envknob or control knob disabled the TCP retry behaviour;
			// just return what we have.
			return resp, nil
		}

		// This is a TCP query from the client, and the UDP response
		// from the upstream DNS server is truncated; map this to an
		// error to cause our retry helper to immediately kick off the
		// TCP retry.
		explicitRetry.Store(true)
		return nil, truncatedResponseError{resp}
	}
	thenTCP := func(ctx context.Context) ([]byte, error) {
		// If we're skipping the TCP fallback, then wait until the
		// context is canceled and return that error (i.e. not
		// returning anything).
		if skipTCP {
			<-ctx.Done()
			return nil, ctx.Err()
		}

		return f.sendTCP(ctx, fq, rr)
	}

	// If the input query is TCP, then don't have a timeout between
	// starting UDP and TCP.
	timeout := udpRaceTimeout
	if !isUDPQuery {
		timeout = 0
	}

	// Kick off the race between the UDP and TCP queries.
	rh := race.New(timeout, firstUDP, thenTCP)
	resp, err := rh.Start(ctx)
	if err == nil {
		return resp, nil
	}

	// If we got a truncated UDP response, return that instead of an error.
	var trErr truncatedResponseError
	if errors.As(err, &trErr) {
		return trErr.res, nil
	}
	return nil, err
}

type truncatedResponseError struct {
	res []byte
}

func (tr truncatedResponseError) Error() string { return "response truncated" }

var errServerFailure = errors.New("response code indicates server issue")
var errTxIDMismatch = errors.New("txid doesn't match")

func (f *forwarder) sendUDP(ctx context.Context, fq *forwardQuery, rr resolverAndDelay) (ret []byte, err error) {
	ipp, ok := rr.name.IPPort()
	if !ok {
		metricDNSFwdErrorType.Add(1)
		return nil, fmt.Errorf("unrecognized resolver type %q", rr.name.Addr)
	}
	metricDNSFwdUDP.Add(1)
	ctx = sockstats.WithSockStats(ctx, sockstats.LabelDNSForwarderUDP, f.logf)

	ln, err := f.packetListener(ipp.Addr())
	if err != nil {
		return nil, err
	}

	// Specify the exact UDP family to work around https://github.com/golang/go/issues/52264
	udpFam := "udp4"
	if ipp.Addr().Is6() {
		udpFam = "udp6"
	}
	conn, err := ln.ListenPacket(ctx, udpFam, ":0")
	if err != nil {
		f.logf("ListenPacket failed: %v", err)
		return nil, err
	}
	defer conn.Close()

	fq.closeOnCtxDone.Add(conn)
	defer fq.closeOnCtxDone.Remove(conn)

	if _, err := conn.WriteToUDPAddrPort(fq.packet, ipp); err != nil {
		metricDNSFwdUDPErrorWrite.Add(1)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, err
	}
	metricDNSFwdUDPWrote.Add(1)

	// The 1 extra byte is to detect packet truncation.
	out := make([]byte, maxResponseBytes+1)
	n, _, err := conn.ReadFromUDPAddrPort(out)
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
		return nil, errTxIDMismatch
	}
	rcode := getRCode(out)
	// don't forward transient errors back to the client when the server fails
	if rcode == dns.RCodeServerFailure {
		f.logf("recv: response code indicating server failure: %d", rcode)
		metricDNSFwdUDPErrorServer.Add(1)
		return nil, errServerFailure
	}

	if truncated {
		// Set the truncated bit if it wasn't already.
		flags := binary.BigEndian.Uint16(out[2:4])
		flags |= dnsFlagTruncated
		binary.BigEndian.PutUint16(out[2:4], flags)

		// TODO(#2067): Remove any incomplete records? RFC 1035 section 6.2
		// states that truncation should head drop so that the authority
		// section can be preserved if possible. However, the UDP read with
		// a too-small buffer has already dropped the end, so that's the
		// best we can do.
	}

	if truncatedFlagSet(out) {
		metricDNSFwdTruncated.Add(1)
	}

	clampEDNSSize(out, maxResponseBytes)
	metricDNSFwdUDPSuccess.Add(1)
	return out, nil
}

var optDNSForwardUseRoutes = envknob.RegisterOptBool("TS_DEBUG_DNS_FORWARD_USE_ROUTES")

// ShouldUseRoutes reports whether the DNS resolver should consider routes when dialing
// upstream nameservers via TCP.
//
// If true, routes should be considered ([tsdial.Dialer.UserDial]), otherwise defer
// to the system routes ([tsdial.Dialer.SystemDial]).
//
// TODO(nickkhyl): Update [tsdial.Dialer] to reuse the bart.Table we create in net/tstun.Wrapper
// to avoid having two bart tables in memory, especially on iOS. Once that's done,
// we can get rid of the nodeAttr/control knob and always use UserDial for DNS.
//
// See tailscale/tailscale#12027.
func ShouldUseRoutes(knobs *controlknobs.Knobs) bool {
	if !buildfeatures.HasDNS {
		return false
	}
	switch runtime.GOOS {
	case "android", "ios":
		// On mobile platforms with lower memory limits (e.g., 50MB on iOS),
		// this behavior is still gated by the "user-dial-routes" nodeAttr.
		return knobs != nil && knobs.UserDialUseRoutes.Load()
	default:
		// On all other platforms, it is the default behavior,
		// but it can be overridden with the "TS_DEBUG_DNS_FORWARD_USE_ROUTES" env var.
		doNotUseRoutes := optDNSForwardUseRoutes().EqualBool(false)
		return !doNotUseRoutes
	}
}

func (f *forwarder) getDialerType() netx.DialFunc {
	if ShouldUseRoutes(f.controlKnobs) {
		return f.dialer.UserDial
	}
	return f.dialer.SystemDial
}

func (f *forwarder) sendTCP(ctx context.Context, fq *forwardQuery, rr resolverAndDelay) (ret []byte, err error) {
	ipp, ok := rr.name.IPPort()
	if !ok {
		metricDNSFwdErrorType.Add(1)
		return nil, fmt.Errorf("unrecognized resolver type %q", rr.name.Addr)
	}
	metricDNSFwdTCP.Add(1)
	ctx = sockstats.WithSockStats(ctx, sockstats.LabelDNSForwarderTCP, f.logf)

	// Specify the exact family to work around https://github.com/golang/go/issues/52264
	tcpFam := "tcp4"
	if ipp.Addr().Is6() {
		tcpFam = "tcp6"
	}

	ctx, cancel := context.WithTimeout(ctx, tcpQueryTimeout)
	defer cancel()

	conn, err := f.getDialerType()(ctx, tcpFam, ipp.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	fq.closeOnCtxDone.Add(conn)
	defer fq.closeOnCtxDone.Remove(conn)

	ctxOrErr := func(err2 error) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, err2
	}

	// Write the query to the server.
	query := make([]byte, len(fq.packet)+2)
	binary.BigEndian.PutUint16(query, uint16(len(fq.packet)))
	copy(query[2:], fq.packet)
	if _, err := conn.Write(query); err != nil {
		metricDNSFwdTCPErrorWrite.Add(1)
		return ctxOrErr(err)
	}

	metricDNSFwdTCPWrote.Add(1)

	// Read the header length back from the server
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		metricDNSFwdTCPErrorRead.Add(1)
		return ctxOrErr(err)
	}

	// Now read the response
	out := make([]byte, length)
	n, err := io.ReadFull(conn, out)
	if err != nil {
		metricDNSFwdTCPErrorRead.Add(1)
		return ctxOrErr(err)
	}

	if n < int(length) {
		f.logf("sendTCP: packet too small (%d bytes)", n)
		return nil, io.ErrUnexpectedEOF
	}
	out = out[:n]
	txid := getTxID(out)
	if txid != fq.txid {
		metricDNSFwdTCPErrorTxID.Add(1)
		return nil, errTxIDMismatch
	}

	rcode := getRCode(out)

	// don't forward transient errors back to the client when the server fails
	if rcode == dns.RCodeServerFailure {
		f.logf("sendTCP: response code indicating server failure: %d", rcode)
		metricDNSFwdTCPErrorServer.Add(1)
		return nil, errServerFailure
	}

	// TODO(andrew): do we need to do this?
	//clampEDNSSize(out, maxResponseBytes)
	metricDNSFwdTCPSuccess.Add(1)
	return out, nil
}

// resolvers returns the resolvers to use for domain.
func (f *forwarder) resolvers(domain dnsname.FQDN) []resolverAndDelay {
	f.mu.Lock()
	routes := f.routes
	cloudHostFallback := f.cloudHostFallback
	f.mu.Unlock()
	for _, route := range routes {
		if route.Suffix == "." || route.Suffix.Contains(domain) {
			return route.Resolvers
		}
	}
	return cloudHostFallback // or nil if no fallback
}

// GetUpstreamResolvers returns the resolvers that would be used to resolve
// the given FQDN.
func (f *forwarder) GetUpstreamResolvers(name dnsname.FQDN) []*dnstype.Resolver {
	resolvers := f.resolvers(name)
	upstreamResolvers := make([]*dnstype.Resolver, 0, len(resolvers))
	for _, r := range resolvers {
		upstreamResolvers = append(upstreamResolvers, r.name)
	}
	return upstreamResolvers
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
	family string // "tcp" or "udp"

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
	domain, typ, err := nameFromQuery(query.bs)
	if err != nil {
		metricDNSFwdErrorName.Add(1)
		return err
	}

	// Guarantee that the ctx we use below is done when this function returns.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Drop DNS service discovery spam, primarily for battery life
	// on mobile.  Things like Spotify on iOS generate this traffic,
	// when browsing for LAN devices.  But even when filtering this
	// out, playing on Sonos still works.
	if hasRDNSBonjourPrefix(domain) {
		metricDNSFwdDropBonjour.Add(1)
		res, err := nxDomainResponse(query)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting to send NXDOMAIN: %w", ctx.Err())
		case responseChan <- res:
			return nil
		}
	}

	if fl := fwdLogAtomic.Load(); fl != nil {
		fl.addName(string(domain))
	}

	clampEDNSSize(query.bs, maxResponseBytes)

	if len(resolvers) == 0 {
		resolvers = f.resolvers(domain)
		if len(resolvers) == 0 {
			metricDNSFwdErrorNoUpstream.Add(1)
			f.health.SetUnhealthy(dnsForwarderFailing, health.Args{health.ArgDNSServers: ""})
			f.logf("no upstream resolvers set, returning SERVFAIL")

			res, err := servfailResponse(query)
			if err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("waiting to send SERVFAIL: %w", ctx.Err())
			case responseChan <- res:
				return nil
			}
		} else {
			f.health.SetHealthy(dnsForwarderFailing)
		}
	}

	fq := &forwardQuery{
		txid:           getTxID(query.bs),
		packet:         query.bs,
		family:         query.family,
		closeOnCtxDone: new(closePool),
	}
	defer fq.closeOnCtxDone.Close()

	if f.verboseFwd {
		domainSha256 := sha256.Sum256([]byte(domain))
		domainSig := base64.RawStdEncoding.EncodeToString(domainSha256[:3])
		f.logf("request(%d, %v, %d, %s) %d...", fq.txid, typ, len(domain), domainSig, len(fq.packet))
	}

	resc := make(chan []byte, 1) // it's fine buffered or not
	errc := make(chan error, 1)  // it's fine buffered or not too
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
				err = fmt.Errorf("resolving using %q: %w", rr.name.Addr, err)
				select {
				case errc <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case resc <- resb:
			case <-ctx.Done():
			}
		}(&resolvers[i])
	}

	var firstErr error
	var numErr int
	for {
		select {
		case v := <-resc:
			select {
			case <-ctx.Done():
				metricDNSFwdErrorContext.Add(1)
				return fmt.Errorf("waiting to send response: %w", ctx.Err())
			case responseChan <- packet{v, query.family, query.addr}:
				if f.verboseFwd {
					f.logf("response(%d, %v, %d) = %d, nil", fq.txid, typ, len(domain), len(v))
				}
				metricDNSFwdSuccess.Add(1)
				f.health.SetHealthy(dnsForwarderFailing)
				return nil
			}
		case err := <-errc:
			if firstErr == nil {
				firstErr = err
			}
			numErr++
			if numErr == len(resolvers) {
				if errors.Is(firstErr, errServerFailure) {
					res, err := servfailResponse(query)
					if err != nil {
						f.logf("building servfail response: %v", err)
						return firstErr
					}

					select {
					case <-ctx.Done():
						metricDNSFwdErrorContext.Add(1)
						metricDNSFwdErrorContextGotError.Add(1)
						var resolverAddrs []string
						for _, rr := range resolvers {
							resolverAddrs = append(resolverAddrs, rr.name.Addr)
						}
						f.health.SetUnhealthy(dnsForwarderFailing, health.Args{health.ArgDNSServers: strings.Join(resolverAddrs, ",")})
					case responseChan <- res:
						if f.verboseFwd {
							f.logf("forwarder response(%d, %v, %d) = %d, %v", fq.txid, typ, len(domain), len(res.bs), firstErr)
						}
						return nil
					}
				}
				return firstErr
			}
		case <-ctx.Done():
			metricDNSFwdErrorContext.Add(1)
			if firstErr != nil {
				metricDNSFwdErrorContextGotError.Add(1)
				return firstErr
			}

			// If we haven't got an error or a successful response,
			// include all resolvers in the error message so we can
			// at least see what what servers we're trying to
			// query.
			var resolverAddrs []string
			for _, rr := range resolvers {
				resolverAddrs = append(resolverAddrs, rr.name.Addr)
			}
			f.health.SetUnhealthy(dnsForwarderFailing, health.Args{health.ArgDNSServers: strings.Join(resolverAddrs, ",")})
			return fmt.Errorf("waiting for response or error from %v: %w", resolverAddrs, ctx.Err())
		}
	}
}

var initListenConfig func(_ *net.ListenConfig, _ *netmon.Monitor, tunName string) error

// nameFromQuery extracts the normalized query name from bs.
func nameFromQuery(bs []byte) (dnsname.FQDN, dns.Type, error) {
	var parser dns.Parser

	hdr, err := parser.Start(bs)
	if err != nil {
		return "", 0, err
	}
	if hdr.Response {
		return "", 0, errNotQuery
	}

	q, err := parser.Question()
	if err != nil {
		return "", 0, err
	}

	n := q.Name.Data[:q.Name.Length]
	fqdn, err := dnsname.ToFQDN(rawNameToLower(n))
	if err != nil {
		return "", 0, err
	}
	return fqdn, q.Type, nil
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
	b.StartQuestions()
	b.Question(p.Question)
	res.bs, err = b.Finish()
	res.addr = req.addr
	return res, err
}

// servfailResponse returns a SERVFAIL error reply for the provided request.
func servfailResponse(req packet) (res packet, err error) {
	p := dnsParserPool.Get().(*dnsParser)
	defer dnsParserPool.Put(p)

	if err := p.parseQuery(req.bs); err != nil {
		return packet{}, err
	}

	h := p.Header
	h.Response = true
	h.Authoritative = true
	h.RCode = dns.RCodeServerFailure
	b := dns.NewBuilder(nil, h)
	b.StartQuestions()
	b.Question(p.Question)
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
