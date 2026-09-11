// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package captivedetection provides a way to detect if the system is connected to a network that has
// a captive portal. It does this by making HTTP requests to known captive portal detection endpoints
// and checking if the HTTP responses indicate that a captive portal might be present.
package captivedetection

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/feature"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// HookPlatformHint, if set, reports whether the host OS has itself detected a
// captive portal on the current network.
//
// The OS is in a better position to know than we are: it sees the association
// and DHCP exchange, and on some platforms it has already run its own probe by
// the time we look. Where available this is both the cheapest and the most
// reliable signal we have, so a positive answer is taken as conclusive.
//
// A negative answer is recorded but not acted upon, because the OS probes have
// their own blind spots and we don't want their false negatives to become ours.
//
// ok reports whether the platform could answer at all.
var HookPlatformHint feature.Hook[func(ctx context.Context) (found, ok bool)]

// Detector checks whether the system is behind a captive portal.
type Detector struct {
	clock func() time.Time

	// lookupIPFn, if non-nil, replaces the actual DNS query made by
	// [Detector.lookupIP]. server is the resolver to ask, or the zero Addr to
	// mean the system resolver. It is set by tests.
	lookupIPFn func(ctx context.Context, server netip.Addr, host string) ([]netip.Addr, error)

	// dialFn, if non-nil, replaces the dialer used for the HTTP probes and the
	// DNS queries, bypassing the interface binding in [Detector.dialTo]. It is
	// set by tests to route both through a virtual network.
	dialFn func(ctx context.Context, network, addr string) (net.Conn, error)

	// httpClient is the HTTP client that is used for captive portal detection. It is configured
	// to not follow redirects, have a short timeout and no keep-alive.
	httpClient *http.Client
	// currIfIndex is the index of the interface that is currently being used by the httpClient.
	currIfIndex int
	// netMon is the network monitor for the current detection attempt, used to
	// keep our sockets out of the Tailscale tunnel and to find the default
	// gateway. It is nil until a detection attempt sets it, and in tests.
	netMon *netmon.Monitor
	// localResolversFn, if non-nil, reports the DNS servers the physical
	// network handed us. See [Detector.SetLocalNetworkResolvers].
	localResolversFn func() []netip.Addr
	// mu guards currIfIndex, netMon and localResolversFn.
	mu syncs.Mutex
	// logf is the logger used for logging messages. If it is nil, log.Printf is used.
	logf logger.Logf
}

// NewDetector creates a new Detector instance for captive portal detection.
func NewDetector(logf logger.Logf) *Detector {
	d := &Detector{logf: logf}
	d.httpClient = &http.Client{
		// No redirects allowed
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:       d.dialContext,
			DisableKeepAlives: true,
		},
		Timeout: Timeout,
	}
	return d
}

func (d *Detector) Now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}

// SetLocalNetworkResolvers tells the detector which DNS servers the physical
// network handed us, so that [Detector.lookupIP] can ask them directly rather
// than going through whatever resolver the system would pick. fn is called once
// per detection attempt, and may return nil.
//
// This matters because on a node using an exit node the system resolver leads
// into the tunnel, which is exactly where a captive portal has cut us off. See
// [Detector.lookupIP].
func (d *Detector) SetLocalNetworkResolvers(fn func() []netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.localResolversFn = fn
}

// Timeout is the timeout for captive portal detection requests. Because the captive portal intercepting our requests
// is usually located on the LAN, this is a relatively short timeout.
const Timeout = 3 * time.Second

// Detect reports whether it detected a captive portal.
//
// It is a convenience wrapper around [Detector.DetectResult] that collapses the
// three possible outcomes to two. Prefer DetectResult: callers that treat an
// inconclusive result as "no captive portal" will clear warnings they
// shouldn't, and will stop looking for a portal that is in fact there.
func (d *Detector) Detect(ctx context.Context, netMon *netmon.Monitor, derpMap *tailcfg.DERPMap, preferredDERPRegionID tailcfg.DERPRegionID) (found bool) {
	return d.DetectResult(ctx, netMon, derpMap, preferredDERPRegionID).Verdict == VerdictPortal
}

// DetectResult attempts to detect whether the system is behind a captive portal,
// and reports what it found along with the evidence behind it. See [Result].
//
// This function might take a while to return, as it will attempt to detect a captive portal on all available interfaces
// by performing multiple HTTP requests. It should be called in a separate goroutine if you want to avoid blocking.
func (d *Detector) DetectResult(ctx context.Context, netMon *netmon.Monitor, derpMap *tailcfg.DERPMap, preferredDERPRegionID tailcfg.DERPRegionID) Result {
	res := d.detectCaptivePortalWithGOOS(ctx, netMon, derpMap, preferredDERPRegionID, runtime.GOOS)
	d.annotatePortalLocality(ctx, &res)
	return res
}

// annotatePortalLocality fills in [Result.PortalURLIsLocal] for a portal we
// found a login URL for.
//
// Whether that URL is on the local network decides whether a client using an
// exit node can be helped at all: a login page on the LAN becomes reachable if
// the LAN is taken back out of the tunnel, while one on the public Internet does
// not, because the default route stays pointed at the exit node either way.
//
// The lookup goes to the physical network's own resolvers, off the tunnel, which
// is both the only way to get an answer at all when an exit node is up and the
// authoritative word on where the page lives: it is the portal's network that
// decided to send us there. A hijacked resolver answering with the portal's own
// address is not a wrong answer for our purposes — it is precisely the case we
// want to report as local.
//
// Anything we cannot determine is left unset rather than guessed at; see the
// callers for why unknown is treated as local.
func (d *Detector) annotatePortalLocality(ctx context.Context, res *Result) {
	if res.Verdict != VerdictPortal || res.PortalURL == "" {
		return
	}
	u, err := url.Parse(res.PortalURL)
	if err != nil || u.Hostname() == "" {
		// A 511's Location header is not required to be absolute, and a
		// relative one tells us nothing about where the portal lives.
		return
	}
	host := u.Hostname()

	// Portals commonly redirect straight to an IP, which needs no lookup.
	if ip, err := netip.ParseAddr(host); err == nil {
		res.PortalURLIsLocal.Set(isLocalAddr(ip))
		return
	}

	// Bound to the interface the portal answered on, so that on a machine with
	// several networks up we ask the one that intercepted us.
	got, err := d.lookupIP(ctx, host, res.ifIndex)
	if err != nil || len(got) == 0 {
		d.logf("[v1] captivedetection: could not resolve portal host %q: %v", host, err)
		return
	}
	res.PortalURLIsLocal.Set(isLocalAddr(got[0]))
}

func (d *Detector) detectCaptivePortalWithGOOS(ctx context.Context, netMon *netmon.Monitor, derpMap *tailcfg.DERPMap, preferredDERPRegionID tailcfg.DERPRegionID, goos string) Result {
	// Remember the monitor for the sockets we're about to open: they have to
	// stay out of the tunnel, and the resolvers we prefer come from it.
	d.mu.Lock()
	d.netMon = netMon
	d.mu.Unlock()

	// Ask the OS first: it's cheaper and more reliable than anything we can
	// probe ourselves.
	if hint, ok := HookPlatformHint.GetOk(); ok {
		if found, answered := hint(ctx); answered && found {
			d.logf("captivedetection: the OS reports a captive portal on this network")
			var ev evidence
			ev.add(SignalPlatformHint, "")
			return ev.result()
		}
	}

	ifState := netMon.InterfaceState()
	if !ifState.AnyInterfaceUp() {
		d.logf("[v2] DetectCaptivePortal: no interfaces up, returning unknown")
		return Result{Verdict: VerdictUnknown}
	}

	endpoints := availableEndpoints(derpMap, preferredDERPRegionID, d.logf, goos)

	// Here we try detecting a captive portal using *all* available interfaces on the system
	// that have a IPv4 address. This is necessary because most systems have multiple interfaces,
	// and most importantly on macOS no default route interface is set until the user has accepted
	// the captive portal alert thrown by the system. If no default route interface is known,
	// we need to try with anything that might remotely resemble a Wi-Fi interface.
	//
	// Interfaces are considered in turn. A clean result from any of them ends the search: it
	// proves traffic is flowing, so nothing another interface could report would change the
	// answer. A portal result does not end it, for the same reason a portal signal doesn't end a
	// single interface's probe pass — a clean result elsewhere outranks it. Warning a user with
	// a working Ethernet connection about the portal on the Wi-Fi they're also associated with
	// would send them chasing a login page they don't need.
	probedAny := false
	gotAnyResponse := false
	var portal *Result
	// Signals from every interface, so an inconclusive result still carries the
	// evidence behind it for the caller's logs and metrics.
	var signals []Signal
	for ifName, i := range ifState.Interface {
		if !i.IsUp() || i.IsLoopback() || interfaceNameDoesNotNeedCaptiveDetection(ifName, goos) {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			d.logf("[v1] DetectCaptivePortal: failed to get addresses for interface %s: %v", ifName, err)
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		d.logf("[v2] attempting to do captive portal detection on interface %s", ifName)
		probedAny = true
		res, gotResponse := d.detectOnInterface(ctx, i.Index, endpoints)
		if gotResponse {
			gotAnyResponse = true
		}
		signals = append(signals, res.Signals...)
		switch res.Verdict {
		case VerdictNoPortal:
			d.logf("DetectCaptivePortal(verdict=%s,ifName=%s,signals=%v)", res.Verdict, ifName, res.Signals)
			return res
		case VerdictPortal:
			d.logf("captivedetection: interface %s looks intercepted (signals=%v); checking the remaining interfaces before reporting", ifName, res.Signals)
			if portal == nil {
				res.ifIndex = i.Index
				portal = &res
			}
		}
	}

	if portal != nil {
		d.logf("DetectCaptivePortal(verdict=%s,signals=%v)", portal.Verdict, portal.Signals)
		return *portal
	}

	if !probedAny || gotAnyResponse {
		// Either we had nothing to probe, or something answered us and it just
		// wasn't conclusive. The escalation below is aimed at networks that
		// drop our probes entirely, so it wouldn't tell us anything new here.
		d.logf("DetectCaptivePortal(verdict=%s,signals=%v)", VerdictUnknown, signals)
		return Result{Verdict: VerdictUnknown, Signals: signals}
	}

	// Every Tailscale-operated endpoint was blackholed. That is what a walled
	// garden looks like from the inside, and it is also what a network with no
	// Internet at all looks like, so we can't conclude anything yet. Escalate
	// to the probes that a portal has to answer in order to function: a
	// hijacked resolver, and the detection URLs that portals are built to
	// intercept.
	d.logf("captivedetection: all endpoints blackholed; escalating to DNS and third-party probes")
	res := d.detectEscalated(ctx, derpMap, endpoints)
	d.logf("DetectCaptivePortal(verdict=%s,escalated,signals=%v)", res.Verdict, res.Signals)
	return res
}

// detectEscalated runs the last-resort probes: DNS interception, plus the OS
// vendors' captive portal detection URLs.
//
// It is only reached when every Tailscale-operated endpoint was blackholed, so
// on a working network these third parties are never contacted.
func (d *Detector) detectEscalated(ctx context.Context, derpMap *tailcfg.DERPMap, endpoints []Endpoint) Result {
	defer d.httpClient.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	var (
		ev   evidence
		evMu sync.Mutex
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		signals := d.probeDNS(ctx, derpMap)
		evMu.Lock()
		defer evMu.Unlock()
		for _, s := range signals {
			ev.add(s, "")
		}
	}()

	// The escalated HTTP probes are not interface-scoped: by this point we've
	// established that no interface could reach a Tailscale endpoint, and
	// picking one to blame would be guesswork.
	thirdParty := endpointsOfTier(endpoints, TierThirdParty, len(endpoints))
	for _, e := range thirdParty {
		wg.Add(1)
		go func(endpoint Endpoint) {
			defer wg.Done()
			s, portalURL, err := d.probeEndpoint(ctx, endpoint, 0)
			if err != nil {
				if ctx.Err() == nil {
					d.logf("[v1] captivedetection: third-party probe of %v failed: %v", endpoint.URL, err)
				}
				return
			}
			evMu.Lock()
			defer evMu.Unlock()
			ev.add(s, portalURL)
		}(e)
	}
	wg.Wait()

	evMu.Lock()
	defer evMu.Unlock()
	return ev.result()
}

// interfaceNameDoesNotNeedCaptiveDetection returns true if an interface does not require captive portal detection
// based on its name. This is useful to avoid making unnecessary HTTP requests on interfaces that are known to not
// require it. We also avoid making requests on the interface prefixes "pdp" and "rmnet", which are cellular data
// interfaces on iOS and Android, respectively, and would be needlessly battery-draining.
func interfaceNameDoesNotNeedCaptiveDetection(ifName string, goos string) bool {
	ifName = strings.ToLower(ifName)
	excludedPrefixes := []string{"tailscale", "tun", "tap", "docker", "kube", "wg", "ipsec"}
	if goos == "windows" {
		excludedPrefixes = append(excludedPrefixes, "loopback", "tunnel", "ppp", "isatap", "teredo", "6to4")
	} else if goos == "darwin" || goos == "ios" {
		excludedPrefixes = append(excludedPrefixes, "pdp", "awdl", "bridge", "ap", "utun", "tap", "llw", "anpi", "lo", "stf", "gif", "xhc", "pktap")
	} else if goos == "android" {
		excludedPrefixes = append(excludedPrefixes, "rmnet", "p2p", "dummy", "sit")
	}
	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(ifName, prefix) {
			return true
		}
	}
	return false
}

// detectOnInterface probes the given interface for signs of a captive portal.
//
// It probes a mix of IP-addressed and hostname-addressed endpoints (see
// [probeSet]) concurrently and combines what they report. gotResponse tells the
// caller whether anything answered at all, which distinguishes an inconclusive
// network from one that is dropping our probes on the floor.
func (d *Detector) detectOnInterface(ctx context.Context, ifIndex int, endpoints []Endpoint) (res Result, gotResponse bool) {
	defer d.httpClient.CloseIdleConnections()

	probes := probeSet(endpoints)
	d.logf("[v2] %d available captive portal detection endpoints; trying %d", len(endpoints), len(probes))

	// We try to detect the captive portal more quickly by making requests to multiple endpoints concurrently.
	//
	// Only a clean response cuts the pass short. It's conclusive: nothing a
	// slower probe could report would change the answer. A portal signal is
	// not, because a clean response from another endpoint outranks it (see
	// [evidence.result]), so aborting the remaining probes there would let a
	// portal verdict stand only because we stopped listening — turning the
	// clean-wins rule into a race. The probes are bounded by [Timeout] anyway.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		ev   evidence
		evMu sync.Mutex
	)

	var wg sync.WaitGroup
	for _, e := range probes {
		wg.Add(1)
		go func(endpoint Endpoint) {
			defer wg.Done()
			s, portalURL, err := d.probeEndpoint(ctx, endpoint, ifIndex)
			if err != nil {
				if ctx.Err() == nil {
					d.logf("[v1] checkCaptivePortalEndpoint failed with endpoint %v: %v", endpoint, err)
				}
				s, portalURL = SignalNoResponse, ""
			}

			evMu.Lock()
			ev.add(s, portalURL)
			conclusive := ev.result().Verdict == VerdictNoPortal
			evMu.Unlock()

			if conclusive {
				// One match is good enough; don't make the caller wait on the
				// remaining probes.
				cancel()
			}
		}(e)
	}
	wg.Wait()

	evMu.Lock()
	defer evMu.Unlock()
	if ev.hasConflict() {
		metricCleanConflict.Add(1)
		d.logf("captivedetection: some endpoints look intercepted but another was provably not; reporting no portal (signals=%v)", ev.signals)
	}
	return ev.result(), ev.gotAnyResponse()
}

// probeEndpoint makes an HTTP request to e using the interface with index
// ifIndex, and reports what the response says about interception. See
// [classify].
func (d *Detector) probeEndpoint(ctx context.Context, e Endpoint, ifIndex int) (s Signal, portalURL string, err error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	u := *e.URL
	v := u.Query()
	v.Add("t", strconv.Itoa(int(d.Now().Unix())))
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return SignalNoResponse, "", err
	}
	req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate, no-transform, max-age=0")

	// Attach the Tailscale challenge header if the endpoint supports it. Not all captive portal detection endpoints
	// support this, so we only attach it if the endpoint does.
	if e.SupportsTailscaleChallenge {
		req.Header.Set("X-Tailscale-Challenge", challengeFor(e))
	}

	d.mu.Lock()
	d.currIfIndex = ifIndex
	d.mu.Unlock()

	// Make the actual request, and check if the response looks like a captive portal or not.
	r, err := d.httpClient.Do(req)
	if err != nil {
		return SignalNoResponse, "", err
	}

	s, portalURL = classify(e, r, d.logf)
	return s, portalURL, nil
}

func (d *Detector) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	ifIndex := d.currIfIndex
	d.mu.Unlock()

	return d.dialTo(ctx, network, addr, ifIndex)
}

// dialTo dials addr on the interface with the given index, or on whichever one
// the system picks if ifIndex is zero.
func (d *Detector) dialTo(ctx context.Context, network, addr string, ifIndex int) (net.Conn, error) {
	if d.dialFn != nil {
		return d.dialFn(ctx, network, addr)
	}

	d.mu.Lock()
	netMon := d.netMon
	d.mu.Unlock()

	return d.dialer(netMon, ifIndex).DialContext(ctx, network, addr)
}

// dialer returns a dialer for a probe that must reach the physical network.
//
// Everything captive portal detection does is a question about the network the
// machine is physically attached to, so none of it may go through Tailscale.
// That is not just a matter of tidiness: a node using an exit node routes the
// default route, and with ExitNodeAllowLANAccess off the local subnets too, into
// the tunnel — which behind a portal goes nowhere. Probes sent that way can only
// ever time out, and we would report that a network we never touched is fine.
//
// netns is the same escape hatch the rest of the client uses (a bypass fwmark on
// Linux, binding to the default interface elsewhere). On top of it we keep the
// existing per-interface binding, which has to be applied second so that it wins
// on Darwin: netns binds to the default interface, while the probe loop exists
// precisely because macOS often has no default route interface until the user
// accepts the captive portal alert.
func (d *Detector) dialer(netMon *netmon.Monitor, ifIndex int) netns.Dialer {
	dl := &net.Dialer{Timeout: Timeout}

	if netMon == nil {
		// No monitor to consult, as in tests. Fall back to a plain dialer
		// rather than panicking in netns.
		dl.Control = func(network, address string, c syscall.RawConn) error {
			return setSocketInterfaceIndex(c, ifIndex, d.logf)
		}
		return dl
	}

	wrapped := netns.FromDialer(d.logf, netMon, dl)
	if netns.IsSOCKSDialer(wrapped) {
		// All traffic is going to a SOCKS proxy, so there is no socket of ours
		// left to bind to an interface.
		return wrapped
	}
	if ifIndex == 0 {
		// No interface in particular, so leave netns's own choice in place.
		// Binding to index zero would clear it.
		return wrapped
	}
	bypass := dl.Control // installed by FromDialer, unless netns is disabled
	dl.Control = func(network, address string, c syscall.RawConn) error {
		if bypass != nil {
			if err := bypass(network, address, c); err != nil {
				return err
			}
		}
		return setSocketInterfaceIndex(c, ifIndex, d.logf)
	}
	return wrapped
}
