// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"cmp"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"go4.org/mem"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// EndpointProvider is an enum that represents the source of an Endpoint.
type EndpointProvider int

const (
	// DERPMapPreferred is used for an endpoint that is a DERP node contained in the current preferred DERP region,
	// as provided by the DERPMap.
	DERPMapPreferred EndpointProvider = iota
	// DERPMapOther is used for an endpoint that is a DERP node, but not contained in the current preferred DERP region.
	DERPMapOther
	// Tailscale is used for endpoints that are the Tailscale coordination server or admin console.
	Tailscale
	// ThirdParty is used for the well-known captive portal detection endpoints
	// operated by OS vendors. See [TierThirdParty].
	ThirdParty
)

func (p EndpointProvider) String() string {
	switch p {
	case DERPMapPreferred:
		return "DERPMapPreferred"
	case Tailscale:
		return "Tailscale"
	case DERPMapOther:
		return "DERPMapOther"
	case ThirdParty:
		return "ThirdParty"
	default:
		return fmt.Sprintf("EndpointProvider(%d)", p)
	}
}

// Tier groups endpoints by the kind of interception they can detect, which
// determines when we're willing to probe them.
type Tier int

const (
	// TierDERPIP endpoints are addressed by literal IP, so they exercise the
	// path without involving DNS. Captive portals that key off the HTTP Host
	// header often blackhole these instead of intercepting them.
	TierDERPIP Tier = iota
	// TierHostname endpoints are Tailscale-operated servers addressed by
	// hostname. These require working DNS and carry a Host header, so they see
	// the interception that TierDERPIP misses. They are always probed alongside
	// TierDERPIP.
	TierHostname
	// TierThirdParty endpoints are the captive portal detection URLs operated
	// by Apple, Google and Microsoft. Portals are built to intercept precisely
	// these, so a walled garden that allowlists nothing else will still answer
	// them. Because they involve contacting third parties, they are only probed
	// as a last resort, once every Tailscale-operated endpoint has been
	// blackholed. Their responses can only ever indicate a portal: we don't
	// control these servers, so a "success" response from one proves nothing
	// and must never clear a warning.
	TierThirdParty
)

func (t Tier) String() string {
	switch t {
	case TierDERPIP:
		return "derp-ip"
	case TierHostname:
		return "hostname"
	case TierThirdParty:
		return "third-party"
	default:
		return fmt.Sprintf("Tier(%d)", int(t))
	}
}

// Endpoint represents a URL that can be used to detect a captive portal, along with the expected
// result of the HTTP request.
type Endpoint struct {
	// URL is the URL that we make an HTTP request to as part of the captive portal detection process.
	URL *url.URL
	// StatusCode is the expected HTTP status code that we expect to see in the response.
	StatusCode int
	// ExpectedContent is a string that we expect to see contained in the response body. If this is non-empty,
	// we will check that the response body contains this string. If it is empty, we will not check the response body
	// and only check the status code.
	ExpectedContent string
	// SupportsTailscaleChallenge is true if the endpoint will return the sent value of the X-Tailscale-Challenge
	// HTTP header in its HTTP response.
	SupportsTailscaleChallenge bool
	// Provider is the source of the endpoint. This is used to prioritize certain endpoints over others
	// (for example, a DERP node in the preferred region should always be used first).
	Provider EndpointProvider
	// Tier is when we're willing to probe this endpoint. See [Tier].
	Tier Tier
}

func (e Endpoint) String() string {
	return fmt.Sprintf("Endpoint{URL=%q, StatusCode=%d, ExpectedContent=%q, SupportsTailscaleChallenge=%v, Provider=%s, Tier=%s}", e.URL, e.StatusCode, e.ExpectedContent, e.SupportsTailscaleChallenge, e.Provider.String(), e.Tier.String())
}

func (e Endpoint) Equal(other Endpoint) bool {
	return e.URL.String() == other.URL.String() &&
		e.StatusCode == other.StatusCode &&
		e.ExpectedContent == other.ExpectedContent &&
		e.SupportsTailscaleChallenge == other.SupportsTailscaleChallenge &&
		e.Provider == other.Provider &&
		e.Tier == other.Tier
}

// The number of endpoints of each tier that a single detection pass probes.
const (
	// numDERPIPProbes is how many [TierDERPIP] endpoints the first pass probes.
	numDERPIPProbes = 4
	// numHostnameProbes is how many [TierHostname] endpoints the first pass
	// probes. This is deliberately never zero: hostname probes are the only
	// ones that see Host-header-based interception, which is the most common
	// kind.
	numHostnameProbes = 2
)

// availableEndpoints returns a set of Endpoints which can be used for captive portal detection by performing
// one or more HTTP requests and looking at the response. The returned Endpoints are ordered by preference,
// with the most preferred Endpoint being the first in the slice.
func availableEndpoints(derpMap *tailcfg.DERPMap, preferredDERPRegionID tailcfg.DERPRegionID, logf logger.Logf, goos string) []Endpoint {
	endpoints := []Endpoint{}

	if derpMap == nil || len(derpMap.Regions) == 0 {
		// When the client first starts, we don't have a DERPMap in LocalBackend yet. In this case,
		// we use the static DERPMap from dnsfallback.
		logf("captivedetection: current DERPMap is empty, using map from dnsfallback")
		derpMap = dnsfallback.GetDERPMap()
	}
	// Use the DERP IPs as captive portal detection endpoints. Using IPs is better than hostnames
	// because they do not depend on DNS resolution. We probe the same nodes by hostname too,
	// because a portal that intercepts by Host header will blackhole the IP form while answering
	// the hostname form; see [TierHostname].
	appendDERPEndpoint := func(host string, tier Tier, p EndpointProvider) {
		str := "http://" + host + "/generate_204"
		u, err := url.Parse(str)
		if err != nil {
			logf("captivedetection: failed to parse DERP node URL %q: %v", str, err)
			return
		}
		endpoints = append(endpoints, Endpoint{u, http.StatusNoContent, "", true, p, tier})
	}
	for _, region := range derpMap.Regions {
		if region.Avoid || region.NoMeasureNoHome {
			continue
		}
		for _, node := range region.Nodes {
			if !node.CanPort80 {
				continue
			}
			p := DERPMapOther
			if region.RegionID == preferredDERPRegionID {
				p = DERPMapPreferred
			}
			if node.IPv4 != "" {
				appendDERPEndpoint(node.IPv4, TierDERPIP, p)
			}
			if node.HostName != "" {
				appendDERPEndpoint(node.HostName, TierHostname, p)
			}
		}
	}

	// Let's also try the default Tailscale coordination server and admin console.
	// These are likely to be blocked on some networks.
	appendTailscaleEndpoint := func(urlString string) {
		u, err := url.Parse(urlString)
		if err != nil {
			logf("captivedetection: failed to parse Tailscale URL %q: %v", urlString, err)
			return
		}
		endpoints = append(endpoints, Endpoint{u, http.StatusNoContent, "", false, Tailscale, TierHostname})
	}
	appendTailscaleEndpoint("http://controlplane.tailscale.com/generate_204")
	appendTailscaleEndpoint("http://login.tailscale.com/generate_204")

	// The OS vendors' own captive portal detection URLs. See [TierThirdParty]
	// for why these are last-resort only.
	appendThirdPartyEndpoint := func(urlString string, statusCode int, expectedContent string) {
		u, err := url.Parse(urlString)
		if err != nil {
			logf("captivedetection: failed to parse third-party URL %q: %v", urlString, err)
			return
		}
		endpoints = append(endpoints, Endpoint{u, statusCode, expectedContent, false, ThirdParty, TierThirdParty})
	}
	appendThirdPartyEndpoint("http://captive.apple.com/hotspot-detect.html", http.StatusOK, "Success")
	appendThirdPartyEndpoint("http://connectivitycheck.gstatic.com/generate_204", http.StatusNoContent, "")
	appendThirdPartyEndpoint("http://www.msftconnecttest.com/connecttest.txt", http.StatusOK, "Microsoft Connect Test")

	// Sort the endpoints by tier, then by provider so that we can prioritize DERP nodes in the
	// preferred region, followed by any other DERP server elsewhere, then followed by Tailscale
	// endpoints.
	slices.SortStableFunc(endpoints, func(x, y Endpoint) int {
		if c := cmp.Compare(x.Tier, y.Tier); c != 0 {
			return c
		}
		return cmp.Compare(x.Provider, y.Provider)
	})

	return endpoints
}

// probeSet returns the endpoints to probe in the first detection pass: a fixed
// number from each of [TierDERPIP] and [TierHostname].
//
// Taking a fixed share of each tier matters. Simply truncating the
// preference-ordered list would drop the hostname endpoints entirely, since
// there are always more DERP nodes than the probe budget, and those are exactly
// the endpoints that detect Host-header-based interception.
func probeSet(endpoints []Endpoint) []Endpoint {
	return append(
		endpointsOfTier(endpoints, TierDERPIP, numDERPIPProbes),
		endpointsOfTier(endpoints, TierHostname, numHostnameProbes)...,
	)
}

// endpointsOfTier returns up to max endpoints of the given tier, preserving the
// order of endpoints.
func endpointsOfTier(endpoints []Endpoint, t Tier, max int) []Endpoint {
	var out []Endpoint
	for _, e := range endpoints {
		if e.Tier != t {
			continue
		}
		out = append(out, e)
		if len(out) == max {
			break
		}
	}
	return out
}

// maxBodyRead is how much of a response body we're willing to read while
// looking for signs of interception. Portal login pages are small, and the
// telltale markers appear near the top.
const maxBodyRead = 4096

// metaRefreshRe matches the URL in a <meta http-equiv="refresh"> tag, which is
// how portals that answer with 200 instead of a redirect send browsers onward.
var metaRefreshRe = regexp.MustCompile(`(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*url\s*=\s*([^"'\s>]+)`)

// scriptLocationRe matches a JavaScript redirect, the other common way a portal
// bounces a browser to its login page.
var scriptLocationRe = regexp.MustCompile(`(?i)(?:window\.)?(?:top\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`)

// classify inspects a response to one of our probes and reports what it tells
// us about interception, along with a portal login URL if the response revealed
// one.
//
// It is deliberately conservative. A response that merely fails to be what we
// expected is not evidence of a captive portal: unhealthy servers, corporate
// HTTP proxies and CDN error pages all produce those, and warning a user about
// a captive portal that isn't there is worse than staying quiet. We only report
// a definitive signal when something positively identifies itself as an
// intermediary, by redirecting us elsewhere, by serving a web page where none
// belongs, by saying so outright with a 511, or by failing to echo a value only
// the real server could know.
func classify(e Endpoint, r *http.Response, logf logger.Logf) (Signal, string) {
	defer r.Body.Close()

	// A redirect to a different host is how most portals announce themselves.
	// A redirect within the same host is not: that's ordinary server behavior,
	// such as a bare-domain to www redirect.
	if r.StatusCode >= 300 && r.StatusCode <= 399 {
		if loc := r.Header.Get("Location"); loc != "" {
			if lu, err := url.Parse(loc); err == nil && lu.Host != "" && !sameHost(lu.Host, e.URL.Host) {
				logf("captivedetection: %v redirected to a different host: %q", e.URL.Host, loc)
				return SignalRedirect, loc
			}
		}
	}

	// RFC 6585: the status code that exists for exactly this purpose.
	if r.StatusCode == http.StatusNetworkAuthenticationRequired {
		logf("captivedetection: %v returned 511 Network Authentication Required", e.URL.Host)
		return SignalHTTP511, r.Header.Get("Location")
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyRead))
	if err != nil {
		logf("[v1] captivedetection: reading response body from %v failed: %v", e.URL.Host, err)
		// We got a response but couldn't read it, so we can't say anything
		// about its content. Fall through and judge it on the status code
		// alone.
	}

	statusOK := r.StatusCode == e.StatusCode
	contentOK := e.ExpectedContent == "" || mem.Contains(mem.B(body), mem.S(e.ExpectedContent))

	// A body where the endpoint promises none is a sign of interception
	// regardless of the status code: portals sometimes answer 204 and rely on
	// the body to carry their login page, which no real 204 handler would do.
	if statusOK && e.StatusCode == http.StatusNoContent && len(body) > 0 {
		if s, pageURL := classifyPage(e, r, body, logf); s != SignalNoEvidence {
			return s, pageURL
		}
	}

	if !statusOK || !contentOK {
		// The response isn't what this endpoint should have produced.
		if s, pageURL := classifyPage(e, r, body, logf); s != SignalNoEvidence {
			return s, pageURL
		}
		// Otherwise this is weak evidence only: an error page from a proxy, a
		// sick server, or a portal that returns a bare status code.
		logf("[v1] captivedetection: unexpected response from %v: status=%d (want %d), contentOK=%v", e.URL.Host, r.StatusCode, e.StatusCode, contentOK)
		return SignalUnexpectedStatus, ""
	}

	// The status and content are what we expected. If this endpoint echoes our
	// challenge, the echo is what distinguishes the real server from something
	// imitating it.
	if e.SupportsTailscaleChallenge {
		want := "response " + challengeFor(e)
		if got := r.Header.Get("X-Tailscale-Response"); got != want {
			logf("captivedetection: %v response lacked the expected X-Tailscale-Response header: want=%q, got=%q", e.URL.Host, want, got)
			return SignalChallengeTampered, ""
		}
		// Proven to have come from the real server.
		return SignalClean, ""
	}

	// A response that looks right, from an endpoint we have no way to
	// authenticate. Headers that only an intermediary would add are worth
	// noting, but on their own they are not enough to act on.
	if hasProxyHeaders(r) {
		logf("[v1] captivedetection: %v response carried proxy headers", e.URL.Host)
		return SignalProxyHeaders, ""
	}

	// Deliberately not SignalClean. A portal can trivially fabricate a plausible
	// response for an endpoint that doesn't echo our challenge, and because a
	// clean signal outranks everything else (see [evidence.result]) accepting
	// one here would let a portal talk us out of a detection we had already
	// made. This applies to the third-party endpoints, whose servers we don't
	// operate, and to any Tailscale endpoint not serving the challenge.
	return SignalNoEvidence, ""
}

// classifyPage decides whether an unexpected response body is a captive portal
// announcing itself, returning [SignalNoEvidence] if it isn't.
//
// Being served a web page where none belongs is not enough on its own. A
// transparent enterprise web proxy answers blocked destinations with an HTML
// "access denied" page, which is byte-for-byte the same kind of evidence — and
// those deployments are common in exactly the corporate networks Tailscale runs
// on. Telling those users to go log in through a browser would be wrong.
//
// What separates the two is that a portal has to get the user somewhere: it
// either points onward to its login page, or it puts the login form in front of
// them. A block page is terminal, with neither.
func classifyPage(e Endpoint, r *http.Response, body []byte, logf logger.Logf) (Signal, string) {
	pageURL, isPage := looksLikeWebPage(r, body)
	if !isPage {
		return SignalNoEvidence, ""
	}
	if pageURL != "" {
		logf("captivedetection: %v answered with a page redirecting to %q (status=%d); intercepted", e.URL.Host, pageURL, r.StatusCode)
		return SignalHTML, pageURL
	}
	if hasLoginForm(body) {
		logf("captivedetection: %v answered with a login form (status=%d); intercepted", e.URL.Host, r.StatusCode)
		return SignalHTML, ""
	}
	logf("[v1] captivedetection: %v answered with a page that goes nowhere (status=%d); more likely a proxy block page than a portal", e.URL.Host, r.StatusCode)
	return SignalNoEvidence, ""
}

// passwordInputRe matches a password field, which a login page has and a proxy
// block page does not.
var passwordInputRe = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)

// hasLoginForm reports whether a page asks the user to sign in.
func hasLoginForm(body []byte) bool {
	return passwordInputRe.Match(body)
}

// sameHost reports whether two URL hosts refer to the same server, ignoring
// port and case.
func sameHost(a, b string) bool {
	strip := func(h string) string {
		h = strings.ToLower(h)
		if i := strings.LastIndexByte(h, ':'); i != -1 && !strings.Contains(h[i:], "]") {
			h = h[:i]
		}
		return strings.TrimSuffix(h, ".")
	}
	return strip(a) == strip(b)
}

// looksLikeWebPage reports whether a response body is a web page rather than
// the empty or plain-text response our endpoints produce, and returns any
// onward URL the page points at.
func looksLikeWebPage(r *http.Response, body []byte) (pageURL string, ok bool) {
	if m := metaRefreshRe.FindSubmatch(body); m != nil {
		// A meta-refresh tag is only ever a browser redirect, so its presence
		// alone identifies a page, whatever the declared content type.
		pageURL = strings.Trim(string(m[1]), `"'`)
		ok = true
	} else if m := scriptLocationRe.FindSubmatch(body); m != nil {
		pageURL = string(m[1])
		ok = true
	}

	if !ok {
		if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "text/html") {
			ok = true
		} else {
			lower := strings.ToLower(string(body))
			ok = strings.Contains(lower, "<html") ||
				strings.Contains(lower, "<!doctype html") ||
				strings.Contains(lower, "<head") ||
				strings.Contains(lower, "<body") ||
				strings.Contains(lower, "<script")
		}
	}
	if !ok {
		return "", false
	}
	// Only hand back an absolute URL: a relative one would resolve against our
	// probe endpoint, which is not where the portal lives.
	if u, err := url.Parse(pageURL); err != nil || !u.IsAbs() {
		pageURL = ""
	}
	return pageURL, true
}

// hasProxyHeaders reports whether a response carries headers that only an
// intermediary would have added.
func hasProxyHeaders(r *http.Response) bool {
	for _, h := range []string{"Proxy-Connection", "Proxy-Authenticate", "X-Squid-Error"} {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// challengeFor returns the X-Tailscale-Challenge value to send to e.
//
// Note: the set of valid characters in a challenge and the total length is
// limited; see isChallengeChar in derp/derpserver for more details.
func challengeFor(e Endpoint) string {
	return "ts_" + e.URL.Host
}
