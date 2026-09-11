// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

// errNXDOMAIN is what a resolver that answered returns for a name that doesn't
// exist, as opposed to one that didn't answer at all. [isNotFound] tells them
// apart, so the distinction has to survive into the fakes.
var errNXDOMAIN = &net.DNSError{Err: "no such host", IsNotFound: true}

// errNoAnswer is a resolver that could not be reached at all, which is what a
// tunneled query to the LAN looks like from behind a captive portal.
var errNoAnswer = errors.New("i/o timeout")

// testDERPMap is a minimal DERP map with one node whose real address we know,
// which is what the hijack probe compares answers against.
func testDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID: 1,
				Nodes: []*tailcfg.DERPNode{
					{Name: "1a", HostName: "derp1a.tailscale.com", IPv4: "1.2.3.4", CanPort80: true},
				},
			},
		},
	}
}

// detectorWithResolver returns a Detector where every resolver, local or
// system, serves answers, keyed by hostname. A host not present in the map gets
// NXDOMAIN.
//
// The wildcard probe's names are randomized, so the key "x.invalid" stands in
// for any name in that domain.
func detectorWithResolver(t *testing.T, answers map[string][]string) *Detector {
	d := NewDetector(t.Logf)
	d.lookupIPFn = func(_ context.Context, _ netip.Addr, host string) ([]netip.Addr, error) {
		return answerFrom(answers, host)
	}
	return d
}

// answerFrom serves host out of answers, in the shape a resolver would.
func answerFrom(answers map[string][]string, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(host, ".")
	strs, ok := answers[host]
	if !ok && strings.HasSuffix(host, ".invalid") {
		strs, ok = answers["x.invalid"]
	}
	if !ok {
		return nil, errNXDOMAIN
	}
	var out []netip.Addr
	for _, s := range strs {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func TestProbeDNSHijack(t *testing.T) {
	tests := []struct {
		name    string
		answers map[string][]string
		want    bool
	}{
		{
			// The resolver told us the truth.
			name:    "honest_answer",
			answers: map[string][]string{"derp1a.tailscale.com": {"1.2.3.4"}},
			want:    false,
		},
		{
			// The classic captive portal: every name resolves to the gateway.
			name:    "hijacked_to_gateway",
			answers: map[string][]string{"derp1a.tailscale.com": {"192.168.1.1"}},
			want:    true,
		},
		{
			name:    "hijacked_to_cgnat",
			answers: map[string][]string{"derp1a.tailscale.com": {"100.64.0.1"}},
			want:    true,
		},
		{
			name:    "hijacked_to_loopback",
			answers: map[string][]string{"derp1a.tailscale.com": {"127.0.0.1"}},
			want:    true,
		},
		{
			// A different public address is indistinguishable from legitimate
			// geo-DNS or a DERP map we haven't refreshed yet, and acting on it
			// would mean warning users about portals that don't exist.
			name:    "different_public_address",
			answers: map[string][]string{"derp1a.tailscale.com": {"9.9.9.9"}},
			want:    false,
		},
		{
			// One of the answers matches, so nobody is lying to us.
			name:    "one_of_several_matches",
			answers: map[string][]string{"derp1a.tailscale.com": {"9.9.9.9", "1.2.3.4"}},
			want:    false,
		},
		{
			name:    "nxdomain",
			answers: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := detectorWithResolver(t, tt.answers)
			if got := d.probeDNSHijack(t.Context(), testDERPMap(), t.Logf); got != tt.want {
				t.Errorf("probeDNSHijack = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProbeDNSWildcard(t *testing.T) {
	tests := []struct {
		name    string
		answers map[string][]string
		want    bool
	}{
		{
			// The correct behavior: names in .invalid never resolve.
			name:    "nxdomain_as_expected",
			answers: nil,
			want:    false,
		},
		{
			// A resolver answering names that cannot exist, with a LAN
			// address. Only a portal does this.
			name:    "wildcard_to_lan",
			answers: map[string][]string{"x.invalid": {"10.0.0.1"}},
			want:    true,
		},
		{
			// Some ISPs answer NXDOMAIN with a public search page. Obnoxious,
			// but not a captive portal.
			name:    "wildcard_to_public_search_page",
			answers: map[string][]string{"x.invalid": {"9.9.9.9"}},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := detectorWithResolver(t, tt.answers)
			if got := d.probeDNSWildcard(t.Context(), t.Logf); got != tt.want {
				t.Errorf("probeDNSWildcard = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProbeDNSWildcardNeedsAgreement checks that a single fabricated answer
// isn't enough: a resolver that answers every name will answer all our probe
// names the same way, whereas one inconsistent answer is more likely a stale
// cache entry or a coincidence.
func TestProbeDNSWildcardNeedsAgreement(t *testing.T) {
	d := NewDetector(t.Logf)
	var n int
	d.lookupIPFn = func(_ context.Context, _ netip.Addr, host string) ([]netip.Addr, error) {
		n++
		// Answer each probe with a different LAN address.
		return []netip.Addr{netip.AddrFrom4([4]byte{192, 168, 1, byte(n)})}, nil
	}
	if d.probeDNSWildcard(t.Context(), t.Logf) {
		t.Error("probeDNSWildcard = true for inconsistent answers, want false")
	}
	if n < 2 {
		t.Errorf("made %d lookups, want at least 2", n)
	}
}

// TestProbeDNSWildcardNamesAreFQDNs checks the probe names end in a dot. Without
// it the resolver appends the network's search domains, which can turn a name
// that must not exist into one that legitimately resolves.
func TestProbeDNSWildcardNamesAreFQDNs(t *testing.T) {
	d := NewDetector(t.Logf)
	var names []string
	d.lookupIPFn = func(_ context.Context, _ netip.Addr, host string) ([]netip.Addr, error) {
		names = append(names, host)
		return nil, errNXDOMAIN
	}
	d.probeDNSWildcard(t.Context(), t.Logf)

	if len(names) == 0 {
		t.Fatal("no lookups made")
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".invalid.") {
			t.Errorf("probe name %q does not end in %q", n, ".invalid.")
		}
	}
}

func TestProbeDNSSignals(t *testing.T) {
	d := detectorWithResolver(t, map[string][]string{
		"derp1a.tailscale.com": {"192.168.1.1"},
		"x.invalid":            {"192.168.1.1"},
	})
	got := d.probeDNS(t.Context(), testDERPMap())
	for _, want := range []Signal{SignalDNSHijack, SignalDNSWildcard} {
		if !slices.Contains(got, want) {
			t.Errorf("probeDNS = %v, missing %v", got, want)
		}
	}
}

func TestDERPNodeWithKnownAddr(t *testing.T) {
	host, addrs := derpNodeWithKnownAddr(testDERPMap())
	if host != "derp1a.tailscale.com" {
		t.Errorf("host = %q, want %q", host, "derp1a.tailscale.com")
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("1.2.3.4") {
		t.Errorf("addrs = %v, want [1.2.3.4]", addrs)
	}

	if host, _ := derpNodeWithKnownAddr(nil); host != "" {
		t.Errorf("host for a nil DERP map = %q, want empty", host)
	}

	// Regions we've been told to avoid are no basis for a comparison.
	dm := testDERPMap()
	dm.Regions[1].Avoid = true
	if host, _ := derpNodeWithKnownAddr(dm); host != "" {
		t.Errorf("host for an avoided region = %q, want empty", host)
	}
}

func TestIsLocalAddr(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"100.64.0.1", true}, // CGNAT
		{"127.0.0.1", true},
		{"169.254.1.1", true}, // link-local
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
		{"2606:4700::1", false},
		{"fd00::1", true}, // IPv6 unique local
	}
	for _, tt := range tests {
		if got := isLocalAddr(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("isLocalAddr(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
	if isLocalAddr(netip.Addr{}) {
		t.Error("isLocalAddr(invalid) = true, want false")
	}
}

// TestAnnotatePortalLocality checks that we can tell a portal login page we
// could still reach from one we could not.
//
// This decides what a client using an exit node gets told: a page on the local
// network can be made reachable by taking the LAN back out of the tunnel, while
// one out on the Internet cannot be reached at all until the exit node is
// turned off. Getting it wrong sends the user to do the wrong thing.
func TestAnnotatePortalLocality(t *testing.T) {
	tests := []struct {
		name      string
		verdict   Verdict
		portalURL string
		answers   map[string][]string
		want      opt.Bool // zero value means "unset"
	}{
		{
			name:      "literal private address needs no lookup",
			verdict:   VerdictPortal,
			portalURL: "http://192.168.1.1/login",
			want:      opt.NewBool(true),
		},
		{
			name:      "literal CGNAT address is local",
			verdict:   VerdictPortal,
			portalURL: "http://100.64.0.1/login",
			want:      opt.NewBool(true),
		},
		{
			name:      "literal public address is not local",
			verdict:   VerdictPortal,
			portalURL: "http://93.184.216.34/login",
			want:      opt.NewBool(false),
		},
		{
			name:      "hostname resolving locally is local",
			verdict:   VerdictPortal,
			portalURL: "http://portal.example/login",
			answers:   map[string][]string{"portal.example": {"10.0.0.1"}},
			want:      opt.NewBool(true),
		},
		{
			name:      "hostname resolving publicly is not local",
			verdict:   VerdictPortal,
			portalURL: "http://login.airline.example/",
			answers:   map[string][]string{"login.airline.example": {"93.184.216.34"}},
			want:      opt.NewBool(false),
		},
		{
			// We can't tell, and callers treat unknown as reachable-on-LAN
			// because that's the recoverable way to be wrong.
			name:      "unresolvable hostname stays unset",
			verdict:   VerdictPortal,
			portalURL: "http://portal.example/login",
			want:      opt.Bool(""),
		},
		{
			// A 511's Location header isn't required to be absolute.
			name:      "relative URL stays unset",
			verdict:   VerdictPortal,
			portalURL: "/login.html",
			want:      opt.Bool(""),
		},
		{
			name:      "no portal URL stays unset",
			verdict:   VerdictPortal,
			portalURL: "",
			want:      opt.Bool(""),
		},
		{
			// Nothing to annotate, and no reason to spend a lookup.
			name:      "non-portal verdict is left alone",
			verdict:   VerdictNoPortal,
			portalURL: "http://192.168.1.1/login",
			want:      opt.Bool(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := detectorWithResolver(t, tt.answers)
			res := Result{Verdict: tt.verdict, PortalURL: tt.portalURL}
			d.annotatePortalLocality(context.Background(), &res)
			if res.PortalURLIsLocal != tt.want {
				t.Errorf("PortalURLIsLocal = %q, want %q", res.PortalURLIsLocal, tt.want)
			}
		})
	}
}

// TestAnnotatePortalLocalityUsesHijackedResolver documents that we deliberately
// resolve through whatever resolver the system would use, hijacked or not.
//
// That isn't a flaw. It's the same lookup the user's browser is about to do, so
// a portal that answers every name with its own address correctly reports as
// reachable on the local network.
func TestAnnotatePortalLocalityUsesHijackedResolver(t *testing.T) {
	d := detectorWithResolver(t, map[string][]string{
		"login.airline.example": {"192.168.1.1"},
	})
	res := Result{Verdict: VerdictPortal, PortalURL: "http://login.airline.example/"}
	d.annotatePortalLocality(context.Background(), &res)
	if local, ok := res.PortalURLIsLocal.Get(); !ok || !local {
		t.Errorf("PortalURLIsLocal = %q, want true", res.PortalURLIsLocal)
	}
}
