// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"runtime"
	"slices"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/natlab/vnet"
)

// The tests in this file run detection against natlab's virtual network, with
// the detector's probes carried by real TCP over real ethernet frames and its
// DNS queries answered by the virtual network's own resolver. Compared to the
// httptest-based tests, what they add is the network itself: a portal that
// intercepts destinations it doesn't own, a walled garden that drops traffic
// silently rather than refusing it, and a resolver that lies. Those are the
// conditions the detector is built for, and they can't be faked with a local
// listener.

const portalLoginURL = "http://portal.example.net/login?ap=natlab"

// natlabEnv is a virtual network with one in-process node, plus a DERP map
// pointing at the network's fake DERP servers.
type natlabEnv struct {
	server  *vnet.Server
	node    *vnet.NetstackNode
	derpMap *tailcfg.DERPMap
}

// newNatlabEnv brings up a virtual network, optionally behind a captive portal.
func newNatlabEnv(t *testing.T, portal *vnet.CaptivePortal) *natlabEnv {
	t.Helper()

	var c vnet.Config
	nw := c.AddNetwork("2.3.4.5", "192.168.0.1/24")
	if portal != nil {
		nw.SetCaptivePortal(portal)
	}
	nodeConf := c.AddNode(nw)

	s, err := vnet.New(&c)
	if err != nil {
		t.Fatalf("vnet.New: %v", err)
	}
	t.Cleanup(s.Close)
	s.SetLoggerForTest(t.Logf)
	// Otherwise background router advertisements interleave with the probe
	// traffic and make the logs hard to read.
	s.StopUnsolicitedRAsForTest()

	nn, err := s.NewNetstackNode(nodeConf)
	if err != nil {
		t.Fatalf("NewNetstackNode: %v", err)
	}
	t.Cleanup(func() { nn.Close() })

	return &natlabEnv{server: s, node: nn, derpMap: natlabDERPMap()}
}

// natlabDERPMap returns a DERP map describing natlab's two fake DERP servers.
// Both are reachable over port 80 and serve /generate_204 with the challenge
// echo, so a probe that reaches one produces a provably clean response.
func natlabDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID: 1,
				Nodes: []*tailcfg.DERPNode{
					{
						Name:      "1a",
						RegionID:  1,
						HostName:  vnet.FakeDERP1Hostname(),
						IPv4:      vnet.FakeDERP1IPv4().String(),
						CanPort80: true,
					},
					{
						Name:      "1b",
						RegionID:  1,
						HostName:  vnet.FakeDERP2Hostname(),
						IPv4:      vnet.FakeDERP2IPv4().String(),
						CanPort80: true,
					},
				},
			},
		},
	}
}

// detect runs a detection attempt whose probes and DNS queries both travel over
// the virtual network.
func (e *natlabEnv) detect(t *testing.T) Result {
	t.Helper()

	d := NewDetector(t.Logf)
	d.dialFn = e.node.DialContext
	d.lookupIPFn = e.node.LookupIP

	netMon := netmon.NewStatic()
	if !hasProbeableInterface(netMon) {
		t.Skip("no usable network interface on this host to iterate over")
	}
	return d.detectCaptivePortalWithGOOS(t.Context(), netMon, e.derpMap, 0, runtime.GOOS)
}

// hasProbeableInterface reports whether detection would probe at all on this
// host.
//
// The detector walks the host's real interface list, because that's how it
// decides what to bind probes to. Here the probes are redirected onto the
// virtual network regardless of which interface is named, so the list only has
// to be non-empty — but if it were empty, detection would return early and the
// test would be asserting nothing.
func hasProbeableInterface(netMon *netmon.Monitor) bool {
	st := netMon.InterfaceState()
	if st == nil || !st.AnyInterfaceUp() {
		return false
	}
	for ifName, i := range st.Interface {
		if !i.IsUp() || i.IsLoopback() || interfaceNameDoesNotNeedCaptiveDetection(ifName, runtime.GOOS) {
			continue
		}
		if addrs, err := i.Addrs(); err == nil && len(addrs) > 0 {
			return true
		}
	}
	return false
}

func hasSignal(res Result, s Signal) bool { return slices.Contains(res.Signals, s) }

// TestNatlabCleanNetwork is the control for everything below: on a working
// virtual network the detector reaches a real DERP server, verifies its
// challenge echo, and reports no portal. Without this, a positive result
// elsewhere could just mean the virtual network was broken.
func TestNatlabCleanNetwork(t *testing.T) {
	res := newNatlabEnv(t, nil).detect(t)

	if res.Verdict != VerdictNoPortal {
		t.Errorf("verdict = %v, want %v (signals=%v)", res.Verdict, VerdictNoPortal, res.Signals)
	}
	if !hasSignal(res, SignalClean) {
		t.Errorf("signals = %v, want a %v among them", res.Signals, SignalClean)
	}
}

// TestNatlabRedirectingPortal covers the most common gateway design: an inline
// transparent proxy that answers port 80 for every destination with a redirect
// to its login page.
func TestNatlabRedirectingPortal(t *testing.T) {
	res := newNatlabEnv(t, &vnet.CaptivePortal{
		Style:         vnet.PortalRedirect,
		LoginURL:      portalLoginURL,
		InterceptHTTP: true,
	}).detect(t)

	if res.Verdict != VerdictPortal {
		t.Fatalf("verdict = %v, want %v (signals=%v)", res.Verdict, VerdictPortal, res.Signals)
	}
	if !hasSignal(res, SignalRedirect) {
		t.Errorf("signals = %v, want a %v among them", res.Signals, SignalRedirect)
	}
	// The login URL is what makes the warning actionable.
	if res.PortalURL != portalLoginURL {
		t.Errorf("PortalURL = %q, want %q", res.PortalURL, portalLoginURL)
	}
}

// TestNatlabMetaRefreshPortal covers gateways that answer 200 with an HTML page
// carrying a meta-refresh instead of redirecting (Cisco ISE, FortiGate).
func TestNatlabMetaRefreshPortal(t *testing.T) {
	res := newNatlabEnv(t, &vnet.CaptivePortal{
		Style:         vnet.PortalMetaRefresh,
		LoginURL:      portalLoginURL,
		InterceptHTTP: true,
	}).detect(t)

	if res.Verdict != VerdictPortal {
		t.Fatalf("verdict = %v, want %v (signals=%v)", res.Verdict, VerdictPortal, res.Signals)
	}
	if !hasSignal(res, SignalHTML) {
		t.Errorf("signals = %v, want a %v among them", res.Signals, SignalHTML)
	}
	if res.PortalURL != portalLoginURL {
		t.Errorf("PortalURL = %q, want %q", res.PortalURL, portalLoginURL)
	}
}

// TestNatlabDNSDrivenWalledGarden is the case that IP-addressed probing cannot
// see, and the reason every detection pass now probes by hostname too.
//
// The gateway drops traffic to everything except itself, and its resolver
// answers every name with its own address. A probe sent to a literal DERP IP
// vanishes; the same probe sent to a DERP hostname lands on the portal and
// comes back as a redirect. Before hostname probes were part of every pass,
// this network was invisible.
func TestNatlabDNSDrivenWalledGarden(t *testing.T) {
	res := newNatlabEnv(t, &vnet.CaptivePortal{
		Style:         vnet.PortalRedirect,
		LoginURL:      portalLoginURL,
		InterceptHTTP: false,
		HijackDNS:     true,
	}).detect(t)

	if res.Verdict != VerdictPortal {
		t.Fatalf("verdict = %v, want %v (signals=%v)", res.Verdict, VerdictPortal, res.Signals)
	}
	if !hasSignal(res, SignalRedirect) {
		t.Errorf("signals = %v, want a %v among them", res.Signals, SignalRedirect)
	}
	// The IP-addressed probes should have gone nowhere, which is what makes
	// this test meaningful rather than a duplicate of the redirect case.
	if !hasSignal(res, SignalNoResponse) {
		t.Errorf("signals = %v, want a %v among them: the literal-IP probes should have been dropped", res.Signals, SignalNoResponse)
	}
	if res.PortalURL != portalLoginURL {
		t.Errorf("PortalURL = %q, want %q", res.PortalURL, portalLoginURL)
	}
}

// TestNatlabSilentWalledGardenWithDNSHijack covers inflight Wi-Fi and the
// harshest airport gateways: nothing answers HTTP anywhere, so every probe
// times out and HTTP can prove nothing at all. The only thing left to find is
// the resolver answering every name with the gateway's address, which is what
// the escalated DNS probes are for.
func TestNatlabSilentWalledGardenWithDNSHijack(t *testing.T) {
	res := newNatlabEnv(t, &vnet.CaptivePortal{
		Style:     vnet.PortalSilent,
		HijackDNS: true,
	}).detect(t)

	if res.Verdict != VerdictPortal {
		t.Fatalf("verdict = %v, want %v (signals=%v)", res.Verdict, VerdictPortal, res.Signals)
	}
	// Either DNS probe is enough on its own; both should fire here, since the
	// resolver answers real names and impossible ones alike.
	if !hasSignal(res, SignalDNSHijack) {
		t.Errorf("signals = %v, want a %v among them", res.Signals, SignalDNSHijack)
	}
	if !hasSignal(res, SignalDNSWildcard) {
		t.Errorf("signals = %v, want a %v among them", res.Signals, SignalDNSWildcard)
	}
}

// TestNatlabSilentWalledGardenNoDNSHijack is the false-negative boundary: a
// network that drops everything and has an honest resolver is indistinguishable
// from a network with no Internet at all. There is nothing to find, so the
// detector must say so rather than guess.
func TestNatlabSilentWalledGardenNoDNSHijack(t *testing.T) {
	res := newNatlabEnv(t, &vnet.CaptivePortal{
		Style:     vnet.PortalSilent,
		HijackDNS: false,
	}).detect(t)

	if res.Verdict != VerdictUnknown {
		t.Errorf("verdict = %v, want %v (signals=%v)", res.Verdict, VerdictUnknown, res.Signals)
	}
}

// TestNatlabProxyBlockPageIsNotAPortal is the false-positive guard, and the
// most important test here.
//
// A transparent enterprise web proxy answering blocked destinations with an
// HTML error page produces the same shape of evidence as a captive portal:
// something else replied, with a web page, where a 204 belonged. But there is
// no login page to send the user to, so raising the warning would send them
// looking for something that doesn't exist. Detection must stay quiet.
func TestNatlabProxyBlockPageIsNotAPortal(t *testing.T) {
	res := newNatlabEnv(t, &vnet.CaptivePortal{
		Style:         vnet.PortalBlockPage,
		InterceptHTTP: true,
	}).detect(t)

	if res.Verdict == VerdictPortal {
		t.Errorf("verdict = %v, want anything but %v (signals=%v, url=%q)", res.Verdict, VerdictPortal, res.Signals, res.PortalURL)
	}
	// It should have been noticed and recorded, just not acted on.
	if !hasSignal(res, SignalUnexpectedStatus) {
		t.Errorf("signals = %v, want a %v among them", res.Signals, SignalUnexpectedStatus)
	}
}
