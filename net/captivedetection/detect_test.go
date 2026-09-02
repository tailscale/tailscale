// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"testing"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

// deadAddr returns a host:port that nothing is listening on, standing in for a
// network that drops or refuses our probes.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// endpointAt builds an Endpoint of the given tier pointing at host:port.
func endpointAt(hostPort string, tier Tier) Endpoint {
	return Endpoint{
		URL:                        must.Get(url.Parse("http://" + hostPort + "/generate_204")),
		StatusCode:                 http.StatusNoContent,
		SupportsTailscaleChallenge: true,
		Tier:                       tier,
	}
}

// TestDetectOnInterface covers how a whole probe pass behaves against the
// network conditions that matter, from a working network to the walled gardens
// that this detector exists to find.
func TestDetectOnInterface(t *testing.T) {
	dead := deadAddr(t)

	// A server that redirects to a login page, as an intercepting gateway does.
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://wifi.example/login", http.StatusFound)
	}))
	defer portal.Close()

	// A real Tailscale /generate_204 handler.
	clean := httptest.NewServer(echoChallenge(http.StatusNoContent, "", ""))
	defer clean.Close()

	// A corporate proxy refusing an unapproved destination.
	blockPage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied by policy"))
	}))
	defer blockPage.Close()

	host := func(srv *httptest.Server) string {
		return must.Get(url.Parse(srv.URL)).Host
	}

	// fill returns n endpoints of the given tier, all pointing at hostPort.
	fill := func(hostPort string, tier Tier, n int) []Endpoint {
		out := make([]Endpoint, 0, n)
		for range n {
			out = append(out, endpointAt(hostPort, tier))
		}
		return out
	}

	tests := []struct {
		name            string
		endpoints       []Endpoint
		wantVerdict     Verdict
		wantURL         string
		wantGotResponse bool
	}{
		{
			// Nothing is wrong: a Tailscale server answered and proved it was
			// the real one.
			name: "working_network",
			endpoints: append(
				fill(host(clean), TierDERPIP, numDERPIPProbes),
				fill(host(clean), TierHostname, numHostnameProbes)...,
			),
			wantVerdict:     VerdictNoPortal,
			wantGotResponse: true,
		},
		{
			// Inflight and most airport Wi-Fi: traffic to bare IPs is dropped,
			// while traffic addressed by hostname is intercepted and
			// redirected. Before hostname probes were part of every pass, this
			// network was invisible to us.
			name: "portal_intercepts_by_hostname_only",
			endpoints: append(
				fill(dead, TierDERPIP, numDERPIPProbes),
				fill(host(portal), TierHostname, numHostnameProbes)...,
			),
			wantVerdict:     VerdictPortal,
			wantURL:         "https://wifi.example/login",
			wantGotResponse: true,
		},
		{
			// A network with no Internet at all is indistinguishable from a
			// walled garden at this stage, so the pass must not conclude
			// anything, and must report that nothing answered so the caller
			// knows to escalate.
			name: "no_internet",
			endpoints: append(
				fill(dead, TierDERPIP, numDERPIPProbes),
				fill(dead, TierHostname, numHostnameProbes)...,
			),
			wantVerdict:     VerdictUnknown,
			wantGotResponse: false,
		},
		{
			// A corporate proxy blocking every destination with a plain error
			// page. There is no portal and nowhere to log in, so warning about
			// one would be wrong. Something did answer, though, so there's no
			// point escalating.
			name: "corporate_proxy_block_page",
			endpoints: append(
				fill(host(blockPage), TierDERPIP, numDERPIPProbes),
				fill(host(blockPage), TierHostname, numHostnameProbes)...,
			),
			wantVerdict:     VerdictUnknown,
			wantGotResponse: true,
		},
		{
			// Split behavior: the hostname probes are intercepted but a DERP IP
			// answered provably cleanly. We stay quiet rather than send the
			// user looking for a login page.
			name: "clean_response_outranks_interception",
			endpoints: append(
				fill(host(clean), TierDERPIP, numDERPIPProbes),
				fill(host(portal), TierHostname, numHostnameProbes)...,
			),
			wantVerdict:     VerdictNoPortal,
			wantGotResponse: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector(t.Logf)
			res, gotResponse := d.detectOnInterface(t.Context(), 0, tt.endpoints)
			if res.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %v, want %v (signals=%v)", res.Verdict, tt.wantVerdict, res.Signals)
			}
			if res.PortalURL != tt.wantURL {
				t.Errorf("PortalURL = %q, want %q", res.PortalURL, tt.wantURL)
			}
			if gotResponse != tt.wantGotResponse {
				t.Errorf("gotResponse = %v, want %v (signals=%v)", gotResponse, tt.wantGotResponse, res.Signals)
			}
		})
	}
}

// deadDERPMap returns a DERP map whose only node is a closed local port, so
// that a full detection run makes no real network requests and every probe
// fails fast.
//
// The address fields carry a port, which a real DERP map never does; the
// endpoint URLs are built by string concatenation, so this reaches a listener
// we control instead of port 80 on the host.
func deadDERPMap(t *testing.T) *tailcfg.DERPMap {
	addr := deadAddr(t)
	return &tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
			1: {
				RegionID: 1,
				Nodes: []*tailcfg.DERPNode{
					{Name: "1a", HostName: addr, IPv4: addr, CanPort80: true},
				},
			},
		},
	}
}

// TestPlatformHint checks the shortcut we take when the host OS has already
// worked out that it's behind a portal.
func TestPlatformHint(t *testing.T) {
	tests := []struct {
		name        string
		found, ok   bool
		wantVerdict Verdict
		wantSignal  bool
	}{
		{
			// The OS knows. Believe it, and skip the probes entirely.
			name: "os_says_portal", found: true, ok: true,
			wantVerdict: VerdictPortal, wantSignal: true,
		},
		{
			// The OS says no. Its probes have their own blind spots, so this
			// doesn't settle anything and we go on to check ourselves.
			name: "os_says_no_portal", found: false, ok: true,
			wantVerdict: VerdictUnknown,
		},
		{
			// The platform couldn't answer.
			name: "os_cannot_answer", found: false, ok: false,
			wantVerdict: VerdictUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := HookPlatformHint.SetForTest(func(context.Context) (bool, bool) {
				return tt.found, tt.ok
			})
			defer restore()

			d := NewDetector(t.Logf)
			// No resolver and no reachable endpoints, so anything other than
			// the platform hint leaves us with no evidence.
			d.lookupIPFn = func(context.Context, string) ([]netip.Addr, error) {
				return nil, errNXDOMAIN
			}
			res := d.detectCaptivePortalWithGOOS(t.Context(), netmon.NewStatic(), deadDERPMap(t), 0, "linux")

			if res.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %v, want %v (signals=%v)", res.Verdict, tt.wantVerdict, res.Signals)
			}
			if got := slices.Contains(res.Signals, SignalPlatformHint); got != tt.wantSignal {
				t.Errorf("has SignalPlatformHint = %v, want %v", got, tt.wantSignal)
			}
		})
	}
}
