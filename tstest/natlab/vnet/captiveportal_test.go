// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestCaptivePortalIntercepts checks that a portalled network answers HTTP on
// port 80 for a destination it has no business answering for, in the shape the
// configured style calls for.
func TestCaptivePortalIntercepts(t *testing.T) {
	const loginURL = "http://portal.example/login"

	tests := []struct {
		name       string
		portal     *CaptivePortal
		wantStatus int
		wantHeader map[string]string
		wantBody   string // substring
	}{
		{
			name:       "redirect",
			portal:     &CaptivePortal{Style: PortalRedirect, LoginURL: loginURL, InterceptHTTP: true},
			wantStatus: http.StatusFound,
			wantHeader: map[string]string{"Location": loginURL},
		},
		{
			name:       "meta_refresh",
			portal:     &CaptivePortal{Style: PortalMetaRefresh, LoginURL: loginURL, InterceptHTTP: true},
			wantStatus: http.StatusOK,
			wantBody:   `<meta http-equiv="refresh" content="0; url=` + loginURL + `">`,
		},
		{
			name:       "block_page",
			portal:     &CaptivePortal{Style: PortalBlockPage, InterceptHTTP: true},
			wantStatus: http.StatusForbidden,
			wantBody:   "Access Denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, nn := newNetstackNodeOnNetwork(t, tt.portal)

			// Ask for the fake DERP server. On an unportalled network this
			// returns 204; here the portal answers instead.
			res, err := httpClientVia(nn).Get("http://" + FakeDERP1IPv4().String() + "/generate_204")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))

			if res.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			for k, want := range tt.wantHeader {
				if got := res.Header.Get(k); got != want {
					t.Errorf("header %s = %q, want %q", k, got, want)
				}
			}
			if tt.wantBody != "" && !strings.Contains(string(body), tt.wantBody) {
				t.Errorf("body = %q, want it to contain %q", body, tt.wantBody)
			}
		})
	}
}

// TestCaptivePortalDNSDrivenWalledGarden covers the design that defeats
// IP-addressed probing: the portal answers only for itself, everything else is
// dropped, and the hijacked resolver is what steers clients to it. A request to
// a literal IP goes nowhere; the same request by name reaches the portal.
func TestCaptivePortalDNSDrivenWalledGarden(t *testing.T) {
	const loginURL = "http://portal.example/login"
	_, nn := newNetstackNodeOnNetwork(t, &CaptivePortal{
		Style:         PortalRedirect,
		LoginURL:      loginURL,
		InterceptHTTP: false,
		HijackDNS:     true,
	})
	if _, err := httpClientViaTimeout(nn, 2*time.Second).Get("http://" + FakeDERP1IPv4().String() + "/generate_204"); err == nil {
		t.Error("GET by literal IP succeeded, want it to be dropped")
	} else {
		t.Logf("GET by literal IP failed as expected: %v", err)
	}

	res, err := httpClientVia(nn).Get("http://" + FakeDERP1Hostname() + "/generate_204")
	if err != nil {
		t.Fatalf("GET by hostname: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusFound)
	}
	if got := res.Header.Get("Location"); got != loginURL {
		t.Errorf("Location = %q, want %q", got, loginURL)
	}
}

// TestCaptivePortalSilentDropsEverything checks the walled-garden case: nothing
// answers on port 80, so a client gets no response at all rather than an error
// page. This is what makes a portalled network indistinguishable from a
// network with no Internet, and it's the condition the DNS probes exist for.
func TestCaptivePortalSilentDropsEverything(t *testing.T) {
	_, nn := newNetstackNodeOnNetwork(t, &CaptivePortal{
		Style:     PortalSilent,
		HijackDNS: true,
	})

	_, err := httpClientViaTimeout(nn, 2*time.Second).Get("http://" + FakeDERP1IPv4().String() + "/generate_204")
	if err == nil {
		t.Fatal("GET succeeded, want it to be dropped")
	}
	t.Logf("GET failed as expected: %v", err)
}

// TestCaptivePortalHijacksDNS checks that a hijacking resolver answers every
// name — including one that cannot exist — with the portal's own address.
func TestCaptivePortalHijacksDNS(t *testing.T) {
	_, nn := newNetstackNodeOnNetwork(t, &CaptivePortal{
		Style:     PortalSilent,
		HijackDNS: true,
	})

	want := nn.gw // the portal lives on the gateway

	for _, name := range []string{
		FakeDERP1Hostname(),
		"controlplane.tailscale.com",
		"nonexistent-name-that-cannot-resolve.invalid.",
	} {
		got, err := nn.LookupIP(t.Context(), name)
		if err != nil {
			t.Errorf("LookupIP(%q): %v", name, err)
			continue
		}
		if len(got) != 1 || got[0].Unmap() != want {
			t.Errorf("LookupIP(%q) = %v, want [%v]", name, got, want)
		}
	}
}

// TestNoPortalDNSIsHonest is the control for the test above: without a portal,
// names resolve to their real addresses and nonexistent names don't resolve.
func TestNoPortalDNSIsHonest(t *testing.T) {
	_, nn := newNetstackNodeOnNetwork(t, nil)

	got, err := nn.LookupIP(t.Context(), FakeDERP1Hostname())
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if len(got) != 1 || got[0].Unmap() != FakeDERP1IPv4() {
		t.Errorf("LookupIP(%q) = %v, want [%v]", FakeDERP1Hostname(), got, FakeDERP1IPv4())
	}

	if got, err := nn.LookupIP(t.Context(), "does-not-exist.invalid."); err == nil && len(got) > 0 {
		t.Errorf("LookupIP of a .invalid name = %v, want no answer", got)
	}
}
