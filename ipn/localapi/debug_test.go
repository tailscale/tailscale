// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tstest"
)

// TestServeDevSetStateStore verifies writing state keys requires a local admin,
// not just PermitWrite; guards against bypassing serve-config's authz check.
func TestServeDevSetStateStore(t *testing.T) {
	tstest.Replace(t, &validLocalHostForTesting, true)

	profileID := ipn.ProfileID("test-profile")
	tests := []struct {
		desc        string
		permitWrite bool
		localAdmin  bool
		wantStatus  int
	}{
		{
			desc:        "no-permission",
			permitWrite: false,
			localAdmin:  false,
			wantStatus:  http.StatusForbidden,
		},
		{
			desc:        "write-not-admin",
			permitWrite: true,
			localAdmin:  false,
			wantStatus:  http.StatusUnauthorized,
		},
		{
			desc:        "write-admin",
			permitWrite: true,
			localAdmin:  true,
			wantStatus:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			h := handlerForTest(t, &Handler{
				PermitWrite: tt.permitWrite,
				Actor:       &ipnauth.TestActor{LocalAdmin: tt.localAdmin},
				b:           newTestLocalBackend(t),
			})
			s := httptest.NewServer(h)
			t.Cleanup(s.Close)

			form := url.Values{
				"key":   {string(ipn.ServeConfigKey(profileID))},
				"value": {"{}"},
			}
			res, err := s.Client().PostForm(s.URL+"/localapi/v0/dev-set-state-store", form)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tt.wantStatus {
				t.Errorf("res.StatusCode = %d, want %d", res.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestServeDebugLogGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desc        string
		permitRead  bool
		permitWrite bool
		wantStatus  int
	}{
		{
			desc:       "read-only-denied",
			permitRead: true,
			wantStatus: http.StatusForbidden,
		},
		{
			desc:        "write-allowed",
			permitRead:  true,
			permitWrite: true,
			wantStatus:  http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			h := handlerForTest(t, &Handler{
				PermitRead:  tt.permitRead,
				PermitWrite: tt.permitWrite,
				b:           newTestLocalBackend(t),
			})
			req := httptest.NewRequest("POST", "http://local-tailscaled.sock/localapi/v0/debug-log",
				strings.NewReader(`{"prefix":"test","lines":["line"]}`))
			resp := httptest.NewRecorder()
			h.serveDebugLog(resp, req)

			if resp.Code != tt.wantStatus {
				t.Errorf("resp.Code = %d, want %d; body: %s", resp.Code, tt.wantStatus, resp.Body.String())
			}
		})
	}
}

func TestServeDebugDialTypesRestrictsAddress(t *testing.T) {
	t.Parallel()

	// Unassigned tailnet IPs: pass the address gate but never connect
	const tsAddr = "100.64.0.1"
	const tsAddrV6 = "fd7a:115c:a1e0::1"
	const subnetRoute = "192.168.0.0/16"

	tests := []struct {
		desc       string
		ip         string
		wantStatus int
	}{
		{
			desc:       "loopback-denied",
			ip:         "127.0.0.1",
			wantStatus: http.StatusBadRequest,
		},
		{
			desc:       "rfc1918-denied",
			ip:         "192.168.1.1",
			wantStatus: http.StatusBadRequest,
		},
		{
			desc:       "public-ip-denied",
			ip:         "8.8.8.8",
			wantStatus: http.StatusBadRequest,
		},
		{
			desc:       "tailscale-allowed",
			ip:         tsAddr,
			wantStatus: http.StatusOK,
		},
		{
			desc:       "tailscale-v6-allowed",
			ip:         tsAddrV6,
			wantStatus: http.StatusOK,
		},
		{
			// Even with 192.168.0.0/16 advertised as a subnet route,
			// the address-class gate must still refuse RFC1918: SystemDial
			// and BareDial don't consult the route table.
			desc:       "advertised-subnet-still-denied",
			ip:         "192.168.1.1",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			routes := []netip.Prefix{tsaddr.CGNATRange()}
			if tt.desc == "advertised-subnet-still-denied" {
				routes = append(routes, netip.MustParsePrefix(subnetRoute))
			}
			b := newTestLocalBackend(t)
			b.Dialer().SetNetMon(netmon.NewStatic())
			b.Dialer().SetRoutes(routes, nil)

			h := handlerForTest(t, &Handler{
				PermitRead:  true,
				PermitWrite: true,
				b:           b,
			})
			// UDP dials complete without traffic, avoiding the TCP connect timeout
			req := httptest.NewRequest("POST", "http://local-tailscaled.sock/localapi/v0/debug-dial-types?ip="+tt.ip+"&port=1&network=udp", nil)
			resp := httptest.NewRecorder()
			h.serveDebugDialTypes(resp, req)

			if resp.Code != tt.wantStatus {
				t.Errorf("resp.Code = %d, want %d; body: %s", resp.Code, tt.wantStatus, resp.Body.String())
			}
		})
	}
}

func TestServeDebugDialTypesReportsDialers(t *testing.T) {
	t.Parallel()

	b := newTestLocalBackend(t)
	b.Dialer().SetNetMon(netmon.NewStatic())
	b.Dialer().SetRoutes([]netip.Prefix{tsaddr.CGNATRange()}, nil)

	h := handlerForTest(t, &Handler{
		PermitRead:  true,
		PermitWrite: true,
		b:           b,
	})
	req := httptest.NewRequest("POST", "http://local-tailscaled.sock/localapi/v0/debug-dial-types?ip=100.64.0.1&port=1&network=udp", nil)
	resp := httptest.NewRecorder()
	h.serveDebugDialTypes(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("resp.Code = %d, want %d; body: %s", resp.Code, http.StatusOK, resp.Body.String())
	}
	for _, name := range []string{"SystemDial", "UserDial", "PeerDial", "BareDial"} {
		if !strings.Contains(resp.Body.String(), "["+name+"]") {
			t.Errorf("output missing %q dialer line; body: %s", name, resp.Body.String())
		}
	}
}
