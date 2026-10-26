// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"tailscale.com/ipn/ipnstate"
)

type fakeHealthLocalClient struct {
	status *ipnstate.Status
	err    error
}

func (f *fakeHealthLocalClient) StatusWithoutPeers(context.Context) (*ipnstate.Status, error) {
	return f.status, f.err
}

func TestHealthChecks(t *testing.T) {
	withIPs := &ipnstate.Status{Self: &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")}}}

	for name, tt := range map[string]struct {
		lc         *fakeHealthLocalClient
		wantLivez  int
		wantReadyz int
	}{
		"tailnet_ips":       {lc: &fakeHealthLocalClient{status: withIPs}, wantLivez: http.StatusOK, wantReadyz: http.StatusOK},
		"no_tailnet_ips":    {lc: &fakeHealthLocalClient{status: &ipnstate.Status{Self: &ipnstate.PeerStatus{}}}, wantLivez: http.StatusOK, wantReadyz: http.StatusServiceUnavailable},
		"no_self":           {lc: &fakeHealthLocalClient{status: &ipnstate.Status{}}, wantLivez: http.StatusOK, wantReadyz: http.StatusServiceUnavailable},
		"localapi_failing":  {lc: &fakeHealthLocalClient{err: errors.New("connection refused")}, wantLivez: http.StatusServiceUnavailable, wantReadyz: http.StatusServiceUnavailable},
		"localapi_timedout": {lc: &fakeHealthLocalClient{err: context.DeadlineExceeded}, wantLivez: http.StatusServiceUnavailable, wantReadyz: http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			registerHealthChecks(mux, tt.lc, t.Logf)
			for path, want := range map[string]int{"/livez": tt.wantLivez, "/readyz": tt.wantReadyz} {
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
				if w.Code != want {
					t.Errorf("GET %s = %d, want %d (body %q)", path, w.Code, want, w.Body.String())
				}
			}
		})
	}
}
