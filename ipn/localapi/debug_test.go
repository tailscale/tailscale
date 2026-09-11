// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
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
