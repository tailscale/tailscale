// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js && !ts_omit_acme

package localapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
)

func TestServeCertStatus(t *testing.T) {
	valid := &tailcfg.C2NTLSCertInfo{
		Valid:     true,
		NotBefore: "2026-01-01T00:00:00Z",
		NotAfter:  "2026-04-01T00:00:00Z",
	}
	missing := &tailcfg.C2NTLSCertInfo{Missing: true, Error: "no certificate"}
	t.Cleanup(ipnlocal.HookCertStatus.SetForTest(func(_ *ipnlocal.LocalBackend, domain string) (*tailcfg.C2NTLSCertInfo, error) {
		switch domain {
		case "valid.example.ts.net":
			return valid, nil
		case "broken.example.ts.net":
			return nil, errors.New("cert store unavailable")
		}
		return missing, nil
	}))

	tests := []struct {
		name       string
		permitRead bool
		domain     string
		wantCode   int
		want       *tailcfg.C2NTLSCertInfo
	}{
		{"valid", true, "valid.example.ts.net", http.StatusOK, valid},
		{"missing", true, "missing.example.ts.net", http.StatusOK, missing},
		{"store_error", true, "broken.example.ts.net", http.StatusInternalServerError, nil},
		{"forbidden", false, "valid.example.ts.net", http.StatusForbidden, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := handlerForTest(t, &Handler{PermitRead: tt.permitRead})
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/localapi/v0/cert-status/"+tt.domain, nil)
			h.serveCertStatus(rec, req)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d; body=%q", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.want == nil {
				return
			}
			var got tailcfg.C2NTLSCertInfo
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal body %q: %v", rec.Body.Bytes(), err)
			}
			if !reflect.DeepEqual(&got, tt.want) {
				t.Errorf("got %+v, want %+v", got, *tt.want)
			}
		})
	}
}
