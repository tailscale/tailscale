// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbe(t *testing.T) {
	for name, tt := range map[string]struct {
		conditions map[string]bool // name -> passing
		checkErr   error
		wantCode   int
		wantBody   string
	}{
		"no_checks":           {wantCode: http.StatusOK},
		"condition_not_set":   {conditions: map[string]bool{"netmap": false}, wantCode: http.StatusServiceUnavailable, wantBody: "netmap: not ready"},
		"condition_set":       {conditions: map[string]bool{"netmap": true}, wantCode: http.StatusOK},
		"one_condition_unset": {conditions: map[string]bool{"netmap": true, "serve": false}, wantCode: http.StatusServiceUnavailable, wantBody: "serve: not ready"},
		"check_fails":         {conditions: map[string]bool{"netmap": true}, checkErr: errors.New("no certs"), wantCode: http.StatusServiceUnavailable, wantBody: "certs: no certs"},
	} {
		t.Run(name, func(t *testing.T) {
			p := &Probe{name: "test", logf: t.Logf}
			for name, pass := range tt.conditions {
				p.AddCondition(name, "not ready").Set(pass)
			}
			p.AddCheck("certs", func(context.Context) error { return tt.checkErr })

			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

// TestProbeNil checks that a nil Probe and the nil Condition it returns can be
// used when health checks are disabled.
func TestProbeNil(t *testing.T) {
	var p *Probe
	p.AddCheck("certs", func(context.Context) error { return nil })
	p.AddCondition("netmap", "not ready").Set(true)
}

func TestRegisterHandlers(t *testing.T) {
	mux := http.NewServeMux()
	lz := RegisterLivezHandlers(mux, t.Logf)
	rz := RegisterReadyzHandlers(mux, t.Logf)
	lz.AddCondition("tailscaled", "not live")
	rz.AddCondition("netmap", "not ready")

	for path, want := range map[string]string{
		"/livez":  "tailscaled: not live",
		"/readyz": "netmap: not ready",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s = %d %q, want 503 containing %q", path, rec.Code, rec.Body.String(), want)
		}
	}
}
