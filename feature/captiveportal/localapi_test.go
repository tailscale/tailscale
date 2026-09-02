// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captiveportal

import (
	"net/http"
	"testing"

	"tailscale.com/health"
	"tailscale.com/net/captivedetection"
	"tailscale.com/tsd"
	"tailscale.com/tstime"
	"tailscale.com/types/opt"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
)

// gateTestExtension returns an Extension wired up for testing canGrantLANBypass,
// with the given policy settings in force.
func gateTestExtension(t *testing.T, policy map[pkey.Key]string) *Extension {
	t.Helper()
	sys := tsd.NewSystem()
	if policy != nil {
		cfg := policytest.Config{}
		for k, v := range policy {
			cfg[k] = v
		}
		sys.PolicyClient.Set(cfg)
	}
	return &Extension{
		logf:                t.Logf,
		sb:                  &stubBackend{sys: sys},
		health:              health.NewTracker(eventbustest.NewBus(t)),
		clock:               newFakeClock(),
		exitNodeBlocksLANFn: func() bool { return true },
		reconfigFn:          func() {},
	}
}

// TestCanGrantLANBypassGates checks the endpoint only answers in the one
// situation it exists for (temporarily allowing a captive portal login page
// to be reached while an exit node is blocking).
func TestCanGrantLANBypassGates(t *testing.T) {
	const url = "http://portal.example/login"
	localPortal := captivedetection.Result{
		Verdict:          captivedetection.VerdictPortal,
		PortalURL:        url,
		PortalURLIsLocal: opt.NewBool(true),
	}

	tests := []struct {
		name     string
		policy   map[pkey.Key]string
		apply    *captivedetection.Result
		wantCode int
	}{
		{
			name:     "no_portal_at_all",
			wantCode: http.StatusConflict,
		},
		{
			// A portal we can help with: this is the one that should work.
			name:     "local_portal_behind_exit_node",
			apply:    &localPortal,
			wantCode: http.StatusOK,
		},
		{
			// Off the LAN, so opening the LAN is a leak that buys nothing. The
			// user has to turn off their exit node, and we say so via a
			// separate warnable rather than granting anything here.
			name: "remote_portal_is_refused",
			apply: &captivedetection.Result{
				Verdict:          captivedetection.VerdictPortal,
				PortalURL:        url,
				PortalURLIsLocal: opt.NewBool(false),
			},
			wantCode: http.StatusConflict,
		},
		{
			// An administrator who pinned local network access off has made a
			// call that a portal login doesn't get to override.
			name:     "policy_never_is_refused",
			policy:   map[pkey.Key]string{pkey.ExitNodeAllowLANAccess: "never"},
			apply:    &localPortal,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "policy_always_is_fine",
			policy:   map[pkey.Key]string{pkey.ExitNodeAllowLANAccess: "always"},
			apply:    &localPortal,
			wantCode: http.StatusOK,
		},
		{
			name:     "policy_user_decides_is_fine",
			policy:   map[pkey.Key]string{pkey.ExitNodeAllowLANAccess: "user-decides"},
			apply:    &localPortal,
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := gateTestExtension(t, tt.policy)
			if tt.apply != nil {
				e.applyResult(*tt.apply)
			}

			code, err := e.canGrantLANBypass()
			if code != tt.wantCode {
				t.Errorf("code = %d (err=%v), want %d", code, err, tt.wantCode)
			}
			if tt.wantCode == http.StatusOK && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantCode != http.StatusOK && err == nil {
				t.Error("want an error explaining the refusal, got nil")
			}
		})
	}
}

// TestCanGrantLANBypassWithoutExitNode checks that the endpoint is inert when
// no exit node is in the way, so it can't be used to open up the local network
// in the ordinary case.
func TestCanGrantLANBypassWithoutExitNode(t *testing.T) {
	e := gateTestExtension(t, nil)
	e.exitNodeBlocksLANFn = func() bool { return false }

	e.applyResult(captivedetection.Result{
		Verdict:   captivedetection.VerdictPortal,
		PortalURL: "http://portal.example/login",
	})
	// The warning is up, but without the arg saying an exit node is in the way
	// there is nothing to grant.
	if code, err := e.canGrantLANBypass(); code != http.StatusConflict {
		t.Errorf("code = %d (err=%v), want %d", code, err, http.StatusConflict)
	}
}

// TestCanGrantLANBypassAfterWarningCleared documents the race a GUI has to cope
// with: detection runs on a backoff, so a pass can clear the warning between
// the button being offered and the user pressing it. Refusing is the honest
// answer, since we're no longer standing behind the warning.
func TestCanGrantLANBypassAfterWarningCleared(t *testing.T) {
	e := gateTestExtension(t, nil)

	e.applyResult(captivedetection.Result{
		Verdict:          captivedetection.VerdictPortal,
		PortalURL:        "http://portal.example/login",
		PortalURLIsLocal: opt.NewBool(true),
	})
	if code, _ := e.canGrantLANBypass(); code != http.StatusOK {
		t.Fatalf("code = %d before the warning cleared, want 200", code)
	}

	e.applyResult(captivedetection.Result{Verdict: captivedetection.VerdictNoPortal})
	if code, _ := e.canGrantLANBypass(); code != http.StatusConflict {
		t.Errorf("code = %d after the warning cleared, want %d", code, http.StatusConflict)
	}
}

// stubBackend is the minimum [ipnext.SafeBackend] the gate checks need: they
// only reach for the policy client.
type stubBackend struct {
	sys *tsd.System
}

func (b *stubBackend) Sys() *tsd.System         { return b.sys }
func (b *stubBackend) Clock() tstime.Clock      { return tstime.StdClock{} }
func (b *stubBackend) TailscaleVarRoot() string { return "" }
