// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"errors"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
	"tailscale.com/util/syspolicy/ptype"
)

func TestExternalTaildropPolicy(t *testing.T) {
	for _, tt := range []struct {
		name    string
		policy  policytest.Config
		allowed bool
	}{
		{"unset", policytest.Config{}, true},
		{"choice", policytest.Config{pkey.AllowExternalTaildrop: ptype.ShowChoiceByPolicy}, true},
		{"always", policytest.Config{pkey.AllowExternalTaildrop: ptype.AlwaysByPolicy}, true},
		{"never", policytest.Config{pkey.AllowExternalTaildrop: ptype.NeverByPolicy}, false},
		{"error", policytest.Config{pkey.AllowExternalTaildrop: errors.New("policy unavailable")}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			own := (&tailcfg.Node{StableID: "own", User: 1}).View()
			other := (&tailcfg.Node{StableID: "other", User: 2}).View()
			nb := testNodeBackend{peers: []tailcfg.NodeView{own, other}}
			e := &Extension{polc: tt.policy, selfUID: 1, nodeBackendForTest: nb, backendState: ipn.Running, capFileSharing: true}
			if err := e.checkSendPolicy("own"); err != nil {
				t.Fatalf("own peer: %v", err)
			}
			if err := e.checkSendPolicy("other"); (err == nil) != tt.allowed {
				t.Fatalf("other peer: %v; allowed=%v", err, tt.allowed)
			}
			// The receive opt-in is separate from outbound policy permission.
			if e.externalReceiveAllowed() {
				t.Fatal("receiving allowed without opt-in")
			}
			e.allowExternalTaildrop.Store(true)
			if got := e.externalReceiveAllowed(); got != tt.allowed {
				t.Fatalf("receive allowed=%v; want %v", got, tt.allowed)
			}
			if !tt.allowed {
				if got := e.taildropTargetStatus(other, nb); got != ipnstate.TaildropTargetPolicyDenied {
					t.Fatalf("status=%v; want policy denied", got)
				}
				// Policy rejection must happen before constructing or sending a request.
				if _, err := e.requestSendConsent(t.Context(), nil, nil, "other", "file", PutRequest{}); err != errExternalTaildropPolicy {
					t.Fatalf("preflight: %v", err)
				}
				if err := e.RespondToConsent("pending", true); err != errExternalTaildropPolicy {
					t.Fatalf("approve: %v", err)
				}
			}
		})
	}
}

func TestConsentApprovalAfterOptOut(t *testing.T) {
	m, _, _ := consentTestManager(t)
	m.opts.AllowExternalTaildrop = func() bool { return false }
	if err := m.resolveConsent("pending", true); err != ErrConsentNotAllowed {
		t.Fatalf("approve after opt-out: %v", err)
	}
}
