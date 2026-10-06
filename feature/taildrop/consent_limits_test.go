// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"fmt"
	"testing"
	"time"
)

// Decided and expired requests retain their history without occupying prompt
// slots. Exercise both the per-peer and receiver-wide limits.
func TestConsentPromptSlotsReleased(t *testing.T) {
	for _, global := range []bool{false, true} {
		for _, action := range []string{"approve", "deny", "expire"} {
			t.Run(fmt.Sprintf("global=%v/%s", global, action), func(t *testing.T) {
				m, clock, _ := consentTestManager(t)
				limit := maxConsentPeerFiles
				if global {
					limit = maxConsentFiles
				}
				for round := range 2 {
					for i := range limit {
						peer := testPeerA
						if global && i >= maxConsentPeerFiles {
							peer = testPeerB
						}
						name := fmt.Sprintf("file-%d-%d", round, i)
						if state, _, err := m.requestConsent(peer, "peer", name, testConsentMetadata(name, 1)); err != nil || state != ConsentPending {
							t.Fatalf("request %s = %v, %v", name, state, err)
						}
						clock.Advance(100 * time.Millisecond)
					}
					if _, _, err := m.requestConsent(testPeerA, "peer", "overflow", testConsentMetadata("overflow", 1)); err != ErrConsentLimit {
						t.Fatalf("full prompt queue: %v", err)
					}
					pending := m.pendingConsentRequests()
					if len(pending) != limit {
						t.Fatalf("pending = %d, want %d", len(pending), limit)
					}
					if action == "expire" {
						clock.Advance(consentPendingTTL)
					} else {
						for _, req := range pending {
							if err := m.resolveConsent(req.RequestID, action == "approve"); err != nil {
								t.Fatal(err)
							}
						}
					}
					if got := len(m.pendingConsentRequests()); got != 0 {
						t.Fatalf("pending after %s = %d", action, got)
					}
					// The just-resolved requests must remain available to idempotent polls.
					m.consent.mu.Lock()
					retained := len(m.consent.requests)
					m.consent.mu.Unlock()
					if retained < limit {
						t.Fatalf("history discarded: %d entries", retained)
					}
				}
			})
		}
	}
}
