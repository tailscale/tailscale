// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appchealth

import (
	"testing"

	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

// hasUpstreamFor returns a hasUpstream func that reports true for any domain
// with a suffix in covered (or if "." is in covered, everything).
func hasUpstreamFor(covered ...string) func(dnsname.FQDN) bool {
	return func(fqdn dnsname.FQDN) bool {
		for _, c := range covered {
			if c == "." || mustFQDN(c).Contains(fqdn) {
				return true
			}
		}
		return false
	}
}

func mustFQDN(s string) dnsname.FQDN {
	f, err := dnsname.ToFQDN(s)
	if err != nil {
		panic(err)
	}
	return f
}

func TestUpdate(t *testing.T) {
	tests := []struct {
		name          string
		acceptDNS     bool
		domains       []string
		hasUpstream   func(dnsname.FQDN) bool
		wantUnhealthy bool
	}{
		{
			name:          "uncovered_domain_is_unhealthy",
			acceptDNS:     true,
			domains:       []string{"ifconfig.me"},
			hasUpstream:   hasUpstreamFor(), // nothing covered
			wantUnhealthy: true,
		},
		{
			name:          "default_resolver_covers_everything",
			acceptDNS:     true,
			domains:       []string{"ifconfig.me"},
			hasUpstream:   hasUpstreamFor("."),
			wantUnhealthy: false,
		},
		{
			name:          "split_route_covers_domain",
			acceptDNS:     true,
			domains:       []string{"foo.example.com"},
			hasUpstream:   hasUpstreamFor("example.com"),
			wantUnhealthy: false,
		},
		{
			name:          "accept_dns_off_is_never_unhealthy",
			acceptDNS:     false,
			domains:       []string{"ifconfig.me"},
			hasUpstream:   hasUpstreamFor(),
			wantUnhealthy: false,
		},
		{
			name:          "no_domains_is_healthy",
			acceptDNS:     true,
			domains:       nil,
			hasUpstream:   hasUpstreamFor(),
			wantUnhealthy: false,
		},
		{
			name:          "one_uncovered_among_covered_is_unhealthy",
			acceptDNS:     true,
			domains:       []string{"foo.example.com", "ifconfig.me"},
			hasUpstream:   hasUpstreamFor("example.com"),
			wantUnhealthy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht := health.NewTracker(eventbustest.NewBus(t))
			var st State
			Update(ht, &st, logger.Discard, tt.acceptDNS, tt.domains, tt.hasUpstream)
			if got := ht.IsUnhealthy(Warnable); got != tt.wantUnhealthy {
				t.Errorf("IsUnhealthy = %v, want %v", got, tt.wantUnhealthy)
			}
			if st.unhealthy != tt.wantUnhealthy {
				t.Errorf("st.unhealthy = %v, want %v", st.unhealthy, tt.wantUnhealthy)
			}
		})
	}
}

// TestUpdateEdgeTriggeredLog verifies the log fires only on the
// healthy->unhealthy transition, not on every call.
func TestUpdateEdgeTriggeredLog(t *testing.T) {
	ht := health.NewTracker(eventbustest.NewBus(t))
	var st State
	var logs []string
	logf := func(format string, args ...any) {
		logs = append(logs, format)
	}
	domains := []string{"ifconfig.me"}
	none := hasUpstreamFor()

	Update(ht, &st, logf, true, domains, none) // healthy -> unhealthy: logs
	Update(ht, &st, logf, true, domains, none) // still unhealthy: no log
	if len(logs) != 1 {
		t.Fatalf("got %d log lines, want 1: %v", len(logs), logs)
	}

	// Recover, then fail again: should log a second time.
	Update(ht, &st, logf, true, domains, hasUpstreamFor(".")) // -> healthy
	if ht.IsUnhealthy(Warnable) {
		t.Fatal("expected healthy after coverage restored")
	}
	Update(ht, &st, logf, true, domains, none) // healthy -> unhealthy again: logs
	if len(logs) != 2 {
		t.Fatalf("got %d log lines, want 2: %v", len(logs), logs)
	}
}

// TestSetHealthy verifies SetHealthy clears the warnable and resets state.
func TestSetHealthy(t *testing.T) {
	ht := health.NewTracker(eventbustest.NewBus(t))
	var st State
	Update(ht, &st, logger.Discard, true, []string{"ifconfig.me"}, hasUpstreamFor())
	if !ht.IsUnhealthy(Warnable) {
		t.Fatal("precondition: expected unhealthy")
	}
	SetHealthy(ht, &st)
	if ht.IsUnhealthy(Warnable) {
		t.Error("expected healthy after SetHealthy")
	}
	if st.unhealthy {
		t.Error("expected st.unhealthy=false after SetHealthy")
	}
}
