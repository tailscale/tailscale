// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The doctor package registers the "doctor" problem diagnosis support into the
// rest of Tailscale.
package doctor

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"time"

	"tailscale.com/doctor"
	"tailscale.com/doctor/ethtool"
	"tailscale.com/doctor/permissions"
	"tailscale.com/doctor/routetable"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

func init() {
	ipnlocal.HookDoctor.Set(visitDoctor)
	ipnlocal.RegisterPeerAPIHandler("/v0/doctor", handleServeDoctor)
}

func handleServeDoctor(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	if !h.CanDebug() {
		http.Error(w, "denied; no debug access", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, "<h1>Doctor Output</h1>")

	fmt.Fprintln(w, "<pre>")

	b := h.LocalBackend()
	visitDoctor(r.Context(), b, func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		fmt.Fprintln(w, html.EscapeString(line))
	})

	fmt.Fprintln(w, "</pre>")
}

func visitDoctor(ctx context.Context, b *ipnlocal.LocalBackend, logf logger.Logf) {
	// We can write logs too fast for logtail to handle, even when
	// opting-out of rate limits. Limit ourselves to at most one message
	// per 20ms and a burst of 60 log lines, which should be fast enough to
	// not block for too long but slow enough that we can upload all lines.
	logf = logger.SlowLoggerWithClock(ctx, logf, 20*time.Millisecond, 60, b.Clock().Now)

	var checks []doctor.Check
	checks = append(checks,
		permissions.Check{},
		routetable.Check{},
		ethtool.Check{},
	)

	// Print a log message if any of the global DNS resolvers are Tailscale
	// IPs; this can interfere with our ability to connect to the Tailscale
	// controlplane.
	checks = append(checks, doctor.CheckFunc("dns-resolvers", func(_ context.Context, logf logger.Logf) error {
		nm := b.NetMap()
		if nm == nil {
			return nil
		}

		for i, resolver := range nm.DNS.Resolvers {
			ipp, ok := resolver.IPPort()
			if ok && tsaddr.IsTailscaleIP(ipp.Addr()) {
				logf("resolver %d is a Tailscale address: %v", i, resolver)
			}
		}
		for i, resolver := range nm.DNS.FallbackResolvers {
			ipp, ok := resolver.IPPort()
			if ok && tsaddr.IsTailscaleIP(ipp.Addr()) {
				logf("fallback resolver %d is a Tailscale address: %v", i, resolver)
			}
		}
		return nil
	}))

	// TODO(andrew): more

	numChecks := len(checks)
	checks = append(checks, doctor.CheckFunc("numchecks", func(_ context.Context, log logger.Logf) error {
		log("%d checks", numChecks)
		return nil
	}))

	doctor.RunChecks(ctx, logf, checks...)
}
