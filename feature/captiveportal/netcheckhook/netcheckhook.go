// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package netcheckhook makes netcheck probe for captive portals during
// full reports. It does so as a side effect of being imported, by
// installing a netcheck hook from init.
package netcheckhook

import (
	"context"
	"log"
	"time"

	"tailscale.com/net/captivedetection"
	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

func init() {
	netcheck.HookStartCaptivePortalDetection.Set(startCaptivePortalDetection)
}

// captivePortalDelay is the duration to wait after starting a netcheck before
// also probing for a captive portal, to let UDP STUN finish first and avoid
// the probe if it's unnecessary. Chosen semi-arbitrarily.
const captivePortalDelay = 200 * time.Millisecond

// startCaptivePortalDetection runs a detection attempt alongside a netcheck.
//
// It is a best-effort check: ctx carries netcheck's overall report deadline
// ([netcheck.ReportTimeout]), which is shorter than a full detection run can
// take, so the escalated probes usually get cut off here and the result comes
// back inconclusive. That's fine — this exists to populate
// [netcheck.Report.CaptivePortal] cheaply. The thorough, retried detection
// happens in the captiveportal extension, whose runs aren't on a report budget.
func startCaptivePortalDetection(ctx context.Context, c *netcheck.Client, dm *tailcfg.DERPMap, preferredDERP tailcfg.DERPRegionID, setCaptivePortal func(opt.Bool)) (done <-chan struct{}, stop func()) {
	logf := c.Logf
	if logf == nil {
		logf = log.Printf
	}

	// This goroutine can't be tracked by the wait group that
	// netcheck.GetReport uses for its probes, since GetReport doesn't
	// wait for that group to finish before returning and we'd get a
	// data race. Instead, completion is signaled by closing ch, which
	// GetReport receives as the done channel.
	ch := make(chan struct{})

	tmr := time.AfterFunc(captivePortalDelay, func() {
		defer close(ch)
		d := captivedetection.NewDetector(logf)
		res := d.DetectResult(ctx, c.NetMon, dm, preferredDERP)
		var found opt.Bool
		switch res.Verdict {
		case captivedetection.VerdictPortal:
			found.Set(true)
		case captivedetection.VerdictNoPortal:
			found.Set(false)
		default:
			// Leave found unset: we learned nothing, and reporting that as
			// "no captive portal" would be a claim we can't support.
		}
		setCaptivePortal(found)
	})

	if c.Verbose {
		// Don't cancel our captive portal check if we're
		// explicitly doing a verbose netcheck.
		return ch, func() {}
	}

	stop = func() {
		if tmr.Stop() {
			// Stopped successfully; need to close the
			// signal channel ourselves.
			close(ch)
			return
		}

		// Did not stop; do nothing and it'll finish by itself
		// and close the signal channel.
	}

	return ch, stop
}
