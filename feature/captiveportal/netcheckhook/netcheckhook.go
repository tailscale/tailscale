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
)

func init() {
	netcheck.HookStartCaptivePortalDetection.Set(startCaptivePortalDetection)
}

// captivePortalDelay is the duration to wait after starting a netcheck before
// also probing for a captive portal, to let UDP STUN finish first and avoid
// the probe if it's unnecessary. Chosen semi-arbitrarily.
const captivePortalDelay = 200 * time.Millisecond

func startCaptivePortalDetection(ctx context.Context, c *netcheck.Client, dm *tailcfg.DERPMap, preferredDERP int, setCaptivePortal func(bool)) (done <-chan struct{}, stop func()) {
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
		found := d.Detect(ctx, c.NetMon, dm, preferredDERP)
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
