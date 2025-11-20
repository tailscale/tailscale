// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_captiveportal

package netcheck

import (
	"context"
	"time"

	"tailscale.com/net/captivedetection"
	"tailscale.com/tailcfg"
)

func init() {
	hookStartCaptivePortalDetection.Set(startCaptivePortalDetection)
}

func startCaptivePortalDetection(ctx context.Context, rs *reportState, dm *tailcfg.DERPMap, preferredDERP int) (done <-chan struct{}, stop func()) {
	c := rs.c

	// NOTE(andrew): we can't simply add this goroutine to the
	// `NewWaitGroupChan` below, since we don't wait for that
	// waitgroup to finish when exiting this function and thus get
	// a data race.
	ch := make(chan struct{})

	tmr := time.AfterFunc(c.captivePortalDelay(), func() {
		defer close(ch)
		d := captivedetection.NewDetector(c.logf)
		found := d.Detect(ctx, c.NetMon, dm, preferredDERP)
		rs.report.CaptivePortal.Set(found)
	})

	stop = func() {
		// Don't cancel our captive portal check if we're
		// explicitly doing a verbose netcheck.
		if c.Verbose {
			return
		}

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
