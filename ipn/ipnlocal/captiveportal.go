// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_captiveportal

package ipnlocal

import (
	"context"
	"time"

	"tailscale.com/health"
	"tailscale.com/net/captivedetection"
	"tailscale.com/util/clientmetric"
)

func init() {
	hookCaptivePortalHealthChange.Set(captivePortalHealthChange)
	hookCheckCaptivePortalLoop.Set(checkCaptivePortalLoop)
}

var metricCaptivePortalDetected = clientmetric.NewCounter("captiveportal_detected")

// captivePortalDetectionInterval is the duration to wait in an unhealthy state with connectivity broken
// before running captive portal detection.
const captivePortalDetectionInterval = 2 * time.Second

func captivePortalHealthChange(b *LocalBackend, state *health.State) {
	isConnectivityImpacted := false
	for _, w := range state.Warnings {
		// Ignore the captive portal warnable itself.
		if w.ImpactsConnectivity && w.WarnableCode != captivePortalWarnable.Code {
			isConnectivityImpacted = true
			break
		}
	}

	// captiveCtx can be changed, and is protected with 'mu'; grab that
	// before we start our select, below.
	//
	// It is guaranteed to be non-nil.
	b.mu.Lock()
	ctx := b.captiveCtx
	b.mu.Unlock()

	// If the context is canceled, we don't need to do anything.
	if ctx.Err() != nil {
		return
	}

	if isConnectivityImpacted {
		b.logf("health: connectivity impacted; triggering captive portal detection")

		// Ensure that we select on captiveCtx so that we can time out
		// triggering captive portal detection if the backend is shutdown.
		select {
		case b.needsCaptiveDetection <- true:
		case <-ctx.Done():
		}
	} else {
		// If connectivity is not impacted, we know for sure we're not behind a captive portal,
		// so drop any warning, and signal that we don't need captive portal detection.
		b.health.SetHealthy(captivePortalWarnable)
		select {
		case b.needsCaptiveDetection <- false:
		case <-ctx.Done():
		}
	}
}

// captivePortalWarnable is a Warnable which is set to an unhealthy state when a captive portal is detected.
var captivePortalWarnable = health.Register(&health.Warnable{
	Code:  "captive-portal-detected",
	Title: "Captive portal detected",
	// High severity, because captive portals block all traffic and require user intervention.
	Severity:            health.SeverityHigh,
	Text:                health.StaticMessage("This network requires you to log in using your web browser."),
	ImpactsConnectivity: true,
})

func checkCaptivePortalLoop(b *LocalBackend, ctx context.Context) {
	var tmr *time.Timer

	maybeStartTimer := func() {
		// If there's an existing timer, nothing to do; just continue
		// waiting for it to expire. Otherwise, create a new timer.
		if tmr == nil {
			tmr = time.NewTimer(captivePortalDetectionInterval)
		}
	}
	maybeStopTimer := func() {
		if tmr == nil {
			return
		}
		if !tmr.Stop() {
			<-tmr.C
		}
		tmr = nil
	}

	for {
		if ctx.Err() != nil {
			maybeStopTimer()
			return
		}

		// First, see if we have a signal on our "healthy" channel, which
		// takes priority over an existing timer. Because a select is
		// nondeterministic, we explicitly check this channel before
		// entering the main select below, so that we're guaranteed to
		// stop the timer before starting captive portal detection.
		select {
		case needsCaptiveDetection := <-b.needsCaptiveDetection:
			if needsCaptiveDetection {
				maybeStartTimer()
			} else {
				maybeStopTimer()
			}
		default:
		}

		var timerChan <-chan time.Time
		if tmr != nil {
			timerChan = tmr.C
		}
		select {
		case <-ctx.Done():
			// All done; stop the timer and then exit.
			maybeStopTimer()
			return
		case <-timerChan:
			// Kick off captive portal check
			b.performCaptiveDetection()
			// nil out timer to force recreation
			tmr = nil
		case needsCaptiveDetection := <-b.needsCaptiveDetection:
			if needsCaptiveDetection {
				maybeStartTimer()
			} else {
				// Healthy; cancel any existing timer
				maybeStopTimer()
			}
		}
	}
}

// shouldRunCaptivePortalDetection reports whether captive portal detection
// should be run. It is enabled by default, but can be disabled via a control
// knob. It is also only run when the user explicitly wants the backend to be
// running.
func (b *LocalBackend) shouldRunCaptivePortalDetection() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.ControlKnobs().DisableCaptivePortalDetection.Load() && b.pm.prefs.WantRunning()
}

// performCaptiveDetection checks if captive portal detection is enabled via controlknob. If so, it runs
// the detection and updates the Warnable accordingly.
func (b *LocalBackend) performCaptiveDetection() {
	if !b.shouldRunCaptivePortalDetection() {
		return
	}

	d := captivedetection.NewDetector(b.logf)
	b.mu.Lock() // for b.hostinfo
	cn := b.currentNode()
	dm := cn.DERPMap()
	preferredDERP := 0
	if b.hostinfo != nil {
		if b.hostinfo.NetInfo != nil {
			preferredDERP = b.hostinfo.NetInfo.PreferredDERP
		}
	}
	ctx := b.ctx
	netMon := b.NetMon()
	b.mu.Unlock()
	found := d.Detect(ctx, netMon, dm, preferredDERP)
	if found {
		if !b.health.IsUnhealthy(captivePortalWarnable) {
			metricCaptivePortalDetected.Add(1)
		}
		b.health.SetUnhealthy(captivePortalWarnable, health.Args{})
	} else {
		b.health.SetHealthy(captivePortalWarnable)
	}
}
