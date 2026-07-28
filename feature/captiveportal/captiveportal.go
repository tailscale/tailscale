// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package captiveportal provides optional captive portal detection,
// warning the user via the health tracker when their network requires
// a browser login before traffic can flow.
package captiveportal

import (
	"context"
	"time"

	"tailscale.com/feature"
	_ "tailscale.com/feature/captiveportal/netcheckhook" // install the netcheck probe hook too
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/captivedetection"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
)

const featureName = "captiveportal"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
}

var metricCaptivePortalDetected = clientmetric.NewCounter("captiveportal_detected")

// captivePortalDetectionInterval is the duration to wait in an unhealthy state with connectivity broken
// before running captive portal detection.
const captivePortalDetectionInterval = 2 * time.Second

// captivePortalWarnable is a Warnable which is set to an unhealthy state when a captive portal is detected.
var captivePortalWarnable = health.Register(&health.Warnable{
	Code:  "captive-portal-detected",
	Title: "Captive portal detected",
	// High severity, because captive portals block all traffic and require user intervention.
	Severity:            health.SeverityHigh,
	Text:                health.StaticMessage("This network requires you to log in using your web browser."),
	ImpactsConnectivity: true,
})

// Extension is the captive portal detection extension.
// There is one per [ipnext.Host] (and hence per LocalBackend).
type Extension struct {
	logf   logger.Logf
	sb     ipnext.SafeBackend
	host   ipnext.Host // from Init
	health *health.Tracker
	ec     *eventbus.Client

	mu syncs.Mutex
	// captiveCtx and captiveCancel are used to control captive portal
	// detection. They are protected by 'mu' and can be changed during the
	// lifetime of the extension.
	//
	// captiveCtx will always be non-nil, though it might be a canceled
	// context. captiveCancel is non-nil if checkCaptivePortalLoop is
	// running, and is set to nil after being canceled.
	captiveCtx    context.Context
	captiveCancel context.CancelFunc

	// needsCaptiveDetection is a channel that is used to signal either
	// that captive portal detection is required (sending true) or that the
	// backend is healthy and captive portal detection is not required
	// (sending false).
	needsCaptiveDetection chan bool
}

func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	// Initialize the context used to control the captive portal detection
	// goroutine in a canceled state, so that it is always non-nil and safe
	// to wait on even before the loop has ever started.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return &Extension{
		logf:                  logf,
		sb:                    sb,
		health:                sb.Sys().HealthTracker.Get(),
		captiveCtx:            ctx,
		needsCaptiveDetection: make(chan bool),
	}, nil
}

func (e *Extension) Name() string { return featureName }

func (e *Extension) Init(h ipnext.Host) error {
	e.host = h
	h.Hooks().BackendStateChange.Add(e.onBackendStateChange)
	e.ec = e.sb.Sys().Bus.Get().Client("captiveportal")
	eventbus.SubscribeFunc(e.ec, e.onHealthChange)
	return nil
}

func (e *Extension) Shutdown() error {
	e.mu.Lock()
	if e.captiveCancel != nil {
		e.captiveCancel()
		e.captiveCancel = nil
	}
	e.mu.Unlock()
	if e.ec != nil {
		e.ec.Close()
	}
	return nil
}

// onBackendStateChange starts or stops the captive portal detection loop as
// the backend enters or leaves the Running state. It is called with
// LocalBackend's mutex held, so it must not call back into LocalBackend.
func (e *Extension) onBackendStateChange(st ipn.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if st == ipn.Running {
		// Start a captive portal detection loop if none has been
		// started.
		if e.captiveCancel == nil {
			e.captiveCtx, e.captiveCancel = context.WithCancel(context.Background())
			go e.checkCaptivePortalLoop(e.captiveCtx)
		}
	} else if e.captiveCancel != nil {
		// Transitioning away from Running; stop any existing captive
		// portal detection loop.
		e.captiveCancel()
		e.captiveCancel = nil

		// NOTE: don't set captiveCtx to nil here, to ensure that we
		// always have a (canceled) context to wait on in
		// onHealthChange.
	}
}

// onHealthChange is called (via the eventbus) whenever the node's health
// state changes. If connectivity appears to be impacted, it signals the
// detection loop to check for a captive portal.
func (e *Extension) onHealthChange(health.Change) {
	state := e.health.CurrentState()
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
	e.mu.Lock()
	ctx := e.captiveCtx
	e.mu.Unlock()

	// If the context is canceled, we don't need to do anything.
	if ctx.Err() != nil {
		return
	}

	if isConnectivityImpacted {
		e.logf("health: connectivity impacted; triggering captive portal detection")

		// Ensure that we select on captiveCtx so that we can time out
		// triggering captive portal detection if the loop is shut down.
		select {
		case e.needsCaptiveDetection <- true:
		case <-ctx.Done():
		}
	} else {
		// If connectivity is not impacted, we know for sure we're not behind a captive portal,
		// so drop any warning, and signal that we don't need captive portal detection.
		e.health.SetHealthy(captivePortalWarnable)
		select {
		case e.needsCaptiveDetection <- false:
		case <-ctx.Done():
		}
	}
}

func (e *Extension) checkCaptivePortalLoop(ctx context.Context) {
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
		case needsCaptiveDetection := <-e.needsCaptiveDetection:
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
			e.performCaptiveDetection(ctx)
			// nil out the timer and its channel to force recreation
			tmr, timerChan = nil, nil
		case needsCaptiveDetection := <-e.needsCaptiveDetection:
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
func (e *Extension) shouldRunCaptivePortalDetection() bool {
	return !e.sb.Sys().ControlKnobs().DisableCaptivePortalDetection.Load() &&
		e.host.Profiles().CurrentPrefs().WantRunning()
}

// performCaptiveDetection checks if captive portal detection is enabled via controlknob. If so, it runs
// the detection and updates the Warnable accordingly.
func (e *Extension) performCaptiveDetection(ctx context.Context) {
	if !e.shouldRunCaptivePortalDetection() {
		return
	}

	d := captivedetection.NewDetector(e.logf)
	dm := e.host.NodeBackend().DERPMap()
	preferredDERP := 0
	if mc, ok := e.sb.Sys().MagicSock.GetOK(); ok {
		if report := mc.GetLastNetcheckReport(ctx); report != nil {
			preferredDERP = report.PreferredDERP
		}
	}
	netMon := e.sb.Sys().NetMon.Get()
	found := d.Detect(ctx, netMon, dm, preferredDERP)
	if found {
		if !e.health.IsUnhealthy(captivePortalWarnable) {
			metricCaptivePortalDetected.Add(1)
		}
		e.health.SetUnhealthy(captivePortalWarnable, health.Args{})
	} else {
		e.health.SetHealthy(captivePortalWarnable)
	}
}
