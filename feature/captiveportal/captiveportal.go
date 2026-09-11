// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package captiveportal provides optional captive portal detection,
// warning the user via the health tracker when their network requires
// a browser login before traffic can flow.
package captiveportal

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	_ "tailscale.com/feature/captiveportal/netcheckhook" // install the netcheck probe hook too
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/captivedetection"
	"tailscale.com/net/netmon"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
)

const featureName = "captiveportal"

func init() {
	if !feature.Register(featureName) {
		return
	}
	ipnext.RegisterExtension(featureName, newExtension)
}

var (
	metricCaptivePortalDetected = clientmetric.NewCounter("captiveportal_detected")

	metricVerdict = map[captivedetection.Verdict]*clientmetric.Metric{
		captivedetection.VerdictPortal:   clientmetric.NewCounter("captiveportal_verdict_portal"),
		captivedetection.VerdictNoPortal: clientmetric.NewCounter("captiveportal_verdict_noportal"),
		captivedetection.VerdictUnknown:  clientmetric.NewCounter("captiveportal_verdict_unknown"),
	}

	// metricPortalURLFound counts detections where we learned a login URL to
	// show the user, as opposed to only being able to tell them a portal exists.
	metricPortalURLFound = clientmetric.NewCounter("captiveportal_portal_url_found")
)

// metricSignal returns the counter for a detection signal, registering it on
// first use. Signal counts are how we tell in the field which probes are
// tiggering.
var metricSignal = func() func(captivedetection.Signal) *clientmetric.Metric {
	m := map[captivedetection.Signal]*clientmetric.Metric{}
	for _, s := range []captivedetection.Signal{
		captivedetection.SignalNoResponse,
		captivedetection.SignalNoEvidence,
		captivedetection.SignalClean,
		captivedetection.SignalRedirect,
		captivedetection.SignalHTML,
		captivedetection.SignalChallengeTampered,
		captivedetection.SignalHTTP511,
		captivedetection.SignalDNSHijack,
		captivedetection.SignalDNSWildcard,
		captivedetection.SignalPlatformHint,
		captivedetection.SignalUnexpectedStatus,
		captivedetection.SignalProxyHeaders,
	} {
		// Signal names are hyphenated for logs; metric names can't be.
		m[s] = clientmetric.NewCounter("captiveportal_signal_" + strings.ReplaceAll(s.String(), "-", "_"))
	}
	return func(s captivedetection.Signal) *clientmetric.Metric { return m[s] }
}()

// captivePortalDetectionInterval is the duration to wait in an unhealthy state with connectivity broken
// before running captive portal detection.
const captivePortalDetectionInterval = 2 * time.Second

// captivePortalRetrySchedule is how long to wait before each successive
// re-check while connectivity stays broken, with the last entry repeating
// indefinitely.
//
// Retrying matters because a portal is often not yet intercepting when we first
// look: the gateway may still be finishing DHCP, and inflight Wi-Fi in
// particular can take a while to come up. A single check a couple of seconds in
// misses all of those.
var captivePortalRetrySchedule = []time.Duration{
	captivePortalDetectionInterval,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
}

// captivePortalWarnable is a Warnable which is set to an unhealthy state when a captive portal is detected.
//
// It covers the two cases where the user can get themselves logged in: no exit
// node is in the way, or one is but the login page lives on the local network,
// so we can offer to take the LAN back out of the tunnel. Those are told apart
// by [health.ArgExitNodeBlocksPortal]. The third case, where the login page is
// somewhere we cannot reach at all, is [captivePortalBlockedWarnable].
//
// We name the URL here, but GUI's should special-case this warnable and provide
// an easy way for the user to open the login page directly and temporaily
// remove the LAN from the tunnel if needed.
var captivePortalWarnable = health.Register(&health.Warnable{
	Code:  "captive-portal-detected",
	Title: "Captive portal detected",
	// High severity, because captive portals block all traffic and require user intervention.
	Severity: health.SeverityHigh,
	Text: func(args health.Args) string {
		u := args[health.ArgURL]
		if args[health.ArgExitNodeBlocksPortal] != "" {
			// Naming the URL on its own would be actively misleading here: the
			// exit node holds the route to it, so the page will not load until
			// local network access is allowed.
			if u != "" {
				return fmt.Sprintf("This network requires you to log in at %s.", u)
			}
			return "This network requires you to log in using your web browser."
		}
		if u != "" {
			return fmt.Sprintf("This network requires you to log in using your web browser. Open %s to continue.", u)
		}
		return "This network requires you to log in using your web browser."
	},
	ImpactsConnectivity: true,
})

// captivePortalBlockedWarnable is a Warnable which is set to an unhealthy state
// when a captive portal was detected but its login page is somewhere we cannot
// make reachable.
//
// It has its own code, rather than being another argument on
// [captivePortalWarnable], because it is the one portal case with no remedy we
// can offer: the login page is out on the Internet, so moving the local network
// out of the tunnel would not help, and only turning the exit node off will.
// A GUI therefore needs to present it as a different thing entirely, not as the
// same warning worded differently.
var captivePortalBlockedWarnable = health.Register(&health.Warnable{
	Code:     "captive-portal-blocked-by-exit-node",
	Title:    "Captive portal login unreachable",
	Severity: health.SeverityHigh,
	Text: func(args health.Args) string {
		if u := args[health.ArgURL]; u != "" {
			return fmt.Sprintf("This network requires you to log in at %s, which is not on this network and cannot be reached while you are using an exit node. Turn off your exit node to log in.", u)
		}
		return "This network requires a browser login that cannot be reached while you are using an exit node. Turn off your exit node to log in."
	},
	ImpactsConnectivity: true,
})

// portalWarnables is every Warnable this package raises to report a captive
// portal. Exactly one of them is ever unhealthy at a time; keeping the list in
// one place is what stops "clear the others" and "is any of them up" from
// drifting apart as cases are added.
var portalWarnables = []*health.Warnable{
	captivePortalWarnable,
	captivePortalBlockedWarnable,
}

// isPortalWarnableCode reports whether c is one of this package's own warnables.
func isPortalWarnableCode(c health.WarnableCode) bool {
	return slices.ContainsFunc(portalWarnables, func(w *health.Warnable) bool {
		return w.Code == c
	})
}

// Extension is the captive portal detection extension.
// There is one per [ipnext.Host] (and hence per LocalBackend).
type Extension struct {
	logf   logger.Logf
	sb     ipnext.SafeBackend
	host   ipnext.Host // from Init
	health *health.Tracker
	ec     *eventbus.Client
	clock  tstime.Clock

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

	// wasImpacted is whether the last health change we saw reported
	// connectivity as impacted. It distinguishes a transition into apparent
	// health, after which a standing portal warning is worth re-confirming
	// promptly, from the steady stream of health events that arrive while
	// nothing is wrong.
	wasImpacted bool

	// needsCaptiveDetection is a channel that is used to signal either
	// that captive portal detection is required (sending true) or that the
	// backend is healthy and captive portal detection is not required
	// (sending false).
	needsCaptiveDetection chan bool

	// recheck signals the detection loop to discard its backoff and look again
	// from the shortest delay, because what it concluded last time no longer
	// applies: either the network underneath us changed, or connectivity came
	// back while we were still warning about a portal.
	recheck chan struct{}

	// lanBypassUntil is when the temporary local network exception granted for
	// a captive portal login expires, or the zero time if none is active.
	// While it is in the future, [Extension.lanBypassActive] reports true and
	// LocalBackend keeps the local network out of the tunnel.
	lanBypassUntil time.Time

	// lanBypassTimer expires lanBypassUntil, or nil if none is active.
	lanBypassTimer tstime.TimerController

	// lastPortalResult is the most recent result that found a portal, kept so
	// that [Extension.refreshPortalWarning] can restate the warning when what
	// we can reach changes. Nil until a portal is found.
	lastPortalResult *captivedetection.Result

	// detectFn, if non-nil, replaces the real detection run. It is set by
	// tests, which exercise the retry scheduling without needing a network or
	// a LocalBackend.
	detectFn func(context.Context) captivedetection.Verdict

	// exitNodeBlocksLANFn, if non-nil, replaces the real prefs check in
	// [Extension.exitNodeBlocksLAN]. It is set by tests, which have no
	// LocalBackend to read prefs from.
	exitNodeBlocksLANFn func() bool

	// reconfigFn, if non-nil, replaces the call that asks LocalBackend to
	// reprogram routes. It is set by tests, which have no [ipnext.Host].
	reconfigFn func()
}

// maxLANBypass is the longest a temporary local network exception can last.
//
// It is deliberately short. The exception exists to get a login page in front
// of a user who is standing there waiting for it, and it undoes a leak
// protection the user (or their administrator) asked for, so it should not
// outlive the login attempt by much. A user who needs longer can ask again, or
// turn off their exit node.
const maxLANBypass = 5 * time.Minute

// lanBypassActive reports whether a temporary local network exception is
// currently in force.
//
// It is registered as [ipnext.Hooks.ExitNodeAllowLANOverride] and so is called
// with LocalBackend's mutex held. It must not call back into LocalBackend.
//
// The deadline is checked here rather than trusted to the timer alone, so that
// a timer which failed to fire cannot strand the exception indefinitely.
func (e *Extension) lanBypassActive() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lanBypassActiveLocked()
}

func (e *Extension) lanBypassActiveLocked() bool {
	return !e.lanBypassUntil.IsZero() && e.clock.Now().Before(e.lanBypassUntil)
}

// reconfig asks LocalBackend to reprogram routes, so that a change to what
// lanBypassActive reports actually reaches the router.
//
// It must not be called with e.mu held: the hook it ultimately triggers takes
// e.mu itself.
func (e *Extension) reconfig() {
	if e.reconfigFn != nil {
		e.reconfigFn()
		return
	}
	if e.host != nil {
		e.host.AuthReconfigAsync()
	}
}

// grantLANBypass opens up the local network for d, capped at [maxLANBypass],
// and reports when the exception will expire.
//
// A non-positive d asks for as long as we're willing to give, which is also
// what any longer request is clamped to.
//
// Callers are responsible for deciding that an exception is warranted; see
// serveAllowLAN, which is the only one.
func (e *Extension) grantLANBypass(d time.Duration) time.Time {
	if d <= 0 || d > maxLANBypass {
		d = maxLANBypass
	}

	e.mu.Lock()
	if e.lanBypassTimer != nil {
		// Stop may return false if the timer already fired and its goroutine is
		// waiting on e.mu. That's fine: the identity check below turns it into a
		// no-op once it gets the lock.
		e.lanBypassTimer.Stop()
		e.lanBypassTimer = nil
	}
	until := e.clock.Now().Add(d)
	e.lanBypassUntil = until
	var timer tstime.TimerController
	timer = e.clock.AfterFunc(d, func() {
		e.mu.Lock()
		if e.lanBypassTimer != timer {
			// We're either not the most recent timer, or we lost the race with
			// a Stop. Either way someone else owns the state now.
			e.mu.Unlock()
			return
		}
		e.lanBypassTimer = nil
		e.lanBypassUntil = time.Time{}
		e.mu.Unlock()

		e.logf("captiveportal: temporary local network access expired after %v", d)
		e.reconfig()
		e.refreshPortalWarning()
	})
	e.lanBypassTimer = timer
	e.mu.Unlock()

	e.logf("captiveportal: allowing local network access for %v to reach a portal login page", d)
	e.reconfig()
	e.refreshPortalWarning()
	return until
}

// revokeLANBypass closes the local network again. It is a no-op if no exception
// is active, and is safe to call repeatedly.
func (e *Extension) revokeLANBypass() {
	e.mu.Lock()
	if e.lanBypassUntil.IsZero() && e.lanBypassTimer == nil {
		e.mu.Unlock()
		return
	}
	if e.lanBypassTimer != nil {
		e.lanBypassTimer.Stop()
		e.lanBypassTimer = nil
	}
	e.lanBypassUntil = time.Time{}
	e.mu.Unlock()

	e.logf("captiveportal: revoking temporary local network access")
	e.reconfig()
	// If a portal warning is still standing, it needs to go back to saying the
	// login page can't be reached. When the warning is already down — the
	// [Extension.clearPortalWarnings] path — this is a no-op.
	e.refreshPortalWarning()
}

// exitNodeBlocksLAN reports whether an exit node is in use and is routing local
// network traffic over the tunnel, which is what makes a portal login page on
// the local network unreachable.
//
// This mirrors the condition in [ipnlocal.LocalBackend.routerConfigLocked] that
// decides whether the local network's prefixes go into Routes or LocalRoutes.
// The two must stay in sync.
func (e *Extension) exitNodeBlocksLAN() bool {
	if e.exitNodeBlocksLANFn != nil {
		return e.exitNodeBlocksLANFn()
	}
	if e.host == nil {
		return false
	}
	prefs := e.host.Profiles().CurrentPrefs()
	if !prefs.Valid() {
		return false
	}
	usingExitNode := prefs.ExitNodeID() != "" || prefs.ExitNodeIP().IsValid()
	return usingExitNode && !prefs.ExitNodeAllowLANAccess()
}

// detect runs one detection attempt and reports the verdict.
func (e *Extension) detect(ctx context.Context) captivedetection.Verdict {
	if e.detectFn != nil {
		return e.detectFn(ctx)
	}
	return e.performCaptiveDetection(ctx)
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
		clock:                 tstime.DefaultClock{},
		captiveCtx:            ctx,
		needsCaptiveDetection: make(chan bool),
		recheck:               make(chan struct{}, 1),
	}, nil
}

func (e *Extension) Name() string { return featureName }

func (e *Extension) Init(h ipnext.Host) error {
	e.host = h
	h.Hooks().BackendStateChange.Add(e.onBackendStateChange)
	h.Hooks().ExitNodeAllowLANOverride.Set(e.lanBypassActive)
	e.ec = e.sb.Sys().Bus.Get().Client("captiveportal")
	eventbus.SubscribeFunc(e.ec, e.onHealthChange)
	eventbus.SubscribeFunc(e.ec, e.onLinkChange)
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
		// Ignore our own warnables. Every one of them impacts connectivity, so
		// counting them here would feed our own detection result back in as
		// evidence that something else has broken the network, and we would
		// keep re-checking a portal we had already found for as long as it
		// stood.
		if w.ImpactsConnectivity && !isPortalWarnableCode(w.WarnableCode) {
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
	wasImpacted := e.wasImpacted
	e.wasImpacted = isConnectivityImpacted
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
		return
	}

	// Connectivity looks fine. That is usually because there is no portal, but
	// it is not proof of one: every warnable that impacts connectivity takes
	// five to ten seconds to become visible, while a check scheduled by a link
	// change runs two seconds in. A portal found on a network we just joined
	// therefore reports its verdict into a health state that still looks clean.
	//
	// Clearing the warning here would throw that verdict away immediately.
	if e.portalWarningUp() {
		if !wasImpacted {
			// Nothing changed; connectivity already looked fine last time. Let
			// the existing backoff run rather than restarting it, or a portal
			// we keep confirming would have us re-checking every couple of
			// seconds indefinitely.
			select {
			case e.needsCaptiveDetection <- true:
			case <-ctx.Done():
			}
			return
		}
		// Connectivity just came back while we were warning about a portal,
		// which is what logging in to one looks like. Confirm that from the
		// short end of the schedule so the warning doesn't outlive the portal
		// by a minute.
		e.logf("captiveportal: connectivity restored with a portal warning up; re-checking")
		e.scheduleRecheck()
		return
	}

	// No portal warning to protect, so the loop has nothing to do.
	select {
	case e.needsCaptiveDetection <- false:
	case <-ctx.Done():
	}
}

// scheduleRecheck asks the detection loop to check again from the start of the
// retry schedule. It never blocks: the channel is buffered, so a burst of
// reasons to re-check collapses into a single one.
func (e *Extension) scheduleRecheck() {
	select {
	case e.recheck <- struct{}{}:
	default:
	}
}

// onLinkChange is called (via the eventbus) when the host's network state
// changes. A change of network invalidates whatever we concluded about the
// previous one, so it schedules a fresh check from the start of the retry
// schedule.
//
// This is the path that catches the common case of a user joining a portalled
// network: associating with airport or hotel Wi-Fi produces a link change long
// before any health warnable has had time to go unhealthy.
func (e *Extension) onLinkChange(cd netmon.ChangeDelta) {
	if !cd.DefaultInterfaceChanged && !cd.InterfaceIPsChanged && !cd.TimeJumped() {
		return
	}

	e.mu.Lock()
	ctx := e.captiveCtx
	e.mu.Unlock()
	if ctx.Err() != nil {
		return
	}

	e.scheduleRecheck()
}

func (e *Extension) checkCaptivePortalLoop(ctx context.Context) {
	var (
		tmr   tstime.TimerController
		tmrCh <-chan time.Time
		// retry is how far into captivePortalRetrySchedule the next check is.
		retry int
		// pendingRecheck records that the armed timer belongs to a re-check
		// asked for by [Extension.scheduleRecheck], which a healthy signal must
		// not cancel. Both of the things that ask for one — a link change, and
		// connectivity returning under a portal warning — publish health
		// changes of their own, so "connectivity is fine" reliably arrives just
		// after the re-check is armed. Letting that stop the timer would mean
		// joining a portalled network went unexamined.
		pendingRecheck bool
	)

	stopTimer := func() {
		if tmr != nil {
			tmr.Stop()
			tmr, tmrCh = nil, nil
		}
	}
	// onHealthySignal handles the loop being told connectivity is fine.
	onHealthySignal := func() {
		if pendingRecheck {
			return
		}
		retry = 0
		stopTimer()
	}
	// armTimer schedules the next check, leaving an already-pending one alone.
	armTimer := func() {
		if tmr != nil {
			return
		}
		d := captivePortalRetrySchedule[min(retry, len(captivePortalRetrySchedule)-1)]
		tmr, tmrCh = e.clock.NewTimer(d)
	}
	defer stopTimer()

	// Once the loop stops, nothing is left that can clear the warning: only a
	// clean detection run does that now, and there will be no more runs. Drop
	// it rather than strand it, since we are no longer in a position to stand
	// behind it — and if the portal is still there when we start up again,
	// detection will find it. This also gives back any local network access
	// granted to reach a login page, which we likewise can no longer justify.
	defer e.clearPortalWarnings()

	for {
		if ctx.Err() != nil {
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
				armTimer()
			} else {
				onHealthySignal()
			}
		default:
		}

		select {
		case <-ctx.Done():
			return
		case <-tmrCh:
			tmr, tmrCh = nil, nil
			pendingRecheck = false
			// Keep checking while connectivity stays broken, backing off as we
			// go. A portal that wasn't intercepting a moment ago may be now.
			if e.detect(ctx) == captivedetection.VerdictNoPortal {
				retry = 0
			} else {
				retry++
				armTimer()
			}
		case <-e.recheck:
			// Whatever we concluded no longer applies: start over from the
			// shortest delay.
			retry = 0
			stopTimer()
			armTimer()
			pendingRecheck = true
		case needsCaptiveDetection := <-e.needsCaptiveDetection:
			if needsCaptiveDetection {
				armTimer()
			} else {
				// Healthy; cancel any existing timer
				onHealthySignal()
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
// the detection and updates the Warnable accordingly. It returns the verdict
// reached, so the caller can decide whether to keep looking.
//
// A [captivedetection.VerdictUnknown] result deliberately leaves the warnable
// as it is. It means we could not tell a walled garden apart from a network
// with no Internet at all, and treating that as an all-clear would both hide
// portals we should be reporting and clear warnings we had good reason to
// raise.
func (e *Extension) performCaptiveDetection(ctx context.Context) captivedetection.Verdict {
	if !e.shouldRunCaptivePortalDetection() {
		// We can't look, so we can't keep asserting what we last saw. Leaving
		// the warning up would strand it: every subsequent check returns here
		// too, and nothing else clears it.
		e.clearPortalWarnings()
		return captivedetection.VerdictUnknown
	}

	d := captivedetection.NewDetector(e.logf)
	d.SetLocalNetworkResolvers(e.localNetworkResolvers)
	dm := e.host.NodeBackend().DERPMap()
	var preferredDERP tailcfg.DERPRegionID
	if mc, ok := e.sb.Sys().MagicSock.GetOK(); ok {
		if report := mc.GetLastNetcheckReport(ctx); report != nil {
			preferredDERP = report.PreferredDERP
		}
	}
	netMon := e.sb.Sys().NetMon.Get()
	res := d.DetectResult(ctx, netMon, dm, preferredDERP)
	e.applyResult(res)
	return res.Verdict
}

// localNetworkResolvers reports the DNS servers the physical network handed us,
// which is what the OS was using before Tailscale took DNS over.
//
// Detection asks them directly rather than going through the system resolver,
// which on a node using an exit node leads into the tunnel and therefore
// nowhere at all from behind a portal. See
// [captivedetection.Detector.SetLocalNetworkResolvers].
//
// Returning nil is fine: the detector falls back to the default gateway, and
// then to the system resolver.
func (e *Extension) localNetworkResolvers() []netip.Addr {
	if !buildfeatures.HasDNS {
		return nil
	}
	dm, ok := e.sb.Sys().DNSManager.GetOK()
	if !ok {
		return nil
	}
	cfg, err := dm.GetBaseConfig()
	if err != nil {
		// Expected on the platforms that don't expose the base configuration.
		e.logf("[v1] captiveportal: no base DNS config to take resolvers from: %v", err)
		return nil
	}
	return cfg.Nameservers
}

// applyResult records a detection result in the health tracker and the client
// metrics.
func (e *Extension) applyResult(res captivedetection.Result) {
	if m := metricVerdict[res.Verdict]; m != nil {
		m.Add(1)
	}
	for _, s := range res.Signals {
		if m := metricSignal(s); m != nil {
			m.Add(1)
		}
	}

	switch res.Verdict {
	case captivedetection.VerdictPortal:
		if !e.portalWarningUp() {
			metricCaptivePortalDetected.Add(1)
		}
		if res.PortalURL != "" {
			metricPortalURLFound.Add(1)
		}
		e.mu.Lock()
		e.lastPortalResult = &res
		e.mu.Unlock()
		e.setPortalWarning(res)
	case captivedetection.VerdictNoPortal:
		e.clearPortalWarnings()
	default:
		e.logf("captiveportal: detection inconclusive (signals=%v); leaving the warning as-is and retrying", res.Signals)
	}
}

// setPortalWarning raises whichever of [portalWarnables] describes the user's
// situation, and clears the others so that only one portal warning is ever up.
//
// Which one depends on whether the user can act on it at all. With no exit node
// in the way, or with one that already permits local network access, the login
// page is simply reachable. With an exit node swallowing local traffic, it
// depends on where the login page lives: on the local network we can offer to
// open that up, while out on the Internet we cannot help, because the default
// route stays pointed at the exit node either way.
//
// A login page we could not locate counts as local. That is the recoverable way
// to be wrong: if opening the local network turns out not to help, the user can
// still turn off their exit node, whereas telling them to turn it off when the
// page was on the LAN all along sends them to disconnect for nothing.
func (e *Extension) setPortalWarning(res captivedetection.Result) {
	args := health.Args{}
	if res.PortalURL != "" {
		args[health.ArgURL] = res.PortalURL
	}

	w := captivePortalWarnable
	if e.exitNodeBlocksLAN() && !e.lanBypassActive() {
		if onLAN, known := res.PortalURLIsLocal.Get(); known && !onLAN {
			w = captivePortalBlockedWarnable
		} else {
			args[health.ArgExitNodeBlocksPortal] = "true"
		}
	}

	// Set the warning we want before clearing the others, so that the user is
	// never momentarily told nothing is wrong.
	e.health.SetUnhealthy(w, args)
	for _, other := range portalWarnables {
		if other != w {
			e.health.SetHealthy(other)
		}
	}
}

// refreshPortalWarning re-raises the standing portal warning so that its
// wording and arguments track a change in whether we can reach the login page,
// without waiting for the next detection pass.
//
// Health arguments are part of a warning's identity ([health.Tracker] compares
// them to decide whether anything changed), so re-setting with the same
// arguments is silently a no-op and only a real change reaches the GUI.
func (e *Extension) refreshPortalWarning() {
	if !e.portalWarningUp() {
		return
	}
	e.mu.Lock()
	res := e.lastPortalResult
	e.mu.Unlock()
	if res == nil {
		return
	}
	e.setPortalWarning(*res)
}

// portalWarningUp reports whether any captive portal warning is currently
// raised.
func (e *Extension) portalWarningUp() bool {
	for _, w := range portalWarnables {
		if e.health.IsUnhealthy(w) {
			return true
		}
	}
	return false
}

// clearPortalWarnings lowers every captive portal warning and revokes any
// temporary local network access granted to get past one.
//
// This is the only thing that lowers the warning, and revoking here is what
// implements "the exception lasts until the portal is actioned": a detection
// run coming back clean is exactly the evidence that the user got themselves
// logged in and no longer needs the local network opened up.
func (e *Extension) clearPortalWarnings() {
	for _, w := range portalWarnables {
		e.health.SetHealthy(w)
	}
	e.revokeLANBypass()
}
