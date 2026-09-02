// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captiveportal

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/health"
	"tailscale.com/net/captivedetection"
	"tailscale.com/net/netmon"
	"tailscale.com/tstime"
	"tailscale.com/types/opt"
	"tailscale.com/util/eventbus/eventbustest"
)

// fakeClock hands out timers the test fires by hand, and records the delay each
// one was armed with so tests can assert on the retry schedule.
type fakeClock struct {
	tstime.StdClock

	// armed receives the delay of every timer created. Buffered, so the
	// detection loop never blocks waiting for the test to read it.
	armed chan time.Duration

	// ch is the most recently created timer's channel.
	ch chan time.Time

	// afterFuncs receives every function armed via AfterFunc, along with the
	// delay it was armed with, so tests can expire it by hand. Without this,
	// AfterFunc would fall through to the embedded StdClock and a test waiting
	// on a five-minute timer would hang.
	afterFuncs chan armedFunc

	mu  sync.Mutex
	now time.Time // guarded by mu
}

// armedFunc is a function scheduled via [fakeClock.AfterFunc].
type armedFunc struct {
	d  time.Duration
	fn func()
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		armed:      make(chan time.Duration, 32),
		afterFuncs: make(chan armedFunc, 32),
		now:        time.Unix(1757000000, 0), // arbitrary fixed instant
	}
}

// Now reports the clock's current instant, which only [fakeClock.advance] moves.
// Overriding the embedded StdClock is what lets tests check that a deadline is
// respected on its own, without relying on a timer having fired.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) AfterFunc(d time.Duration, fn func()) tstime.TimerController {
	c.afterFuncs <- armedFunc{d, fn}
	return noopTimer{}
}

// nextAfterFunc returns the next function armed via AfterFunc, failing if none
// is armed promptly.
func (c *fakeClock) nextAfterFunc(t *testing.T) armedFunc {
	t.Helper()
	select {
	case af := <-c.afterFuncs:
		return af
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an AfterFunc to be armed")
		return armedFunc{}
	}
}

func (c *fakeClock) NewTimer(d time.Duration) (tstime.TimerController, <-chan time.Time) {
	ch := make(chan time.Time, 1)
	c.ch = ch
	c.armed <- d
	return noopTimer{}, ch
}

// nextArmed returns the delay of the next timer armed, failing if none is armed
// promptly.
func (c *fakeClock) nextArmed(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-c.armed:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a check to be scheduled")
		return 0
	}
}

// fire expires the most recently armed timer.
func (c *fakeClock) fire(t *testing.T) {
	t.Helper()
	select {
	case c.ch <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out firing the timer")
	}
}

type noopTimer struct{}

func (noopTimer) Reset(time.Duration) bool { return true }
func (noopTimer) Stop() bool               { return true }

// testExtension returns an Extension wired up for scheduling tests, with
// detection stubbed out to return verdicts from the given sequence (the last
// one repeating).
func testExtension(t *testing.T, clock *fakeClock, verdicts ...captivedetection.Verdict) (*Extension, chan captivedetection.Verdict) {
	t.Helper()

	ran := make(chan captivedetection.Verdict, 32)
	var n int
	e := &Extension{
		logf:                  t.Logf,
		health:                health.NewTracker(eventbustest.NewBus(t)),
		clock:                 clock,
		needsCaptiveDetection: make(chan bool),
		recheck:               make(chan struct{}, 1),
		detectFn: func(context.Context) captivedetection.Verdict {
			v := verdicts[min(n, len(verdicts)-1)]
			n++
			ran <- v
			return v
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.captiveCtx, e.captiveCancel = ctx, cancel
	t.Cleanup(cancel)
	go e.checkCaptivePortalLoop(ctx)

	return e, ran
}

// TestRetryBackoff checks that a network which stays broken keeps getting
// re-checked, with the delay growing so the retries don't become a drain.
//
// Retrying is the point: a gateway is often not yet intercepting when we first
// look, so a single check a couple of seconds in misses the portal entirely.
func TestRetryBackoff(t *testing.T) {
	clock := newFakeClock()
	e, ran := testExtension(t, clock, captivedetection.VerdictUnknown)

	e.needsCaptiveDetection <- true

	// The delays should follow the schedule and then hold at its last value,
	// rather than either stopping or hammering the network forever.
	want := append(slices.Clone(captivePortalRetrySchedule), captivePortalRetrySchedule[len(captivePortalRetrySchedule)-1])
	for i, wantDelay := range want {
		if got := clock.nextArmed(t); got != wantDelay {
			t.Fatalf("check %d scheduled in %v, want %v", i, got, wantDelay)
		}
		clock.fire(t)
		if got := <-ran; got != captivedetection.VerdictUnknown {
			t.Fatalf("check %d verdict = %v", i, got)
		}
	}
}

// TestNoPortalResetsBackoff checks that once we've established a network is
// fine, the next problem starts from the short delay again rather than from
// wherever the last backoff left off.
func TestNoPortalResetsBackoff(t *testing.T) {
	clock := newFakeClock()
	e, ran := testExtension(t, clock,
		captivedetection.VerdictUnknown,
		captivedetection.VerdictUnknown,
		captivedetection.VerdictNoPortal,
	)

	e.needsCaptiveDetection <- true

	// Two inconclusive checks, so the backoff advances.
	for range 2 {
		clock.nextArmed(t)
		clock.fire(t)
		<-ran
	}
	// The third says the network is fine.
	if got := clock.nextArmed(t); got != captivePortalRetrySchedule[2] {
		t.Fatalf("third check scheduled in %v, want %v", got, captivePortalRetrySchedule[2])
	}
	clock.fire(t)
	if got := <-ran; got != captivedetection.VerdictNoPortal {
		t.Fatalf("third verdict = %v", got)
	}

	// A new problem should be checked at the shortest delay.
	e.needsCaptiveDetection <- true
	if got, want := clock.nextArmed(t), captivePortalRetrySchedule[0]; got != want {
		t.Errorf("check after recovery scheduled in %v, want %v", got, want)
	}
}

// TestLinkChangeTriggersCheck covers the case this whole path exists for: a user
// joining a portalled network. Associating with airport Wi-Fi produces a link
// change well before any health warnable has had time to go unhealthy, so the
// link change alone has to be enough to start looking.
func TestLinkChangeTriggersCheck(t *testing.T) {
	clock := newFakeClock()
	e, ran := testExtension(t, clock, captivedetection.VerdictPortal)

	e.recheck <- struct{}{}

	if got, want := clock.nextArmed(t), captivePortalRetrySchedule[0]; got != want {
		t.Fatalf("check scheduled in %v, want %v", got, want)
	}
	clock.fire(t)
	if got := <-ran; got != captivedetection.VerdictPortal {
		t.Errorf("verdict = %v, want %v", got, captivedetection.VerdictPortal)
	}
}

// TestLinkChangeResetsBackoff checks that moving to a new network starts the
// schedule over. Whatever we'd concluded about the old network says nothing
// about this one, and by then the backoff may be a minute long.
func TestLinkChangeResetsBackoff(t *testing.T) {
	clock := newFakeClock()
	e, ran := testExtension(t, clock, captivedetection.VerdictUnknown)

	e.needsCaptiveDetection <- true
	for range 3 {
		clock.nextArmed(t)
		clock.fire(t)
		<-ran
	}
	// Drain the delay armed after the third check so we only see what the link
	// change schedules.
	clock.nextArmed(t)

	e.recheck <- struct{}{}
	if got, want := clock.nextArmed(t), captivePortalRetrySchedule[0]; got != want {
		t.Errorf("check after link change scheduled in %v, want %v", got, want)
	}
}

// TestHealthySignalStopsChecking checks that we stop probing once connectivity
// is known to be working.
func TestHealthySignalStopsChecking(t *testing.T) {
	clock := newFakeClock()
	e, _ := testExtension(t, clock, captivedetection.VerdictUnknown)

	e.needsCaptiveDetection <- true
	clock.nextArmed(t)

	// Report healthy, then confirm the next problem starts from the shortest
	// delay, which also proves the loop is still alive and the retry counter
	// was reset.
	e.needsCaptiveDetection <- false
	e.needsCaptiveDetection <- true
	if got, want := clock.nextArmed(t), captivePortalRetrySchedule[0]; got != want {
		t.Errorf("check scheduled in %v, want %v", got, want)
	}
}

// TestRecheckSurvivesHealthySignal checks that a scheduled re-check isn't
// cancelled by a healthy signal that arrives right behind it.
//
// This is not hypothetical ordering: a link change publishes health changes of
// its own, and the connectivity warnables it clears take five to ten seconds to
// come back and become visible. So "connectivity is fine" routinely lands
// microseconds after the link change armed our check, and letting it stop the
// timer meant joining a portalled network was never examined at all.
func TestRecheckSurvivesHealthySignal(t *testing.T) {
	clock := newFakeClock()
	e, ran := testExtension(t, clock, captivedetection.VerdictPortal)

	e.recheck <- struct{}{}
	if got, want := clock.nextArmed(t), captivePortalRetrySchedule[0]; got != want {
		t.Fatalf("check scheduled in %v, want %v", got, want)
	}

	e.needsCaptiveDetection <- false

	clock.fire(t)
	select {
	case got := <-ran:
		if got != captivedetection.VerdictPortal {
			t.Errorf("verdict = %v, want %v", got, captivedetection.VerdictPortal)
		}
	case <-time.After(5 * time.Second):
		t.Error("the healthy signal cancelled the re-check")
	}
}

// TestLoopExitClearsWarning checks that stopping the loop drops any portal
// warning. Nothing but a clean detection run clears the warning now, so a
// warning left standing when the loop exits would never come down.
func TestLoopExitClearsWarning(t *testing.T) {
	clock := newFakeClock()
	e, _ := testExtension(t, clock, captivedetection.VerdictPortal)

	e.health.SetUnhealthy(captivePortalWarnable, health.Args{})
	e.captiveCancel()

	deadline := time.Now().Add(5 * time.Second)
	for e.health.IsUnhealthy(captivePortalWarnable) {
		if time.Now().After(deadline) {
			t.Fatal("portal warning still up after the detection loop stopped")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestOnLinkChangeFiltersUninterestingDeltas checks we don't re-probe on every
// network event, only on the ones that could mean we're on a different network.
func TestOnLinkChangeFiltersUninterestingDeltas(t *testing.T) {
	tests := []struct {
		name  string
		delta netmon.ChangeDelta
		want  bool
	}{
		{
			name:  "nothing_relevant_changed",
			delta: netmon.ChangeDelta{},
			want:  false,
		},
		{
			name:  "default_interface_changed",
			delta: netmon.ChangeDelta{DefaultInterfaceChanged: true},
			want:  true,
		},
		{
			name:  "interface_ips_changed",
			delta: netmon.ChangeDelta{InterfaceIPsChanged: true},
			want:  true,
		},
		{
			// Waking from sleep: we may be somewhere else entirely.
			name:  "time_jumped",
			delta: netmon.ChangeDelta{JumpDuration: time.Minute},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e := &Extension{
				logf:       t.Logf,
				captiveCtx: ctx,
				recheck:    make(chan struct{}, 1),
			}

			e.onLinkChange(tt.delta)

			var got bool
			select {
			case <-e.recheck:
				got = true
			default:
			}
			if got != tt.want {
				t.Errorf("scheduled a re-check = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestOnLinkChangeCoalesces checks that the burst of link changes a settling
// interface produces turns into one re-check, not a queue of them.
func TestOnLinkChangeCoalesces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Extension{
		logf:       t.Logf,
		captiveCtx: ctx,
		recheck:    make(chan struct{}, 1),
	}

	for range 10 {
		e.onLinkChange(netmon.ChangeDelta{DefaultInterfaceChanged: true})
	}

	n := 0
	for {
		select {
		case <-e.recheck:
			n++
			continue
		default:
		}
		break
	}
	if n != 1 {
		t.Errorf("queued %d re-checks, want 1", n)
	}
}

// TestOnLinkChangeWhileStopped checks that link changes are ignored when the
// detection loop isn't running, so they can't wedge the eventbus subscriber.
func TestOnLinkChangeWhileStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := &Extension{
		logf:       t.Logf,
		captiveCtx: ctx,
		recheck:    make(chan struct{}, 1),
	}

	e.onLinkChange(netmon.ChangeDelta{DefaultInterfaceChanged: true})

	select {
	case <-e.recheck:
		t.Error("scheduled a re-check while the detection loop was stopped")
	default:
	}
}

// TestApplyResult covers how each verdict maps onto the health warning.
//
// The inconclusive cases are the important ones. Reporting "no captive portal"
// when we simply couldn't tell would clear a warning we had good reason to
// raise, and would leave a user on airline Wi-Fi with no hint of why nothing
// works.
func TestApplyResult(t *testing.T) {
	tests := []struct {
		name string
		// startUnhealthy sets the warning before applying the result, to test
		// what a later result does to an existing warning.
		startUnhealthy bool
		res            captivedetection.Result
		wantUnhealthy  bool
		wantTextHas    string
	}{
		{
			name:          "portal_raises_warning",
			res:           captivedetection.Result{Verdict: captivedetection.VerdictPortal},
			wantUnhealthy: true,
			wantTextHas:   "log in using your web browser",
		},
		{
			// Knowing where the portal is turns the warning into something the
			// user can act on directly.
			name: "portal_with_url_says_where_to_go",
			res: captivedetection.Result{
				Verdict:   captivedetection.VerdictPortal,
				PortalURL: "https://wifi.example/login",
			},
			wantUnhealthy: true,
			wantTextHas:   "https://wifi.example/login",
		},
		{
			name:           "no_portal_clears_warning",
			startUnhealthy: true,
			res:            captivedetection.Result{Verdict: captivedetection.VerdictNoPortal},
			wantUnhealthy:  false,
		},
		{
			// We couldn't tell. Leave the warning up: it was raised on
			// evidence, and this result is not evidence against it.
			name:           "unknown_leaves_warning_up",
			startUnhealthy: true,
			res:            captivedetection.Result{Verdict: captivedetection.VerdictUnknown},
			wantUnhealthy:  true,
		},
		{
			// And equally, an inconclusive result must not invent a warning.
			name:          "unknown_does_not_raise_warning",
			res:           captivedetection.Result{Verdict: captivedetection.VerdictUnknown},
			wantUnhealthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ht := health.NewTracker(eventbustest.NewBus(t))
			e := &Extension{logf: t.Logf, health: ht}

			if tt.startUnhealthy {
				ht.SetUnhealthy(captivePortalWarnable, health.Args{})
			}

			e.applyResult(tt.res)

			if got := ht.IsUnhealthy(captivePortalWarnable); got != tt.wantUnhealthy {
				t.Fatalf("IsUnhealthy = %v, want %v", got, tt.wantUnhealthy)
			}
			if tt.wantTextHas != "" {
				var found bool
				for _, w := range ht.CurrentState().Warnings {
					if w.WarnableCode == captivePortalWarnable.Code {
						found = true
						if !strings.Contains(w.Text, tt.wantTextHas) {
							t.Errorf("warning text = %q, want it to contain %q", w.Text, tt.wantTextHas)
						}
					}
				}
				if !found {
					t.Error("captive portal warning not present in health state")
				}
			}
		})
	}
}

// onHealthChangeTestExtension returns an Extension with a real health tracker
// and a buffered signal channel, for driving onHealthChange directly without a
// detection loop to receive from it.
func onHealthChangeTestExtension(t *testing.T) *Extension {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &Extension{
		logf:                  t.Logf,
		health:                health.NewTracker(eventbustest.NewBus(t)),
		captiveCtx:            ctx,
		needsCaptiveDetection: make(chan bool, 1),
		recheck:               make(chan struct{}, 1),
	}
}

// signal reports what onHealthChange told the detection loop to do, if
// anything.
func signal(e *Extension) (v bool, sent bool) {
	select {
	case v := <-e.needsCaptiveDetection:
		return v, true
	default:
		return false, false
	}
}

func recheckScheduled(e *Extension) bool {
	select {
	case <-e.recheck:
		return true
	default:
		return false
	}
}

// TestPortalWarningSurvivesCleanHealthState is the regression test for the
// warning tearing itself down the instant it was raised.
//
// Raising the warning publishes a health change, and we subscribe to health
// changes, so our own detection result comes straight back to us here. Treating
// "no other warnable says connectivity is impacted" as proof there is no portal
// meant we then cleared the warning we had just set, microseconds later. It is
// not proof: connectivity warnables take five to ten seconds to become visible,
// and a check scheduled by a link change runs two seconds in, so the network we
// most need to detect is exactly the one whose health state still looks clean.
func TestPortalWarningSurvivesCleanHealthState(t *testing.T) {
	e := onHealthChangeTestExtension(t)

	e.applyResult(captivedetection.Result{Verdict: captivedetection.VerdictPortal})
	if !e.health.IsUnhealthy(captivePortalWarnable) {
		t.Fatal("a portal verdict did not raise the warning")
	}

	// The health change our own SetUnhealthy published, arriving while nothing
	// else has reported connectivity as impacted.
	e.onHealthChange(health.Change{})

	if !e.health.IsUnhealthy(captivePortalWarnable) {
		t.Error("portal warning was cleared by the health change that raising it published")
	}
	if v, sent := signal(e); sent && !v {
		t.Error("told the detection loop to stop while a portal warning was up")
	}
}

// TestConnectivityRestoredReconfirms checks that connectivity coming back under
// a standing portal warning schedules a prompt re-check. That transition is
// what logging in to a portal looks like, and the check is what clears the
// warning; without it the warning would linger for however long the backoff had
// grown to.
func TestConnectivityRestoredReconfirms(t *testing.T) {
	e := onHealthChangeTestExtension(t)
	e.health.SetUnhealthy(captivePortalWarnable, health.Args{})

	// Connectivity was impacted, and now nothing reports that it is.
	e.wasImpacted = true
	e.onHealthChange(health.Change{})

	if !e.health.IsUnhealthy(captivePortalWarnable) {
		t.Error("portal warning cleared without a clean detection run to justify it")
	}
	if !recheckScheduled(e) {
		t.Error("no re-check scheduled after connectivity came back under a portal warning")
	}
}

// TestSteadyHealthDoesNotResetBackoff checks that the ordinary stream of health
// events, arriving while connectivity already looked fine, leaves the schedule
// alone. Restarting it each time would have us re-checking every couple of
// seconds for as long as the portal stands.
func TestSteadyHealthDoesNotResetBackoff(t *testing.T) {
	e := onHealthChangeTestExtension(t)
	e.health.SetUnhealthy(captivePortalWarnable, health.Args{})

	e.onHealthChange(health.Change{})
	if recheckScheduled(e) {
		t.Error("restarted the retry schedule on a health event that changed nothing")
	}
	if v, sent := signal(e); !sent || !v {
		t.Errorf("signalled the loop with (%v, sent=%v), want (true, sent=true)", v, sent)
	}
}

// testConnectivityWarnable stands in for a real connectivity warnable, minus
// the TimeToVisible the real ones carry, so a test can make connectivity look
// impacted right away.
var testConnectivityWarnable = health.Register(&health.Warnable{
	Code:                "test-connectivity-impacted",
	Title:               "Test connectivity warnable",
	Severity:            health.SeverityMedium,
	Text:                health.StaticMessage("test"),
	ImpactsConnectivity: true,
})

// TestImpactedConnectivityTriggersCheck checks the entry point into detection:
// a warnable that impacts connectivity, other than our own, asks the loop to
// look for a portal.
func TestImpactedConnectivityTriggersCheck(t *testing.T) {
	e := onHealthChangeTestExtension(t)
	e.health.SetUnhealthy(testConnectivityWarnable, health.Args{})

	e.onHealthChange(health.Change{})

	if v, sent := signal(e); !sent || !v {
		t.Errorf("signalled the loop with (%v, sent=%v), want (true, sent=true)", v, sent)
	}
	if !e.wasImpacted {
		t.Error("did not record connectivity as impacted")
	}

	// And our own warning must not be what keeps that going, or a portal
	// verdict would hold the loop open by itself.
	e.health.SetHealthy(testConnectivityWarnable)
	e.health.SetUnhealthy(captivePortalWarnable, health.Args{})
	e.onHealthChange(health.Change{})
	if e.wasImpacted {
		t.Error("counted our own portal warning as impacted connectivity")
	}
}

// TestNoWarningStopsChecking checks we still stop probing when connectivity is
// fine and there's no portal warning to confirm — the case the healthy branch
// exists for.
func TestNoWarningStopsChecking(t *testing.T) {
	e := onHealthChangeTestExtension(t)

	e.onHealthChange(health.Change{})

	if v, sent := signal(e); !sent || v {
		t.Errorf("signalled the loop with (%v, sent=%v), want (false, sent=true)", v, sent)
	}
}

// bypassTestExtension returns an Extension with a real health tracker and a
// controllable clock, for exercising the local network exception without a
// LocalBackend to reconfigure.
func bypassTestExtension(t *testing.T, clock *fakeClock, exitNodeBlocksLAN bool) (*Extension, *health.Tracker, *int) {
	t.Helper()
	var reconfigs int
	e := &Extension{
		logf:                t.Logf,
		health:              health.NewTracker(eventbustest.NewBus(t)),
		clock:               clock,
		exitNodeBlocksLANFn: func() bool { return exitNodeBlocksLAN },
		reconfigFn:          func() { reconfigs++ },
	}
	return e, e.health, &reconfigs
}

// TestPortalWarningPicksTheActionableCase checks that we raise the warning the
// user can actually do something about.
//
// The three cases lead to three different things to tell someone: open a URL,
// let us open the local network so you can open that URL, or turn off your exit
// node because we cannot reach it at all. Telling a user to open a page that
// their exit node is blackholing is the failure this exists to prevent.
func TestPortalWarningPicksTheActionableCase(t *testing.T) {
	const url = "http://portal.example/login"

	tests := []struct {
		name              string
		exitNodeBlocksLAN bool
		portalURL         string
		portalURLIsLocal  opt.Bool
		wantWarnable      *health.Warnable
		wantArgSet        bool
	}{
		{
			name:         "no_exit_node_just_open_the_url",
			portalURL:    url,
			wantWarnable: captivePortalWarnable,
		},
		{
			// The exit node is holding the route to a page on the LAN, which we
			// can offer to give back.
			name:              "exit_node_with_local_portal_offers_lan",
			exitNodeBlocksLAN: true,
			portalURL:         url,
			portalURLIsLocal:  opt.NewBool(true),
			wantWarnable:      captivePortalWarnable,
			wantArgSet:        true,
		},
		{
			// Off the LAN, so opening the LAN would be a leak that bought the
			// user nothing. Only turning the exit node off will work.
			name:              "exit_node_with_remote_portal_says_turn_it_off",
			exitNodeBlocksLAN: true,
			portalURL:         url,
			portalURLIsLocal:  opt.NewBool(false),
			wantWarnable:      captivePortalBlockedWarnable,
		},
		{
			// We couldn't locate the page. Offering the LAN is the recoverable
			// guess: if it doesn't help, turning off the exit node still will,
			// whereas telling them to disconnect when the page was on the LAN
			// all along costs them their exit node for nothing.
			name:              "unknown_location_is_treated_as_local",
			exitNodeBlocksLAN: true,
			portalURL:         url,
			wantWarnable:      captivePortalWarnable,
			wantArgSet:        true,
		},
		{
			name:              "unknown_location_and_no_url",
			exitNodeBlocksLAN: true,
			wantWarnable:      captivePortalWarnable,
			wantArgSet:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, ht, _ := bypassTestExtension(t, newFakeClock(), tt.exitNodeBlocksLAN)

			e.applyResult(captivedetection.Result{
				Verdict:          captivedetection.VerdictPortal,
				PortalURL:        tt.portalURL,
				PortalURLIsLocal: tt.portalURLIsLocal,
			})

			if !ht.IsUnhealthy(tt.wantWarnable) {
				t.Fatalf("%s is not unhealthy, want it to be", tt.wantWarnable.Code)
			}
			// Exactly one portal warning at a time, or a GUI shows two
			// warnings about the same portal giving contradictory advice.
			for _, w := range portalWarnables {
				if w != tt.wantWarnable && ht.IsUnhealthy(w) {
					t.Errorf("%s is also unhealthy, want only %s", w.Code, tt.wantWarnable.Code)
				}
			}

			ws, ok := ht.CurrentState().Warnings[tt.wantWarnable.Code]
			if !ok {
				t.Fatalf("%s missing from health state", tt.wantWarnable.Code)
			}
			if got := ws.Args[health.ArgExitNodeBlocksPortal] != ""; got != tt.wantArgSet {
				t.Errorf("%s set = %v, want %v", health.ArgExitNodeBlocksPortal, got, tt.wantArgSet)
			}
		})
	}
}

// TestLANBypassSuppressesTheArg checks that once we've opened the local
// network, we stop telling the user it needs opening.
func TestLANBypassSuppressesTheArg(t *testing.T) {
	clock := newFakeClock()
	e, ht, _ := bypassTestExtension(t, clock, true)

	res := captivedetection.Result{
		Verdict:          captivedetection.VerdictPortal,
		PortalURL:        "http://portal.example/login",
		PortalURLIsLocal: opt.NewBool(true),
	}
	e.applyResult(res)
	if ht.CurrentState().Warnings[captivePortalWarnable.Code].Args[health.ArgExitNodeBlocksPortal] == "" {
		t.Fatal("want the exit-node arg set before the bypass is granted")
	}

	e.grantLANBypass(maxLANBypass)
	clock.nextAfterFunc(t) // consume the expiry timer

	// The page is reachable now, so the warning should just name it.
	ws := ht.CurrentState().Warnings[captivePortalWarnable.Code]
	if ws.Args[health.ArgExitNodeBlocksPortal] != "" {
		t.Errorf("want the exit-node arg cleared while the bypass is active, got args %v", ws.Args)
	}
	if !strings.Contains(ws.Text, "Open http://portal.example/login") {
		t.Errorf("text = %q, want it to name the URL plainly", ws.Text)
	}

	// And when it lapses, we go back to saying so.
	e.revokeLANBypass()
	if ht.CurrentState().Warnings[captivePortalWarnable.Code].Args[health.ArgExitNodeBlocksPortal] == "" {
		t.Error("want the exit-node arg set again after the bypass is revoked")
	}
}

// TestLANBypassExpires checks that the exception is bounded in time. It undoes
// a leak protection the user asked for, so it must not outlive its purpose.
func TestLANBypassExpires(t *testing.T) {
	clock := newFakeClock()
	e, _, reconfigs := bypassTestExtension(t, clock, true)

	until := e.grantLANBypass(maxLANBypass)
	if want := clock.Now().Add(maxLANBypass); !until.Equal(want) {
		t.Errorf("until = %v, want %v", until, want)
	}
	if !e.lanBypassActive() {
		t.Fatal("bypass is not active right after being granted")
	}
	if *reconfigs != 1 {
		t.Errorf("reconfigs = %d, want 1 after granting", *reconfigs)
	}

	af := clock.nextAfterFunc(t)
	if af.d != maxLANBypass {
		t.Errorf("timer armed for %v, want %v", af.d, maxLANBypass)
	}
	af.fn()

	if e.lanBypassActive() {
		t.Error("bypass is still active after its timer fired")
	}
	if *reconfigs != 2 {
		t.Errorf("reconfigs = %d, want 2 after expiry", *reconfigs)
	}
}

// TestLANBypassRespectsDeadlineWithoutTimer checks the deadline is honored on
// its own. A timer that never runs must not be able to strand the exception
// open indefinitely.
func TestLANBypassRespectsDeadlineWithoutTimer(t *testing.T) {
	clock := newFakeClock()
	e, _, _ := bypassTestExtension(t, clock, true)

	e.grantLANBypass(maxLANBypass)
	clock.nextAfterFunc(t) // arm but never fire it

	if !e.lanBypassActive() {
		t.Fatal("bypass is not active right after being granted")
	}
	clock.advance(maxLANBypass + time.Second)
	if e.lanBypassActive() {
		t.Error("bypass still reports active past its deadline")
	}
}

// TestLANBypassDurations checks a caller cannot ask for longer than we're
// willing to give, and that asking for nothing in particular gets the maximum
// rather than a grant that expires immediately.
func TestLANBypassDurations(t *testing.T) {
	tests := []struct {
		name string
		ask  time.Duration
		want time.Duration
	}{
		{"over_the_max_is_clamped", 24 * time.Hour, maxLANBypass},
		{"zero_means_the_max", 0, maxLANBypass},
		{"negative_means_the_max", -time.Minute, maxLANBypass},
		{"under_the_max_is_honored", 30 * time.Second, 30 * time.Second},
		{"exactly_the_max", maxLANBypass, maxLANBypass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newFakeClock()
			e, _, _ := bypassTestExtension(t, clock, true)

			until := e.grantLANBypass(tt.ask)
			if af := clock.nextAfterFunc(t); af.d != tt.want {
				t.Errorf("timer armed for %v, want %v", af.d, tt.want)
			}
			if got := until.Sub(clock.Now()); got != tt.want {
				t.Errorf("expiry is %v out, want %v", got, tt.want)
			}
			if !e.lanBypassActive() {
				t.Error("bypass is not active after being granted")
			}
		})
	}
}

// TestNoPortalRevokesLANBypass checks that logging in to the portal is what
// ends the exception, which is the "until the portal is actioned" half of its
// lifetime.
func TestNoPortalRevokesLANBypass(t *testing.T) {
	clock := newFakeClock()
	e, ht, _ := bypassTestExtension(t, clock, true)

	e.applyResult(captivedetection.Result{Verdict: captivedetection.VerdictPortal})
	e.grantLANBypass(maxLANBypass)
	clock.nextAfterFunc(t)
	if !e.lanBypassActive() {
		t.Fatal("bypass is not active")
	}

	// A clean run is the evidence that the user got themselves logged in.
	e.applyResult(captivedetection.Result{Verdict: captivedetection.VerdictNoPortal})

	if e.lanBypassActive() {
		t.Error("bypass survived a clean detection run")
	}
	for _, w := range portalWarnables {
		if ht.IsUnhealthy(w) {
			t.Errorf("%s is still unhealthy after a clean run", w.Code)
		}
	}
}

// TestUnknownVerdictKeepsLANBypass checks an inconclusive run does not take the
// exception away.
//
// This is the common case immediately after logging in: authorization takes a
// few seconds to propagate, so the next pass often can't tell either way.
// Revoking there would slam the door while the user is still mid-login.
func TestUnknownVerdictKeepsLANBypass(t *testing.T) {
	clock := newFakeClock()
	e, _, _ := bypassTestExtension(t, clock, true)

	e.applyResult(captivedetection.Result{Verdict: captivedetection.VerdictPortal})
	e.grantLANBypass(maxLANBypass)
	clock.nextAfterFunc(t)

	e.applyResult(captivedetection.Result{Verdict: captivedetection.VerdictUnknown})
	if !e.lanBypassActive() {
		t.Error("an inconclusive run revoked the bypass")
	}
}

// TestBlockedWarnableDoesNotLookLikeOtherBreakage checks that raising the
// off-LAN portal warning doesn't make us mistake our own output for a
// third-party connectivity failure.
//
// Both portal warnables set ImpactsConnectivity, and we subscribe to health
// changes, so our own SetUnhealthy comes straight back to onHealthChange. If it
// counted our warnable, we'd conclude something else had broken the network and
// keep re-checking a portal we had already confirmed. That regression is what
// the previous fix in this area was about; a second warnable reopens it unless
// both codes are excluded.
func TestBlockedWarnableDoesNotLookLikeOtherBreakage(t *testing.T) {
	e := onHealthChangeTestExtension(t)
	e.exitNodeBlocksLANFn = func() bool { return true }
	e.clock = newFakeClock()

	e.applyResult(captivedetection.Result{
		Verdict:          captivedetection.VerdictPortal,
		PortalURL:        "http://login.airline.example/",
		PortalURLIsLocal: opt.NewBool(false),
	})
	if !e.health.IsUnhealthy(captivePortalBlockedWarnable) {
		t.Fatal("want the off-LAN portal warning raised")
	}

	e.onHealthChange(health.Change{})

	e.mu.Lock()
	wasImpacted := e.wasImpacted
	e.mu.Unlock()
	if wasImpacted {
		t.Error("onHealthChange counted our own portal warning as impacted connectivity")
	}
}

// TestPortalWarningUpSeesBothWarnables checks that the loop's notion of "a
// portal warning is standing" covers the off-LAN case too, so an off-LAN portal
// gets the same protection from being cleared by a clean-looking health state.
func TestPortalWarningUpSeesBothWarnables(t *testing.T) {
	for _, w := range portalWarnables {
		t.Run(string(w.Code), func(t *testing.T) {
			e, ht, _ := bypassTestExtension(t, newFakeClock(), false)
			if e.portalWarningUp() {
				t.Fatal("portalWarningUp is true with no warning set")
			}
			ht.SetUnhealthy(w, health.Args{})
			if !e.portalWarningUp() {
				t.Errorf("portalWarningUp is false with %s unhealthy", w.Code)
			}
		})
	}
}
