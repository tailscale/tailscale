// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package exitnodehealth

import (
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/wgint"
)

func TestExitNodeResponsiveness(t *testing.T) {
	for _, mode := range []string{"silent", "disco", "bidirectional", "counter-reset", "zero-reset", "tx-only", "rx-only", "historical"} {
		t.Run(mode, func(t *testing.T) {
			b := newExitNodeHealthTestBackend(t, nil)
			b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})
			e := extOf(t, b)
			start := mono.Now()
			e.responsiveness.started = start
			k := e.responsiveness.key
			tx, rx := uint64(1000), uint64(1000)
			e.responsiveness.window = 45 * time.Second
			e.responsiveness.txBytes, e.responsiveness.rxBytes = tx, rx
			for d := time.Duration(0); d <= 2*exitNodeResponseTimeout; d += 3 * time.Second {
				now := start.Add(d)
				e.recordActivity(k, now, false, false, 45*time.Second)
				switch mode {
				case "disco":
					e.recordActivity(k, now, false, true, 45*time.Second)
				case "bidirectional":
					tx += 100
					rx += 100
				case "counter-reset":
					tx--
					rx--
				case "zero-reset":
					tx, rx = 0, 0
				case "tx-only":
					tx += 100
				case "rx-only":
					rx += 100
				}
				e.mu.Lock()
				e.observeTraffic(tx, rx, now)
				e.evaluateResponsiveness(now)
				e.mu.Unlock()
				want := mode != "disco" && mode != "bidirectional" && mode != "counter-reset" && d >= exitNodeResponseTimeout
				if got := b.HealthTracker().IsUnhealthy(exitNodeUnresponsiveWarnable); got != want {
					t.Fatalf("at %v unhealthy=%v want=%v", d, got, want)
				}
			}
			now := start.Add(2*exitNodeResponseTimeout + 3*time.Second)
			e.recordActivity(k, now, true, false, 45*time.Second)
			if b.HealthTracker().IsUnhealthy(exitNodeUnresponsiveWarnable) {
				t.Fatal("idle retained warning")
			}
			now = now.Add(time.Hour)
			e.recordActivity(k, now, false, false, 45*time.Second)
			e.mu.Lock()
			e.evaluateResponsiveness(now)
			e.mu.Unlock()
			if b.HealthTracker().IsUnhealthy(exitNodeUnresponsiveWarnable) {
				t.Fatal("resume lacked grace")
			}
		})
	}
}

func TestExitNodeResponsivenessActivation(t *testing.T) {
	for _, observedIdle := range []bool{false, true} {
		for _, responded := range []bool{false, true} {
			name := "initial"
			if observedIdle {
				name = "resume"
			}
			if responded {
				name += "-with-old-response"
			}
			t.Run(name, func(t *testing.T) {
				b := newExitNodeHealthTestBackend(t, nil)
				b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})
				e := extOf(t, b)
				start := e.responsiveness.started
				k := e.responsiveness.key
				const window = 45 * time.Second
				if observedIdle {
					e.recordActivity(k, start.Add(3*time.Second), true, false, window)
				}
				if responded {
					e.recordActivity(k, start.Add(6*time.Second), false, true, window)
				}
				// Selection may precede the first active heartbeat by a long time,
				// without an intervening idle report. Neither that time nor an old
				// response should shorten the grace period when activity begins.
				active := start.Add(time.Hour)
				for d := time.Duration(0); d <= exitNodeResponseTimeout; d += 3 * time.Second {
					now := active.Add(d)
					e.recordActivity(k, now, false, false, window)
					e.mu.Lock()
					started := e.responsiveness.started
					e.evaluateResponsiveness(now)
					e.mu.Unlock()
					if started != active {
						t.Fatalf("at %v started=%v want=%v", d, started, active)
					}
					want := d >= exitNodeResponseTimeout
					if got := b.HealthTracker().IsUnhealthy(exitNodeUnresponsiveWarnable); got != want {
						t.Fatalf("at %v unhealthy=%v want=%v", d, got, want)
					}
				}
			})
		}
	}
}

func TestSplitReportFiltersTransition(t *testing.T) {
	b := newExitNodeHealthTestBackend(t, nil)
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})
	e := extOf(t, b)
	c := new(magicsock.Conn)
	activityObservers.Store(c, e)
	t.Cleanup(func() { activityObservers.Delete(c) })
	start := mono.Now()
	e.responsiveness.started = start
	k := e.responsiveness.key
	for d := time.Duration(0); d <= exitNodeResponseTimeout; d += 3 * time.Second {
		reportExitNodeHeartbeatStateLocked(c, k, start.Add(d), false, false, 45*time.Second)
	}
	if b.HealthTracker().IsUnhealthy(exitNodeUnresponsiveWarnable) {
		t.Fatal("inside-lock report published before traffic filter")
	}
	lookups := 0
	checkExitNodeResponsiveness(c, k, func(key.NodePublic) (wgint.Peer, bool) {
		// Counter lookup must happen without holding the extension mutex.
		e.mu.Lock()
		e.mu.Unlock()
		lookups++
		return wgint.Peer{}, false
	})
	if lookups != 1 || !b.HealthTracker().IsUnhealthy(exitNodeUnresponsiveWarnable) {
		t.Fatal("outside-lock filter failed to publish unresponsive transition")
	}
	reportExitNodeHeartbeatStateLocked(c, k, start.Add(time.Minute+3*time.Second), true, false, 45*time.Second)
	checkExitNodeResponsiveness(c, k, func(key.NodePublic) (wgint.Peer, bool) {
		t.Fatal("idle looked up counters")
		return wgint.Peer{}, false
	})
	if b.HealthTracker().IsUnhealthy(exitNodeUnresponsiveWarnable) {
		t.Fatal("idle retained warning")
	}
}

func TestExitNodeResponsivenessLifecycle(t *testing.T) {
	b := newExitNodeHealthTestBackend(t, nil)
	b.ForTest().SetPrefs(&ipn.Prefs{WantRunning: true, ExitNodeID: "exit1"})
	e := extOf(t, b)
	start := mono.Now()
	e.responsiveness.started = start
	k := e.responsiveness.key
	for d := time.Duration(0); d <= exitNodeResponseTimeout; d += 3 * time.Second {
		now := start.Add(d)
		e.recordActivity(k, now, false, false, 45*time.Second)
		e.mu.Lock()
		e.evaluateResponsiveness(now)
		e.mu.Unlock()
	}
	w := b.HealthTracker().CurrentState().Warnings[exitNodeUnresponsiveWarnable.Code]
	want := "The selected exit node \"my-gateway\" has not responded since " + start.WallTime().UTC().Format(time.RFC3339) + ". Internet connectivity may be affected."
	if w.Text != want {
		t.Fatalf("warning=%q want=%q", w.Text, want)
	}
	b.ForTest().SetState(ipn.NeedsMachineAuth)
	e.recordActivity(k, start.Add(time.Minute), false, false, 45*time.Second)
	if b.HealthTracker().IsUnhealthy(exitNodeUnresponsiveWarnable) {
		t.Fatal("state change retained warning")
	}
	b.ForTest().SetState(ipn.Running)
	b.ForTest().ApplyNetMap(nil)
	if !e.responsiveness.key.IsZero() {
		t.Fatal("netmap clear retained selection")
	}
}
