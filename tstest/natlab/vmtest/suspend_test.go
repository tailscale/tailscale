// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
)

// TestSuspendResume is a smoke test for [vmtest.Env.Suspend] and
// [vmtest.Env.Resume] (QMP stop/cont on a QEMU-backed node).
//
// Topology: two gokrazy nodes a and b on easy NATs. The test establishes a
// WireGuard tunnel between them, suspends b, and asserts three things:
//
//  1. While b is suspended, packets to it black-hole: a single TSMP ping
//     from a gets no answer within its 5s budget (QEMU drops packets sent
//     to a stopped VM).
//  2. b's guest clock pauses while suspended: the guest's wall clock
//     (sampled via the Date header on HTTP responses from its in-guest test
//     agent, 1s granularity) advances by roughly suspendDur less than the
//     host's clock across the suspend window. This is the "frozen timers"
//     property that makes Suspend useful for reproducing suspend-induced
//     path-death bugs like tailscale/tailscale#20082.
//  3. Connectivity recovers after Resume, within a bounded budget.
//
// Budgets:
//
//   - Initial a→b TSMP ping: 30s, same generous bring-up budget as
//     TestDiscoKeyChange (first-time tunnel setup, not what's under test).
//   - Suspend window: 15s total. Long enough that the 1s-granularity guest
//     clock check has plenty of margin (we require ≥10s of observed guest
//     clock lag) and that the in-window ping demonstrably black-holes, while
//     staying cheap for CI. Deliberately shorter than any tailscaled/relay
//     session timeout: this test only smoke-tests the suspend mechanism, not
//     session-expiry recovery.
//   - Post-resume recovery ping: 30s. In practice recovery is near-immediate
//     (the 15s pause is far shorter than the WireGuard session lifetime and
//     both peers' endpoints are unchanged, so the first retried packet gets
//     through; observed locally at <1s). The budget mostly absorbs the
//     suspended node's own wake-up transient (virtio queue refill, agent
//     connection retries) on slow CI hosts.
func TestSuspendResume(t *testing.T) {
	env := vmtest.New(t)
	a := easy(env)
	b := easy(env)

	tunnelStep := env.AddStep("Ping " + a.Name() + " → " + b.Name() + " TSMP (establish tunnel)")
	suspendStep := env.AddStep("Suspend " + b.Name())
	blackholeStep := env.AddStep("Verify traffic to suspended " + b.Name() + " black-holes")
	resumeStep := env.AddStep("Resume " + b.Name())
	clockStep := env.AddStep("Verify " + b.Name() + "'s guest clock paused while suspended")
	recoverStep := env.AddStep("Ping " + a.Name() + " → " + b.Name() + " TSMP (recovery after resume)")

	env.Start()

	tunnelStep.Begin()
	if err := env.Ping(a, b, tailcfg.PingTSMP, 30*time.Second); err != nil {
		tunnelStep.Fatal(err)
	}
	tunnelStep.End(nil)

	// Capture b's Tailscale IP now; while b is suspended we can't ask it.
	bIP := env.Status(b).Self.TailscaleIPs[0]

	hostBefore := time.Now()
	guestBefore := guestWallClock(t, b)

	const suspendDur = 15 * time.Second
	suspendStep.Begin()
	env.Suspend(b)
	suspendedAt := time.Now()
	suspendStep.End(nil)

	// While b is stopped, a's TSMP pings to it must go unanswered. A single
	// non-retried ping with a 5s budget: far longer than the <100ms a direct
	// LAN-speed TSMP round trip takes once a tunnel is up, so a success here
	// would mean the VM wasn't really paused. The failure must also be a
	// genuine timeout — the request running essentially the full budget while
	// a's tailscaled waits for a reply that never comes — and not some instant
	// error from a broken ping path (a's agent unreachable, bad IP, etc.),
	// which would pass a mere "any error" check without proving packet drop.
	blackholeStep.Begin()
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	pingStart := time.Now()
	pr, err := a.Agent().PingWithOpts(pingCtx, bIP, tailcfg.PingTSMP, local.PingOpts{})
	pingElapsed := time.Since(pingStart)
	cancel()
	if err == nil && pr.Err == "" {
		blackholeStep.Fatalf("TSMP ping from %s to suspended %s unexpectedly succeeded", a.Name(), b.Name())
	}
	prErr := ""
	if err == nil {
		prErr = pr.Err
	}
	if pingElapsed < 4*time.Second {
		blackholeStep.Fatalf("TSMP ping from %s to suspended %s failed after only %v (err=%v, pr.Err=%q), want a ≥4s timeout of the 5s budget; ping path looks broken rather than black-holed",
			a.Name(), b.Name(), pingElapsed.Round(time.Millisecond), err, prErr)
	}
	t.Logf("ping to suspended %s timed out as expected after %v (err=%v, pr.Err=%q)",
		b.Name(), pingElapsed.Round(time.Millisecond), err, prErr)
	blackholeStep.End(nil)

	// Keep b suspended for suspendDur total.
	if d := time.Until(suspendedAt.Add(suspendDur)); d > 0 {
		time.Sleep(d)
	}

	resumeStep.Begin()
	env.Resume(b)
	resumeStep.End(nil)

	// The guest's clocks pause across QMP stop/cont (see [vmtest.Env.Suspend]),
	// so b's wall clock should now lag the host's by ≈suspendDur — bounded on
	// both sides. Too little lag means the guest clock never paused (or QEMU
	// advanced it on cont); too much means it stopped permanently or stepped
	// backward. Both clocks run at the same rate outside the suspend window,
	// so extra latency in sampling guestAfter doesn't change the measured lag.
	//
	// clockSlack absorbs the measurement noise: the Date header has 1s
	// granularity, and two samples bracket the window, so up to ~2s of
	// quantization error; plus sub-second QMP command latency and goroutine
	// scheduling skew around the stop/cont edges. 5s is comfortably above all
	// of that while still far below suspendDur (15s), so the window cleanly
	// separates "paused for the suspend window" from both "never paused"
	// (lag ≈ 0) and "still frozen/stepped backward" (lag ≫ suspendDur).
	const clockSlack = 5 * time.Second
	clockStep.Begin()
	guestAfter := guestWallClock(t, b)
	hostElapsed := time.Since(hostBefore)
	guestElapsed := guestAfter.Sub(guestBefore)
	lag := hostElapsed - guestElapsed
	t.Logf("clock check: host elapsed %v, guest elapsed %v, guest clock lag %v (suspended for %v)",
		hostElapsed.Round(time.Millisecond), guestElapsed, lag.Round(time.Millisecond), suspendDur)
	if lag < suspendDur-clockSlack {
		clockStep.Fatalf("guest clock lag = %v, want ≥ %v; guest clock doesn't appear to have paused during suspend",
			lag.Round(time.Millisecond), suspendDur-clockSlack)
	}
	if lag > suspendDur+clockSlack {
		clockStep.Fatalf("guest clock lag = %v, want ≤ %v; guest clock appears to have stopped permanently or stepped backward",
			lag.Round(time.Millisecond), suspendDur+clockSlack)
	}
	clockStep.End(nil)

	recoverStep.Begin()
	if err := env.Ping(a, b, tailcfg.PingTSMP, 30*time.Second); err != nil {
		recoverStep.Fatal(err)
	}
	recoverStep.End(nil)
}

// guestWallClock returns n's current wall-clock time as reported by the Date
// header (1s granularity) on an HTTP response from its in-guest test agent.
// It retries for up to 30s — right after a resume, the agent's connection to
// the test harness may need a moment to recover — and fatals on failure.
func guestWallClock(t *testing.T, n *vmtest.Node) time.Time {
	t.Helper()
	var got time.Time
	if err := tstest.WaitFor(30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/ip", nil)
		if err != nil {
			return err
		}
		res, err := n.Agent().HTTPClient.Do(req)
		if err != nil {
			return err
		}
		res.Body.Close()
		got, err = http.ParseTime(res.Header.Get("Date"))
		return err
	}); err != nil {
		t.Fatalf("guestWallClock(%s): %v", n.Name(), err)
	}
	return got
}
