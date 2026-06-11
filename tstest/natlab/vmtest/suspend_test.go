// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/net/udprelay/status"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
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

// TestPeerRelaySuspendResume is a full-stack VM reproduction of the literal
// repro steps from tailscale/tailscale#20082: two nodes whose only viable
// UDP path is a peer relay exchange traffic over it, one of them then
// suspends for longer than the relay session's steady-state lifetime, the
// relay server reaps the idle session, and the suspended node wakes.
//
// Topology mirrors TestPeerRelay / TestHardHardViaPeerRelay: a and b behind
// HardNAT with no portmapping services (direct impossible), the relay behind
// One2OneNAT (its STUN-discovered WAN endpoint is reachable from both), and
// the env created with [vmtest.PeerRelayGrants]. The relay node's relay
// server additionally gets shrunken endpoint lifetimes via the
// debug-peer-relay-server-lifetimes LocalAPI debug action
// ([local.Client.DebugSetPeerRelayServerLifetimes]), compressing the issue's
// 5m+ steady-state reap into seconds: with bind=5s (also the GC tick
// interval) and steadyState=15s, a client that idles is reaped within
// steadyState+tick = 20s. The lifetimes are set immediately after the relay
// server is enabled and before the a↔b relay path is established, since
// server endpoints are advertised to clients with the lifetime values in
// effect at allocation time.
//
// The #20082 mechanism this drives: magicsock's receiveIP hands wireguard-go
// a *lazyEndpoint (frozen on the receive-time epAddr) instead of the real
// *endpoint whenever a WireGuard packet arrives on a relay (VNI) path and
// the periodic connection-noted verification fires (recurring once per >10s
// of WG receive activity per peer), or the packet looks like a handshake
// initiation. wireguard-go's callback-configured peers do not get
// disableRoaming, so SetEndpointFromPacket installs that *lazyEndpoint as
// the peer's TX endpoint, where it sticks until the next inbound packet
// replaces it. All TX via a retained *lazyEndpoint (data and handshake
// retries alike) goes through Conn.Send's lazyEndpoint branch straight to
// the frozen relay epAddr, bypassing endpoint.send and with it DERP fallback
// and path re-discovery. Once the relay session is reaped server-side, a
// peer holding such an endpoint black-holes; if both peers hold one, neither
// side's packets can arrive to replace the other's endpoint and the
// black-hole is permanent (the disco plane meanwhile happily re-establishes
// a fresh relay session that the frozen WireGuard TX never uses).
//
// Pre-suspend traffic is shaped so that both sides hold a *lazyEndpoint at
// the suspend instant (the in-process repro,
// magicsock.TestPeerRelaySessionReapRecovery, forces the same state by
// rewinding endpoint.lastRecvWG; here we get it with legitimate traffic
// only):
//
//  1. Bidirectional TSMP pings for trafficDur=12s exercise the relay path
//     (covering at least one ~10s connection-noted verification handoff,
//     the recurring production poisoning event), ending with an a→b ping.
//
//  2. A quiesce of quiesceDur=25s with no overlay traffic. During the
//     quiesce the only WireGuard packet is a single passive keepalive
//     (wireguard-go KeepaliveTimeout=10s after the final traffic ping's
//     reply is received by a, who then sends nothing; receiving a
//     keepalive schedules no keepalive in return, so the chain stops
//     there), so by the end of it each side's last WG receive is >10s old:
//     a's is the traffic-ping reply at quiesce start, b's is a's keepalive
//     at quiesce+10s. 25s = KeepaliveTimeout(10s) + connection-noted
//     threshold (10s) + 5s margin. Disco heartbeats (3s interval) continue
//     during the quiesce on both sides and keep the relay session's
//     per-client lastSeen fresh, so steadyState=15s cannot reap it
//     pre-suspend.
//
//  3. A final ICMP ping b→a. Each side receives exactly one WireGuard
//     packet, >10s after its last WG receive, so each receive trips the
//     connection-noted handoff and leaves BOTH wireguard-go peers holding
//     a *lazyEndpoint frozen on the relay session epAddr. b is suspended
//     immediately after.
//
//     The ping type and direction both matter:
//
//     ICMP, not TSMP: a LocalAPI TSMP ping unconditionally sends a TSMP
//     disco-key advertisement right behind the echo request
//     (wgengine.Ping calls sendTSMPDiscoAdvertisement; not gated by
//     TS_USE_CACHED_NETMAP, which only gates magicsock's periodic
//     advertisements), so the ping receiver always gets two back-to-back
//     WireGuard data packets and the second — received <10s after the
//     first — is handed up with the healthy *endpoint, immediately
//     replacing the just-planted *lazyEndpoint. An ICMP ping is a single
//     data packet each way.
//
//     From b (the node about to be suspended): the side that receives
//     data without replying at the WireGuard layer schedules a passive
//     keepalive 10s out. For the final exchange that side is the
//     requester (its reply is generated and sent by the responder's
//     TUN/kernel, canceling the responder's pending keepalive). QEMU does
//     not actually drop packets sent to a stopped VM's unix-socket
//     netdev: they queue in the socket buffer and are delivered at wake,
//     when the suspended guest's frozen CLOCK_MONOTONIC makes its last WG
//     receive look only ~1s old, so any queued WireGuard *transport*
//     packet would be handed up with the healthy *endpoint and
//     "un-poison" the woken node. Making b the requester freezes the
//     pending keepalive inside b rather than queueing it toward b. The
//     only WireGuard packets a then originates during the suspend window
//     are its ~15s "stopped hearing back" handshake initiations, sent via
//     its retained *lazyEndpoint straight to the relay session: copies
//     relayed pre-reap queue toward b but an initiation received on a VNI
//     path is always handed up as a *lazyEndpoint, so they keep b
//     poisoned rather than rescuing it, and copies sent post-reap are
//     dropped by the relay.
//
// Suspend window: suspendDur=40s total — steadyState(15s) + GC tick(5s) +
// 20s margin, within which the reap is verified server-side by polling
// DebugPeerRelaySessions on the relay until the original session's VNI is
// gone (budget reapBudget=30s: 15s+5s plus 10s poll/VM-scheduling slack).
// 40s also lets a's disco-plane state for the dead path fully decay
// (trustUDPAddrDuration=6.5s) while staying far below WireGuard's
// RejectAfterTime (3m), so post-fix recovery does not even need a fresh
// handshake.
//
// Recovery budgets after Resume: a→b TSMP within recoverBudget=90s. Post-fix
// the math is: b's wake transient (virtio queue refill, DERP reconnect, a
// few seconds) + a's first retried packet falling back to DERP
// (trust on the dead path long expired) + at worst one WireGuard handshake
// retry cycle (RekeyTimeout=5s); tens of seconds at most, observed
// near-immediate in the in-process repro, with the rest of the budget
// absorbing slow-CI slop. Then b→a within 30s (tunnel already
// re-established; budget covers b's remaining wake transient). Finally the
// peer relay path itself must re-establish: PingExpect peer-relay with the
// sibling tests' 60s budget (covers the discoverUDPRelayPathsInterval=30s
// rate limit plus margin).
//
// EXPECTED ON CURRENT MAIN (pre-#20082-fix): the recovery assertion FAILS —
// the black-hole of the issue's repro (observed deterministically, 4/4 local
// runs). Failure output includes the disco-plane route view, relay session
// state, and node statuses to show the signature: disco pings still succeed
// (DERP route; the disco plane even allocates fresh relay sessions, which
// never bind because the WireGuard plane is dead) while TSMP traffic
// black-holes in both directions, with a's wireguard-go retrying handshake
// initiations into the reaped relay session every 5s for the whole window.
//
// Whole-test wall time budget: 3 VM boots + ~10-60s relay path
// establishment + 12s traffic + 25s quiesce + 40s suspend + recovery (≤90s
// fail / seconds pass) + ≤60s relay re-establishment ≈ 5 min (observed:
// ~3min fail on current main).
func TestPeerRelaySuspendResume(t *testing.T) {
	const (
		relayBindLifetime        = 5 * time.Second  // also the relay-server endpoint GC tick interval
		relaySteadyStateLifetime = 15 * time.Second // idle (per client) time before a bound session is reaped
		trafficDur               = 12 * time.Second // covers ≥1 connection-noted verification handoff (~10s)
		quiesceDur               = 25 * time.Second // KeepaliveTimeout(10s) + connection-noted threshold(10s) + margin
		reapBudget               = 30 * time.Second // steadyState(15s) + GC tick(5s) + poll/VM slack
		suspendDur               = 40 * time.Second // ≥ reap upper bound (20s) + margin; ≪ RejectAfterTime(3m)
		recoverBudget            = 90 * time.Second // DERP fallback + handshake retry + wake/CI slop; see doc comment
	)

	env := vmtest.New(t, vmtest.PeerRelayGrants())

	aNet := env.AddNetwork("1.0.0.1", "192.168.1.1/24", vnet.HardNAT)
	bNet := env.AddNetwork("2.0.0.1", "192.168.2.1/24", vnet.HardNAT)
	relayNet := env.AddNetwork("3.0.0.1", "192.168.3.1/24", vnet.One2OneNAT)

	// a and b run at wireguard-go log verbosity with their syslog mirrored
	// into the harness output: when this test fails (pre-fix, or on a
	// regression) the essential evidence is in their logs — endless
	// wireguard-go "Sending handshake initiation" retries against the
	// reaped relay session, and magicsock lazyEndpoint handoffs. The relay
	// node's syslog is mirrored too, for relay server lifecycle logging.
	// TS_USE_CACHED_NETMAP=false disables the periodic TSMP disco-key
	// advertisements (wgengine/magicsock maybeSendTSMPDiscoAdvert; once per
	// 2 minutes per peer, riding the ~5s call-me-maybe cadence that relay
	// paths sustain). An advertisement is an extra WireGuard data packet:
	// when one lands adjacent to the final poisoning exchange below, the
	// receiver gets two back-to-back packets and the second (received <10s
	// after the first) is handed up with the healthy *endpoint, replacing
	// the just-planted *lazyEndpoint and masking the bug. The 2-minute
	// cadence is anchored at first peer contact during bring-up, which lands
	// the tick unpredictably relative to the suspend instant, so suppress
	// advertisements rather than trying to dodge them.
	a := env.AddNode("a", aNet, vmtest.OS(vmtest.Gokrazy),
		vnet.VerboseSyslog,
		vnet.TailscaledEnv{Key: "TS_LOG_VERBOSITY", Value: "2"},
		vnet.TailscaledEnv{Key: "TS_USE_CACHED_NETMAP", Value: "false"})
	b := env.AddNode("b", bNet, vmtest.OS(vmtest.Gokrazy),
		vnet.VerboseSyslog,
		vnet.TailscaledEnv{Key: "TS_LOG_VERBOSITY", Value: "2"},
		vnet.TailscaledEnv{Key: "TS_USE_CACHED_NETMAP", Value: "false"})
	relay := env.AddNode("relay", relayNet, vmtest.OS(vmtest.Gokrazy),
		vnet.VerboseSyslog)

	enableRelayStep := env.AddStep("Enable peer-relay server on relay")
	lifetimesStep := env.AddStep("Shrink relay endpoint lifetimes")
	pathStep := env.AddStep("Disco ping a → b (want peer-relay path)")
	sessionStep := env.AddStep("Record relay session VNI")
	trafficStep := env.AddStep("Bidirectional TSMP traffic over relay path")
	quiesceStep := env.AddStep("Quiesce overlay traffic")
	poisonStep := env.AddStep("Final ICMP ping b → a (lazyEndpoint handoff both sides)")
	suspendStep := env.AddStep("Suspend b")
	reapStep := env.AddStep("Relay reaps idle session")
	resumeStep := env.AddStep("Resume b")
	recoverStep := env.AddStep("TSMP connectivity recovers a ↔ b")
	relayAgainStep := env.AddStep("Peer-relay path re-establishes")

	env.Start()

	enableRelayStep.Begin()
	if err := env.EnableRelayServer(relay); err != nil {
		enableRelayStep.Fatal(err)
	}
	enableRelayStep.End(nil)

	// Shrink the relay server's endpoint lifetimes before any session is
	// allocated (see doc comment). The LocalAPI debug action errors if the
	// relay server is not (yet) running; EnableRelayServer's EditPrefs
	// starts it synchronously via the profile-change hook, but tolerate
	// propagation delay with a short retry loop. 10s is pure LocalAPI
	// latency budget.
	lifetimesStep.Begin()
	if err := tstest.WaitFor(10*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return relay.Agent().DebugSetPeerRelayServerLifetimes(ctx, relayBindLifetime, relaySteadyStateLifetime)
	}); err != nil {
		lifetimesStep.Fatalf("DebugSetPeerRelayServerLifetimes(%v, %v): %v", relayBindLifetime, relaySteadyStateLifetime, err)
	}
	t.Logf("relay server lifetimes set: bind=%v steadyState=%v", relayBindLifetime, relaySteadyStateLifetime)
	lifetimesStep.End(nil)

	// 60s: the relay server was only just enabled via EditPrefs, so a and b
	// must learn its endpoint from a netmap update and allocate a relay
	// session before a disco ping can ride it. Same budget as TestPeerRelay
	// and RunConnectivityTestViaPeerRelay.
	pathStep.Begin()
	if err := env.PingExpect(a, b, vmtest.PingRoutePeerRelay, 60*time.Second); err != nil {
		env.DumpStatus(a)
		env.DumpStatus(b)
		env.DumpStatus(relay)
		pathStep.Fatalf("waiting for peer-relay path a → b: %v", err)
	}
	pathStep.End(nil)

	// boundRelaySessions returns the relay server's sessions for which both
	// clients have completed the bind handshake. Sessions still inside the
	// bind window (e.g. allocated by a path-discovery probe and never bound)
	// are excluded; they expire on their own after bindLifetime.
	boundRelaySessions := func() ([]status.ServerSession, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv, err := relay.Agent().DebugPeerRelaySessions(ctx)
		if err != nil {
			return nil, err
		}
		var bound []status.ServerSession
		for _, s := range srv.Sessions {
			if s.Client1.Endpoint.IsValid() && s.Client2.Endpoint.IsValid() {
				bound = append(bound, s)
			}
		}
		return bound, nil
	}

	// Record the session's VNI so the reap of this specific session can be
	// asserted later, regardless of any new sessions path discovery may
	// allocate in the meantime. 10s: the session is already carrying disco
	// pings, this only absorbs LocalAPI latency.
	sessionStep.Begin()
	var vni uint32
	if err := tstest.WaitFor(10*time.Second, func() error {
		bound, err := boundRelaySessions()
		if err != nil {
			return err
		}
		if len(bound) != 1 {
			return fmt.Errorf("got %d bound relay sessions, want 1: %+v", len(bound), bound)
		}
		vni = bound[0].VNI
		return nil
	}); err != nil {
		sessionStep.Fatal(err)
	}
	t.Logf("peer-relay session established, VNI=%d", vni)
	sessionStep.End(nil)

	// Keep TSMP traffic flowing in both directions so relay-path
	// verification handoffs occur (see doc comment). 5s per ping: the
	// tunnel is up and each ping is a LAN-speed round trip; a timeout here
	// means the relay path died under traffic. The loop body ends with the
	// a→b ping so the keepalive math in the quiesce (doc comment, traffic
	// shaping step 2) starts from a known state.
	trafficStep.Begin()
	trafficDeadline := time.Now().Add(trafficDur)
	for time.Now().Before(trafficDeadline) {
		if err := env.Ping(b, a, tailcfg.PingTSMP, 5*time.Second); err != nil {
			trafficStep.Fatal(err)
		}
		if err := env.Ping(a, b, tailcfg.PingTSMP, 5*time.Second); err != nil {
			trafficStep.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	trafficStep.End(nil)

	quiesceStep.Begin()
	time.Sleep(quiesceDur)
	quiesceStep.End(nil)

	// The poisoning ping (see doc comment, traffic shaping step 3: ICMP for
	// its single-packet-per-direction property, issued from b so the
	// passive keepalive it schedules freezes inside b at suspend). It must
	// succeed: it both plants the frozen endpoints and proves the relay
	// path was still alive at the suspend instant.
	poisonStep.Begin()
	if err := env.Ping(b, a, tailcfg.PingICMP, 5*time.Second); err != nil {
		poisonStep.Fatal(err)
	}
	poisonStep.End(nil)

	suspendStep.Begin()
	env.Suspend(b)
	suspendedAt := time.Now()
	suspendStep.End(nil)

	// With b's vCPUs stopped, b stops sending through the relay session, so
	// its per-client lastSeen goes stale and the next GC tick after
	// steadyState reaps the session. Poll for that, identified by VNI.
	reapStep.Begin()
	reapDeadline := suspendedAt.Add(reapBudget)
	for {
		bound, err := boundRelaySessions()
		if err != nil {
			reapStep.Fatalf("DebugPeerRelaySessions: %v", err)
		}
		alive := false
		for _, s := range bound {
			if s.VNI == vni {
				alive = true
				break
			}
		}
		if !alive {
			t.Logf("relay session VNI=%d reaped %v after suspend",
				vni, time.Since(suspendedAt).Round(time.Second))
			break
		}
		if time.Now().After(reapDeadline) {
			reapStep.Fatalf("relay session VNI=%d still present %v after suspending b; want reaped within %v (steadyState=%v + GC tick=%v + slack)",
				vni, time.Since(suspendedAt).Round(time.Second), reapBudget, relaySteadyStateLifetime, relayBindLifetime)
		}
		time.Sleep(time.Second)
	}
	reapStep.End(nil)

	// Keep b suspended for suspendDur total (see doc comment).
	if d := time.Until(suspendedAt.Add(suspendDur)); d > 0 {
		time.Sleep(d)
	}

	resumeStep.Begin()
	env.Resume(b)
	resumeStep.End(nil)

	// dumpBlackholeEvidence logs the state that distinguishes the #20082
	// black-hole from ordinary breakage: the disco plane's view of the a→b
	// route (pre-fix the disco ping still succeeds — typically via DERP —
	// while WireGuard traffic black-holes) and the relay server's session
	// table (the original VNI gone; fresh allocations may appear, unbound,
	// from ongoing path discovery).
	dumpBlackholeEvidence := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if st, err := b.Agent().Status(ctx); err == nil && len(st.Self.TailscaleIPs) > 0 {
			if pr, err := a.Agent().PingWithOpts(ctx, st.Self.TailscaleIPs[0], tailcfg.PingDisco, local.PingOpts{}); err != nil {
				t.Logf("evidence: disco ping a → b failed: %v", err)
			} else {
				t.Logf("evidence: disco ping a → b: err=%q endpoint=%q derp=%d peer-relay=%q",
					pr.Err, pr.Endpoint, pr.DERPRegionID, pr.PeerRelay)
			}
		} else {
			t.Logf("evidence: can't get b's status for disco probe: %v", err)
		}
		if srv, err := relay.Agent().DebugPeerRelaySessions(ctx); err != nil {
			t.Logf("evidence: DebugPeerRelaySessions: %v", err)
		} else {
			t.Logf("evidence: relay sessions (original VNI=%d): %+v", vni, srv.Sessions)
		}
		env.DumpStatus(a)
		env.DumpStatus(b)
		env.DumpStatus(relay)
	}

	// Recovery, the assertion that pins the post-#20082-fix behavior (and
	// FAILS on pre-fix main; see doc comment for the budget math). The
	// outer loop re-issues env.Ping because its initial Status lookup of b
	// is a single shot that may fail while b's agent connection is still
	// recovering from the wake.
	recoverStep.Begin()
	var lastErr error
	for deadline := time.Now().Add(recoverBudget); ; {
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		if err := env.Ping(a, b, tailcfg.PingTSMP, min(10*time.Second, remain)); err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		// Black-hole: the issue's repro outcome. Log the b→a direction too
		// before failing — pre-fix both directions are dead.
		if err := env.Ping(b, a, tailcfg.PingTSMP, 5*time.Second); err != nil {
			t.Logf("evidence: TSMP ping b → a also failing: %v", err)
		} else {
			t.Logf("evidence: TSMP ping b → a unexpectedly works")
		}
		dumpBlackholeEvidence()
		recoverStep.Fatalf("no TSMP connectivity a → b within %v of resuming b (relay session reaped during suspend; tailscale/tailscale#20082 black-hole): %v",
			recoverBudget, lastErr)
	}
	t.Logf("a → b TSMP recovered %v after resume", time.Since(suspendedAt.Add(suspendDur)).Round(time.Second))
	if err := env.Ping(b, a, tailcfg.PingTSMP, 30*time.Second); err != nil {
		dumpBlackholeEvidence()
		recoverStep.Fatalf("no TSMP connectivity b → a after a → b recovered: %v", err)
	}
	recoverStep.End(nil)

	// The peer relay path itself must come back, not just DERP. 60s as in
	// the sibling peer-relay tests; covers the 30s relay path discovery
	// rate limit plus margin.
	relayAgainStep.Begin()
	if err := env.PingExpect(a, b, vmtest.PingRoutePeerRelay, 60*time.Second); err != nil {
		dumpBlackholeEvidence()
		relayAgainStep.Fatalf("waiting for peer-relay path a → b to re-establish: %v", err)
	}
	relayAgainStep.End(nil)
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
