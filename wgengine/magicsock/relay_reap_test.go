// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/tstest"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// markNextWGRecvNoted rewinds ms's [endpoint.lastRecvWG] for peer so that the
// next WireGuard packet received from peer is treated as a periodic
// connection-noted event by [Conn.receiveIP], which for Geneve-encapsulated
// (peer relay) paths hands wireguard-go a [*lazyEndpoint] for peer
// verification rather than the resolved [*endpoint]. wireguard-go then
// retains that [*lazyEndpoint] as the peer's endpoint until a later packet
// replaces it. This deterministically reproduces the state a production node
// is in whenever the most recent packet from a relay path was a verification
// handoff (a recurring, roughly 10-second cadence event) or a WireGuard
// handshake initiation.
func markNextWGRecvNoted(t *testing.T, ms *magicStack, peer key.NodePublic) {
	t.Helper()
	ms.conn.mu.Lock()
	ep, ok := ms.conn.peerMap.endpointForNodeKey(peer)
	ms.conn.mu.Unlock()
	if !ok {
		t.Fatalf("no magicsock endpoint for %v on %s", peer.ShortString(), ms)
	}
	ep.lastRecvWG.StoreAtomic(mono.Now().Add(-time.Minute))
}

// wgPeerEndpointString returns the "endpoint=" value wireguard-go reports for
// peer via UAPI, or "" if unset. A magicsock [*endpoint] renders as the
// peer's public key in hex ([endpoint.DstToString]), while a [*lazyEndpoint]
// renders as its frozen packet source [epAddr], e.g. "127.0.0.1:444:vni:96",
// making the two distinguishable. It is non-fatal so it can also be used
// from failure diagnostics paths.
func wgPeerEndpointString(ms *magicStack, peer key.NodePublic) (string, error) {
	uapi, err := ms.dev.IpcGet()
	if err != nil {
		return "", fmt.Errorf("IpcGet on %s: %v", ms, err)
	}
	var inPeer bool
	for line := range strings.SplitSeq(uapi, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "public_key":
			inPeer = v == peer.UntypedHexString()
		case "endpoint":
			if inPeer {
				return v, nil
			}
		}
	}
	return "", nil
}

// TestPeerRelaySessionReapRecovery reproduces tailscale/tailscale#20082
// in-process: a pair of peers whose only UDP path is a session through a peer
// relay server go idle, the relay server reaps the session, and the peers
// must recover data-plane connectivity (DERP fallback, followed by relay path
// re-establishment) once traffic resumes.
//
// This test is EXPECTED TO FAIL until #20082 is fixed. On current main,
// wireguard-go retains a [*lazyEndpoint] whose frozen src is the reaped relay
// session's epAddr: all subsequent TX for the peer (data and handshake
// retries alike) is transmitted directly to the dead relay session by
// [Conn.Send]'s [*lazyEndpoint] branch, bypassing [endpoint.send] and with it
// DERP fallback and path re-discovery, black-holing the peer until the nodes
// are restarted. The assertions below intentionally demand only the correct
// post-fix behavior (bounded recovery), not any particular fix mechanism.
//
// The test is event-driven: it blocks on relay path installs
// ([Conn.testOnlyRelayEndpointReadyHook] via mesh.pathReady), relay session
// reaps ([udprelay.Server.SetEndpointRemovedHookForTest]), and tun packet
// deliveries of uniquely-tagged pings. Timeouts exist only as failure
// deadlines and resend backstops (lost packets produce no event).
func TestPeerRelaySessionReapRecovery(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	mesh := newRelayedMeshForTest(t, logf)

	// Observe relay session reaps as events. Registered before any traffic
	// so no removal can be missed.
	reapedVNI := make(chan uint32, 16)
	mesh.server.SetEndpointRemovedHookForTest(func(vni uint32) {
		select {
		case reapedVNI <- vni:
		default: // the hook must never block the GC loop
		}
	})

	// pingSeq uniquely tags each ping payload so a wait matches exactly the
	// packet it sent; stale or duplicate deliveries of earlier pings (e.g.
	// in-flight stragglers from a stopped pinger, or late deliveries of a
	// previous attempt's ping) are discarded by whichever wait encounters
	// them, making deliveries attributable across calls.
	ipOf := map[*magicStack]netip.Addr{mesh.m1: mesh.m1.IP(), mesh.m2: mesh.m2.IP()}
	var pingSeq atomic.Int64
	// tryPing sends a single uniquely-tagged ICMP ping from src to dst and
	// reports whether that specific packet transited within timeout. It
	// blocks on the tun inbound channel (the delivery event); the timeout is
	// the resend backstop for genuinely lost packets, which produce no
	// event.
	tryPing := func(src, dst *magicStack, timeout time.Duration) bool {
		tag := fmt.Appendf(nil, "relay-reap-%d", pingSeq.Add(1))
		pkt := packet.Generate(packet.ICMP4Header{
			IP4Header: packet.IP4Header{
				Src: ipOf[src],
				Dst: ipOf[dst],
			},
			Type: packet.ICMP4EchoRequest,
			Code: packet.ICMP4NoCode,
		}, tag)
		deadline := time.After(timeout)
		select {
		case src.tun.Outbound <- pkt:
		case <-deadline:
			return false
		}
		for {
			select {
			case got := <-dst.tun.Inbound:
				if bytes.HasSuffix(got, tag) {
					return true
				}
				// A stale or duplicate delivery of an earlier ping;
				// discard and keep waiting for ours.
			case <-deadline:
				return false
			}
		}
	}

	// Phase 1: establish the relay path with bidirectional traffic, exactly
	// like TestPeerRelayE2E: ping continuously until both sides install the
	// relay path as bestAddr (the pathReady events), then confirm the relay
	// server reports a session with both clients bound and forwarding. Each
	// pathReady event was triggered by a disco pong forwarded through the
	// session, which requires both clients bound with counted forwarded
	// packets, so a single (poll-free) check suffices.
	stopPing1 := newPinger(t, logf, mesh.m1, mesh.m2)
	stopPing2 := newPinger(t, logf, mesh.m2, mesh.m1)
	pingersStopped := false
	stopPingers := func() {
		if !pingersStopped {
			pingersStopped = true
			stopPing1()
			stopPing2()
		}
	}
	defer stopPingers()

	mustPeerRelay(t, logf, mesh, mesh.m1, mesh.m2)
	mustPeerRelay(t, logf, mesh, mesh.m2, mesh.m1)

	baseline, err := relaySessionWithBothClientsBound(mesh.server)
	if err != nil {
		t.Fatal(err)
	}
	logf("relay session established: vni=%d", baseline.VNI)

	// Phase 2: stop all overlay traffic, and arrange for the last WireGuard
	// packet each side received to have carried a [*lazyEndpoint] handoff,
	// so wireguard-go idles holding a [*lazyEndpoint] frozen on the relay
	// session's epAddr. In production this state recurs naturally (periodic
	// connection-noted verification handoffs roughly every 10s of relay
	// traffic, and every inbound WireGuard handshake initiation); here it is
	// forced deterministically by rewinding lastRecvWG before a final ping
	// in each direction. Disco traffic (heartbeats etc.) never reaches
	// wireguard-go and so cannot replace its endpoints afterwards.
	//
	// Each round blocks only on its own pings' delivery events. wireguard-go
	// preserves per-peer receive ordering, so once a round's tagged ping is
	// delivered, any pinger stragglers sent before it have already been
	// processed; the UAPI read then reflects the final pre-idle endpoint. A
	// straggler can consume the rewound lastRecvWG mark (it gets the lazy
	// handoff and the round's own ping then re-installs the resolved
	// *endpoint), in which case the UAPI check fails and the next round
	// converges: stragglers are finite once the pingers are stopped.
	stopPingers()
	drainTunInbound(mesh.m1.tun.Inbound)
	drainTunInbound(mesh.m2.tun.Inbound)

	handoff := false
	for range 3 {
		markNextWGRecvNoted(t, mesh.m2, mesh.m1.Public()) // m1->m2 final ping RX at m2
		markNextWGRecvNoted(t, mesh.m1, mesh.m2.Public()) // m2->m1 final ping RX at m1
		// Pre-reap, over a healthy session: failure to transit at all is a
		// mesh failure regardless of #20082, so a generous fatal backstop.
		if !tryPing(mesh.m1, mesh.m2, 10*time.Second) || !tryPing(mesh.m2, mesh.m1, 10*time.Second) {
			t.Fatal("connectivity lost before the relay session was reaped")
		}
		ep12, err12 := wgPeerEndpointString(mesh.m1, mesh.m2.Public())
		ep21, err21 := wgPeerEndpointString(mesh.m2, mesh.m1.Public())
		if err12 != nil || err21 != nil {
			t.Fatalf("reading wireguard-go peer endpoints: %v, %v", err12, err21)
		}
		logf("wireguard-go endpoints after final pings: m1->m2 %q, m2->m1 %q", ep12, ep21)
		if strings.Contains(ep12, ":vni:") && strings.Contains(ep21, ":vni:") {
			handoff = true
			break
		}
	}
	if !handoff {
		// Not fatal: a fixed build may legitimately never leave a
		// [*lazyEndpoint] installed in wireguard-go. The recovery assertions
		// below are the behavior under test.
		logf("wireguard-go did not retain *lazyEndpoint peer endpoints; recovery assertions still apply")
	}

	// Phase 3: shrink the relay server endpoint lifetimes so its GC loop
	// reaps the now-idle session, and block on the removal event.
	// steadyState=10ms expires the session at the first GC tick unless a
	// packet from each client arrived within the last 10ms (disco
	// heartbeats are seconds apart, so this converges immediately);
	// bind=500ms paces the GC loop, putting the first tick 500ms after
	// SetLifetimesForTest pokes it. The 10s deadline is ~20 GC ticks of
	// slack.
	//
	// Restore generous lifetimes as soon as the reap is observed so that
	// post-reap re-established sessions persist: bind=5s is orders of
	// magnitude above in-process handshake latency, and steadyState=5m (the
	// production default) prevents further idle reaps. Also registered as a
	// cleanup at shrink time so the server is never left with the
	// aggressive values on a failure exit from the wait below.
	restoreLifetimes := func() { mesh.server.SetLifetimesForTest(5*time.Second, 5*time.Minute) }
	t.Cleanup(restoreLifetimes)
	mesh.server.SetLifetimesForTest(500*time.Millisecond, 10*time.Millisecond)
	reapTimeout := time.NewTimer(10 * time.Second)
	defer reapTimeout.Stop()
waitReap:
	for {
		select {
		case vni := <-reapedVNI:
			if vni == baseline.VNI {
				break waitReap
			}
			// Some other endpoint (e.g. a never-bound allocation); keep
			// waiting for the established session.
		case <-reapTimeout.C:
			t.Fatalf("relay session vni=%d was not reaped: %+v", baseline.VNI, mesh.server.GetSessions())
		}
	}
	logf("relay session vni=%d reaped", baseline.VNI)
	restoreLifetimes()

	// Phase 4: resume traffic and assert data-plane connectivity recovers.
	// Attempts alternate between the two directions, each blocking on its
	// delivery event with a 1s resend backstop (early post-reap sends can be
	// legitimately lost even on a fixed build, e.g. into a stale-but-trusted
	// bestAddr, and lost packets produce no event to wait on).
	//
	// Deadline derivation: post-fix, resumed TX flows through
	// [endpoint.send], which mirrors traffic to DERP whenever bestAddr is
	// missing or untrusted; the WireGuard session keys are still valid
	// (established well within RejectAfterTime=3m), so the first resumed
	// ping should transit DERP within milliseconds. The worst case stacks
	// bestAddr trust expiry (trustUDPAddrDuration=6.5s, if a stale relay
	// bestAddr is still trusted at resume time) on a WireGuard handshake
	// retry interval (RekeyTimeout=5s) if a rekey raced the reap; 30s is
	// roughly 2.5x that worst case to absorb race-detector and CI
	// scheduling slop.
	const recoveryDeadline = 30 * time.Second
	deadline := time.Now().Add(recoveryDeadline)
	var ok12, ok21 bool
	for time.Now().Before(deadline) && !(ok12 && ok21) {
		backstop := func() time.Duration { return min(time.Second, time.Until(deadline)) }
		if !ok12 {
			ok12 = tryPing(mesh.m1, mesh.m2, backstop())
		}
		if !ok21 {
			ok21 = tryPing(mesh.m2, mesh.m1, backstop())
		}
	}
	if !ok12 || !ok21 {
		// Failure diagnostics (non-fatal introspection only).
		fmtEP := func(ms *magicStack, peer key.NodePublic) string {
			s, err := wgPeerEndpointString(ms, peer)
			if err != nil {
				return fmt.Sprintf("<%v>", err)
			}
			return s
		}
		t.Fatalf("tailscale/tailscale#20082: data-plane connectivity did not recover within %v of relay session reap (m1->m2 ok=%v, m2->m1 ok=%v).\n"+
			"wireguard-go peer endpoints: m1->m2 %q, m2->m1 %q (an ip:port:vni:N value is a *lazyEndpoint frozen on the reaped relay session; a fixed build recovers regardless).\n"+
			"relay server sessions: %+v\n"+
			"Mechanism: wireguard-go retains a *lazyEndpoint whose src is the reaped relay session epAddr; Conn.Send's *lazyEndpoint branch transmits all TX (data and handshake retries) directly to the dead session, bypassing endpoint.send and with it DERP fallback and path re-discovery, so the peers black-hole indefinitely.",
			recoveryDeadline, ok12, ok21,
			fmtEP(mesh.m1, mesh.m2.Public()),
			fmtEP(mesh.m2, mesh.m1.Public()),
			mesh.server.GetSessions())
	}
	logf("data-plane connectivity recovered after relay session reap")

	// Phase 5: the relay path must also re-establish: block until both
	// clients install a new relay path (pathReady events with a VNI other
	// than the reaped session's; the server allocates VNIs monotonically,
	// and events for the old session were consumed in phase 1), then
	// confirm the server reports the new session with both clients bound
	// and forwarding (single check; see phase 1 for why no poll is needed).
	// No pingers are required: the phase 4 recovery pings refreshed
	// lastSendExt on both endpoints, so disco heartbeats (and with them
	// relay path discovery) run for sessionActiveTimeout=45s beyond them.
	//
	// Deadline derivation: relay path discovery is rate-limited per
	// endpoint by discoverUDPRelayPathsInterval=30s and a cycle may have
	// just preceded the reap, so the next eligible cycle can be up to ~30s
	// out (within the 45s heartbeat window anchored at phase 4 traffic);
	// allocation, handshake, and binding are then sub-second in-process.
	// 45s covers the rate limit with 50% margin.
	relayReadyTimeout := time.NewTimer(45 * time.Second)
	defer relayReadyTimeout.Stop()
	for _, m := range []*magicStack{mesh.m1, mesh.m2} {
	waitNewPath:
		for {
			select {
			case ev := <-mesh.pathReady[m]:
				if ev.addr.vni.Get() == baseline.VNI {
					continue // a stale pre-reap install event
				}
				logf("new relay path on %s to %v: %v vni=%d", m, ev.peer.ShortString(), ev.addr.ap, ev.addr.vni.Get())
				break waitNewPath
			case <-relayReadyTimeout.C:
				t.Fatalf("relay path did not re-establish on %s after session reap: %+v", m, mesh.server.GetSessions())
			}
		}
	}
	session, err := relaySessionWithBothClientsBound(mesh.server)
	if err != nil {
		t.Fatalf("relay session did not re-establish after reap: %v", err)
	}
	if session.VNI == baseline.VNI {
		t.Fatalf("relay session vni=%d matches the reaped session, want a new allocation", session.VNI)
	}
	logf("relay session re-established: vni=%d", session.VNI)
}
