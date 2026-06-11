// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/net/packet"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/logger"
)

// TestDirectPathDeathRecovery exercises what happens when an established
// direct UDP path between two nodes dies underneath an active connection,
// e.g. because a NAT mapping expired or a firewall lost its state while the
// client slept.
//
// Topology: ms1 is behind an endpoint-independent ("easy") NAT with a
// stateful firewall; ms2 and the STUN server sit directly on the fake
// internet. The NAT and its firewall share an injectable test clock that is
// frozen for the duration of the test, so NAT mappings and firewall sessions
// never expire on their own. To kill the path, the test jumps the clock
// forward past natlab.DefaultMappingTimeout in one step, which atomically
// expires every NAT mapping and firewall session even though
// wireguard/disco keepalive traffic is still flowing (each outbound packet
// refreshes the deadline relative to the frozen clock, so the jump always
// wins). After the jump, inbound packets to ms1's old WAN ip:port are
// dropped, and ms1's next outbound packet allocates a brand new WAN
// ip:port, exactly like a real NAT binding expiry.
//
// The test asserts:
//
//  1. ms2->ms1 connectivity recovers within recoverDeadline. magicsock
//     trusts a direct path for trustUDPAddrDuration (6.5s) after the last
//     pong, so the worst-case blackhole is ~6.5s of remaining trust; after
//     that addrForSendLocked sends to both the (dead) bestAddr and DERP,
//     so the first recovered ping typically arrives via DERP fallback.
//  2. A direct path to ms1's *new* WAN address re-establishes within
//     directDeadline (same 30s bound as mustDirect, see issues #654 and
//     #3247 for discussion of that bound).
//
// If (1) fails, a likely culprit is the lazyEndpoint poisoning described in
// tailscale/tailscale#20082: wireguard-go roams its peer endpoint to the
// [conn.Endpoint] of the last received packet, and if that is a
// [*lazyEndpoint] whose frozen src is the dead pre-expiry address,
// Conn.Send transmits directly to the dead address, bypassing magicsock's
// DERP fallback. The failure diagnostics below report the magicsock
// endpoint state to help distinguish that case.
//
// The test is event-driven throughout: ping payloads are uniquely tagged
// and waited for on the tun channels (so stale deliveries can never satisfy
// a later wait, removing any need for settle sleeps or queue draining), and
// path state transitions are awaited via setBestAddrHookForTests rather
// than by polling. The only timers are failure deadlines, the per-attempt
// ping resend backstop (a lost UDP packet produces no event, and WireGuard
// does not retransmit data packets), and the phase 3 traffic cadence.
func TestDirectPathDeathRecovery(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	// This test depends on default (non-silent-disco) behavior, where
	// endpoints heartbeat and re-discover paths in the background. Pin the
	// knob in case an earlier test in the package left it toggled.
	// envknob.Setenv (not t.Setenv) is required: the knob is a registered
	// bool, and plain os.Setenv would not update envknob's cached value.
	oldSD := os.Getenv("TS_DEBUG_ENABLE_SILENT_DISCO")
	envknob.Setenv("TS_DEBUG_ENABLE_SILENT_DISCO", "false")
	t.Cleanup(func() { envknob.Setenv("TS_DEBUG_ENABLE_SILENT_DISCO", oldSD) })

	// bestAddrChanged is a condition-variable-style wakeup: it receives a
	// (coalesced) token whenever any endpoint's bestAddr is updated.
	// Waiters re-check the actual state after every wakeup; the channel
	// carries no state itself. Installed before the stacks exist so no
	// transition can be missed.
	bestAddrChanged := make(chan struct{}, 1)
	tstest.Replace(t, &setBestAddrHookForTests, func(*endpoint) {
		select {
		case bestAddrChanged <- struct{}{}:
		default:
		}
	})

	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	// natClock is frozen: it only moves when the test calls Advance.
	// It governs NAT mapping and firewall session expiry, and nothing
	// else; magicsock itself runs on the real clock.
	natClock := &tstest.Clock{}

	mstun := &natlab.Machine{Name: "stun"}
	m1 := &natlab.Machine{Name: "m1"}
	nat1 := &natlab.Machine{Name: "nat1"}
	m2 := &natlab.Machine{Name: "m2"}

	inet := natlab.NewInternet()
	lan1 := &natlab.Network{
		Name:    "lan1",
		Prefix4: netip.MustParsePrefix("192.168.0.0/24"),
	}

	sif := mstun.Attach("eth0", inet)
	nat1WAN := nat1.Attach("wan", inet)
	nat1LAN := nat1.Attach("lan1", lan1)
	m1.Attach("eth0", lan1)
	m2.Attach("eth0", inet)
	lan1.SetDefaultGateway(nat1LAN)

	nat1.PacketHandler = &natlab.SNAT44{
		Machine:           nat1,
		ExternalInterface: nat1WAN,
		TimeNow:           natClock.Now,
		Firewall: &natlab.Firewall{
			TrustedInterface: nat1LAN,
			TimeNow:          natClock.Now,
		},
	}

	derpMap, cleanupDERP := runDERPAndStun(t, logf, mstun, sif.V4())
	defer cleanupDERP()

	ms1 := newMagicStack(t, logger.WithPrefix(logf, "conn1: "), m1, derpMap)
	defer ms1.Close()
	ms2 := newMagicStack(t, logger.WithPrefix(logf, "conn2: "), m2, derpMap)
	defer ms2.Close()

	cleanupMesh := meshStacks(logf, nil, ms1, ms2)
	defer cleanupMesh()

	ipOf := map[*magicStack]netip.Addr{ms1: ms1.IP(), ms2: ms2.IP()}
	logf("IPs: %s %s", ipOf[ms1], ipOf[ms2])

	// pingSeq uniquely tags each ping payload so a wait matches exactly
	// the packet it sent; stale or duplicate deliveries of earlier pings
	// are discarded by whichever wait encounters them.
	var pingSeq atomic.Int64
	// tryPing sends a single uniquely-tagged ICMP ping from src to dst and
	// reports whether that specific packet transited within timeout. It
	// blocks on the tun inbound channel (the delivery event); the timeout
	// is the resend backstop for genuinely lost packets, which produce no
	// event.
	tryPing := func(src, dst *magicStack, timeout time.Duration) bool {
		tag := fmt.Appendf(nil, "direct-path-death-%d", pingSeq.Add(1))
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
	// pingUntil resends tryPing (1s resend backstop per attempt) until one
	// transits or timeout elapses. There are no sleeps: each attempt
	// blocks on the delivery event.
	pingUntil := func(src, dst *magicStack, timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if tryPing(src, dst, min(time.Second, time.Until(deadline))) {
				return true
			}
		}
		return false
	}
	// directAddr reports from's current usable direct path to to's node:
	// a valid, non-relay bestAddr within its trust window. This mirrors
	// the addrForSendLocked condition for sending exclusively via UDP.
	directAddr := func(from, to *magicStack) (addr string, ok bool) {
		from.conn.mu.Lock()
		de, found := from.conn.peerMap.endpointForNodeKey(to.Public())
		from.conn.mu.Unlock()
		if !found {
			return "", false
		}
		de.mu.Lock()
		defer de.mu.Unlock()
		ep := de.bestAddr.epAddr
		if !ep.ap.IsValid() || ep.vni.IsSet() || mono.Now().After(de.trustBestAddrUntil) {
			return "", false
		}
		return ep.String(), true
	}
	// waitDirect blocks until from has a usable direct path to to that
	// differs from notAddr, waking on bestAddr changes (see
	// setBestAddrHookForTests) rather than polling.
	waitDirect := func(from, to *magicStack, notAddr string, timeout time.Duration) (string, bool) {
		deadline := time.After(timeout)
		for {
			if addr, ok := directAddr(from, to); ok && addr != notAddr {
				return addr, true
			}
			select {
			case <-bestAddrChanged:
				// Wakeup only; loop to re-check the actual state.
			case <-deadline:
				return "", false
			}
		}
	}
	// endpointState returns from's magicsock state for its path to to,
	// for use in logs and failure diagnostics.
	endpointState := func(from, to *magicStack) string {
		from.conn.mu.Lock()
		de, ok := from.conn.peerMap.endpointForNodeKey(to.Public())
		from.conn.mu.Unlock()
		if !ok {
			return "(no endpoint in peerMap)"
		}
		de.mu.Lock()
		defer de.mu.Unlock()
		return fmt.Sprintf("bestAddr=%v trusted=%v derpAddr=%v",
			de.bestAddr.epAddr, mono.Now().Before(de.trustBestAddrUntil), de.derpAddr)
	}

	// Phase 1: establish connectivity and a direct path in both
	// directions. (Each side must send through the tun for its session to
	// be active, which is what activates heartbeats and path discovery.)
	if !pingUntil(ms1, ms2, 30*time.Second) {
		t.Fatal("initial ms1->ms2 connectivity never established")
	}
	if !pingUntil(ms2, ms1, 30*time.Second) {
		t.Fatal("initial ms2->ms1 connectivity never established")
	}
	if addr, ok := waitDirect(ms1, ms2, "", 30*time.Second); !ok {
		t.Fatalf("no direct path ms1->ms2 established; ms1 state: %s", endpointState(ms1, ms2))
	} else {
		logf("direct link ms1->ms2 found with addr %s", addr)
	}
	oldAddr, ok := waitDirect(ms2, ms1, "", 30*time.Second)
	if !ok {
		t.Fatalf("no direct path ms2->ms1 established; ms2 state: %s", endpointState(ms2, ms1))
	}
	logf("phase 1 done: direct path ms2->ms1 via %s; ms2 state: %s", oldAddr, endpointState(ms2, ms1))

	// Phase 2: kill the path. Jumping the (frozen) NAT clock expires all
	// NAT mappings and firewall sessions at once: ms1's old WAN ip:port
	// goes dead, and its next outbound packet gets a fresh WAN ip:port.
	killAt := time.Now()
	natClock.Advance(natlab.DefaultMappingTimeout + time.Second)
	logf("NAT mappings and firewall sessions expired (clock advanced %v)", natlab.DefaultMappingTimeout+time.Second)

	// Characterize (but don't assert) the immediate blackhole: ms2 still
	// trusts the dead bestAddr for up to trustUDPAddrDuration, so this
	// ping normally fails. It can sneak through if wireguard-go happens
	// to roam to ms1's new WAN address first (e.g. via a passive
	// keepalive from ms1 arriving from the new mapping).
	if tryPing(ms2, ms1, time.Second) {
		logf("note: ms2->ms1 ping immediately after NAT expiry still transited")
	} else {
		logf("ms2->ms1 blackholed immediately after NAT expiry, as expected")
	}

	// Recovery bound: up to trustUDPAddrDuration (6.5s) of remaining
	// trust in the dead bestAddr, plus a heartbeatInterval (3s) and disco
	// ping timeout (100ms in tests) for the path to be noticed dead and
	// DERP fallback to kick in, plus generous margin for slow CI.
	const recoverDeadline = 15 * time.Second
	if !pingUntil(ms2, ms1, recoverDeadline) {
		t.Fatalf("ms2->ms1 connectivity did not recover within %v of NAT mapping expiry.\n"+
			"Expected: after trustUDPAddrDuration (%v) magicsock sends to both the dead bestAddr and DERP, restoring connectivity via DERP.\n"+
			"A known way this fails is tailscale/tailscale#20082: wireguard-go retains a stale *lazyEndpoint whose frozen src is the dead pre-expiry address (%s), so transmits bypass magicsock's DERP fallback and blackhole.\n"+
			"ms2's magicsock state for ms1: %s",
			recoverDeadline, trustUDPAddrDuration, oldAddr, endpointState(ms2, ms1))
	}
	logf("ms2->ms1 connectivity recovered %v after NAT mapping expiry; ms2 state: %s", time.Since(killAt).Round(time.Millisecond), endpointState(ms2, ms1))

	// Phase 3: a direct path must re-establish, and it must be to ms1's
	// new WAN address: the old mapping is dead, so recovering "directly"
	// to oldAddr would mean the kill never took effect. The wait itself is
	// event-driven (waitDirect); a background pinger keeps traffic flowing
	// meanwhile, as this scenario is about a path dying under an active
	// connection (and outbound traffic to an untrusted bestAddr is itself
	// a path discovery trigger). The pinger's ticker is the traffic
	// cadence of the simulated connection, not a condition poll.
	//
	// natlab allocates the new WAN port at random (Machine.pickEphemPort,
	// rand.IntN over a 32k pool), so the new mapping could theoretically
	// land on the just-freed old port (~1/32768 odds). If that ever
	// happens this wait fails loudly by timing out — it cannot pass
	// wrongly — and a retry won't reproduce it.
	const directDeadline = 30 * time.Second
	pingerStop := make(chan struct{})
	pingerDone := make(chan struct{})
	go func() {
		defer close(pingerDone)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			tryPing(ms2, ms1, 450*time.Millisecond)
			select {
			case <-pingerStop:
				return
			case <-ticker.C:
			}
		}
	}()
	newAddr, ok := waitDirect(ms2, ms1, oldAddr, directDeadline)
	close(pingerStop)
	<-pingerDone
	if !ok {
		t.Fatalf("ms2->ms1 direct path did not re-establish to a new address within %v of NAT mapping expiry (old addr %s); ms2's magicsock state for ms1: %s",
			directDeadline, oldAddr, endpointState(ms2, ms1))
	}
	logf("direct path ms2->ms1 re-established via %s (was %s) %v after NAT mapping expiry", newAddr, oldAddr, time.Since(killAt).Round(time.Millisecond))

	// And traffic still flows, in both directions, on the new path.
	if !pingUntil(ms2, ms1, 10*time.Second) {
		t.Errorf("ms2->ms1 ping failed after direct path re-established; ms2 state: %s", endpointState(ms2, ms1))
	}
	if !pingUntil(ms1, ms2, 10*time.Second) {
		t.Error("ms1->ms2 ping failed after direct path re-established")
	}
}
