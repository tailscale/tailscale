// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"iter"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"tailscale.com/control/controlknobs"
	"tailscale.com/disco"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/util/ringlog"
)

func TestEndpointDiscoPingTimeoutPathHealthModes(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	for _, tt := range []struct {
		name            string
		mode            controlknobs.PathHealthMode
		timeouts        int
		wantBestPresent bool
	}{
		{"off-first-timeout-clears", controlknobs.PathHealthOff, 1, false},
		{"shadow-first-timeout-clears", controlknobs.PathHealthShadow, 1, false},
		{"enforce-first-timeout-retains", controlknobs.PathHealthEnforce, 1, true},
		{"enforce-second-timeout-retains", controlknobs.PathHealthEnforce, 2, true},
		{"enforce-third-spanning-timeout-clears", controlknobs.PathHealthEnforce, 3, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				knobs := new(controlknobs.Knobs)
				knobs.MagicsockPathHealthMode.Store(uint64(tt.mode))
				now := mono.Now()
				st := &endpointState{}
				st.directPathHealth = new(directPathHealth)
				st.directPathHealth.materialize(1)
				de := &endpoint{
					c:                  &Conn{logf: func(string, ...any) {}, controlKnobs: knobs},
					bestAddr:           addrQuality{epAddr: epAddr{ap: addr}},
					trustBestAddrUntil: now.Add(-time.Second),
					sentPing:           make(map[stun.TxID]sentPing),
					endpointState:      map[netip.AddrPort]*endpointState{addr: st},
				}
				for i := range tt.timeouts {
					probeAt := now.Add(time.Duration(i) * heartbeatInterval)
					txid := stun.NewTxID()
					timer := time.NewTimer(time.Hour)
					timer.Stop()
					de.sentPing[txid] = sentPing{
						to:                         epAddr{ap: addr},
						at:                         probeAt,
						timer:                      timer,
						purpose:                    pingHeartbeat,
						directPathHealthGeneration: 1,
					}
					de.discoPingTimeout(txid)
				}
				if got := de.bestAddr.ap.IsValid(); got != tt.wantBestPresent {
					t.Fatalf("best present = %v; want %v; health=%+v", got, tt.wantBestPresent, st.directPathHealth)
				}
			})
		})
	}
}

func TestEnforceGenerationZeroTimeoutCannotClearTrackedSelectedPath(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	now := mono.Now()
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	st := &endpointState{directPathHealth: &directPathHealth{generation: 1, state: directPathHealthy}}
	de := &endpoint{
		c:                  &Conn{logf: func(string, ...any) {}, controlKnobs: knobs},
		bestAddr:           addrQuality{epAddr: epAddr{ap: addr}},
		trustBestAddrUntil: now.Add(-time.Second),
		sentPing:           make(map[stun.TxID]sentPing),
		endpointState:      map[netip.AddrPort]*endpointState{addr: st},
	}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.sentPing[txid] = sentPing{to: epAddr{ap: addr}, at: now, timer: timer, purpose: pingDiscovery, size: 1400}
	de.discoPingTimeout(txid)
	if !de.bestAddr.ap.IsValid() {
		t.Fatal("generation-zero PMTU/legacy timeout cleared health-tracked selected path")
	}
}

func TestEnforceHealthOnlyPongRefreshesSelectedTrust(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	st := &endpointState{directPathHealth: &directPathHealth{generation: 1, state: directPathSuspect}}
	de := &endpoint{
		c:                  &Conn{logf: func(string, ...any) {}, controlKnobs: knobs, peerMap: newPeerMap()},
		bestAddr:           addrQuality{epAddr: epAddr{ap: addr}},
		trustBestAddrUntil: mono.Now().Add(-time.Second),
		sentPing:           make(map[stun.TxID]sentPing),
		endpointState:      map[netip.AddrPort]*endpointState{addr: st},
		debugUpdates:       ringlog.New[EndpointChange](10),
	}
	de.c.discoAtomic.Set(key.NewDisco())
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.sentPing[txid] = sentPing{to: epAddr{ap: addr}, at: mono.Now(), timer: timer, purpose: pingDiscovery, directPathHealthGeneration: 1, directPathHealthOnly: true}
	de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: addr}, &discoInfo{}, epAddr{ap: addr})
	if !mono.Now().Before(de.trustBestAddrUntil) || st.directPathHealth.state != directPathHealthy {
		t.Fatalf("health-only Pong did not restore selected trust/health: trust=%v health=%+v", de.trustBestAddrUntil, st.directPathHealth)
	}
}

func TestEnforceUnreachableSelectsHealthyDirectAlternative(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	failed := netip.MustParseAddrPort("192.0.2.1:7")
	alternative := netip.MustParseAddrPort("192.0.2.2:7")
	now := mono.Now()
	de := &endpoint{
		c:                  &Conn{logf: func(string, ...any) {}, controlKnobs: knobs},
		bestAddr:           addrQuality{epAddr: epAddr{ap: failed}},
		trustBestAddrUntil: now.Add(-time.Second),
		sentPing:           make(map[stun.TxID]sentPing),
		endpointState: map[netip.AddrPort]*endpointState{
			failed:      {directPathHealth: &directPathHealth{generation: 1, state: directPathSuspect, misses: 2, firstMissAt: now.Add(-2 * heartbeatInterval), haveProbe: true, lastProbeAt: now.Add(-heartbeatInterval)}},
			alternative: {directPathHealth: &directPathHealth{generation: 2, state: directPathHealthy, haveProbe: true, lastProbeAt: now}, recentPongs: []pongReply{{latency: time.Millisecond, pongAt: now, from: alternative}}},
		},
	}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.sentPing[txid] = sentPing{to: epAddr{ap: failed}, at: now, timer: timer, purpose: pingHeartbeat, directPathHealthGeneration: 1}
	de.discoPingTimeout(txid)
	if de.bestAddr.ap != alternative {
		t.Fatalf("best = %v; want healthy direct alternative %v", de.bestAddr.ap, alternative)
	}
}

func TestEnforceUnreachableRejectsAlternativeWithStalePongHistory(t *testing.T) {
	failed := netip.MustParseAddrPort("192.0.2.1:7")
	alternative := netip.MustParseAddrPort("192.0.2.2:7")
	now := mono.Now()
	de := &endpoint{endpointState: map[netip.AddrPort]*endpointState{
		failed: {directPathHealth: &directPathHealth{generation: 1, state: directPathUnreachable}},
		alternative: {
			directPathHealth: &directPathHealth{generation: 2, state: directPathHealthy},
			recentPongs:      []pongReply{{latency: time.Millisecond, pongAt: now.Add(-time.Minute), from: alternative}},
		},
	}}
	if de.selectHealthyAlternativeLocked(failed) {
		t.Fatal("selected alternative using Pong history from before current health generation")
	}
	st := de.endpointState[alternative]
	st.directPathHealth.haveProbe = true
	st.directPathHealth.lastProbeAt = now
	st.recentPongs[0].pongAt = now.Add(-time.Nanosecond)
	if de.selectHealthyAlternativeLocked(failed) {
		t.Fatal("selected alternative using Pong older than current generation probe")
	}
}

func TestDirectPathHealthSize(t *testing.T) {
	if got := unsafe.Sizeof(directPathHealth{}); got > 64 {
		t.Fatalf("directPathHealth is %d bytes; want at most 64", got)
	}
}

func TestEndpointStateUsesHealthPointer(t *testing.T) {
	if unsafe.Sizeof(endpointState{}.directPathHealth) != unsafe.Sizeof(uintptr(0)) {
		t.Fatal("endpointState does not store health state by pointer")
	}
}

func BenchmarkDirectPathHealthReduce(b *testing.B) {
	var h directPathHealth
	h.materialize(1)
	e := directPathHealthEvent{generation: 1, outcome: directPathHealthPong}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		e.probeAt = mono.Time(i + 1)
		e.at = e.probeAt
		h.reduce(e)
	}
}

func TestAuthenticatedDirectRecvIsInboundOnlyEvidence(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	const generation = 41
	t0 := mono.Time(600 * time.Second)
	st := &endpointState{}
	st.directPathHealth = new(directPathHealth)
	st.directPathHealth.materialize(generation)
	de := &endpoint{endpointState: map[netip.AddrPort]*endpointState{addr: st}}

	de.noteAuthenticatedDirectRecvLocked(epAddr{ap: addr}, generation, t0.Add(heartbeatInterval+time.Nanosecond))
	if st.directPathHealth.state != directPathHealthy || st.directPathHealth.misses != 0 {
		t.Fatalf("authenticated receive promoted or mutated liveness: %+v", st.directPathHealth)
	}
	for _, probeAt := range []mono.Time{t0, t0.Add(heartbeatInterval), t0.Add(2 * heartbeatInterval)} {
		de.reduceDirectPathHealthLocked(sentPing{
			to:                         epAddr{ap: addr},
			at:                         probeAt,
			directPathHealthGeneration: generation,
		}, discoPingTimedOut, probeAt.Add(pingTimeoutDuration), false)
	}
	if st.directPathHealth.state != directPathSuspect {
		t.Fatalf("state = %v; want suspect while authenticated inbound is fresh", st.directPathHealth.state)
	}
}

func TestStaleAuthenticatedDirectRecvDoesNotPreventRetirement(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	const generation = 43
	t0 := mono.Time(700 * time.Second)
	st := &endpointState{}
	st.directPathHealth = new(directPathHealth)
	st.directPathHealth.materialize(generation)
	de := &endpoint{endpointState: map[netip.AddrPort]*endpointState{addr: st}}
	de.noteAuthenticatedDirectRecvLocked(epAddr{ap: addr}, generation, t0.Add(time.Nanosecond))

	for _, probeAt := range []mono.Time{t0, t0.Add(heartbeatInterval), t0.Add(2 * heartbeatInterval)} {
		decision := de.reduceDirectPathHealthLocked(sentPing{
			to:                         epAddr{ap: addr},
			at:                         probeAt,
			directPathHealthGeneration: generation,
		}, discoPingTimedOut, probeAt.Add(pingTimeoutDuration), false)
		if probeAt == t0.Add(2*heartbeatInterval) && !decision.clearCandidate {
			t.Fatal("stale authenticated receive prevented dead-path retirement")
		}
	}
	if st.directPathHealth.state != directPathUnreachable {
		t.Fatalf("state = %v; want unreachable", st.directPathHealth.state)
	}
}

func TestLazyEndpointAuthenticatedEvidenceRequiresMatchingPeer(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	peer := key.NewNode().Public()
	st := &endpointState{}
	st.directPathHealth = new(directPathHealth)
	st.directPathHealth.materialize(1)
	st.directPathHealth.state = directPathSuspect
	de := &endpoint{publicKey: peer, endpointState: map[netip.AddrPort]*endpointState{addr: st}}
	le := &lazyEndpoint{c: &Conn{}, maybeEP: de, src: epAddr{ap: addr}, pathHealthEvidence: true, pathHealthGeneration: 1}

	raw32 := func(k key.NodePublic) (ret [32]byte) {
		copy(ret[:], k.AppendTo(nil))
		return ret
	}
	le.FromPeer(raw32(key.NewNode().Public()))
	if st.directPathHealth.haveAuthenticatedRecv {
		t.Fatal("wrong peer key recorded authenticated evidence")
	}
	le.FromPeer(raw32(peer))
	if !st.directPathHealth.haveAuthenticatedRecv {
		t.Fatal("matching peer key did not record authenticated evidence")
	}
}

func TestLazyEndpointStaleGenerationDoesNotRecordEvidence(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	peer := key.NewNode().Public()
	st := &endpointState{}
	st.directPathHealth = new(directPathHealth)
	st.directPathHealth.materialize(2)
	st.directPathHealth.state = directPathSuspect
	de := &endpoint{publicKey: peer, endpointState: map[netip.AddrPort]*endpointState{addr: st}}
	le := &lazyEndpoint{c: &Conn{}, maybeEP: de, src: epAddr{ap: addr}, pathHealthEvidence: true, pathHealthGeneration: 1}
	var raw [32]byte
	copy(raw[:], peer.AppendTo(nil))
	le.FromPeer(raw)
	if st.directPathHealth.haveAuthenticatedRecv {
		t.Fatal("stale generation recorded authenticated evidence")
	}
}

func TestDirectPathHealthTimeoutThreshold(t *testing.T) {
	var h directPathHealth
	const generation = 7
	t0 := mono.Time(100 * time.Second)
	h.materialize(generation)

	for i, at := range []mono.Time{t0, t0.Add(heartbeatInterval), t0.Add(2 * heartbeatInterval)} {
		got := h.reduce(directPathHealthEvent{
			generation: generation,
			probeAt:    at.Add(-pingTimeoutDuration),
			at:         at,
			outcome:    directPathHealthTimeout,
		})
		wantClear := i == 2
		if got.clearCandidate != wantClear {
			t.Fatalf("timeout %d: clearCandidate = %v, want %v", i+1, got.clearCandidate, wantClear)
		}
		wantState := directPathSuspect
		if wantClear {
			wantState = directPathUnreachable
		}
		if h.state != wantState {
			t.Fatalf("timeout %d: state = %v, want %v", i+1, h.state, wantState)
		}
	}
}

func TestDirectPathHealthClearDecisionIsOneShot(t *testing.T) {
	var h directPathHealth
	const generation = 8
	t0 := mono.Time(150 * time.Second)
	h.materialize(generation)
	for i := range 3 {
		probeAt := t0.Add(time.Duration(i) * heartbeatInterval)
		h.reduce(directPathHealthEvent{generation: generation, probeAt: probeAt, at: probeAt.Add(pingTimeoutDuration), outcome: directPathHealthTimeout})
	}
	probeAt := t0.Add(3 * heartbeatInterval)
	if d := h.reduce(directPathHealthEvent{generation: generation, probeAt: probeAt, at: probeAt.Add(pingTimeoutDuration), outcome: directPathHealthTimeout}); d.clearCandidate {
		t.Fatal("unreachable candidate emitted a second clear decision")
	}
}

func TestDirectPathHealthThirdTimeoutRequiresHeartbeatSpan(t *testing.T) {
	var h directPathHealth
	const generation = 3
	t0 := mono.Time(200 * time.Second)
	h.materialize(generation)

	for i, at := range []mono.Time{t0, t0.Add(time.Second), t0.Add(2 * heartbeatInterval).Add(-time.Nanosecond)} {
		d := h.reduce(directPathHealthEvent{
			generation: generation,
			probeAt:    at.Add(-pingTimeoutDuration),
			at:         at,
			outcome:    directPathHealthTimeout,
		})
		if d.clearCandidate {
			t.Fatalf("timeout %d unexpectedly cleared candidate", i+1)
		}
	}
	if h.state != directPathSuspect {
		t.Fatalf("state = %v, want Suspect", h.state)
	}

	at := t0.Add(2 * heartbeatInterval)
	d := h.reduce(directPathHealthEvent{
		generation: generation,
		probeAt:    at.Add(-pingTimeoutDuration),
		at:         at,
		outcome:    directPathHealthTimeout,
	})
	if !d.clearCandidate || h.state != directPathUnreachable {
		t.Fatalf("fourth independent timeout: decision=%+v state=%v; want clear and Unreachable", d, h.state)
	}
}

func TestDirectPathHealthPongResetsMisses(t *testing.T) {
	var h directPathHealth
	const generation = 9
	t0 := mono.Time(300 * time.Second)
	h.materialize(generation)

	for _, at := range []mono.Time{t0, t0.Add(heartbeatInterval)} {
		h.reduce(directPathHealthEvent{generation: generation, probeAt: at, at: at.Add(pingTimeoutDuration), outcome: directPathHealthTimeout})
	}
	pongAt := t0.Add(2 * heartbeatInterval)
	h.reduce(directPathHealthEvent{generation: generation, probeAt: pongAt, at: pongAt.Add(time.Millisecond), outcome: directPathHealthPong})
	if h.state != directPathHealthy || h.misses != 0 {
		t.Fatalf("after pong: state=%v misses=%d; want Healthy and zero", h.state, h.misses)
	}

	timeoutAt := t0.Add(3 * heartbeatInterval)
	d := h.reduce(directPathHealthEvent{generation: generation, probeAt: timeoutAt, at: timeoutAt.Add(pingTimeoutDuration), outcome: directPathHealthTimeout})
	if d.clearCandidate || h.state != directPathSuspect || h.misses != 1 {
		t.Fatalf("after new timeout: decision=%+v state=%v misses=%d; want retained Suspect with one miss", d, h.state, h.misses)
	}
}

func TestDirectPathHealthIgnoresStaleDuplicateAndWrongGeneration(t *testing.T) {
	var h directPathHealth
	const generation = 11
	t0 := mono.Time(400 * time.Second)
	h.materialize(generation)
	first := directPathHealthEvent{generation: generation, probeAt: t0, at: t0.Add(pingTimeoutDuration), outcome: directPathHealthTimeout}
	h.reduce(first)

	for _, e := range []directPathHealthEvent{
		first,
		{generation: generation, probeAt: t0.Add(-time.Nanosecond), at: t0.Add(time.Second), outcome: directPathHealthPong},
		{generation: generation + 1, probeAt: t0.Add(heartbeatInterval), at: t0.Add(heartbeatInterval + pingTimeoutDuration), outcome: directPathHealthTimeout},
	} {
		if d := h.reduce(e); d.clearCandidate {
			t.Fatalf("ignored event %+v requested clear", e)
		}
	}
	if h.state != directPathSuspect || h.misses != 1 || h.lastProbeAt != t0 {
		t.Fatalf("state changed after ignored events: %+v", h)
	}
}

func TestEndpointMaterializesNewCandidateGeneration(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthShadow))
	de := &endpoint{
		c:             &Conn{controlKnobs: knobs},
		endpointState: make(map[netip.AddrPort]*endpointState),
		debugUpdates:  ringlog.New[EndpointChange](10),
	}
	first := netip.MustParseAddrPort("192.0.2.1:7")
	second := netip.MustParseAddrPort("192.0.2.2:7")
	de.setEndpointsLocked(netipAddrPorts{first})
	firstGeneration := de.endpointState[first].directPathHealth.generation
	if firstGeneration == 0 {
		t.Fatal("first candidate has zero generation")
	}
	de.setEndpointsLocked(netipAddrPorts{second})
	secondGeneration := de.endpointState[second].directPathHealth.generation
	if secondGeneration == 0 || secondGeneration == firstGeneration {
		t.Fatalf("second generation = %d, first = %d", secondGeneration, firstGeneration)
	}
}

func TestEndpointDoesNotMaterializeHealthWhenOff(t *testing.T) {
	de := &endpoint{
		c:             &Conn{},
		endpointState: make(map[netip.AddrPort]*endpointState),
		debugUpdates:  ringlog.New[EndpointChange](10),
	}
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	de.setEndpointsLocked(netipAddrPorts{addr})
	if got := de.endpointState[addr].directPathHealth; got != nil {
		t.Fatalf("off mode materialized health %+v", got)
	}
}

func TestEndpointLazilyMaterializesExistingCandidateWhenEnabled(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	de := &endpoint{
		c:             &Conn{controlKnobs: knobs},
		endpointState: map[netip.AddrPort]*endpointState{addr: {}},
	}
	if got := de.directPathHealthProbeGenerationLocked(epAddr{ap: addr}, pingHeartbeat, 0); got != 0 {
		t.Fatalf("off mode generation = %d; want 0", got)
	}
	knobs.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
	if got := de.directPathHealthProbeGenerationLocked(epAddr{ap: addr}, pingHeartbeat, 0); got == 0 {
		t.Fatal("enabled mode did not materialize existing candidate")
	}
	knobs.UpdateFromNodeAttributes(nil)
	if got := de.directPathHealthProbeGenerationLocked(epAddr{ap: addr}, pingHeartbeat, 0); got != 0 {
		t.Fatalf("disabled mode generation = %d; want 0", got)
	}
	if de.endpointState[addr].directPathHealth != nil || de.directPathHealthCount != 0 {
		t.Fatal("disabling mode retained stale health state")
	}
	knobs.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
	if got := de.directPathHealthProbeGenerationLocked(epAddr{ap: addr}, pingHeartbeat, 0); got == 0 {
		t.Fatal("re-enabling mode did not start fresh health state")
	}
}

func TestEndpointModeEpochResetsAcrossUnobservedOffTransition(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	de := &endpoint{c: &Conn{controlKnobs: knobs}, endpointState: map[netip.AddrPort]*endpointState{addr: {}}}
	oldGeneration := de.directPathHealthProbeGenerationLocked(epAddr{ap: addr}, pingHeartbeat, 0)
	de.endpointState[addr].directPathHealth.misses = 2
	knobs.UpdateFromNodeAttributes(nil)
	knobs.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
	newGeneration := de.directPathHealthProbeGenerationLocked(epAddr{ap: addr}, pingHeartbeat, 0)
	if newGeneration == 0 || newGeneration == oldGeneration || de.endpointState[addr].directPathHealth.misses != 0 {
		t.Fatalf("unobserved off transition retained stale health: old=%d new=%d state=%+v", oldGeneration, newGeneration, de.endpointState[addr].directPathHealth)
	}
}

func TestEndpointResetNeverReissuesCapturedGeneration(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	st := new(endpointState)
	de := &endpoint{c: &Conn{controlKnobs: knobs}, endpointState: map[netip.AddrPort]*endpointState{addr: st}}
	de.materializeDirectPathHealthLocked(&st.directPathHealth)
	de.noteConnectivityChange()
	captured := st.directPathHealth.generation
	knobs.UpdateFromNodeAttributes(nil)
	knobs.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
	got := de.directPathHealthProbeGenerationLocked(epAddr{ap: addr}, pingHeartbeat, 0)
	if got == captured {
		t.Fatalf("generation %d was reissued after reset and mode epoch change", got)
	}
}

func TestDirectPathHealthCandidateBound(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	de := &endpoint{c: &Conn{controlKnobs: knobs}, endpointState: make(map[netip.AddrPort]*endpointState)}
	for i := range maxDirectPathHealthCandidates + 1 {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 7)
		st := new(endpointState)
		de.endpointState[addr] = st
		de.materializeDirectPathHealthLocked(&st.directPathHealth)
	}
	if de.directPathHealthCount != maxDirectPathHealthCandidates {
		t.Fatalf("health candidate count = %d; want %d", de.directPathHealthCount, maxDirectPathHealthCandidates)
	}
	last := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(maxDirectPathHealthCandidates + 1)}), 7)
	if de.endpointState[last].directPathHealth != nil {
		t.Fatal("candidate beyond bound materialized health state")
	}
	first := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), 7)
	de.debugUpdates = ringlog.New[EndpointChange](10)
	de.deleteEndpointLocked("test", first)
	de.materializeDirectPathHealthLocked(&de.endpointState[last].directPathHealth)
	if de.endpointState[last].directPathHealth == nil || de.directPathHealthCount != maxDirectPathHealthCandidates {
		t.Fatal("deleting a tracked candidate did not free health capacity")
	}
}

func TestDirectPathHealthBudgetPrioritizesSelectedCandidate(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	de := &endpoint{c: &Conn{controlKnobs: knobs, logf: func(string, ...any) {}}, endpointState: make(map[netip.AddrPort]*endpointState)}
	for i := range maxDirectPathHealthCandidates {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 7)
		st := &endpointState{lastGotPing: time.Now()}
		de.endpointState[addr] = st
		de.materializeDirectPathHealthLocked(&st.directPathHealth)
	}
	selected := netip.MustParseAddrPort("198.51.100.1:7")
	de.endpointState[selected] = new(endpointState)
	de.bestAddr = addrQuality{epAddr: epAddr{ap: selected}}
	de.rebalanceDirectPathHealthLocked()
	if de.endpointState[selected].directPathHealth == nil {
		t.Fatal("selected candidate did not receive bounded health state")
	}
	if de.directPathHealthCount != maxDirectPathHealthCandidates {
		t.Fatalf("health candidate count = %d; want %d", de.directPathHealthCount, maxDirectPathHealthCandidates)
	}
	de.trustBestAddrUntil = mono.Time(1)
	de.sentPing = make(map[stun.TxID]sentPing)
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.sentPing[txid] = sentPing{
		to:                         epAddr{ap: selected},
		at:                         mono.Now(),
		timer:                      timer,
		purpose:                    pingHeartbeat,
		directPathHealthGeneration: de.endpointState[selected].directPathHealth.generation,
	}
	de.discoPingTimeout(txid)
	if !de.bestAddr.ap.IsValid() {
		t.Fatal("selected candidate was cleared by its first timeout after budget rebalance")
	}
}

func TestDirectPathHealthBudgetPrioritizesNetmapCandidates(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	de := &endpoint{c: &Conn{controlKnobs: knobs}, endpointState: make(map[netip.AddrPort]*endpointState)}
	for i := range maxDirectPathHealthCandidates {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 7)
		st := &endpointState{lastGotPing: time.Now()}
		de.endpointState[addr] = st
		de.materializeDirectPathHealthLocked(&st.directPathHealth)
	}
	netmapAddr := netip.MustParseAddrPort("198.51.100.2:7")
	de.setEndpointsLocked(netipAddrPorts{netmapAddr})
	if de.endpointState[netmapAddr].directPathHealth == nil {
		t.Fatal("netmap candidate did not receive bounded health state")
	}
}

func TestDirectPathHealthBudgetTreatsCallMeMaybeAsRuntime(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	de := &endpoint{c: &Conn{controlKnobs: knobs}, endpointState: make(map[netip.AddrPort]*endpointState)}
	for i := range maxDirectPathHealthCandidates {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 7)
		de.endpointState[addr] = &endpointState{callMeMaybeTime: time.Now(), index: indexSentinelDeleted}
	}
	netmapAddr := netip.MustParseAddrPort("198.51.100.3:7")
	de.endpointState[netmapAddr] = &endpointState{index: 0}
	de.rebalanceDirectPathHealthLocked()
	if de.endpointState[netmapAddr].directPathHealth == nil {
		t.Fatal("CallMeMaybe candidates displaced netmap candidate")
	}
}

func TestDirectPathHealthBudgetPrefersRecentRuntimeEvidence(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	de := &endpoint{c: &Conn{controlKnobs: knobs}, endpointState: make(map[netip.AddrPort]*endpointState)}
	now := time.Now()
	var newest netip.AddrPort
	for i := range maxDirectPathHealthCandidates + 1 {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 7)
		de.endpointState[addr] = &endpointState{lastGotPing: now.Add(time.Duration(i) * time.Second), index: indexSentinelDeleted}
		newest = addr
	}
	de.rebalanceDirectPathHealthLocked()
	if de.endpointState[newest].directPathHealth == nil {
		t.Fatal("newest runtime evidence was excluded from health budget")
	}
	oldest := netip.MustParseAddrPort("192.0.2.1:7")
	if de.endpointState[oldest].directPathHealth != nil {
		t.Fatal("oldest unconfirmed runtime candidate retained health budget")
	}
}

func TestDiscoKeyChangeInvalidatesHealthGenerationAndPendingProbe(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	oldDisco := key.NewDisco().Public()
	de := &endpoint{
		c:             &Conn{controlKnobs: knobs, logf: func(string, ...any) {}},
		endpointState: map[netip.AddrPort]*endpointState{addr: {index: 0}},
		sentPing:      make(map[stun.TxID]sentPing),
		debugUpdates:  ringlog.New[EndpointChange](10),
	}
	de.updateDiscoKey(oldDisco)
	oldGeneration := de.directPathHealthProbeGenerationLocked(epAddr{ap: addr}, pingHeartbeat, 0)
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.sentPing[txid] = sentPing{to: epAddr{ap: addr}, timer: timer, purpose: pingHeartbeat, directPathHealthGeneration: oldGeneration}
	newDisco := key.NewDisco().Public()
	n := (&tailcfg.Node{DiscoKey: newDisco, Endpoints: []netip.AddrPort{addr}}).View()
	de.updateFromNode(n, false, false)
	newGeneration := de.endpointState[addr].directPathHealth.generation
	if newGeneration == oldGeneration || newGeneration == 0 {
		t.Fatalf("DiscoKey change generation: old=%d new=%d", oldGeneration, newGeneration)
	}
	if _, ok := de.sentPing[txid]; ok {
		t.Fatal("DiscoKey change retained old pending health probe")
	}
}

func TestSilentDiscoEnforceSchedulesHeartbeat(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	de := &endpoint{c: &Conn{controlKnobs: knobs}, heartbeatDisabled: true}
	de.noteTxActivityExtTriggerLocked(mono.Now())
	if de.heartBeatTimer != nil {
		de.heartBeatTimer.Stop()
		t.Fatal("silent disco scheduled heartbeat while path health was off")
	}
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	de.noteTxActivityExtTriggerLocked(mono.Now())
	if de.heartBeatTimer == nil {
		t.Fatal("silent disco enforce did not schedule health heartbeat")
	}
	de.heartBeatTimer.Stop()
}

type netipAddrPorts []netip.AddrPort

func (s netipAddrPorts) All() iter.Seq2[int, netip.AddrPort] {
	return slices.All(s)
}

func TestEndpointDirectPathHealthProbeGeneration(t *testing.T) {
	direct := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	peerRelay := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:7")}
	peerRelay.vni.Set(1)
	derp := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1)}
	const generation = 17
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthShadow))
	de := &endpoint{c: &Conn{controlKnobs: knobs}, endpointState: map[netip.AddrPort]*endpointState{
		direct.ap: {directPathHealth: &directPathHealth{generation: generation}},
	}}

	for _, tt := range []struct {
		name    string
		to      epAddr
		purpose discoPingPurpose
		ordinal int
		want    uint32
	}{
		{"discovery-base", direct, pingDiscovery, 0, generation},
		{"discovery-MTU", direct, pingDiscovery, 1, 0},
		{"heartbeat-base", direct, pingHeartbeat, 0, generation},
		{"CLI", direct, pingCLI, 0, 0},
		{"UDP-lifetime", direct, pingHeartbeatForUDPLifetime, 0, 0},
		{"DERP", derp, pingDiscovery, 0, 0},
		{"peer-relay", peerRelay, pingDiscovery, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := de.directPathHealthProbeGenerationLocked(tt.to, tt.purpose, tt.ordinal); got != tt.want {
				t.Fatalf("generation = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDiscoveryMTUBurstHasUnpaddedBaseHealthProbe(t *testing.T) {
	direct := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	sizes, mtuProbe := discoPingSizes(direct, pingDiscovery, 0, true, controlknobs.PathHealthEnforce)
	if !mtuProbe {
		t.Fatal("discovery MTU probing was not enabled")
	}
	if len(sizes) < 2 || sizes[0] != 0 {
		t.Fatalf("ping sizes = %v; want unpadded base followed by MTU probes", sizes)
	}
}

func TestDiscoveryMTUBurstOffPreservesLegacySizes(t *testing.T) {
	direct := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	sizes, mtuProbe := discoPingSizes(direct, pingDiscovery, 0, true, controlknobs.PathHealthOff)
	if !mtuProbe || len(sizes) == 0 || sizes[0] == 0 {
		t.Fatalf("off mode sizes = %v, mtuProbe=%v; want legacy MTU probes without added base ping", sizes, mtuProbe)
	}
}

func TestDiscoveryWithoutPMTUPreservesPromotableLegacyProbe(t *testing.T) {
	direct := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	sizes, _ := discoPingSizes(direct, pingDiscovery, 0, false, controlknobs.PathHealthEnforce)
	if len(sizes) != 2 || sizes[0] != 0 || sizes[1] != 0 {
		t.Fatalf("sizes = %v; want separate health-only and legacy discovery probes", sizes)
	}
}

func TestBadEndpointEnforceMarksSuspectWithoutClearingBest(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.UpdateFromNodeAttributes(tailcfg.NodeCapMap{tailcfg.NodeAttrMagicsockPathHealthEnforce: nil})
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	st := new(endpointState)
	de := &endpoint{
		c:             &Conn{controlKnobs: knobs},
		bestAddr:      addrQuality{epAddr: addr},
		endpointState: map[netip.AddrPort]*endpointState{addr.ap: st},
	}
	de.materializeDirectPathHealthLocked(&st.directPathHealth)
	de.noteBadEndpoint(addr)
	if !de.bestAddr.ap.IsValid() || st.directPathHealth.state != directPathSuspect {
		t.Fatalf("bad endpoint: best=%v health=%+v; want retained Suspect", de.bestAddr, st.directPathHealth)
	}
}

func TestShadowHealthOnlyPongDoesNotPromotePath(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthShadow))
	pm := newPeerMap()
	c := &Conn{logf: func(string, ...any) {}, controlKnobs: knobs, peerMap: pm}
	c.discoAtomic.Set(key.NewDisco())
	st := &endpointState{}
	st.directPathHealth = new(directPathHealth)
	st.directPathHealth.materialize(1)
	de := &endpoint{c: c, sentPing: make(map[stun.TxID]sentPing), endpointState: map[netip.AddrPort]*endpointState{addr: st}}
	txid := stun.NewTxID()
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	de.sentPing[txid] = sentPing{to: epAddr{ap: addr}, at: mono.Now(), timer: timer, purpose: pingDiscovery, directPathHealthGeneration: 1, directPathHealthOnly: true}
	if !de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: addr}, &discoInfo{}, epAddr{ap: addr}) {
		t.Fatal("Pong TxID was not recognized")
	}
	if de.bestAddr.ap.IsValid() || de.trustBestAddrUntil != 0 {
		t.Fatalf("shadow health-only pong changed path: best=%v trust=%v", de.bestAddr, de.trustBestAddrUntil)
	}
}

func TestEndpointDiscoPingTimeoutFeedsDirectPathHealthWithoutChangingLegacy(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	const generation = 29
	synctest.Test(t, func(t *testing.T) {
		now := mono.Now()
		st := &endpointState{}
		st.directPathHealth = new(directPathHealth)
		st.directPathHealth.materialize(generation)
		knobs := new(controlknobs.Knobs)
		knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthShadow))
		de := &endpoint{
			c:                  &Conn{logf: func(string, ...any) {}, controlKnobs: knobs},
			bestAddr:           addrQuality{epAddr: epAddr{ap: addr}},
			trustBestAddrUntil: now.Add(-time.Second),
			sentPing:           make(map[stun.TxID]sentPing),
			endpointState:      map[netip.AddrPort]*endpointState{addr: st},
		}
		txid := stun.NewTxID()
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		de.sentPing[txid] = sentPing{
			to:                         epAddr{ap: addr},
			at:                         now.Add(-pingTimeoutDuration),
			timer:                      timer,
			purpose:                    pingHeartbeat,
			directPathHealthGeneration: generation,
		}

		de.discoPingTimeout(txid)
		if st.directPathHealth.state != directPathSuspect || st.directPathHealth.misses != 1 {
			t.Fatalf("health after timeout: %+v", st.directPathHealth)
		}
		if de.bestAddr.ap.IsValid() {
			t.Fatal("legacy timeout behavior did not clear expired bestAddr")
		}
	})
}

func TestEndpointHandlePongFeedsDirectPathHealth(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	const generation = 31
	synctest.Test(t, func(t *testing.T) {
		now := mono.Now()
		st := &endpointState{}
		st.directPathHealth = new(directPathHealth)
		st.directPathHealth.materialize(generation)
		st.directPathHealth.reduce(directPathHealthEvent{
			generation: generation,
			probeAt:    now.Add(-2 * heartbeatInterval),
			at:         now.Add(-2*heartbeatInterval + pingTimeoutDuration),
			outcome:    directPathHealthTimeout,
		})
		pm := newPeerMap()
		knobs := new(controlknobs.Knobs)
		knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthShadow))
		c := &Conn{logf: func(string, ...any) {}, peerMap: pm, controlKnobs: knobs}
		c.discoAtomic.Set(key.NewDisco())
		de := &endpoint{
			c:                  c,
			bestAddr:           addrQuality{epAddr: epAddr{ap: addr}},
			trustBestAddrUntil: now.Add(time.Hour),
			sentPing:           make(map[stun.TxID]sentPing),
			endpointState:      map[netip.AddrPort]*endpointState{addr: st},
			debugUpdates:       ringlog.New[EndpointChange](10),
		}
		txid := stun.NewTxID()
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		de.sentPing[txid] = sentPing{
			to:                         epAddr{ap: addr},
			at:                         now.Add(-time.Millisecond),
			timer:                      timer,
			purpose:                    pingHeartbeat,
			directPathHealthGeneration: generation,
		}

		if !de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: addr}, &discoInfo{}, epAddr{ap: addr}) {
			t.Fatal("Pong TxID was not recognized")
		}
		if st.directPathHealth.state != directPathHealthy || st.directPathHealth.misses != 0 {
			t.Fatalf("health after direct base Pong: %+v", st.directPathHealth)
		}
	})
}

func TestEndpointPongFromDifferentSourceModeSemantics(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	other := netip.MustParseAddrPort("192.0.2.2:7")
	peerRelay := epAddr{ap: other}
	peerRelay.vni.Set(1)
	const generation = 37
	for _, tt := range []struct {
		name        string
		mode        controlknobs.PathHealthMode
		src         epAddr
		wantPromote bool
	}{
		{"shadow-preserves-legacy", controlknobs.PathHealthShadow, epAddr{ap: other}, true},
		{"enforce-rejects-wrong-direct-source", controlknobs.PathHealthEnforce, epAddr{ap: other}, false},
		{"enforce-rejects-peer-relay-source", controlknobs.PathHealthEnforce, peerRelay, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := mono.Now()
				st := &endpointState{}
				st.directPathHealth = new(directPathHealth)
				st.directPathHealth.materialize(generation)
				st.directPathHealth.reduce(directPathHealthEvent{
					generation: generation,
					probeAt:    now.Add(-heartbeatInterval),
					at:         now,
					outcome:    directPathHealthTimeout,
				})
				pm := newPeerMap()
				knobs := new(controlknobs.Knobs)
				knobs.MagicsockPathHealthMode.Store(uint64(tt.mode))
				c := &Conn{logf: func(string, ...any) {}, peerMap: pm, controlKnobs: knobs}
				c.discoAtomic.Set(key.NewDisco())
				de := &endpoint{
					c:             c,
					sentPing:      make(map[stun.TxID]sentPing),
					endpointState: map[netip.AddrPort]*endpointState{addr: st, other: {}},
					debugUpdates:  ringlog.New[EndpointChange](10),
				}
				txid := stun.NewTxID()
				timer := time.NewTimer(time.Hour)
				timer.Stop()
				de.sentPing[txid] = sentPing{
					to:                         epAddr{ap: addr},
					at:                         now,
					timer:                      timer,
					purpose:                    pingHeartbeat,
					directPathHealthGeneration: generation,
				}
				if !de.handlePongConnLocked(&disco.Pong{TxID: txid, Src: other}, &discoInfo{}, tt.src) {
					t.Fatal("Pong TxID was not recognized")
				}
				if st.directPathHealth.state != directPathSuspect || st.directPathHealth.misses != 1 {
					t.Fatalf("wrong-source pong changed health: %+v", st.directPathHealth)
				}
				if got := de.bestAddr.ap.IsValid(); got != tt.wantPromote {
					t.Fatalf("wrong-source pong promoted=%v, want %v; best=%v trust=%v", got, tt.wantPromote, de.bestAddr, de.trustBestAddrUntil)
				}
			})
		})
	}
}

func TestEndpointLateValidPongRecoversAfterTimeout(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	const generation = 39
	synctest.Test(t, func(t *testing.T) {
		knobs := new(controlknobs.Knobs)
		knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
		pm := newPeerMap()
		c := &Conn{logf: func(string, ...any) {}, peerMap: pm, controlKnobs: knobs}
		c.discoAtomic.Set(key.NewDisco())
		now := mono.Now()
		st := &endpointState{}
		st.directPathHealth = new(directPathHealth)
		st.directPathHealth.materialize(generation)
		de := &endpoint{
			c:                  c,
			bestAddr:           addrQuality{epAddr: epAddr{ap: addr}},
			trustBestAddrUntil: now.Add(-time.Second),
			sentPing:           make(map[stun.TxID]sentPing),
			endpointState:      map[netip.AddrPort]*endpointState{addr: st},
			debugUpdates:       ringlog.New[EndpointChange](10),
		}
		var lastTxID stun.TxID
		for i := range 3 {
			probeAt := now.Add(time.Duration(i) * heartbeatInterval)
			lastTxID = stun.NewTxID()
			timer := time.NewTimer(time.Hour)
			timer.Stop()
			de.sentPing[lastTxID] = sentPing{
				to:                         epAddr{ap: addr},
				at:                         probeAt,
				timer:                      timer,
				purpose:                    pingHeartbeat,
				directPathHealthGeneration: generation,
			}
			de.discoPingTimeout(lastTxID)
		}
		if st.directPathHealth.state != directPathUnreachable || de.bestAddr.ap.IsValid() {
			t.Fatalf("after timeout: health=%+v best=%v; want unreachable with no best", st.directPathHealth, de.bestAddr)
		}
		if !de.handlePongConnLocked(&disco.Pong{TxID: lastTxID, Src: addr}, &discoInfo{}, epAddr{ap: addr}) {
			t.Fatal("late valid Pong TxID was not recognized")
		}
		if st.directPathHealth.state != directPathHealthy || !de.bestAddr.ap.IsValid() {
			t.Fatalf("after late Pong: health=%+v best=%v; want healthy direct path", st.directPathHealth, de.bestAddr)
		}
	})
}

func TestEnforceSilentDiscoPreDecryptActivityDoesNotRefreshTrust(t *testing.T) {
	knobs := new(controlknobs.Knobs)
	knobs.MagicsockPathHealthMode.Store(uint64(controlknobs.PathHealthEnforce))
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	de := &endpoint{
		c:                  &Conn{controlKnobs: knobs},
		heartbeatDisabled:  true,
		bestAddr:           addrQuality{epAddr: addr},
		trustBestAddrUntil: mono.Time(10),
	}
	de.noteRecvActivity(addr, mono.Time(100))
	if de.trustBestAddrUntil != mono.Time(10) {
		t.Fatalf("pre-decrypt activity refreshed enforce trust to %v", de.trustBestAddrUntil)
	}
}

func TestEndpointReduceDirectPathHealthLocked(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:7")
	const generation = 23
	st := &endpointState{}
	st.directPathHealth = new(directPathHealth)
	st.directPathHealth.materialize(generation)
	de := &endpoint{endpointState: map[netip.AddrPort]*endpointState{addr: st}}
	t0 := mono.Time(500 * time.Second)

	sp := sentPing{to: epAddr{ap: addr}, at: t0, directPathHealthGeneration: generation}
	de.reduceDirectPathHealthLocked(sp, discoPingTimedOut, t0.Add(pingTimeoutDuration), false)
	if st.directPathHealth.state != directPathSuspect || st.directPathHealth.misses != 1 {
		t.Fatalf("after base timeout: %+v", st.directPathHealth)
	}

	// Non-base ping outcomes never carry a health generation and are excluded.
	excluded := sp
	excluded.at = t0.Add(heartbeatInterval)
	excluded.directPathHealthGeneration = 0
	de.reduceDirectPathHealthLocked(excluded, discoPingTimedOut, excluded.at.Add(pingTimeoutDuration), false)
	if st.directPathHealth.misses != 1 {
		t.Fatalf("excluded outcome changed misses to %d", st.directPathHealth.misses)
	}

	pong := sp
	pong.at = t0.Add(2 * heartbeatInterval)
	de.reduceDirectPathHealthLocked(pong, discoPongReceived, pong.at.Add(time.Millisecond), true)
	if st.directPathHealth.state != directPathHealthy || st.directPathHealth.misses != 0 {
		t.Fatalf("after direct base pong: %+v", st.directPathHealth)
	}

	// The same Pong received over a non-direct path is not health evidence.
	de.reduceDirectPathHealthLocked(sentPing{
		to:                         epAddr{ap: addr},
		at:                         t0.Add(3 * heartbeatInterval),
		directPathHealthGeneration: generation,
	}, discoPongReceived, t0.Add(3*heartbeatInterval+time.Millisecond), false)
	if st.directPathHealth.lastProbeAt != pong.at {
		t.Fatalf("non-direct pong advanced lastProbeAt to %v", st.directPathHealth.lastProbeAt)
	}
}
