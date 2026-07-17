// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"slices"

	"tailscale.com/control/controlknobs"
	"tailscale.com/tstime/mono"
)

const maxDirectPathHealthCandidates = 16

// directPathHealthState is the health of one materialized direct UDP candidate.
type directPathHealthState uint8

const (
	directPathHealthy directPathHealthState = iota
	directPathSuspect
	directPathUnreachable
)

func (s directPathHealthState) String() string {
	switch s {
	case directPathHealthy:
		return "healthy"
	case directPathSuspect:
		return "suspect"
	case directPathUnreachable:
		return "unreachable"
	default:
		return "unknown"
	}
}

type directPathHealthOutcome uint8

const (
	directPathHealthPong directPathHealthOutcome = iota
	directPathHealthTimeout
)

type directPathHealthEvent struct {
	generation uint32
	probeAt    mono.Time
	at         mono.Time
	outcome    directPathHealthOutcome
}

type directPathHealthDecision struct {
	clearCandidate bool
}

// directPathHealth is the bounded event reducer state for one materialized
// direct UDP candidate. It is intentionally timer-free; callers provide event
// timestamps from the existing disco ping lifecycle.
type directPathHealth struct {
	firstMissAt           mono.Time
	lastAuthenticatedRecv mono.Time
	lastProbeAt           mono.Time
	generation            uint32
	misses                uint8
	state                 directPathHealthState
	haveProbe             bool
	haveAuthenticatedRecv bool
}

func (h *directPathHealth) materialize(generation uint32) {
	*h = directPathHealth{generation: generation, state: directPathHealthy}
}

func (h *directPathHealth) noteAuthenticatedRecv(at mono.Time) {
	if at > h.lastAuthenticatedRecv {
		h.lastAuthenticatedRecv = at
		h.haveAuthenticatedRecv = true
	}
}

func (h *directPathHealth) reduce(e directPathHealthEvent) (d directPathHealthDecision) {
	if e.generation != h.generation || (h.haveProbe && (e.probeAt < h.lastProbeAt || e.probeAt == h.lastProbeAt && e.outcome != directPathHealthPong)) {
		return d
	}
	h.haveProbe = true
	h.lastProbeAt = e.probeAt
	switch e.outcome {
	case directPathHealthPong:
		h.firstMissAt = 0
		h.misses = 0
		h.state = directPathHealthy
	case directPathHealthTimeout:
		if h.state == directPathUnreachable {
			return d
		}
		if h.misses == 0 {
			h.firstMissAt = e.probeAt
		}
		if h.misses < 3 {
			h.misses++
		}
		h.state = directPathSuspect
		if h.misses >= 3 && e.probeAt.Sub(h.firstMissAt) >= 2*heartbeatInterval {
			h.state = directPathUnreachable
			d.clearCandidate = true
		}
	}
	return d
}

// materializeDirectPathHealthLocked initializes the reducer for a newly
// materialized direct candidate and returns its unique generation.
func (de *endpoint) materializeDirectPathHealthLocked(h **directPathHealth) {
	if de.syncDirectPathHealthModeLocked() == controlknobs.PathHealthOff {
		return
	}
	if *h != nil || de.directPathHealthCount >= maxDirectPathHealthCandidates {
		return
	}
	*h = new(directPathHealth)
	(*h).materialize(de.nextDirectPathHealthGenerationLocked())
	de.directPathHealthCount++
}

func (de *endpoint) nextDirectPathHealthGenerationLocked() uint32 {
	de.directPathHealthGeneration++
	if de.directPathHealthGeneration == 0 {
		de.directPathHealthGeneration++
	}
	return de.directPathHealthGeneration
}

// rebalanceDirectPathHealthLocked reserves the bounded health budget for the
// selected candidate first, then netmap candidates, then runtime-discovered
// candidates. Candidates outside the budget retain legacy behavior.
func (de *endpoint) rebalanceDirectPathHealthLocked() {
	if de.syncDirectPathHealthModeLocked() == controlknobs.PathHealthOff {
		return
	}
	priority := make([]netip.AddrPort, 0, len(de.endpointState))
	if ap := de.bestAddr.ap; ap.IsValid() && !de.bestAddr.vni.IsSet() && de.endpointState[ap] != nil {
		priority = append(priority, ap)
	}
	appendClass := func(class int) {
		var aps []netip.AddrPort
		for ap, st := range de.endpointState {
			gotClass := 2 // runtime-discovered
			if st.index >= 0 {
				gotClass = 0 // netmap
			} else if !st.callMeMaybeTime.IsZero() {
				gotClass = 1 // CallMeMaybe runtime
			}
			if ap == de.bestAddr.ap || gotClass != class {
				continue
			}
			aps = append(aps, ap)
		}
		slices.SortFunc(aps, func(a, b netip.AddrPort) int {
			sa, sb := de.endpointState[a], de.endpointState[b]
			evidence := func(st *endpointState) mono.Time {
				if st.directPathHealth == nil {
					return 0
				}
				return max(st.directPathHealth.lastProbeAt, st.directPathHealth.lastAuthenticatedRecv)
			}
			if ea, eb := evidence(sa), evidence(sb); ea != eb {
				if ea > eb {
					return -1
				}
				return 1
			}
			if !sa.lastGotPing.Equal(sb.lastGotPing) {
				if sa.lastGotPing.After(sb.lastGotPing) {
					return -1
				}
				return 1
			}
			return a.Compare(b)
		})
		priority = append(priority, aps...)
	}
	appendClass(0)
	appendClass(1)
	appendClass(2)

	keep := make(map[netip.AddrPort]bool, min(len(priority), maxDirectPathHealthCandidates))
	for _, ap := range priority[:min(len(priority), maxDirectPathHealthCandidates)] {
		keep[ap] = true
	}
	de.directPathHealthCount = 0
	for ap, st := range de.endpointState {
		if !keep[ap] {
			st.directPathHealth = nil
			continue
		}
		if st.directPathHealth == nil {
			st.directPathHealth = new(directPathHealth)
			st.directPathHealth.materialize(de.nextDirectPathHealthGenerationLocked())
		}
		de.directPathHealthCount++
	}
}

// directPathHealthProbeGenerationLocked classifies an outgoing ping. A zero
// generation excludes the ping from direct path health. Only one ping (ordinal
// zero) from a discovery MTU burst is the logical base outcome.
func (de *endpoint) directPathHealthProbeGenerationLocked(to epAddr, purpose discoPingPurpose, ordinal int) uint32 {
	if !to.isDirect() || ordinal != 0 || (purpose != pingDiscovery && purpose != pingHeartbeat) {
		return 0
	}
	if de.syncDirectPathHealthModeLocked() == controlknobs.PathHealthOff {
		return 0
	}
	if st := de.endpointState[to.ap]; st != nil {
		if st.directPathHealth == nil {
			de.materializeDirectPathHealthLocked(&st.directPathHealth)
		}
		if st.directPathHealth != nil {
			return st.directPathHealth.generation
		}
	}
	return 0
}

// reduceDirectPathHealthLocked adapts the existing disco ping lifecycle to the
// direct path health reducer. It does not apply clearCandidate; feature control
// and enforcement are intentionally left to a later task.
func (de *endpoint) reduceDirectPathHealthLocked(sp sentPing, result discoPingResult, now mono.Time, pongDirect bool) directPathHealthDecision {
	if sp.directPathHealthGeneration == 0 || de.syncDirectPathHealthModeLocked() == controlknobs.PathHealthOff {
		return directPathHealthDecision{}
	}
	st := de.endpointState[sp.to.ap]
	if st == nil {
		return directPathHealthDecision{}
	}
	var outcome directPathHealthOutcome
	switch result {
	case discoPingTimedOut:
		outcome = directPathHealthTimeout
	case discoPongReceived:
		if !pongDirect {
			return directPathHealthDecision{}
		}
		outcome = directPathHealthPong
	default:
		return directPathHealthDecision{}
	}
	if st.directPathHealth == nil {
		return directPathHealthDecision{}
	}
	before := st.directPathHealth.state
	previousProbeAt := st.directPathHealth.lastProbeAt
	d := st.directPathHealth.reduce(directPathHealthEvent{
		generation: sp.directPathHealthGeneration,
		probeAt:    sp.at,
		at:         now,
		outcome:    outcome,
	})
	// Authenticated receive evidence is inbound-only. It may defer retirement
	// once, but every subsequent deferral requires newer authenticated traffic
	// since the previous health probe. A stale packet must not preserve a
	// subsequently blackholed path forever.
	if d.clearCandidate && st.directPathHealth.haveAuthenticatedRecv && st.directPathHealth.lastAuthenticatedRecv > previousProbeAt {
		d.clearCandidate = false
		st.directPathHealth.state = directPathSuspect
	}
	after := st.directPathHealth.state
	switch {
	case before == directPathHealthy && after == directPathSuspect:
		metricPathHealthHealthyToSuspect.Add(1)
	case before == directPathSuspect && after == directPathHealthy:
		metricPathHealthSuspectToHealthy.Add(1)
	case before == directPathSuspect && after == directPathUnreachable:
		metricPathHealthSuspectToUnreachable.Add(1)
	}
	return d
}

func (de *endpoint) pathHealthMode() controlknobs.PathHealthMode {
	if de.c == nil {
		return controlknobs.PathHealthShadow
	}
	return de.c.controlKnobs.PathHealthMode()
}

func (de *endpoint) resetDirectPathHealthLocked() {
	de.directPathHealthCount = 0
	de.latePathHealthPong = latePathHealthPong{}
	for _, st := range de.endpointState {
		st.directPathHealth = nil
	}
}

func (de *endpoint) invalidateDirectPathHealthLocked() {
	de.resetDirectPathHealthLocked()
	for txid, sp := range de.sentPing {
		if sp.directPathHealthGeneration != 0 {
			sp.timer.Stop()
			delete(de.sentPing, txid)
		}
	}
	de.rebalanceDirectPathHealthLocked()
}

func (de *endpoint) syncDirectPathHealthModeLocked() controlknobs.PathHealthMode {
	if de.c == nil {
		return controlknobs.PathHealthShadow
	}
	if de.c.controlKnobs == nil {
		return controlknobs.PathHealthOff
	}
	mode, epoch := de.c.controlKnobs.PathHealthState()
	if epoch != de.directPathHealthEpoch {
		de.resetDirectPathHealthLocked()
		de.directPathHealthEpoch = epoch
	}
	return mode
}

// noteAuthenticatedDirectRecvLocked records a successfully authenticated
// WireGuard packet for the exact direct underlay source. It is inbound-only
// evidence: it never promotes a path to healthy or refreshes UDP trust.
func (de *endpoint) noteAuthenticatedDirectRecvLocked(src epAddr, generation uint32, at mono.Time) {
	if !src.isDirect() {
		return
	}
	if st := de.endpointState[src.ap]; st != nil && st.directPathHealth != nil && st.directPathHealth.generation == generation {
		st.directPathHealth.noteAuthenticatedRecv(at)
	}
}

func (de *endpoint) selectHealthyAlternativeLocked(failed netip.AddrPort) bool {
	var best addrQuality
	for ap, st := range de.endpointState {
		if ap == failed || st.directPathHealth == nil || st.directPathHealth.state != directPathHealthy ||
			!st.directPathHealth.haveProbe || len(st.recentPongs) == 0 {
			continue
		}
		pong := st.recentPongs[st.recentPong]
		if pong.pongAt < st.directPathHealth.lastProbeAt {
			continue
		}
		candidate := addrQuality{epAddr: epAddr{ap: ap}, latency: pong.latency}
		if !best.ap.IsValid() || betterAddr(candidate, best) {
			best = candidate
		}
	}
	if !best.ap.IsValid() {
		return false
	}
	de.setBestAddrLocked(best)
	de.bestAddrAt = mono.Now()
	de.trustBestAddrUntil = de.bestAddrAt.Add(trustUDPAddrDuration)
	return true
}
