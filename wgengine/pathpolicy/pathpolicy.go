// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package pathpolicy implements the client-side evaluation of [tailcfg.PathPolicy]
// rules received from the control plane. It resolves tag-based rules against the
// current network map and provides ordered path-entry lists to the magicsock
// path-selection machinery.
//
// See https://github.com/tailscale/tailscale/issues/17765 for the tracking issue.
package pathpolicy

import (
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// Engine evaluates [tailcfg.PathPolicy] rules against the current network map.
// The zero value is ready for use (no-op: returns nil, meaning no policy).
//
// Engine is not safe for concurrent use; callers must synchronise externally.
type Engine struct {
	policy *tailcfg.PathPolicy // last PathPolicy received; may be nil
	nm     *netmap.NetworkMap  // last netmap; may be nil
}

// Update refreshes the engine's view of the network map and the path policy
// it carries. Callers must call Update every time the netmap changes.
func (e *Engine) Update(nm *netmap.NetworkMap) {
	e.nm = nm
	if nm != nil {
		e.policy = nm.PathPolicy
	} else {
		e.policy = nil
	}
}

// PathEntriesFor returns the ordered [tailcfg.PathEntry] list that governs
// traffic from selfNode to dstPeer, or nil if no rule matches (meaning the
// default latency-based selection applies unchanged).
//
// The first PathRule whose Src tags match selfNode and whose Dst tags match
// dstPeer is returned; subsequent rules are ignored.
func (e *Engine) PathEntriesFor(selfNode, dstPeer tailcfg.NodeView) []tailcfg.PathEntry {
	entries, _ := e.PathEntriesAndRuleIdxFor(selfNode, dstPeer)
	return entries
}

// PathEntriesAndRuleIdxFor is like [Engine.PathEntriesFor] but also returns
// the zero-based index of the matched rule, or -1 if no rule matched.
func (e *Engine) PathEntriesAndRuleIdxFor(selfNode, dstPeer tailcfg.NodeView) (entries []tailcfg.PathEntry, ruleIdx int) {
	if e.policy == nil {
		return nil, -1
	}
	for i, rule := range e.policy.Rules {
		if nodeMatchesAnyTag(selfNode, rule.Src) && nodeMatchesAnyTag(dstPeer, rule.Dst) {
			return rule.Path, i
		}
	}
	return nil, -1
}

// CandidateRelayChains returns the ordered relay-chain candidates implied by
// the path policy for dstPeer. Each element is a slice of peer node views
// representing one relay hop in order (index 0 = first relay after src).
// Only [tailcfg.PathEntryRelay] entries are returned; direct and DERP entries
// are handled separately by the magicsock machinery.
//
// Returns nil if no relay-chain entries are present for dstPeer.
func (e *Engine) CandidateRelayChains(selfNode, dstPeer tailcfg.NodeView) [][][]tailcfg.NodeView {
	entries := e.PathEntriesFor(selfNode, dstPeer)
	if len(entries) == 0 || e.nm == nil {
		return nil
	}
	var chains [][][]tailcfg.NodeView
	for _, entry := range entries {
		if entry.Type != tailcfg.PathEntryRelay || len(entry.Hops) == 0 {
			continue
		}
		chain := make([][]tailcfg.NodeView, len(entry.Hops))
		for i, tag := range entry.Hops {
			chain[i] = nodesForTag(e.nm, tag)
		}
		chains = append(chains, chain)
	}
	return chains
}

// SingleHopRelayNodesFor returns the deduplicated set of netmap peers that are
// named as single-hop relay candidates in entries. Only [tailcfg.PathEntryRelay]
// entries with exactly one hop are considered; multi-hop entries are skipped
// (multi-hop chain forwarding is handled at the relay server level; client-side
// candidate selection for multi-hop is future work).
//
// Returns nil if no matching entries exist or e.nm is nil.
func (e *Engine) SingleHopRelayNodesFor(entries []tailcfg.PathEntry) []tailcfg.NodeView {
	if e.nm == nil {
		return nil
	}
	seen := make(map[tailcfg.StableNodeID]bool)
	var out []tailcfg.NodeView
	for _, entry := range entries {
		if entry.Type != tailcfg.PathEntryRelay || len(entry.Hops) != 1 {
			continue
		}
		for _, node := range nodesForTag(e.nm, entry.Hops[0]) {
			if !seen[node.StableID()] {
				seen[node.StableID()] = true
				out = append(out, node)
			}
		}
	}
	return out
}
// af. An empty af means both families are allowed.
func AFAllowed(af tailcfg.PathEntryAF, addr netip.Addr) bool {
	switch af {
	case tailcfg.PathEntryAFIPv4:
		return addr.Is4()
	case tailcfg.PathEntryAFIPv6:
		return addr.Is6()
	default:
		return true
	}
}

// nodeMatchesAnyTag reports whether node carries at least one of the given tags.
// Returns false for an empty tag list (no rule should match nothing).
func nodeMatchesAnyTag(node tailcfg.NodeView, tags []string) bool {
	if len(tags) == 0 {
		return false
	}
	nodeTags := node.Tags()
	for _, want := range tags {
		if nodeTags.ContainsFunc(func(t string) bool { return t == want }) {
			return true
		}
	}
	return false
}

// nodesForTag returns all peers in nm that carry the given tag.
// Results are sorted by StableID for deterministic ordering.
func nodesForTag(nm *netmap.NetworkMap, tag string) []tailcfg.NodeView {
	var out []tailcfg.NodeView
	for _, p := range nm.Peers {
		if p.Tags().ContainsFunc(func(t string) bool { return t == tag }) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b tailcfg.NodeView) int {
		if a.StableID() < b.StableID() {
			return -1
		}
		if a.StableID() > b.StableID() {
			return 1
		}
		return 0
	})
	return out
}
