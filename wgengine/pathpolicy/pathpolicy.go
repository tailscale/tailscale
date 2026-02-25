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
//
// Resolution priority:
//   - Forward (self∈Src, peer∈Dst): Uplink > Path
//   - Reverse (self∈Dst, peer∈Src): Downlink > Path; nil means default
func (e *Engine) PathEntriesAndRuleIdxFor(selfNode, dstPeer tailcfg.NodeView) (entries []tailcfg.PathEntry, ruleIdx int) {
	if e.policy == nil {
		return nil, -1
	}
	for i, rule := range e.policy.Rules {
		srcMatchesSelf := nodeMatchesAnyTag(selfNode, rule.Src)
		dstMatchesPeer := nodeMatchesAnyTag(dstPeer, rule.Dst)
		if srcMatchesSelf && dstMatchesPeer {
			// Forward direction: Uplink > Path.
			if len(rule.Uplink) > 0 {
				return rule.Uplink, i
			}
			return rule.Path, i
		}
		// Reverse direction: self is the Dst, peer is the Src.
		if nodeMatchesAnyTag(selfNode, rule.Dst) && nodeMatchesAnyTag(dstPeer, rule.Src) {
			// Downlink > Path; nil Downlink (with no Path) = default best-route.
			if len(rule.Downlink) > 0 {
				return rule.Downlink, i
			}
			return rule.Path, i
		}
	}
	return nil, -1
}

// AFAllowed reports whether addr is allowed by the address-family constraint
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
