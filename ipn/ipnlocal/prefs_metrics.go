// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
)

// Counter metrics for edit/change events
var (
	// metricExitNodeEnabled is incremented when the user enables an exit node independent of the node's characteristics.
	metricExitNodeEnabled = clientmetric.NewCounter("prefs_exit_node_enabled")
	// metricExitNodeEnabledSuggested is incremented when the user enables the suggested exit node.
	metricExitNodeEnabledSuggested = clientmetric.NewCounter("prefs_exit_node_enabled_suggested")
	// metricExitNodeEnabledMullvad is incremented when the user enables a Mullvad exit node.
	metricExitNodeEnabledMullvad = clientmetric.NewCounter("prefs_exit_node_enabled_mullvad")
	// metricWantRunningEnabled is incremented when WantRunning transitions from false to true.
	metricWantRunningEnabled = clientmetric.NewCounter("prefs_want_running_enabled")
	// metricWantRunningDisabled is incremented when WantRunning transitions from true to false.
	metricWantRunningDisabled = clientmetric.NewCounter("prefs_want_running_disabled")
)

type exitNodeProperty string

const (
	exitNodeTypePreferred exitNodeProperty = "suggested" // The exit node is the last suggested exit node
	exitNodeTypeMullvad   exitNodeProperty = "mullvad"   // The exit node is a Mullvad exit node
)

// prefsMetricsEditEvent encapsulates information needed to record metrics related
// to any changes to preferences.
type prefsMetricsEditEvent struct {
	change                *ipn.MaskedPrefs     // the preference mask used to update the preferences
	pNew                  ipn.PrefsView        // new preferences (after ApplyUpdates)
	pOld                  ipn.PrefsView        // old preferences (before ApplyUpdates)
	node                  *nodeBackend         // the node the event is associated with
	lastSuggestedExitNode tailcfg.StableNodeID // the last suggested exit node
}

// record records changes to preferences as clientmetrics.
func (e *prefsMetricsEditEvent) record() error {
	if e.change == nil || e.node == nil {
		return errors.New("prefsMetricsEditEvent: missing required fields")
	}

	// Record up/down events.
	if e.change.WantRunningSet && (e.pNew.WantRunning() != e.pOld.WantRunning()) {
		if e.pNew.WantRunning() {
			metricWantRunningEnabled.Add(1)
		} else {
			metricWantRunningDisabled.Add(1)
		}
	}

	// Record any changes to exit node settings.
	if e.change.ExitNodeIDSet || e.change.ExitNodeIPSet {
		if exitNodeTypes, ok := e.exitNodeType(e.pNew.ExitNodeID()); ok {
			// We have switched to a valid exit node if ok is true.
			metricExitNodeEnabled.Add(1)

			// We may have some additional characteristics we should also record.
			for _, t := range exitNodeTypes {
				switch t {
				case exitNodeTypePreferred:
					metricExitNodeEnabledSuggested.Add(1)
				case exitNodeTypeMullvad:
					metricExitNodeEnabledMullvad.Add(1)
				}
			}
		}
	}
	return nil
}

// exitNodeTypesLocked returns type of exit node for the given stable ID.
// An exit node may have multiple type (can be both mullvad and preferred
// simultaneously for example).
//
// This will return ok as true if the supplied stable ID resolves to a known peer,
// false otherwise.  The caller is responsible for ensuring that the id belongs to
// an exit node.
func (e *prefsMetricsEditEvent) exitNodeType(id tailcfg.StableNodeID) (props []exitNodeProperty, isNode bool) {
	if !buildfeatures.HasUseExitNode {
		return nil, false
	}
	var peer tailcfg.NodeView

	if peer, isNode = e.node.PeerByStableID(id); isNode {
		if tailcfg.StableNodeID(id) == e.lastSuggestedExitNode {
			props = append(props, exitNodeTypePreferred)
		}
		if peer.IsWireGuardOnly() {
			props = append(props, exitNodeTypeMullvad)
		}
	}
	return props, isNode
}
