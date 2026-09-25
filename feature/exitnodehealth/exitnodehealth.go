// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package exitnodehealth reports unusable exit node configurations via
// health warnables.
//
// It does not infer or probe data-plane reachability.
package exitnodehealth

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tsconst"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

const featureName = "exitnodehealth"

func init() {
	if !feature.Register(featureName) {
		return
	}
	ipnext.RegisterExtension(featureName, newExtension)
}

func newExtension(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
	if !buildfeatures.HasHealth || !buildfeatures.HasUseExitNode {
		return nil, ipnext.SkipExtension
	}
	return &extension{logf: logf, health: b.Sys().HealthTracker.Get(), polc: b.Sys().PolicyClientOrDefault()}, nil
}

// extension owns the health state for one backend.
type extension struct {
	host ipnext.Host

	logf   logger.Logf
	health *health.Tracker
	polc   policyclient.Client

	// mu protects the fields below.
	//
	// Extension callbacks hold the backend mutex before acquiring mu;
	// never acquire the backend mutex while holding mu.
	mu                sync.Mutex
	state             ipn.State
	networkConfigured bool
	policyOverridden  bool
	closed            bool
	reason            ExitNodeHealthVerdict // last reported reason, for transition logs
	lastID            tailcfg.StableNodeID  // last evaluated selection, independent of name caching

	// Remember a peer's name and/or ID so warnings can still identify it after removal.
	// It may prove useful to persist this across sessions, but for now we only remember it while the backend is running.
	// It is used only for decoration of the health warning.   We can always infer the ID or IP from a policy-forced node
	// which is the only case where the user cannot fix the problem themselves.
	lastKnownID   tailcfg.StableNodeID
	lastKnownName string
}

func (*extension) Name() string { return featureName }

func (e *extension) Init(h ipnext.Host) error {
	e.host = h
	h.Hooks().BackendStateChange.Add(e.onBackendStateChange)
	h.Hooks().ProfileStateChange.Add(e.onProfileStateChange)
	h.Hooks().NetworkConfiguredChange.Add(e.onNetworkConfiguredChange)
	h.Hooks().OnPeerUpdate.Add(e.onPeerUpdate)
	h.Hooks().ExitNodePolicyOverrideChange.Add(e.onPolicyOverrideChange)
	return nil
}

func (e *extension) Shutdown() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

func (e *extension) onBackendStateChange(state ipn.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = state
	e.updateLocked()
}

func (e *extension) onProfileStateChange(_ ipn.LoginProfileView, _ ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !sameNode {
		e.lastKnownID, e.lastKnownName = "", ""
	}
	e.updateLocked()
}

func (e *extension) onNetworkConfiguredChange(configured bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.networkConfigured = configured
	e.updateLocked()
}

func (e *extension) onPeerUpdate() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.updateLocked()
}

func (e *extension) onPolicyOverrideChange(overridden bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policyOverridden = overridden
	e.updateLocked()
}

// healthContext is the extension's input to warning evaluation.
type healthContext struct {
	State             ipn.State
	NetworkConfigured bool
	Prefs             ipn.PrefsView
	Peer              tailcfg.NodeView
	PolicyOverridden  bool
}

// updateLocked reads the current selection during an extension callback.
// Both the backend mutex and e.mu are held, so these inputs are consistent.
func (e *extension) updateLocked() {
	if e.closed {
		return
	}
	prefs := e.host.Profiles().CurrentPrefs()
	node := e.host.NodeBackend()
	peer, _ := node.PeerByStableID(prefs.ExitNodeID())
	e.updateWarnableLocked(healthContext{
		State:             e.state,
		NetworkConfigured: e.networkConfigured,
		Prefs:             prefs,
		Peer:              peer,
		PolicyOverridden:  e.policyOverridden,
	})
}

// ExitNodeHealthVerdict describes why the selected exit node cannot carry
// internet traffic. It is reported as [ArgExitNodeReason].
type ExitNodeHealthVerdict string

const (
	// ExitNodeOK means the exit node configuration is fine: either no exit
	// node is selected, or the selected one is a peer offering exit routes.
	ExitNodeOK ExitNodeHealthVerdict = ""

	// ExitNodeNotInTailnet means the selected exit node is not among the
	// current peers, so it has presumably left the tailnet.
	ExitNodeNotInTailnet ExitNodeHealthVerdict = "not-in-tailnet"

	// ExitNodeNoExitRoutes means the selected exit node is a current peer but
	// doesn't contribute the default routes, so it either stopped advertising
	// them or its routes are not approved.
	ExitNodeNoExitRoutes ExitNodeHealthVerdict = "no-exit-routes"

	// ExitNodeNotYetSelected means an exit node is required but none has been
	// chosen yet, so blackhole routes remain in place.
	ExitNodeNotYetSelected ExitNodeHealthVerdict = "not-yet-selected"
)

// Bespoke args for exit node health warnables.
const (
	// ArgExitNodeName provides a Warnable with a human-readable identifier for
	// the selected exit node: its display name if it is (or recently was) a
	// known peer, otherwise its stable node ID or IP address. It is empty if
	// no particular exit node has been selected.
	ArgExitNodeName health.Arg = "exit-node-name"

	// ArgExitNodeReason provides a Warnable with the reason the selected exit
	// node cannot carry internet traffic: "not-in-tailnet", "no-exit-routes",
	// or "not-yet-selected". It lets GUIs distinguish the cases without
	// parsing the rendered message.
	ArgExitNodeReason health.Arg = "exit-node-reason"

	// ArgExitNodePolicyForced is "true" when the selected exit node is
	// mandated by the ExitNodeID or ExitNodeIP policy settings, meaning the
	// user cannot resolve the problem themselves and should contact their
	// network administrator.
	ArgExitNodePolicyForced health.Arg = "exit-node-policy-forced"
)

// exitNodeUnavailableWarnable is a Warnable for when the selected exit node
// cannot carry internet traffic, either because it is no longer part of the
// tailnet, because it isn't offering exit node service, or because an exit
// node is required but none has been selected yet. In all of those cases the
// blackhole routes described on ipn.Prefs.ExitNodeID are installed and
// internet traffic is dropped, which is safe but otherwise silent.
//
// It is distinct from an exit node that is present and selected but which we
// cannot reach; that is a connectivity problem rather than a configuration
// one.
var exitNodeUnavailableWarnable = health.Register(&health.Warnable{
	Code:  tsconst.HealthWarnableExitNodeUnavailable,
	Title: "Exit node unavailable",
	// High severity because this is likely breaking the user's internet connectivity,
	// and they need to take action to fix it or report it.
	Severity: health.SeverityHigh,
	// Don't warn about the exit node when Tailscale is off or the network is
	// down; those both imply that we don't know the current exit node selection
	// or its status.
	DependsOn:           []*health.Warnable{health.IPNStateWarnable, health.NetworkStatusWarnable},
	ImpactsConnectivity: true,
	// Brief suppression to avoid flashing warnings for transient exit node problems or
	// during setup.
	TimeToVisible: 5 * time.Second,
	Text:          warnableText,
})

// warnableText renders the message for [exitNodeUnavailableWarnable]
// from its args: what's wrong, what it means, and what to do about it.
func warnableText(args health.Args) string {
	var sb strings.Builder
	name := args[ArgExitNodeName]
	switch ExitNodeHealthVerdict(args[ArgExitNodeReason]) {
	case ExitNodeNoExitRoutes:
		if name == "" {
			sb.WriteString("The selected exit node is not offering exit node service.")
		} else {
			fmt.Fprintf(&sb, "The selected exit node %q is not offering exit node service.", name)
		}
	case ExitNodeNotYetSelected:
		sb.WriteString("An exit node is required by policy, but no exit node is available to use.")
	case ExitNodeNotInTailnet:
		if name == "" {
			sb.WriteString("The selected exit node is no longer available on your tailnet.")
		} else {
			fmt.Fprintf(&sb, "The selected exit node %q is no longer available on your tailnet.", name)
		}
	default:
		sb.WriteString("The selected exit node is unavailable.")
	}

	sb.WriteString(" Internet traffic is being dropped to avoid leaking it to the local network.")
	if args[ArgExitNodePolicyForced] == "true" {
		sb.WriteString(" This exit node is required by your network administrator; contact them for help.")
	} else {
		sb.WriteString(" Select a different exit node, or turn off exit node use.")
	}
	return sb.String()
}

// evaluateExitNodeStatus reports a known problem with the selected exit node,
// and a human-readable name for it.
//
// The returned name is the selected exit node's display name if it is a
// current peer, otherwise its stable ID or IP address, or empty if no
// particular exit node has been selected.
func evaluateExitNodeStatus(c healthContext) (ExitNodeHealthVerdict, string) {
	prefs := c.Prefs
	if !c.NetworkConfigured || !prefs.Valid() || !prefs.WantRunning() || (c.State != ipn.Running && c.State != ipn.Starting) {
		// We don't know the peers yet, or aren't routing any traffic at all,
		// so there's nothing to warn about.
		return ExitNodeOK, ""
	}
	switch id := prefs.ExitNodeID(); {
	case id == ipn.UnresolvedExitNodeID:
		return ExitNodeNotYetSelected, ""
	case id != "":
		peer := c.Peer
		if !peer.Valid() {
			return ExitNodeNotInTailnet, string(id)
		}
		if !tsaddr.ContainsExitRoutes(peer.AllowedIPs()) {
			return ExitNodeNoExitRoutes, peer.ComputedName()
		}
		return ExitNodeOK, peer.ComputedName()
	case prefs.ExitNodeIP().IsValid():
		// LocalBackend.resolveExitNodeIPLocked clears ExitNodeIP once it
		// finds the peer at that address, so a still-set ExitNodeIP means no
		// current peer has it.
		return ExitNodeNotInTailnet, prefs.ExitNodeIP().String()
	}
	return ExitNodeOK, ""
}

// forcedByPolicy reports whether the current exit node selection
// is mandated by the ExitNodeID or ExitNodeIP policy settings, in which case
// the user can't fix an unusable exit node themselves.  This affects the
// string we render in the surfaced health warning.
func (e *extension) forcedByPolicy(overridden bool) bool {
	if !buildfeatures.HasSystemPolicy || overridden {
		return false
	}
	if v, _ := e.polc.GetString(pkey.ExitNodeID, ""); v != "" {
		return true
	}
	v, _ := e.polc.GetString(pkey.ExitNodeIP, "")
	return v != ""
}

// updateWarnableLocked raises or clears [exitNodeUnavailableWarnable] to
// reflect known problems with the selected exit node.
func (e *extension) updateWarnableLocked(c healthContext) {
	// Forget peer names when network configuration is cleared, so a new
	// profile cannot inherit the previous profile's warning.
	if !c.NetworkConfigured {
		e.lastKnownID, e.lastKnownName = "", ""
	}
	prefs := c.Prefs
	reason, name := evaluateExitNodeStatus(c)
	id := prefs.ExitNodeID()

	idChanged := id != e.lastID
	e.lastID = id

	// Remember the exit node's display name while it is still a peer, so that
	// the warning can name it once it disappears and only its stable ID is
	// left in the prefs.
	if c.NetworkConfigured && c.Peer.Valid() {
		if name != "" {
			e.lastKnownID, e.lastKnownName = id, name
		}
	} else if name == string(id) && e.lastKnownID == id && e.lastKnownName != "" {
		name = e.lastKnownName
	}

	if reason != e.reason || idChanged {
		switch {
		case reason != ExitNodeOK && name != "":
			e.logf("exit node %q is unusable (%s); dropping internet traffic", name, reason)
		case reason != ExitNodeOK:
			e.logf("selected exit node is unusable (%s); dropping internet traffic", reason)
		default:
			e.logf("exit node selection is usable again")
		}
		e.reason = reason
	}

	if reason == ExitNodeOK {
		e.health.SetHealthy(exitNodeUnavailableWarnable)
		return
	}
	e.health.SetUnhealthy(exitNodeUnavailableWarnable, e.warnableArgs(reason, name, c.PolicyOverridden))
}

// warnableArgs builds the [health.Args] describing an unusable
// exit node for [exitNodeUnavailableWarnable].
func (e *extension) warnableArgs(reason ExitNodeHealthVerdict, name string, overridden bool) health.Args {
	args := health.Args{ArgExitNodeReason: string(reason)}
	if name != "" {
		args[ArgExitNodeName] = name
	}
	if e.forcedByPolicy(overridden) {
		args[ArgExitNodePolicyForced] = "true"
	}
	return args
}
