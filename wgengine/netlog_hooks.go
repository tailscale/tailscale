// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"net/netip"

	"tailscale.com/feature"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/eventbus"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
)

// NetLogSource provides the network flow logging feature what it needs
// from the rest of the system (in practice, ipnlocal.LocalBackend):
// on-demand node lookups and the current audit logging identity.
type NetLogSource interface {
	// SelfNode returns the current self node and its owning user profile.
	// The views are invalid if there is no current node.
	SelfNode() (tailcfg.NodeView, tailcfg.UserProfileView)

	// NodeByAddr returns the node assigned the given address along with
	// its owning user profile.
	// ok is false if no node is known to own addr.
	NodeByAddr(addr netip.Addr) (node tailcfg.NodeView, user tailcfg.UserProfileView, ok bool)

	// NetLogIDs returns the audit logging IDs from the current netmap,
	// along with whether exit node flows should be logged.
	// ok is false if network flow logging should not run.
	NetLogIDs() (nodeID, domainID logid.PrivateID, logExitFlows bool, ok bool)
}

// NetLogger is the engine's handle on the network flow logger
// lifecycle, implemented by the feature/netlog package.
//
// Reconfig and ReconfigDone are only called from [Engine.Reconfig],
// serialized by the engine's internal lock. Shutdown may be called
// concurrently with them from [Engine.Close].
type NetLogger interface {
	// Reconfig is called near the top of every [Engine.Reconfig],
	// before its ErrNoChanges early return (so identity-only changes
	// still take effect) and before the router is configured (so a
	// starting logger captures initial packets). It reports whether
	// network logging state changed, which suppresses the engine's
	// ErrNoChanges early return.
	Reconfig(routerCfg *router.Config, routerChanged bool) (changed bool)

	// ReconfigDone is called at the end of [Engine.Reconfig], after
	// the router is configured, so that a logger stopping as a result
	// of the preceding Reconfig call captures final packets. It may
	// block to flush pending messages.
	ReconfigDone()

	// Shutdown stops the logger. It may block to flush pending
	// messages, bounded by an internal upload timeout.
	Shutdown()
}

// NetLoggerDeps are the engine-owned dependencies passed to
// [HookNewNetLogger] to construct a [NetLogger].
type NetLoggerDeps struct {
	Logf   logger.Logf
	Tun    *tstun.Wrapper
	Sock   *magicsock.Conn
	NetMon *netmon.Monitor
	Health *health.Tracker
	Bus    *eventbus.Bus

	// Source returns the [NetLogSource] installed via
	// [Engine.SetNetLogSource], or nil if none has been installed yet.
	// It is a func because the source is installed after the engine
	// (and thus the NetLogger) is constructed.
	Source func() NetLogSource
}

// HookNewNetLogger is set by the feature/netlog package to construct
// each engine's [NetLogger]. If unset, network flow logging is not
// linked into the binary and the engine skips all NetLogger calls.
var HookNewNetLogger feature.Hook[func(NetLoggerDeps) NetLogger]
