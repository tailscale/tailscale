// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"tailscale.com/feature"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// Bird is the engine's handle on the BIRD Internet Routing Daemon
// integration, implemented by the feature/bird package. It enables the
// "tailscale" protocol in BIRD while this node is a primary subnet
// router and disables it otherwise.
//
// Reconfig and ReconfigDone are only called from [Engine.Reconfig],
// serialized by the engine's internal lock. Close is called from
// [Engine.Close].
type Bird interface {
	// Reconfig recomputes from the given self node whether this node is
	// a primary subnet router. It is called near the top of every
	// [Engine.Reconfig], before its ErrNoChanges early return. It
	// reports whether the primary subnet router state changed, which
	// suppresses the engine's ErrNoChanges early return.
	Reconfig(self tailcfg.NodeView) (changed bool)

	// ReconfigDone is called at the end of [Engine.Reconfig], after the
	// router is configured, and applies any protocol state change
	// computed by the preceding Reconfig call.
	ReconfigDone()

	// Close disables the protocol and closes the connection to BIRD.
	Close()
}

// HookNewBird is set by the feature/bird package to construct each
// engine's [Bird], connecting to the BIRD unix socket at socketPath.
// If unset, BIRD integration is not linked into the binary and
// [Config.BIRDSocket] must not be set.
var HookNewBird feature.Hook[func(logf logger.Logf, socketPath string) (Bird, error)]
