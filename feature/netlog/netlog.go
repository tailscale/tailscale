// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package netlog registers the network flow logging feature and wires
// it into the WireGuard engine. The logger implementation itself lives
// in tailscale.com/wgengine/netlog.
package netlog

import (
	"context"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/types/logid"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netlog"
	"tailscale.com/wgengine/router"
)

func init() {
	feature.Register("netlog")
	wgengine.HookNewNetLogger.Set(newNetLogger)
}

// uploadTimeout is the maximum time to wait when shutting down the
// network logger as it uploads the final network log messages.
const uploadTimeout = 5 * time.Second

// netLogger implements [wgengine.NetLogger] on top of [netlog.Logger],
// tracking the logging identity and running state across engine
// reconfigurations. One netLogger exists per engine.
type netLogger struct {
	deps   wgengine.NetLoggerDeps
	logger netlog.Logger

	// The fields below are only accessed from Reconfig and
	// ReconfigDone, which the engine serializes under its internal
	// lock.

	// nodeID and domainID are the logging IDs from the last Reconfig,
	// or zero if logging was not enabled then.
	nodeID, domainID logid.PrivateID
	// logExitFlows is whether exit node flows were logged as of the
	// last Reconfig.
	logExitFlows bool
	// shouldRun is whether the last Reconfig wanted the logger
	// running. ReconfigDone consults it to shut down a stopping
	// logger after the router has been reconfigured.
	shouldRun bool
}

func newNetLogger(deps wgengine.NetLoggerDeps) wgengine.NetLogger {
	return &netLogger{deps: deps}
}

func (nl *netLogger) Reconfig(routerCfg *router.Config, routerChanged bool) (changed bool) {
	logf := nl.deps.Logf
	src := nl.deps.Source()

	var nodeID, domainID logid.PrivateID
	var logExitFlows bool
	if src != nil {
		if nid, did, lef, ok := src.NetLogIDs(); ok {
			nodeID, domainID, logExitFlows = nid, did, lef
		}
	}
	idsValid := !nodeID.IsZero() && !domainID.IsZero()
	idsWereValid := !nl.nodeID.IsZero() && !nl.domainID.IsZero()
	changed = nodeID != nl.nodeID || domainID != nl.domainID || logExitFlows != nl.logExitFlows
	idsChanged := idsValid && idsWereValid && changed
	nl.nodeID, nl.domainID, nl.logExitFlows = nodeID, domainID, logExitFlows

	nl.shouldRun = idsValid && !routerCfg.Equal(&router.Config{}) && !envknob.NoLogsNoSupport()

	// Shut down the logger if the IDs changed while it was running,
	// letting the startup logic below bring it back up with the new
	// identity.
	if idsChanged && nl.logger.Running() {
		logf("wgengine: Reconfig: shutting down network logger")
		nl.shutdown()
	}

	// Start the logger before the engine configures the router so
	// that it captures initial packets.
	if nl.shouldRun && !nl.logger.Running() {
		logf("wgengine: Reconfig: starting up network logger (node:%s tailnet:%s)", nodeID.Public(), domainID.Public())
		if err := nl.logger.Startup(logf, src, nodeID, domainID, nl.deps.Tun, nl.deps.Sock, nl.deps.NetMon, nl.deps.Health, nl.deps.Bus, logExitFlows); err != nil {
			logf("wgengine: Reconfig: error starting up network logger: %v", err)
		}
		nl.logger.ReconfigRoutes(routerCfg)
	} else if routerChanged && nl.logger.Running() {
		nl.logger.ReconfigRoutes(routerCfg)
	}
	return changed
}

func (nl *netLogger) ReconfigDone() {
	// Shut down a stopping logger only now, after the engine has
	// configured the router, so that it captures final packets.
	if !nl.shouldRun && nl.logger.Running() {
		nl.deps.Logf("wgengine: Reconfig: shutting down network logger")
		nl.shutdown()
	}
}

func (nl *netLogger) Shutdown() {
	nl.shutdown()
}

// shutdown stops the logger, waiting up to uploadTimeout for it to
// flush its final messages.
func (nl *netLogger) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), uploadTimeout)
	defer cancel()
	if err := nl.logger.Shutdown(ctx); err != nil {
		nl.deps.Logf("wgengine: error shutting down network logger: %v", err)
	}
}
