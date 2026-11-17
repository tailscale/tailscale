// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_exitnodehealth && !ts_omit_health && !ts_omit_useexitnode

package magicsock

import (
	"time"

	"tailscale.com/feature"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgint"
)

// HookExitNodeHeartbeatStateLocked records idle state and disco pong responses
// for exit node health monitoring under magicsock locks. It must not acquire
// backend or magicsock locks or call WireGuard.
var HookExitNodeHeartbeatStateLocked feature.Hook[func(*Conn, key.NodePublic, mono.Time, bool, bool, time.Duration)]

// HookExitNodeCheckResponsiveness checks WireGuard traffic counters
// and updates exit node responsiveness warnings after endpoint.mu is released.
// Only the enabled feature looks up counters and retains history; magicsock has
// no payload/state.
var HookExitNodeCheckResponsiveness feature.Hook[func(*Conn, key.NodePublic, func(key.NodePublic) (wgint.Peer, bool))]

func (de *endpoint) reportExitNodeHeartbeatStateLocked() {
	if report, ok := HookExitNodeHeartbeatStateLocked.GetOk(); ok {
		now := mono.Now()
		idle := de.heartbeatDisabled || de.lastSendExt.IsZero() || now.Sub(de.lastSendExt) > sessionActiveTimeout ||
			!de.c.havePrivateKey.Load() || de.c.networkDown()
		report(de.c, de.publicKey, now, idle, false, sessionActiveTimeout)
	}
}

func (de *endpoint) checkExitNodeResponsiveness() {
	if report, ok := HookExitNodeCheckResponsiveness.GetOk(); ok {
		report(de.c, de.publicKey, de.c.getPeerByKey)
	}
}

func (c *Conn) reportExitNodePong(k key.NodePublic, now mono.Time) {
	if report, ok := HookExitNodeHeartbeatStateLocked.GetOk(); ok {
		report(c, k, now, false, true, sessionActiveTimeout)
	}
}
