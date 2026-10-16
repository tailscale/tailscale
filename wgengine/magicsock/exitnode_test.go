// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_exitnodehealth && !ts_omit_health && !ts_omit_useexitnode

package magicsock

import (
	"testing"
	"time"

	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgint"
)

func TestExitNodeReportLockBoundary(t *testing.T) {
	c := newTestConn(t)
	de := &endpoint{c: c, publicKey: key.NewNode().Public(), heartbeatDisabled: true}
	locked, outside := 0, 0
	restore := HookExitNodeHeartbeatStateLocked.SetForTest(func(*Conn, key.NodePublic, mono.Time, bool, bool, time.Duration) {
		if de.mu.TryLock() {
			de.mu.Unlock()
			t.Error("heartbeat state reported without endpoint lock")
		}
		locked++
	})
	defer restore()
	restoreOutside := HookExitNodeCheckResponsiveness.SetForTest(func(conn *Conn, k key.NodePublic, getPeer func(key.NodePublic) (wgint.Peer, bool)) {
		conn.mu.Lock()
		de.mu.Lock()
		de.mu.Unlock()
		conn.mu.Unlock()
		outside++
	})
	defer restoreOutside()
	// Exercise the real deferred callbacks, including the early-return paths.
	de.heartbeat()
	de.heartbeatForLifetime()
	if locked != 2 || outside != 2 {
		t.Fatal("split reports were not delivered")
	}
	if de.heartBeatTimer != nil || len(de.sentPing) != 0 || !de.lastSendAny.IsZero() {
		t.Fatal("reports created work or traffic")
	}
}
