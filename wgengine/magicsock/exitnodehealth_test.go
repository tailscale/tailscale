// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"testing"

	"tailscale.com/health"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
)

// newConnWithHealth returns a magicsock Conn wired up to a fresh
// health.Tracker so tests can observe warnable transitions without
// spinning up the full magicStack.
func newConnWithHealth(t *testing.T) (*Conn, *health.Tracker) {
	t.Helper()
	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	c := newConn(t.Logf)
	c.health = ht
	return c, ht
}

func TestExitNodeReachabilityNoOpWhenNotSet(t *testing.T) {
	c, ht := newConnWithHealth(t)

	peer := key.NewNode().Public()
	c.NoteExitNodeReachabilityResult(peer, errors.New("send failed"))
	if ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("warnable set even though no exit node was configured")
	}
	c.NoteExitNodeReachabilityResult(peer, nil)
	if ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("warnable set after success with no exit node")
	}
	if c.exitNodeUnhealthy.Load() {
		t.Fatalf("exitNodeUnhealthy=true after no-op path")
	}
}

func TestExitNodeReachabilityFailureMarksUnhealthy(t *testing.T) {
	c, ht := newConnWithHealth(t)

	exit := key.NewNode().Public()
	c.SetExitNodePeer(exit, "exitbox")

	c.NoteExitNodeReachabilityResult(exit, errors.New("no UDP or DERP addr"))

	if !ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("warnable not set after send failure to exit node")
	}
	if !c.exitNodeUnhealthy.Load() {
		t.Fatalf("exitNodeUnhealthy=false after send failure")
	}
}

func TestExitNodeReachabilitySuccessClearsWarnable(t *testing.T) {
	c, ht := newConnWithHealth(t)

	exit := key.NewNode().Public()
	c.SetExitNodePeer(exit, "thepacketsmustflow")
	c.NoteExitNodeReachabilityResult(exit, errors.New("the packets are not flowing"))
	if !ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("warnable should be set")
	}

	c.NoteExitNodeReachabilityResult(exit, nil)

	if ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("warnable still set after successful send")
	}
	if c.exitNodeUnhealthy.Load() {
		t.Fatalf("exitNodeUnhealthy=true after clear")
	}
}

func TestExitNodeReachabilityOnlyReactsToConfiguredPeer(t *testing.T) {
	c, ht := newConnWithHealth(t)

	exit := key.NewNode().Public()
	other := key.NewNode().Public()
	c.SetExitNodePeer(exit, "thepacketsmustflow")

	c.NoteExitNodeReachabilityResult(other, errors.New("the packets are not flowing"))

	if ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("send failure to non-exit peer raised exit-node warning")
	}
}

func TestExitNodeSwitchingClearsPriorWarning(t *testing.T) {
	c, ht := newConnWithHealth(t)

	a := key.NewNode().Public()
	b := key.NewNode().Public()
	c.SetExitNodePeer(a, "exit-a")
	c.NoteExitNodeReachabilityResult(a, errors.New("the packets are not flowing"))
	if !ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("precondition: warnable should be set for peer a")
	}

	c.SetExitNodePeer(b, "exit-b")

	if ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("switching exit node did not clear the prior peer's warning")
	}
	if c.exitNodeUnhealthy.Load() {
		t.Fatalf("exitNodeUnhealthy=true after peer switch")
	}
}

func TestExitNodeClearingResetsWarning(t *testing.T) {
	c, ht := newConnWithHealth(t)

	exit := key.NewNode().Public()
	c.SetExitNodePeer(exit, "exitbox")
	c.NoteExitNodeReachabilityResult(exit, errors.New("the packets are not flowing"))
	if !ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("precondition: warnable should be set")
	}

	c.SetExitNodePeer(key.NodePublic{}, "")

	if ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("clearing the exit node did not clear the warning")
	}
	if c.exitNodeUnhealthy.Load() {
		t.Fatalf("exitNodeUnhealthy=true after clearing exit node")
	}
}

func TestExitNodeSetSameKeyIsIdempotent(t *testing.T) {
	c, ht := newConnWithHealth(t)

	exit := key.NewNode().Public()
	c.SetExitNodePeer(exit, "exitbox")
	c.NoteExitNodeReachabilityResult(exit, errors.New("boom"))
	if !ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("precondition: warnable should be set")
	}

	// Re-setting the same key must not clear the warning — nothing about
	// the tracked peer has changed.
	c.SetExitNodePeer(exit, "exitbox-refreshed-name")

	if !ht.IsUnhealthy(health.ExitNodeUnreachableWarnable) {
		t.Fatalf("warnable was cleared when re-setting the same exit node key")
	}
}
