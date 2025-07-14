// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"errors"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// TestPeerCapMap tests that the node capability map (CapMap) is included in peer information.
func TestPeerCapMap(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)

	// Spin up two nodes.
	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()

	n2 := NewTestNode(t, env)
	d2 := n2.StartDaemon()
	n2.AwaitListening()
	n2.MustUp()
	n2.AwaitRunning()

	n1.AwaitIP4()
	n2.AwaitIP4()

	// Get the nodes from the control server.
	nodes := env.Control.AllNodes()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d nodes", len(nodes))
	}

	// Figure out which node is which by comparing keys.
	st1 := n1.MustStatus()
	var tn1, tn2 *tailcfg.Node
	for _, n := range nodes {
		if n.Key == st1.Self.PublicKey {
			tn1 = n
		} else {
			tn2 = n
		}
	}

	// Set CapMap on both nodes.
	caps := make(tailcfg.NodeCapMap)
	caps["example:custom"] = []tailcfg.RawMessage{`"value"`}
	caps["example:enabled"] = []tailcfg.RawMessage{`true`}

	env.Control.SetNodeCapMap(tn1.Key, caps)
	env.Control.SetNodeCapMap(tn2.Key, caps)

	// Check that nodes see each other's CapMap.
	if err := tstest.WaitFor(10*time.Second, func() error {
		st1 := n1.MustStatus()
		st2 := n2.MustStatus()

		if len(st1.Peer) == 0 || len(st2.Peer) == 0 {
			return errors.New("no peers")
		}

		// Check n1 sees n2's CapMap.
		p1 := st1.Peer[st1.Peers()[0]]
		if p1.CapMap == nil {
			return errors.New("peer CapMap is nil")
		}
		if p1.CapMap["example:custom"] == nil || p1.CapMap["example:enabled"] == nil {
			return errors.New("peer CapMap missing entries")
		}

		// Check n2 sees n1's CapMap.
		p2 := st2.Peer[st2.Peers()[0]]
		if p2.CapMap == nil {
			return errors.New("peer CapMap is nil")
		}
		if p2.CapMap["example:custom"] == nil || p2.CapMap["example:enabled"] == nil {
			return errors.New("peer CapMap missing entries")
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}

// TestSetNodeCapMap tests that SetNodeCapMap updates are propagated to peers.
func TestSetNodeCapMap(t *testing.T) {
	tstest.Shard(t)
	tstest.Parallel(t)
	env := NewTestEnv(t)

	n1 := NewTestNode(t, env)
	d1 := n1.StartDaemon()
	n1.AwaitListening()
	n1.MustUp()
	n1.AwaitRunning()

	nodes := env.Control.AllNodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d nodes", len(nodes))
	}
	node1 := nodes[0]

	// Set initial CapMap.
	caps := make(tailcfg.NodeCapMap)
	caps["test:state"] = []tailcfg.RawMessage{`"initial"`}
	env.Control.SetNodeCapMap(node1.Key, caps)

	// Start second node and verify it sees the first node's CapMap.
	n2 := NewTestNode(t, env)
	d2 := n2.StartDaemon()
	n2.AwaitListening()
	n2.MustUp()
	n2.AwaitRunning()

	if err := tstest.WaitFor(5*time.Second, func() error {
		st := n2.MustStatus()
		if len(st.Peer) == 0 {
			return errors.New("no peers")
		}
		p := st.Peer[st.Peers()[0]]
		if p.CapMap == nil || p.CapMap["test:state"] == nil {
			return errors.New("peer CapMap not set")
		}
		if string(p.CapMap["test:state"][0]) != `"initial"` {
			return errors.New("wrong CapMap value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	d1.MustCleanShutdown(t)
	d2.MustCleanShutdown(t)
}
