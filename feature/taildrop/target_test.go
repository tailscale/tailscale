// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"fmt"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
)

func TestFileTargets(t *testing.T) {
	e := new(Extension)

	_, err := e.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("before connect: got %q; want %q", got, want)
	}

	e.nodeBackendForTest = testNodeBackend{peers: nil}

	_, err = e.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("non-running netmap: got %q; want %q", got, want)
	}

	e.backendState = ipn.Running
	_, err = e.FileTargets()
	if got, want := fmt.Sprint(err), "file sharing not enabled by Tailscale admin"; got != want {
		t.Errorf("without cap: got %q; want %q", got, want)
	}

	e.capFileSharing = true
	got, err := e.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}

	var nodeID tailcfg.NodeID = 1234
	peer := &tailcfg.Node{
		ID:       nodeID,
		Hostinfo: (&tailcfg.Hostinfo{OS: "tvOS"}).View(),
	}
	e.nodeBackendForTest = testNodeBackend{peers: []tailcfg.NodeView{peer.View()}}

	got, err = e.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}
}

type testNodeBackend struct {
	ipnext.NodeBackend
	peers []tailcfg.NodeView
}

func (t testNodeBackend) AppendMatchingPeers(peers []tailcfg.NodeView, f func(tailcfg.NodeView) bool) []tailcfg.NodeView {
	for _, p := range t.peers {
		if f(p) {
			peers = append(peers, p)
		}
	}
	return peers
}
