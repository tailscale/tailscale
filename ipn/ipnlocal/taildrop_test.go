// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_taildrop

package ipnlocal

import (
	"fmt"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/deptest"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
)

func TestFileTargets(t *testing.T) {
	b := new(LocalBackend)
	_, err := b.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("before connect: got %q; want %q", got, want)
	}

	b.netMap = new(netmap.NetworkMap)
	_, err = b.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("non-running netmap: got %q; want %q", got, want)
	}

	b.state = ipn.Running
	_, err = b.FileTargets()
	if got, want := fmt.Sprint(err), "file sharing not enabled by Tailscale admin"; got != want {
		t.Errorf("without cap: got %q; want %q", got, want)
	}

	b.capFileSharing = true
	got, err := b.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}

	var peerMap map[tailcfg.NodeID]tailcfg.NodeView
	mak.NonNil(&peerMap)
	var nodeID tailcfg.NodeID
	nodeID = 1234
	peer := &tailcfg.Node{
		ID:       1234,
		Hostinfo: (&tailcfg.Hostinfo{OS: "tvOS"}).View(),
	}
	peerMap[nodeID] = peer.View()
	b.peers = peerMap
	got, err = b.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}
	// (other cases handled by TestPeerAPIBase above)
}

func TestOmitTaildropDeps(t *testing.T) {
	deptest.DepChecker{
		Tags:   "ts_omit_taildrop",
		GOOS:   "linux",
		GOARCH: "amd64",
		BadDeps: map[string]string{
			"tailscale.com/taildrop":         "should be omitted",
			"tailscale.com/feature/taildrop": "should be omitted",
		},
	}.Check(t)
}
