// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"fmt"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
)

func TestFileTargets(t *testing.T) {
	e := new(extension)
	e.lb = &ipnlocal.LocalBackend{}

	_, err := e.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("before connect: got %q; want %q", got, want)
	}

	e.netMap = new(netmap.NetworkMap)
	_, err = e.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("non-running netmap: got %q; want %q", got, want)
	}

	e.stateForTest = ptr.To(ipn.Running)
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
	e.netMap.Peers = []tailcfg.NodeView{peer.View()}

	got, err = e.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}
}
