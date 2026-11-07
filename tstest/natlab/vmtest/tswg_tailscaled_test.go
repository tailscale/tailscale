// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/wgengine/tswg"
)

// TestTSWGTailscaledDirect runs tailscaled with the tswg kernel data plane
// (TS_DEBUG_TSWG=1) on two gokrazy VMs behind separate easy NATs, so that
// disco's NAT traversal over the socket that magicsock shares with the
// kernel finds a direct path, and checks that the kernel then sends to the
// peer directly.
func TestTSWGTailscaledDirect(t *testing.T) {
	testTSWGTailscaled(t, vnet.EasyNAT, true)
}

// TestTSWGTailscaledDERP is like TestTSWGTailscaledDirect, but behind hard
// NATs on both sides, so that there's no direct path and all traffic goes
// from the kernel through tailscaled's loopback bridge to DERP and back.
func TestTSWGTailscaledDERP(t *testing.T) {
	testTSWGTailscaled(t, vnet.HardNAT, false)
}

func testTSWGTailscaled(t *testing.T, nat vnet.NAT, wantDirect bool) {
	dir := tswgDir(t)
	ko := buildTSWGForGokrazy(t, dir)

	env := vmtest.New(t)
	var nodes []*vmtest.Node
	for i := range 2 {
		nodes = append(nodes, env.AddNode(fmt.Sprintf("tswg%d", i+1),
			env.AddNetwork(
				fmt.Sprintf("2.%d.%d.%d", i+1, i+1, i+1),
				fmt.Sprintf("192.168.%d.1/24", i+1), nat),
			vmtest.OS(vmtest.Gokrazy),
			vnet.TailscaledEnv{Key: "TS_DEBUG_TSWG", Value: "1"}))
	}
	env.Start()

	// tailscaled started before the module was loaded, so it fell back
	// to TUN. Load the module and restart tailscaled to switch to the
	// kernel data plane.
	for _, n := range nodes {
		tta(t, n, "POST", "/tswg/load", ko)
		env.RestartTailscaled(n)
	}

	show := func(n *vmtest.Node) (*tswg.Device, error) {
		var d tswg.Device
		res, err := ttaErr(n, "GET", "/tswg/show?dev=tailscale0", nil)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(res), &d); err != nil {
			return nil, err
		}
		return &d, nil
	}
	for _, n := range nodes {
		if err := tstest.WaitFor(30*time.Second, func() error {
			d, err := show(n)
			if err != nil {
				return err
			}
			if !d.UserSocket4 {
				return fmt.Errorf("tailscale0 has no shared IPv4 socket")
			}
			if len(d.Peers) != 1 {
				return fmt.Errorf("tailscale0 has %d peers, want 1", len(d.Peers))
			}
			return nil
		}); err != nil {
			t.Fatalf("[%s] kernel data plane not set up: %v", n.Name(), err)
		}
	}

	ip2 := env.Status(nodes[1]).Self.TailscaleIPs[0]
	env.LANPing(nodes[0], ip2)

	// Wait for the kernel's endpoint for the peer to settle: direct, or
	// tailscaled's loopback bridge.
	var d *tswg.Device
	err := tstest.WaitFor(60*time.Second, func() error {
		pingOnce(t, nodes[0], ip2) // keep the session active
		var err error
		d, err = show(nodes[0])
		if err != nil {
			return err
		}
		if len(d.Peers) != 1 {
			return fmt.Errorf("%d peers", len(d.Peers))
		}
		ep := d.Peers[0].Endpoint
		if isDirect := !ep.Addr().IsLoopback(); isDirect != wantDirect {
			return fmt.Errorf("kernel endpoint for peer is %v; want direct=%v", ep, wantDirect)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p := d.Peers[0]
	t.Logf("[%s] kernel peer %v: endpoint=%v rx=%d tx=%d handshake=%v no-roam=%v",
		nodes[0].Name(), p.PublicKey.ShortString(), p.Endpoint, p.RxBytes, p.TxBytes, p.LastHandshake, p.NoRoam)
	if !p.NoRoam {
		t.Errorf("kernel peer has NoRoam = false, want true")
	}
	if p.LastHandshake.IsZero() || p.RxBytes == 0 || p.TxBytes == 0 {
		t.Errorf("kernel peer hasn't handshaken or exchanged traffic: %+v", p)
	}

	// And the tunnel still works, both ways, on the settled path.
	env.LANPing(nodes[0], ip2)
	env.LANPing(nodes[1], env.Status(nodes[0]).Self.TailscaleIPs[0])
}

// ttaErr is like tta but returns errors instead of failing the test.
func ttaErr(n *vmtest.Node, method, path string, body []byte) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://unused"+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	res, err := n.Agent().HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("%s %s: %s: %s", method, path, res.Status, resBody)
	}
	return string(resBody), nil
}
