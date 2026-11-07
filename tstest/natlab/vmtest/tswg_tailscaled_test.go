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
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/wgengine/tswg"
)

// tswgTailscaled is a test fixture of two gokrazy VMs, each behind its own
// NAT, running tailscaled with the tswg kernel data plane.
type tswgTailscaled struct {
	t     *testing.T
	env   *vmtest.Env
	nodes []*vmtest.Node
}

// newTSWGTailscaled boots two gokrazy VMs behind NATs of type nat with
// TS_DEBUG_TSWG=1, loads tswg, restarts tailscaled so that it switches
// from TUN (its fallback while the module wasn't loaded) to the kernel
// data plane, and waits for the kernel device to be set up.
func newTSWGTailscaled(t *testing.T, nat vnet.NAT) *tswgTailscaled {
	dir := tswgDir(t)
	ko := buildTSWGForGokrazy(t, dir)

	f := &tswgTailscaled{t: t, env: vmtest.New(t)}
	for i := range 2 {
		f.nodes = append(f.nodes, f.env.AddNode(fmt.Sprintf("tswg%d", i+1),
			f.env.AddNetwork(
				fmt.Sprintf("2.%d.%d.%d", i+1, i+1, i+1),
				fmt.Sprintf("192.168.%d.1/24", i+1), nat),
			vmtest.OS(vmtest.Gokrazy),
			vnet.TailscaledEnv{Key: "TS_DEBUG_TSWG", Value: "1"}))
	}
	f.env.Start()

	for _, n := range f.nodes {
		tta(t, n, "POST", "/tswg/load", ko)
		f.env.RestartTailscaled(n)
	}
	for _, n := range f.nodes {
		f.waitKernelReady(n)
	}
	return f
}

// show returns the state of n's kernel tailscale0 device.
func (f *tswgTailscaled) show(n *vmtest.Node) (*tswg.Device, error) {
	res, err := ttaErr(n, "GET", "/tswg/show?dev=tailscale0", nil)
	if err != nil {
		return nil, err
	}
	var d tswg.Device
	if err := json.Unmarshal([]byte(res), &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// waitKernelReady waits for n's tailscaled to have set up its kernel
// device: a shared socket and the other node as a peer.
func (f *tswgTailscaled) waitKernelReady(n *vmtest.Node) {
	f.t.Helper()
	if err := tstest.WaitFor(30*time.Second, func() error {
		d, err := f.show(n)
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
		f.t.Fatalf("[%s] kernel data plane not set up: %v", n.Name(), err)
	}
}

// waitKernelPath pings from n to peerIP until n's kernel endpoint for its
// only peer is direct (if wantDirect) or the loopback bridge (if not), and
// returns the kernel's view of the peer then. It fails the test if that
// doesn't happen within timeout.
func (f *tswgTailscaled) waitKernelPath(n *vmtest.Node, peerIP netip.Addr, wantDirect bool, timeout time.Duration) tswg.Peer {
	f.t.Helper()
	var p tswg.Peer
	err := tstest.WaitFor(timeout, func() error {
		pingOnce(f.t, n, peerIP) // keep the session active
		d, err := f.show(n)
		if err != nil {
			return err
		}
		if len(d.Peers) != 1 {
			return fmt.Errorf("%d peers", len(d.Peers))
		}
		p = d.Peers[0]
		if isDirect := !p.Endpoint.Addr().IsLoopback(); isDirect != wantDirect {
			return fmt.Errorf("kernel endpoint for peer is %v; want direct=%v", p.Endpoint, wantDirect)
		}
		return nil
	})
	if err != nil {
		f.t.Fatalf("[%s] %v", n.Name(), err)
	}
	return p
}

// ip returns n's Tailscale IPv4 address.
func (f *tswgTailscaled) ip(n *vmtest.Node) netip.Addr {
	return f.env.Status(n).Self.TailscaleIPs[0]
}

// metric returns the value of n's client metric name.
func (f *tswgTailscaled) metric(n *vmtest.Node, name string) int64 {
	return f.env.ClientMetrics(n)[name].Value
}

// TestTSWGTailscaledDirect runs tailscaled with the tswg kernel data plane
// on two gokrazy VMs behind separate easy NATs, so that disco's NAT
// traversal over the socket that magicsock shares with the kernel finds a
// direct path, and checks that the kernel then sends to the peer directly.
func TestTSWGTailscaledDirect(t *testing.T) {
	testTSWGTailscaledPath(t, vnet.EasyNAT, true)
}

// TestTSWGTailscaledDERP is like TestTSWGTailscaledDirect, but behind hard
// NATs on both sides, so that there's no direct path and all traffic goes
// from the kernel through tailscaled's loopback bridge to DERP and back.
func TestTSWGTailscaledDERP(t *testing.T) {
	testTSWGTailscaledPath(t, vnet.HardNAT, false)
}

func testTSWGTailscaledPath(t *testing.T, nat vnet.NAT, wantDirect bool) {
	f := newTSWGTailscaled(t, nat)
	n1, n2 := f.nodes[0], f.nodes[1]
	ip2 := f.ip(n2)
	f.env.LANPing(n1, ip2)

	// Wait for the kernel's endpoint for the peer to settle: direct, or
	// tailscaled's loopback bridge.
	p := f.waitKernelPath(n1, ip2, wantDirect, 60*time.Second)
	t.Logf("[%s] kernel peer %v: endpoint=%v rx=%d tx=%d handshake=%v no-roam=%v",
		n1.Name(), p.PublicKey.ShortString(), p.Endpoint, p.RxBytes, p.TxBytes, p.LastHandshake, p.NoRoam)
	if !p.NoRoam {
		t.Errorf("kernel peer has NoRoam = false, want true")
	}
	if p.LastHandshake.IsZero() || p.RxBytes == 0 || p.TxBytes == 0 {
		t.Errorf("kernel peer hasn't handshaken or exchanged traffic: %+v", p)
	}

	// And the tunnel still works, both ways, on the settled path.
	f.env.LANPing(n1, ip2)
	f.env.LANPing(n2, f.ip(n1))
}

// TestTSWGTailscaledPathFallback checks that when a direct path dies, the
// kernel falls back to sending via tailscaled's loopback bridge (and so
// DERP) once magicsock stops trusting the path, with nothing polling: no
// packet arrives to say the path is gone, so it relies on magicsock's
// trust expiry timer.
func TestTSWGTailscaledPathFallback(t *testing.T) {
	f := newTSWGTailscaled(t, vnet.EasyNAT)
	n1, n2 := f.nodes[0], f.nodes[1]
	ip2 := f.ip(n2)
	f.env.LANPing(n1, ip2)
	f.waitKernelPath(n1, ip2, true, 60*time.Second)

	// Break the direct path: n1 drops all UDP from n2's public address
	// (DERP, over TCP, still works).
	tta(t, n1, "POST", "/tswg/drop-udp-from?ip=2.2.2.2", nil)

	// magicsock trusts a path for 6.5 seconds after its last pong.
	start := time.Now()
	f.waitKernelPath(n1, ip2, false, 30*time.Second)
	t.Logf("kernel fell back to the bridge %v after the direct path broke", time.Since(start).Round(time.Second))

	// And the tunnel works over DERP.
	f.env.LANPing(n1, ip2)
	f.env.LANPing(n2, f.ip(n1))
}

// TestTSWGTailscaledIdleTrustExpiry checks that when a session goes idle,
// so that magicsock stops heartbeating and its trust in the direct path
// lapses (with no packet or ping timeout to mark the moment), the kernel
// stops sending to the peer directly, as wireguard-go would, so that the
// next packets go through magicsock (DERP, plus the candidate path) until
// the path is trusted again. That relies on magicsock's trust expiry timer.
func TestTSWGTailscaledIdleTrustExpiry(t *testing.T) {
	f := newTSWGTailscaled(t, vnet.EasyNAT)
	n1, n2 := f.nodes[0], f.nodes[1]
	ip2 := f.ip(n2)
	f.env.LANPing(n1, ip2)
	f.waitKernelPath(n1, ip2, true, 60*time.Second)

	// Send nothing. magicsock considers a session idle after 45 seconds
	// and then trusts its path for at most 6.5 more.
	start := time.Now()
	if err := tstest.WaitFor(90*time.Second, func() error {
		d, err := f.show(n1)
		if err != nil {
			return err
		}
		if len(d.Peers) != 1 {
			return fmt.Errorf("%d peers", len(d.Peers))
		}
		if ep := d.Peers[0].Endpoint; !ep.Addr().IsLoopback() {
			return fmt.Errorf("kernel endpoint still direct: %v", ep)
		}
		return nil
	}); err != nil {
		t.Fatalf("kernel kept sending directly after the session went idle: %v", err)
	}
	t.Logf("kernel moved to the bridge %v into the idle period", time.Since(start).Round(time.Second))

	// Traffic makes the path trusted, and direct, again.
	f.env.LANPing(n1, ip2)
	f.waitKernelPath(n1, ip2, true, 30*time.Second)
}

// TestTSWGTailscaledTSMP checks TSMP in kernel mode: TSMP pings (and their
// pongs), which tailscaled sends and answers through raw sockets on the
// kernel device, and the TSMP disco key advertisements that tailscaled
// sends when the kernel establishes a session, as wireguard-go does.
func TestTSWGTailscaledTSMP(t *testing.T) {
	f := newTSWGTailscaled(t, vnet.EasyNAT)
	n1, n2 := f.nodes[0], f.nodes[1]

	// Establishing the session makes each side advertise its disco key
	// to the other over TSMP.
	f.env.LANPing(n1, f.ip(n2))
	const recvMetric = "magicsock_tsmp_disco_key_advertisement_received"
	for _, n := range f.nodes {
		if err := tstest.WaitFor(15*time.Second, func() error {
			if v := f.metric(n, recvMetric); v == 0 {
				return fmt.Errorf("%s = 0", recvMetric)
			}
			return nil
		}); err != nil {
			t.Errorf("[%s] no TSMP disco key advertisement received: %v", n.Name(), err)
		}
	}

	for _, pair := range [][2]*vmtest.Node{{n1, n2}, {n2, n1}} {
		if err := f.env.Ping(pair[0], pair[1], tailcfg.PingTSMP, 30*time.Second); err != nil {
			t.Errorf("TSMP ping %s -> %s: %v", pair[0].Name(), pair[1].Name(), err)
		}
	}
}

// TestTSWGTailscaledPeerRestart checks that when a peer restarts (and so
// loses its WireGuard session), the kernel forgets its stale session as
// soon as tailscaled learns the peer's new disco key, so that the next
// packet starts a new handshake. Without that, the kernel would keep
// sending with dead keys until WireGuard's own timeouts start a new
// handshake about 15 seconds later.
func TestTSWGTailscaledPeerRestart(t *testing.T) {
	f := newTSWGTailscaled(t, vnet.EasyNAT)
	n1, n2 := f.nodes[0], f.nodes[1]
	ip2 := f.ip(n2)
	f.env.LANPing(n1, ip2)

	n2Key := f.env.Status(n2).Self.PublicKey
	oldDisco, ok, err := f.env.PeerDiscoKey(n1, n2Key)
	if err != nil || !ok {
		t.Fatalf("getting %s's disco key for %s: ok=%v, %v", n1.Name(), n2.Name(), ok, err)
	}

	// Restarting tailscaled on n2 recreates its kernel device, losing the
	// session, and gives it a new disco key.
	f.env.RestartTailscaled(n2)
	f.waitKernelReady(n2)
	if err := tstest.WaitFor(30*time.Second, func() error {
		k, ok, err := f.env.PeerDiscoKey(n1, n2Key)
		if err != nil {
			return err
		}
		if !ok || k == oldDisco {
			return fmt.Errorf("still has the old disco key")
		}
		return nil
	}); err != nil {
		t.Fatalf("%s never learned %s's new disco key: %v", n1.Name(), n2.Name(), err)
	}

	// The first round of pings from n1 must get through.
	if !pingOnce(t, n1, ip2) {
		t.Errorf("first ping after %s restarted failed; the stale session wasn't cleared", n2.Name())
	}
	if logs := f.env.NodeLogs(n1); !strings.Contains(logs, "tswg: clearing session with") {
		t.Errorf("%s's logs don't mention clearing the session", n1.Name())
	}
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
