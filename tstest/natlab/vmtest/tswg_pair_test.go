// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"testing"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/tswg"
)

// tswgPair is a test fixture of two VMs on one LAN, each with the tswg
// module loaded and a tsw0 device peered with the other, using UDP sockets
// that tta shares with the device, as tailscaled's magicsock will.
type tswgPair struct {
	t     *testing.T
	env   *vmtest.Env
	lan   *vnet.Network
	nodes [2]*vmtest.Node
	keys  [2]key.NodePrivate
	ports [2]uint16 // each node's current shared socket port
}

// newTSWGPair boots two VMs running osImg and loads tswg on both. It
// doesn't configure the devices; call up for that.
func newTSWGPair(t *testing.T, osImg vmtest.OSImage) *tswgPair {
	dir := tswgDir(t)
	var ko []byte
	if osImg.IsGokrazy {
		ko = buildTSWGForGokrazy(t, dir)
	}

	env := vmtest.New(t)
	p := &tswgPair{
		t:     t,
		env:   env,
		lan:   env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT),
		keys:  [2]key.NodePrivate{key.NewNode(), key.NewNode()},
		ports: [2]uint16{51820, 51820},
	}
	for i := range p.nodes {
		p.nodes[i] = env.AddNode(fmt.Sprintf("tswg%d", i+1), p.lan, vmtest.OS(osImg), vmtest.DontJoinTailnet())
	}
	env.Start()

	files := &tswgFiles{t: t, env: env, dir: dir}
	for _, n := range p.nodes {
		if osImg.IsGokrazy {
			tta(t, n, "POST", "/tswg/load", ko)
		} else {
			// Distro kernels have tswg's dependencies (udp_tunnel and
			// crypto libraries) as modules, which init_module(2) can't
			// resolve, so use modprobe.
			installTSWG(t, env, files, n)
		}
	}
	return p
}

// tunIP returns node i's address inside the tunnel.
func (p *tswgPair) tunIP(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, 99, 0, byte(i + 1)})
}

// lanAddr returns node i's LAN address and current shared socket port.
func (p *tswgPair) lanAddr(i int) netip.AddrPort {
	return netip.AddrPortFrom(p.nodes[i].LanIP(p.lan), p.ports[i])
}

// up creates (if needed) and configures node i's tsw0, with a new shared
// socket on p.ports[i] (closing any previous one) and the other node as its
// peer, at that node's current LAN address and port.
func (p *tswgPair) up(i int) {
	p.t.Helper()
	j := 1 - i
	priv, _ := p.keys[i].MarshalText()
	q := url.Values{
		"dev":         {"tsw0"},
		"addr":        {p.tunIP(i).String() + "/24"},
		"private-key": {string(priv)},
		"listen-port": {fmt.Sprint(p.ports[i])},
		"peer":        {p.keys[j].Public().String()},
		"endpoint":    {p.lanAddr(j).String()},
		"allowed-ips": {p.tunIP(j).String() + "/32"},
		"user-socket": {"1"},
	}
	tta(p.t, p.nodes[i], "POST", "/tswg/up?"+q.Encode(), nil)
}

// show returns the state of node i's tsw0.
func (p *tswgPair) show(i int) *tswg.Device {
	p.t.Helper()
	var d tswg.Device
	if err := json.Unmarshal([]byte(tta(p.t, p.nodes[i], "GET", "/tswg/show?dev=tsw0", nil)), &d); err != nil {
		p.t.Fatalf("[%s] parsing /tswg/show: %v", p.nodes[i].Name(), err)
	}
	return &d
}

// peer returns the state of node i's only peer.
func (p *tswgPair) peer(i int) *tswg.Peer {
	p.t.Helper()
	d := p.show(i)
	if len(d.Peers) != 1 {
		p.t.Fatalf("[%s] got %d peers, want 1", p.nodes[i].Name(), len(d.Peers))
	}
	return &d.Peers[0]
}

// setPeer updates node i's peer with the given /tswg/peer query
// parameters (endpoint, no-roam).
func (p *tswgPair) setPeer(i int, q url.Values) {
	p.t.Helper()
	q.Set("dev", "tsw0")
	q.Set("peer", p.keys[1-i].Public().String())
	tta(p.t, p.nodes[i], "POST", "/tswg/peer?"+q.Encode(), nil)
}

// recv returns, and forgets, the datagrams that node i's shared socket has
// received in userspace.
func (p *tswgPair) recv(i int) []tswgDatagram {
	p.t.Helper()
	var dgs []tswgDatagram
	if err := json.Unmarshal([]byte(tta(p.t, p.nodes[i], "GET", "/tswg/sock-recv?dev=tsw0", nil)), &dgs); err != nil {
		p.t.Fatalf("[%s] parsing /tswg/sock-recv: %v", p.nodes[i].Name(), err)
	}
	return dgs
}

// ping pings node j's tunnel address from node i, retrying for up to two
// minutes, and fails the test if it never succeeds.
func (p *tswgPair) ping(i, j int) {
	p.t.Helper()
	p.env.LANPing(p.nodes[i], p.tunIP(j))
}

// pingFails reports whether a single round of pings from node i to node j's
// tunnel address gets no reply.
func (p *tswgPair) pingFails(i, j int) bool {
	p.t.Helper()
	return !pingOnce(p.t, p.nodes[i], p.tunIP(j))
}
