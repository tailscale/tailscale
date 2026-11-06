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
	"net/url"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/tswg"
)

// pingOnce reports whether a single tta ping (4 echo requests) from n to ip
// gets a reply.
func pingOnce(t *testing.T, n *vmtest.Node, ip netip.Addr) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://unused/ping?host="+ip.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := n.Agent().HTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	return res.StatusCode == 200
}

// tswgDatagram is a datagram received by tta on a socket shared with tswg.
type tswgDatagram struct {
	From netip.AddrPort
	Data []byte
}

// isWireGuardMessage reports whether b looks like a WireGuard message.
func isWireGuardMessage(b []byte) bool {
	return len(b) >= 4 && b[0] >= 1 && b[0] <= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0
}

// TestTSWGGokrazySharedSocket checks that a tswg device can share a UDP
// socket with userspace, as tailscaled's magicsock will: tta opens the
// socket and passes its fd to the device. The tunnel must work over it,
// non-WireGuard datagrams (disco, STUN) must reach userspace with the
// sender's shared socket as their source, no WireGuard messages may leak to
// userspace, and closing the socket must detach it so that a new one can
// take its place.
func TestTSWGGokrazySharedSocket(t *testing.T) {
	testTSWGSharedSocket(t, vmtest.Gokrazy)
}

// TestTSWGUbuntuSharedSocket is like TestTSWGGokrazySharedSocket, but on
// Ubuntu 24.04's stock 6.8 kernel, which exercises the compat paths.
func TestTSWGUbuntuSharedSocket(t *testing.T) {
	testTSWGSharedSocket(t, vmtest.Ubuntu2404)
}

func testTSWGSharedSocket(t *testing.T, osImg vmtest.OSImage) {
	dir := tswgDir(t)
	var ko []byte
	if osImg.IsGokrazy {
		ko = buildTSWGForGokrazy(t, dir)
	}

	env := vmtest.New(t)
	lan := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	n1 := env.AddNode("tswg1", lan, vmtest.OS(osImg), vmtest.DontJoinTailnet())
	n2 := env.AddNode("tswg2", lan, vmtest.OS(osImg), vmtest.DontJoinTailnet())
	env.Start()

	nodes := []*vmtest.Node{n1, n2}
	files := &tswgFiles{t: t, env: env, dir: dir}
	for _, n := range nodes {
		if osImg.IsGokrazy {
			tta(t, n, "POST", "/tswg/load", ko)
		} else {
			// Distro kernels have tswg's dependencies (udp_tunnel and
			// crypto libraries) as modules, which init_module(2) can't
			// resolve, so use modprobe.
			installTSWG(t, env, files, n)
		}
	}

	const port = 51820
	keys := []key.NodePrivate{key.NewNode(), key.NewNode()}
	tunIP := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, 99, 0, byte(i + 1)}) }
	lanAddr := func(i int) netip.AddrPort { return netip.AddrPortFrom(nodes[i].LanIP(lan), port) }
	up := func(i int) {
		t.Helper()
		j := 1 - i
		priv, _ := keys[i].MarshalText()
		q := url.Values{
			"dev":         {"tsw0"},
			"addr":        {tunIP(i).String() + "/24"},
			"private-key": {string(priv)},
			"listen-port": {fmt.Sprint(port)},
			"peer":        {keys[j].Public().String()},
			"endpoint":    {lanAddr(j).String()},
			"allowed-ips": {tunIP(j).String() + "/32"},
			"user-socket": {"1"},
		}
		tta(t, nodes[i], "POST", "/tswg/up?"+q.Encode(), nil)
	}
	show := func(i int) *tswg.Device {
		t.Helper()
		var d tswg.Device
		if err := json.Unmarshal([]byte(tta(t, nodes[i], "GET", "/tswg/show?dev=tsw0", nil)), &d); err != nil {
			t.Fatalf("[%s] parsing /tswg/show: %v", nodes[i].Name(), err)
		}
		return &d
	}
	recv := func(i int) []tswgDatagram {
		t.Helper()
		var dgs []tswgDatagram
		if err := json.Unmarshal([]byte(tta(t, nodes[i], "GET", "/tswg/sock-recv?dev=tsw0", nil)), &dgs); err != nil {
			t.Fatalf("[%s] parsing /tswg/sock-recv: %v", nodes[i].Name(), err)
		}
		return dgs
	}
	checkNoWireGuardLeaked := func(i int, dgs []tswgDatagram) {
		t.Helper()
		for _, dg := range dgs {
			if isWireGuardMessage(dg.Data) {
				t.Errorf("[%s] WireGuard message (type %d, %d bytes) from %v leaked to userspace",
					nodes[i].Name(), dg.Data[0], len(dg.Data), dg.From)
			}
		}
	}

	for i := range nodes {
		up(i)
	}

	// The tunnel works over the shared sockets.
	env.LANPing(n1, tunIP(1))
	for i, n := range nodes {
		d := show(i)
		if !d.UserSocket4 {
			t.Errorf("[%s] UserSocket4 = false, want true", n.Name())
		}
		checkTSWGDevice(t, n, d, keys[i].Public(), port)
	}

	// Non-WireGuard datagrams sent from one shared socket arrive on the
	// other in userspace, from the same address the tunnel uses.
	checkNoWireGuardLeaked(1, recv(1))
	disco := append([]byte("TS\xf0\x9f\x92\xac"), "fake disco ping"...)
	stun := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	for _, b := range [][]byte{disco, stun} {
		tta(t, n1, "POST", "/tswg/sock-send?dev=tsw0&to="+lanAddr(1).String(), b)
	}
	var got []tswgDatagram
	deadline := time.Now().Add(10 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		got = append(got, recv(1)...)
		time.Sleep(200 * time.Millisecond)
	}
	checkNoWireGuardLeaked(1, got)
	for _, want := range [][]byte{disco, stun} {
		found := false
		for _, dg := range got {
			if bytes.Equal(dg.Data, want) {
				found = true
				if dg.From != lanAddr(0) {
					t.Errorf("datagram %q came from %v, want %v (the sender's shared socket)", want, dg.From, lanAddr(0))
				}
			}
		}
		if !found {
			t.Errorf("datagram %q not received in userspace; got %d datagrams: %+v", want, len(got), got)
		}
	}

	// The tunnel still works, and still nothing leaks.
	env.LANPing(n1, tunIP(1))
	checkNoWireGuardLeaked(1, recv(1))

	// Closing the shared socket detaches it from the device, which then
	// has no socket at all, so the tunnel stops working.
	tta(t, n2, "POST", "/tswg/sock-close?dev=tsw0", nil)
	if d := show(1); d.UserSocket4 {
		t.Errorf("[%s] after closing the socket, UserSocket4 = true, want false", n2.Name())
	}
	if pingOnce(t, n1, tunIP(1)) {
		t.Errorf("ping over the tunnel succeeded after %s closed its socket", n2.Name())
	}

	// A new shared socket takes its place, and the tunnel works again.
	up(1)
	if d := show(1); !d.UserSocket4 {
		t.Errorf("[%s] after reattaching, UserSocket4 = false, want true", n2.Name())
	}
	env.LANPing(n1, tunIP(1))
	checkNoWireGuardLeaked(1, recv(1))
}
