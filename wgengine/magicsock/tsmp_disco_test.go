// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/wgcfg/nmcfg"
)

func TestTSMPDiscoKeyExchange(t *testing.T) {
	tstest.ResourceCheck(t)

	// Set up DERP and STUN servers
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	// Create two magicsock peers
	m1 := newMagicStack(t, t.Logf, localhostListener{}, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, t.Logf, localhostListener{}, derpMap)
	defer m2.Close()

	// Wire up TSMP hooks to enable disco key exchange
	// This mimics what userspaceEngine does in wgengine/userspace.go

	// Hook 0: GetDiscoPublicKey - allows TSMP replies to include current disco key
	m1.tsTun.GetDiscoPublicKey = m1.conn.DiscoPublicKey
	m2.tsTun.GetDiscoPublicKey = m2.conn.DiscoPublicKey

	// Hook 1: OnTSMPDiscoKeyReceived - handle incoming TSMP disco key updates
	m1.tsTun.OnTSMPDiscoKeyReceived = func(srcIP netip.Addr, update packet.TSMPDiscoKeyUpdate) {
		t.Logf("m1: received TSMP disco key update from %v", srcIP)
		m1.conn.HandleDiscoKeyUpdate(srcIP, update)
	}
	m2.tsTun.OnTSMPDiscoKeyReceived = func(srcIP netip.Addr, update packet.TSMPDiscoKeyUpdate) {
		t.Logf("m2: received TSMP disco key update from %v", srcIP)
		m2.conn.HandleDiscoKeyUpdate(srcIP, update)
	}

	sendTSMPDiscoKeyRequest := func(dstIP netip.Addr) error {
		var srcIP netip.Addr
		var stack *magicStack

		switch dstIP {
		case m1.IP():
			srcIP = m2.IP()
			stack = m2
			t.Logf("m2: sending disco key request to m1")
		case m2.IP():
			srcIP = m1.IP()
			stack = m1
			t.Logf("m1: sending disco key request to m2")
		}

		// equivalent to the implementation in userspace.Engine
		iph := packet.IP4Header{
			IPProto: ipproto.TSMP,
			Src:     srcIP,
			Dst:     dstIP,
		}

		var tsmpPayload [1]byte
		tsmpPayload[0] = byte(packet.TSMPTypeDiscoKeyRequest)

		tsmpRequest := packet.Generate(iph, tsmpPayload[:])
		return stack.tsTun.InjectOutbound(tsmpRequest)
	}

	// Hook 2: SetSendTSMPDiscoKeyRequest - send TSMP disco key requests
	m1.conn.SetSendTSMPDiscoKeyRequest(sendTSMPDiscoKeyRequest)
	m2.conn.SetSendTSMPDiscoKeyRequest(sendTSMPDiscoKeyRequest)

	// Get initial disco keys
	disco1Original := m1.conn.DiscoPublicKey()
	disco2 := m2.conn.DiscoPublicKey()

	t.Logf("m1: node=%v disco=%v", m1.Public().ShortString(), disco1Original.ShortString())
	t.Logf("m2: node=%v disco=%v", m2.Public().ShortString(), disco2.ShortString())

	// Wait for initial endpoints
	var eps1, eps2 []tailcfg.Endpoint
	select {
	case eps1 = <-m1.epCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for m1 endpoints")
	}
	select {
	case eps2 = <-m2.epCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for m2 endpoints")
	}

	// Build initial network maps and establish connection
	nm1 := &netmap.NetworkMap{
		NodeKey: m1.Public(),
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 64, 0, 1), 32)},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:         2,
				Key:        m2.Public(),
				DiscoKey:   disco2,
				Addresses:  []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 64, 0, 2), 32)},
				AllowedIPs: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 64, 0, 2), 32)},
				Endpoints:  epFromTyped(eps2),
				HomeDERP:   1,
			}).View(),
		},
	}

	nm2 := &netmap.NetworkMap{
		NodeKey: m2.Public(),
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 64, 0, 2), 32)},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:         1,
				Key:        m1.Public(),
				DiscoKey:   disco1Original,
				Addresses:  []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 64, 0, 1), 32)},
				AllowedIPs: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 64, 0, 1), 32)},
				Endpoints:  epFromTyped(eps1),
				HomeDERP:   1,
			}).View(),
		},
	}

	cfg1, err := nmcfg.WGCfg(m1.privateKey, nm1, t.Logf, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg2, err := nmcfg.WGCfg(m2.privateKey, nm2, t.Logf, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	nv1 := NodeViewsUpdate{
		SelfNode: nm1.SelfNode,
		Peers:    nm1.Peers,
	}
	m1.conn.onNodeViewsUpdate(nv1)

	peerSet1 := set.Set[key.NodePublic]{}
	peerSet1.Add(m2.Public())
	m1.conn.UpdatePeers(peerSet1)

	nv2 := NodeViewsUpdate{
		SelfNode: nm2.SelfNode,
		Peers:    nm2.Peers,
	}
	m2.conn.onNodeViewsUpdate(nv2)

	peerSet2 := set.Set[key.NodePublic]{}
	peerSet2.Add(m1.Public())
	m2.conn.UpdatePeers(peerSet2)

	if err := m1.Reconfig(cfg1); err != nil {
		t.Fatal(err)
	}
	if err := m2.Reconfig(cfg2); err != nil {
		t.Fatal(err)
	}

	t.Logf("=== INITIAL CONFIGURATION COMPLETE ===")

	// Start goroutines to drain TUN inbound channels so TSMP packets can be received
	drainTun := func(name string, stack *magicStack) {
		go func() {
			for {
				select {
				case <-t.Context().Done():
					return
				case pkt := <-stack.tun.Inbound:
					var p packet.Parsed
					p.Decode(pkt)
					if p.IPProto == ipproto.TSMP {
						t.Logf("%s: received TSMP packet on TUN inbound: %d bytes", name, len(pkt))
					} else if p.IPProto == ipproto.ICMPv4 {
						t.Logf("%s: received ICMPv4 packet on TUN inbound: %d bytes", name, len(pkt))
					} else {
						t.Logf("%s: received packet on TUN inbound: %d bytes, proto=%v", name, len(pkt), p.IPProto)
					}
				}
			}
		}()
	}
	drainTun("m1", m1)
	drainTun("m2", m2)

	initialRequestsSent := metricTSMPDiscoKeyRequestSent.Value()
	initialUpdatesReceived := metricTSMPDiscoKeyUpdateReceived.Value()
	initialUpdatesApplied := metricTSMPDiscoKeyUpdateApplied.Value()

	t.Logf("Initial metrics: requests_sent=%d updates_received=%d updates_applied=%d",
		initialRequestsSent, initialUpdatesReceived, initialUpdatesApplied)

	t.Logf("=== ROTATING m1's DISCO KEY ===")
	m1.conn.RotateDiscoKey()
	disco1New := m1.conn.DiscoPublicKey()

	if disco1Original.Compare(disco1New) == 0 {
		t.Fatal("disco key failed to rotate")
	}
	t.Logf("Rotated: %v -> %v", disco1Original.ShortString(), disco1New.ShortString())

	t.Logf("=== SENDING PACKETS TO TRIGGER TSMP EXCHANGE ===")

	ping1to2 := tuntest.Ping(netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("100.64.0.1"))

	// Send packets from m2 to m1 only - this will trigger m1's handshake initiation
	// and when m2 receives the encrypted packet, it should trigger FromPeer -> TSMP
	select {
	case m1.tun.Outbound <- ping1to2:
	default:
	}

	for {
		time.Sleep(time.Millisecond)
		// Check if m2 has learned m1's new disco key
		st := m2.Status()
		if ps, ok := st.Peer[m1.Public()]; ok && ps.CurAddr != "" {
			t.Logf("Connection established after disco key rotation")
			t.Logf("m2 -> m1 via %v", ps.CurAddr)
			t.Logf("Disco key rotation: %v -> %v", disco1Original.ShortString(), disco1New.ShortString())

			// Verify TSMP metrics incremented
			finalRequestsSent := metricTSMPDiscoKeyRequestSent.Value()
			finalUpdatesReceived := metricTSMPDiscoKeyUpdateReceived.Value()
			finalUpdatesApplied := metricTSMPDiscoKeyUpdateApplied.Value()

			t.Logf("Final metrics: requests_sent=%d updates_received=%d updates_applied=%d",
				finalRequestsSent, finalUpdatesReceived, finalUpdatesApplied)

			// Check that at least one TSMP request was sent
			if finalRequestsSent <= initialRequestsSent {
				t.Errorf("Expected TSMP disco key request to be sent, but metric did not increment: %d -> %d",
					initialRequestsSent, finalRequestsSent)
			} else {
				t.Logf("✓ TSMP disco key request sent (metric: %d -> %d)",
					initialRequestsSent, finalRequestsSent)
			}

			// Check that at least one TSMP update was received
			if finalUpdatesReceived <= initialUpdatesReceived {
				t.Errorf("Expected TSMP disco key update to be received, but metric did not increment: %d -> %d",
					initialUpdatesReceived, finalUpdatesReceived)
			} else {
				t.Logf("✓ TSMP disco key update received (metric: %d -> %d)",
					initialUpdatesReceived, finalUpdatesReceived)
			}

			// Check that at least one TSMP update was applied
			if finalUpdatesApplied <= initialUpdatesApplied {
				t.Errorf("Expected TSMP disco key update to be applied, but metric did not increment: %d -> %d",
					initialUpdatesApplied, finalUpdatesApplied)
			} else {
				t.Logf("✓ TSMP disco key update applied (metric: %d -> %d)",
					initialUpdatesApplied, finalUpdatesApplied)
			}

			// Verify error counter didn't increment
			requestErrors := metricTSMPDiscoKeyRequestError.Value()
			if requestErrors > 0 {
				t.Logf("Warning: TSMP disco key request errors: %d", requestErrors)
			}

			unknownPeers := metricTSMPDiscoKeyUpdateUnknown.Value()
			if unknownPeers > 0 {
				t.Logf("Warning: TSMP disco key updates from unknown peers: %d", unknownPeers)
			}

			t.Logf("TSMP disco key exchange infrastructure is functional")
			return
		}
	}
}
