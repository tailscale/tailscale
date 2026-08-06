// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/net/netmon"
	"tailscale.com/tsconst"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
)

const maxDirectPathRecovery = time.Second

// TestDirectPathFailureAfterShortWakeUsesKnownAlternate models a peer with a
// fast public endpoint and a known-working slower private endpoint. It compares
// a Rebind+ReSTUN control with the ReSTUN-only short-wake action. Both must move
// CurAddr to the healthy private endpoint without waiting for the failed public
// endpoint's trust window to expire.
func TestDirectPathFailureAfterShortWakeUsesKnownAlternate(t *testing.T) {
	tstest.ResourceCheck(t)

	// magicsock tests shorten both values globally. Use production timing so
	// this test exercises the same trusted-path window as a real node.
	oldPingTimeout := pingTimeoutDuration
	oldPingInterval := discoPingInterval
	pingTimeoutDuration = tsconst.DefaultPingTimeout
	discoPingInterval = tsconst.DefaultPingInterval
	defer func() {
		pingTimeoutDuration = oldPingTimeout
		discoPingInterval = oldPingInterval
	}()

	state := &netmon.State{HaveV4: true}
	shortWake, err := netmon.NewChangeDelta(state, state, 55*time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	if !shortWake.TimeJumped() || shortWake.RebindLikelyRequired {
		t.Fatalf("short-wake delta = {TimeJumped:%v RebindLikelyRequired:%v}; want {true false}", shortWake.TimeJumped(), shortWake.RebindLikelyRequired)
	}

	// Compare the current short-wake action with a control that also resets
	// endpoint state by rebinding before starting endpoint discovery.
	for _, tt := range []struct {
		name       string
		wakeAction func(*Conn)
	}{
		{"rebind-restun-control", func(c *Conn) {
			c.SetNetworkUp(true)
			c.Rebind()
			c.ReSTUN("link-change-major")
		}},
		{"restun-only", func(c *Conn) {
			c.SetNetworkUp(true)
			c.ReSTUN("link-change-minor")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testDirectPathFailureAfterShortWake(t, tt.wakeAction)
		})
	}
}

func testDirectPathFailureAfterShortWake(t *testing.T, wakeAction func(*Conn)) {
	clientHandler := &dualPathClientHandler{privatePathDelay: 20 * time.Millisecond}
	client := &natlab.Machine{Name: "client", PacketHandler: clientHandler}
	peer := &natlab.Machine{Name: "peer"}
	stunMachine := &natlab.Machine{Name: "stun"}
	inet := natlab.NewInternet()
	privateLAN := &natlab.Network{
		Name:    "private",
		Prefix4: netip.MustParsePrefix("10.17.65.0/24"),
	}
	stunIF := stunMachine.Attach("eth0", inet)
	clientPublicIF := client.Attach("public", inet)
	peerPublicIF := peer.Attach("public", inet)
	clientPrivateIF := client.Attach("private", privateLAN)
	peerPrivateIF := peer.Attach("private", privateLAN)

	derpMap, cleanupDERP := runDERPAndStun(t, t.Logf, stunMachine, stunIF.V4())
	defer cleanupDERP()

	// Build the peer first so the packet handler can match the complete public
	// and private UDP endpoints before the client starts any goroutines.
	peerStack := newMagicStack(t, logger.WithPrefix(t.Logf, "peer: "), peer, derpMap)
	defer peerStack.Close()
	publicPeerAddr := netip.AddrPortFrom(peerPublicIF.V4(), peerStack.conn.LocalPort())
	privatePeerAddr := netip.AddrPortFrom(peerPrivateIF.V4(), peerStack.conn.LocalPort())
	clientHandler.publicIF = clientPublicIF
	clientHandler.privateIF = clientPrivateIF
	clientHandler.publicPeer = publicPeerAddr
	clientHandler.privatePeer = privatePeerAddr

	clientStack := newMagicStack(t, logger.WithPrefix(t.Logf, "client: "), client, derpMap)
	defer clientStack.Close()
	peerStack.conn.SetStaticEndpoints(views.SliceOf([]netip.AddrPort{privatePeerAddr}))

	cleanupMesh := meshStacks(t.Logf, nil, clientStack, peerStack)
	defer cleanupMesh()

	trafficCtx, stopTraffic := context.WithCancel(context.Background())
	var trafficWG sync.WaitGroup
	var nextSequence atomic.Uint32
	deliveries := make(chan deliveredPing, 256)
	trafficWG.Add(1)
	go func() {
		defer trafficWG.Done()
		for {
			select {
			case <-trafficCtx.Done():
				return
			case packet := <-peerStack.tun.Inbound:
				sequence, ok := pingSequence(packet)
				if !ok {
					continue
				}
				select {
				case deliveries <- deliveredPing{sequence: sequence, at: mono.Now()}:
				case <-trafficCtx.Done():
					return
				}
			}
		}
	}()
	defer func() {
		stopTraffic()
		trafficWG.Wait()
	}()

	sendPing := func() (uint16, bool) {
		sequence := uint16(nextSequence.Add(1))
		select {
		case clientStack.tun.Outbound <- sequencedPing(peerStack.IP(), clientStack.IP(), sequence):
			return sequence, true
		case <-trafficCtx.Done():
			return 0, false
		}
	}
	mustSendPing := func() uint16 {
		sequence, ok := sendPing()
		if !ok {
			t.Fatal("traffic stopped while sending ping")
		}
		return sequence
	}

	// Initially suppress the public endpoint so the private endpoint is a
	// proven, known-good candidate before public is allowed to win discovery.
	waitForPeerEndpoint(t, clientStack, peerStack, 5*time.Second)
	forceFullDirectDiscovery(t, clientStack, peerStack)
	privateSequence := mustSendPing()
	waitForPeerAddr(t, clientStack, peerStack, privatePeerAddr, 10*time.Second)
	waitForPingDelivery(t, deliveries, privateSequence-1, 2*time.Second)
	t.Logf("baseline: private direct path %v is selected and carrying traffic", privatePeerAddr)

	clientHandler.mode.Store(int32(dualPathPublicAllowed))
	publicDiscoveryStarted := mono.Now()
	forceFullDirectDiscovery(t, clientStack, peerStack)
	publicSequence := mustSendPing()
	waitForPeerAddr(t, clientStack, peerStack, publicPeerAddr, 5*time.Second)
	pathState := waitForTrustedPathState(t, clientStack, peerStack, publicPeerAddr, privatePeerAddr, publicDiscoveryStarted)
	waitForPingDelivery(t, deliveries, publicSequence-1, 2*time.Second)
	t.Logf("public path %v wins discovery: public RTT=%v, private RTT=%v, trust remaining=%v", publicPeerAddr, pathState.publicLatency, pathState.privateLatency, pathState.trustUntil.Sub(mono.Now()))

	// Continuous WireGuard traffic drives endpoint reevaluation after the
	// selected public path stops working, matching the AWS reproduction.
	trafficWG.Add(1)
	go func() {
		defer trafficWG.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-trafficCtx.Done():
				return
			case <-ticker.C:
				if _, ok := sendPing(); !ok {
					return
				}
			}
		}
	}()
	streamWatermark := uint16(nextSequence.Load())
	waitForPingDelivery(t, deliveries, streamWatermark, 2*time.Second)

	clientHandler.publicPacketsDropped.Store(0)
	peerDiscoKey := peerStack.conn.DiscoPublicKey()
	peerPort := peerStack.conn.LocalPort()
	clientDiscoKey := clientStack.conn.DiscoPublicKey()
	clientPort := clientStack.conn.LocalPort()
	derpPacketsBefore := clientStack.conn.metrics.outboundPacketsDERPTotal.Value()

	clientHandler.mode.Store(int32(dualPathPublicBlackholed))
	failureStarted := mono.Now()
	wakeAction(clientStack.conn)
	recoveredAt := waitForPeerAddr(t, clientStack, peerStack, privatePeerAddr, trustUDPAddrDuration+2*time.Second)
	recovery := recoveredAt.Sub(failureStarted)

	// A packet allocated after CurAddr changed proves data still traverses the
	// selected private path; sequence filtering ignores older queued packets.
	postRecoverySequence := mustSendPing()
	postRecoveryDelivery := waitForPingDelivery(t, deliveries, postRecoverySequence-1, 2*time.Second)

	if dropped := clientHandler.publicPacketsDropped.Load(); dropped == 0 {
		t.Error("the exact public UDP endpoint did not drop any packets")
	} else {
		t.Logf("public UDP endpoint dropped %d packets", dropped)
	}
	if got := peerStack.conn.DiscoPublicKey(); got != peerDiscoKey {
		t.Errorf("peer disco key changed during path failure: got %v, want %v", got.ShortString(), peerDiscoKey.ShortString())
	}
	if got := peerStack.conn.LocalPort(); got != peerPort {
		t.Errorf("peer UDP port changed during path failure: got %d, want %d", got, peerPort)
	}
	if got := clientStack.conn.DiscoPublicKey(); got != clientDiscoKey {
		t.Errorf("client disco key changed during path failure: got %v, want %v", got.ShortString(), clientDiscoKey.ShortString())
	}
	if got := clientStack.conn.LocalPort(); got != clientPort {
		t.Errorf("client UDP port changed during path failure: got %d, want %d", got, clientPort)
	}
	if !recoveredAt.Before(pathState.trustUntil) {
		t.Errorf("private path recovered after %v, but only after the original public trust deadline", recovery)
	}
	if recovery > maxDirectPathRecovery {
		t.Errorf("private path recovered after %v; want recovery within %v", recovery, maxDirectPathRecovery)
	}
	if postRecoveryDelivery.at.Before(recoveredAt) {
		t.Errorf("post-recovery ping sequence %d was delivered before CurAddr selected private", postRecoveryDelivery.sequence)
	}
	derpPackets := clientStack.conn.metrics.outboundPacketsDERPTotal.Value() - derpPacketsBefore
	t.Logf("private CurAddr selected after %v; post-recovery ping sequence %d delivered after %v; DERP data packets during recovery=%d", recovery, postRecoveryDelivery.sequence, postRecoveryDelivery.at.Sub(failureStarted), derpPackets)
}

type deliveredPing struct {
	sequence uint16
	at       mono.Time
}

func sequencedPing(dst, src netip.Addr, sequence uint16) []byte {
	p := tuntest.Ping(dst, src)
	binary.BigEndian.PutUint16(p[26:28], sequence)
	binary.BigEndian.PutUint16(p[22:24], 0)
	binary.BigEndian.PutUint16(p[22:24], internetChecksum(p[20:]))
	return p
}

func pingSequence(p []byte) (uint16, bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 1 || p[20] != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint16(p[26:28]), true
}

func internetChecksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint32(p[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func waitForPingDelivery(t *testing.T, deliveries <-chan deliveredPing, after uint16, timeout time.Duration) deliveredPing {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case delivery := <-deliveries:
			if delivery.sequence > after {
				return delivery
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for a ping delivery after sequence %d", after)
		}
	}
}

type dualPathMode int32

const (
	dualPathPrivateOnly dualPathMode = iota
	dualPathPublicAllowed
	dualPathPublicBlackholed
)

// dualPathClientHandler models the source-side tc rules used by the AWS
// reproduction. Initial setup suppresses the public endpoint in both
// directions. Failure drops only source-egress UDP to the exact public
// endpoint, while the private endpoint retains a one-way 20ms delay.
type dualPathClientHandler struct {
	publicIF, privateIF  *natlab.Interface
	publicPeer           netip.AddrPort
	privatePeer          netip.AddrPort
	privatePathDelay     time.Duration
	mode                 atomic.Int32
	publicPacketsDropped atomic.Int64
}

func (h *dualPathClientHandler) HandleIn(p *natlab.Packet, iif *natlab.Interface) *natlab.Packet {
	if dualPathMode(h.mode.Load()) == dualPathPrivateOnly && iif == h.publicIF && p.Src == h.publicPeer {
		h.publicPacketsDropped.Add(1)
		return nil
	}
	return p
}

func (h *dualPathClientHandler) HandleOut(p *natlab.Packet, oif *natlab.Interface) *natlab.Packet {
	mode := dualPathMode(h.mode.Load())
	if oif == h.publicIF && p.Dst == h.publicPeer && (mode == dualPathPrivateOnly || mode == dualPathPublicBlackholed) {
		h.publicPacketsDropped.Add(1)
		return nil
	}
	if oif == h.privateIF && p.Dst == h.privatePeer {
		time.Sleep(h.privatePathDelay)
	}
	return p
}

func (h *dualPathClientHandler) HandleForward(p *natlab.Packet, _, _ *natlab.Interface) *natlab.Packet {
	return p
}

func peerCurAddr(from, to *magicStack) string {
	peer, ok := from.Status().Peer[to.Public()]
	if !ok {
		return ""
	}
	return peer.CurAddr
}

func waitForPeerAddr(t *testing.T, from, to *magicStack, want netip.AddrPort, timeout time.Duration) mono.Time {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := peerCurAddr(from, to); got == want.String() {
			return mono.Now()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for endpoint %q; got %q", want, peerCurAddr(from, to))
	return 0
}

func waitForPeerEndpoint(t *testing.T, from, to *magicStack, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		from.conn.mu.Lock()
		_, ok := from.conn.peerMap.endpointForNodeKey(to.Public())
		from.conn.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for endpoint for peer %v", to.Public())
}

func forceFullDirectDiscovery(t *testing.T, from, to *magicStack) {
	t.Helper()
	from.conn.mu.Lock()
	de, ok := from.conn.peerMap.endpointForNodeKey(to.Public())
	from.conn.mu.Unlock()
	if !ok {
		t.Fatalf("no endpoint for peer %v", to.Public())
	}
	de.mu.Lock()
	for _, state := range de.endpointState {
		state.lastPing = 0
	}
	de.sendDiscoPingsLocked(mono.Now(), true)
	de.mu.Unlock()
}

type trustedPathState struct {
	publicLatency  time.Duration
	privateLatency time.Duration
	trustUntil     mono.Time
}

func waitForTrustedPathState(t *testing.T, from, to *magicStack, public, private netip.AddrPort, discoveryStarted mono.Time) trustedPathState {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last trustedPathState
	for time.Now().Before(deadline) {
		from.conn.mu.Lock()
		de, ok := from.conn.peerMap.endpointForNodeKey(to.Public())
		if !ok {
			from.conn.mu.Unlock()
			t.Fatalf("no endpoint for peer %v", to.Public())
		}
		de.mu.Lock()
		from.conn.mu.Unlock()

		publicState, publicOK := de.endpointState[public]
		privateState, privateOK := de.endpointState[private]
		publicLatency, publicPongOK := time.Duration(0), false
		privateLatency, privatePongOK := time.Duration(0), false
		var publicPongAt, privatePongAt mono.Time
		if publicOK {
			publicLatency, publicPongOK = publicState.latencyLocked()
			if publicPongOK {
				publicPongAt = publicState.recentPongs[publicState.recentPong].pongAt
			}
		}
		if privateOK {
			privateLatency, privatePongOK = privateState.latencyLocked()
			if privatePongOK {
				privatePongAt = privateState.recentPongs[privateState.recentPong].pongAt
			}
		}
		last = trustedPathState{
			publicLatency:  publicLatency,
			privateLatency: privateLatency,
			trustUntil:     de.trustBestAddrUntil,
		}
		ready := de.bestAddr.ap == public &&
			publicPongOK && !publicPongAt.Before(discoveryStarted) &&
			privatePongOK && !privatePongAt.Before(discoveryStarted)
		de.mu.Unlock()
		if ready {
			if publicLatency >= privateLatency {
				t.Fatalf("public endpoint latency %v did not beat private endpoint latency %v", publicLatency, privateLatency)
			}
			if remaining := last.trustUntil.Sub(mono.Now()); remaining < maxDirectPathRecovery+2*time.Second {
				t.Fatalf("public endpoint trust remaining = %v; want at least %v", remaining, maxDirectPathRecovery+2*time.Second)
			}
			return last
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("public endpoint is not trusted with fresh public and private candidates; last state: %+v", last)
	return trustedPathState{}
}
