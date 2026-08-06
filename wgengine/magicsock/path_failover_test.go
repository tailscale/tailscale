// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/disco"
	"tailscale.com/tsconst"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

const maxStablePathFailover = time.Second

// TestDirectPathFailureWithStablePeerIdentity models a client with one network
// interface that reaches a peer's public and private endpoints through
// different upstream routes. Both endpoints use the same peer disco key and
// UDP port. The public endpoint is initially faster and becomes trusted, then
// its upstream path is blackholed while the slower private path remains healthy.
//
// The ReSTUN-only case matches the AWS reproduction. The Rebind+ReSTUN case is
// a control showing that resetting peer path state avoids waiting for the
// failed public endpoint's trust window to expire.
func TestDirectPathFailureWithStablePeerIdentity(t *testing.T) {
	tstest.ResourceCheck(t)

	oldPingTimeout := pingTimeoutDuration
	oldPingInterval := discoPingInterval
	pingTimeoutDuration = tsconst.DefaultPingTimeout
	discoPingInterval = tsconst.DefaultPingInterval
	defer func() {
		pingTimeoutDuration = oldPingTimeout
		discoPingInterval = oldPingInterval
	}()

	for _, tt := range []struct {
		name   string
		action func(*Conn)
	}{
		{"rebind-restun-control", func(c *Conn) {
			c.Rebind()
			c.ReSTUN("stable-peer-path-failure-control")
		}},
		{"restun-only", func(c *Conn) {
			c.ReSTUN("stable-peer-path-failure")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testDirectPathFailureWithStablePeerIdentity(t, tt.action)
		})
	}
}

func testDirectPathFailureWithStablePeerIdentity(t *testing.T, action func(*Conn)) {
	clientLAN := &natlab.Network{
		Name:    "client-lan",
		Prefix4: netip.MustParsePrefix("192.168.50.0/24"),
	}
	publicNet := natlab.NewInternet()
	privateNet := &natlab.Network{
		Name:    "private-backbone",
		Prefix4: netip.MustParsePrefix("10.17.65.0/24"),
	}

	clientObserver := new(stablePathClientObserver)
	client := &natlab.Machine{Name: "client", PacketHandler: clientObserver}
	gateway := &natlab.Machine{Name: "gateway"}
	peer := &natlab.Machine{Name: "peer"}
	stunMachine := &natlab.Machine{Name: "stun"}

	// The gateway's first interface is its default route. The private network
	// gets a more-specific connected route, so destination IP chooses the
	// upstream path while the client always sends through eth0.
	gatewayPublicIF := gateway.Attach("public", publicNet)
	gatewayClientIF := gateway.Attach("client", clientLAN)
	gatewayPrivateIF := gateway.Attach("private", privateNet)
	clientIF := client.Attach("eth0", clientLAN)
	peerPublicIF := peer.Attach("public", publicNet)
	peerPrivateIF := peer.Attach("private", privateNet)
	stunIF := stunMachine.Attach("eth0", publicNet)
	clientLAN.SetDefaultGateway(gatewayClientIF)

	derpMap, cleanupDERP := runDERPAndStun(t, t.Logf, stunMachine, stunIF.V4())
	defer cleanupDERP()

	peerStack := newMagicStack(t, logger.WithPrefix(t.Logf, "peer: "), peer, derpMap)
	defer peerStack.Close()
	peerPort := peerStack.conn.LocalPort()
	publicPeerAddr := netip.AddrPortFrom(peerPublicIF.V4(), peerPort)
	privatePeerAddr := netip.AddrPortFrom(peerPrivateIF.V4(), peerPort)
	peerStack.conn.SetStaticEndpoints(views.SliceOf([]netip.AddrPort{privatePeerAddr}))

	natClock := new(tstest.Clock)
	gatewayHandler := &stablePathGateway{
		clientIF:     gatewayClientIF,
		publicIF:     gatewayPublicIF,
		privateIF:    gatewayPrivateIF,
		clientAddr:   clientIF.V4(),
		publicPeer:   publicPeerAddr,
		privatePeer:  privatePeerAddr,
		privateDelay: 20 * time.Millisecond,
	}
	gatewayHandler.publicNAT = &natlab.SNAT44{
		Machine:           gateway,
		ExternalInterface: gatewayPublicIF,
		Type:              natlab.EndpointIndependentNAT,
		TimeNow:           natClock.Now,
	}
	gatewayHandler.privateNAT = &natlab.SNAT44{
		Machine:           gateway,
		ExternalInterface: gatewayPrivateIF,
		Type:              natlab.EndpointIndependentNAT,
		TimeNow:           natClock.Now,
	}
	gatewayHandler.publicBlocked.Store(true)
	gateway.PacketHandler = gatewayHandler

	clientObserver.clientIF = clientIF
	clientObserver.publicPeer = publicPeerAddr
	clientObserver.privatePeer = privatePeerAddr

	clientStack := newMagicStack(t, logger.WithPrefix(t.Logf, "client: "), client, derpMap)
	defer clientStack.Close()
	peerDiscoKey := peerStack.conn.DiscoPublicKey()
	clientDiscoKey := clientStack.conn.DiscoPublicKey()
	clientPort := clientStack.conn.LocalPort()

	// Advertise only the two endpoint aliases under test to the client. They
	// share one peer disco key and one UDP port throughout the test.
	cleanupMesh := meshStacks(t.Logf, func(idx int, nm *netmap.NetworkMap) {
		if idx != 0 {
			return
		}
		for i, peer := range nm.Peers {
			if peer.Key() != peerStack.Public() {
				continue
			}
			n := peer.AsStruct()
			n.Endpoints = []netip.AddrPort{publicPeerAddr, privatePeerAddr}
			nm.Peers[i] = n.View()
		}
	}, clientStack, peerStack)
	defer cleanupMesh()

	trafficCtx, stopTraffic := context.WithCancel(context.Background())
	var trafficWG sync.WaitGroup
	var nextSequence atomic.Uint32
	deliveries := make(chan stablePathDelivery, 256)
	trafficWG.Add(1)
	go func() {
		defer trafficWG.Done()
		for {
			select {
			case <-trafficCtx.Done():
				return
			case packet := <-peerStack.tun.Inbound:
				sequence, ok := stablePathPingSequence(packet)
				if !ok {
					continue
				}
				select {
				case deliveries <- stablePathDelivery{sequence: sequence, at: mono.Now()}:
				case <-trafficCtx.Done():
					return
				}
			}
		}
	}()

	sendPing := func() (uint16, bool) {
		sequence := uint16(nextSequence.Add(1))
		select {
		case clientStack.tun.Outbound <- stablePathPing(peerStack.IP(), clientStack.IP(), sequence):
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

	// Independent private-underlay echo traffic demonstrates that the upstream
	// private route remains bidirectionally healthy throughout the failure.
	underlayReceiver, err := peer.ListenPacket(trafficCtx, "udp4", ":0")
	if err != nil {
		t.Fatalf("listen for private-underlay probes: %v", err)
	}
	underlaySender, err := client.ListenPacket(trafficCtx, "udp4", ":0")
	if err != nil {
		underlayReceiver.Close()
		t.Fatalf("create private-underlay probe sender: %v", err)
	}
	underlayPort := uint16(underlayReceiver.LocalAddr().(*net.UDPAddr).Port)
	underlayDst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerPrivateIF.V4(), underlayPort))
	var underlayRoundTrips atomic.Uint64
	var lastUnderlayRoundTrip atomic.Int64
	trafficWG.Add(3)
	go func() {
		defer trafficWG.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-trafficCtx.Done():
				return
			case <-ticker.C:
				if _, err := underlaySender.WriteTo([]byte{1}, underlayDst); err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer trafficWG.Done()
		buf := make([]byte, 1)
		for {
			n, src, err := underlayReceiver.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := underlayReceiver.WriteTo(buf[:n], src); err != nil {
				return
			}
		}
	}()
	go func() {
		defer trafficWG.Done()
		buf := make([]byte, 1)
		for {
			if _, _, err := underlaySender.ReadFrom(buf); err != nil {
				return
			}
			underlayRoundTrips.Add(1)
			lastUnderlayRoundTrip.Store(int64(mono.Now()))
		}
	}()
	defer func() {
		stopTraffic()
		underlaySender.Close()
		underlayReceiver.Close()
		trafficWG.Wait()
	}()

	// Establish the private endpoint as a proven alternate before allowing the
	// lower-latency public endpoint to win discovery.
	stablePathWaitForPeerEndpoint(t, clientStack, peerStack, 5*time.Second)
	stablePathForceFullDiscovery(t, clientStack, peerStack)
	activationSequence := mustSendPing()
	stablePathWaitForDelivery(t, deliveries, activationSequence-1, 2*time.Second)
	stablePathWaitForPeerAddr(t, clientStack, peerStack, privatePeerAddr, 10*time.Second)
	privateSequence := mustSendPing()
	stablePathWaitForDelivery(t, deliveries, privateSequence-1, 2*time.Second)

	gatewayHandler.publicBlocked.Store(false)
	publicDiscoveryStarted := mono.Now()
	stablePathForceFullDiscovery(t, clientStack, peerStack)
	stablePathWaitForPeerAddr(t, clientStack, peerStack, publicPeerAddr, 5*time.Second)
	pathState := stablePathWaitForTrustedCandidates(t, clientStack, peerStack, publicPeerAddr, privatePeerAddr, publicDiscoveryStarted, trustUDPAddrDuration-500*time.Millisecond)
	publicSequence := mustSendPing()
	stablePathWaitForDelivery(t, deliveries, publicSequence-1, 2*time.Second)
	t.Logf("public path %v selected over private path %v: public RTT=%v private RTT=%v trust remaining=%v", publicPeerAddr, privatePeerAddr, pathState.publicLatency, pathState.privateLatency, pathState.trustUntil.Sub(mono.Now()))

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

	wgPeerBefore, ok := clientStack.dev.LookupActivePeer(peerStack.Public().Raw32())
	if !ok {
		t.Fatal("WireGuard peer is not active before path failure")
	}
	if got := peerStack.conn.DiscoPublicKey(); got != peerDiscoKey {
		t.Fatalf("peer disco key changed during setup: got %v, want %v", got.ShortString(), peerDiscoKey.ShortString())
	}
	if got := peerStack.conn.LocalPort(); got != peerPort {
		t.Fatalf("peer UDP port changed during setup: got %d, want %d", got, peerPort)
	}
	if got := clientStack.conn.DiscoPublicKey(); got != clientDiscoKey {
		t.Fatalf("client disco key changed during setup: got %v, want %v", got.ShortString(), clientDiscoKey.ShortString())
	}
	if got := clientStack.conn.LocalPort(); got != clientPort {
		t.Fatalf("client UDP port changed during setup: got %d, want %d", got, clientPort)
	}
	baselineWatermark := uint16(nextSequence.Load())
	lastBeforeFailure := stablePathWaitForDelivery(t, deliveries, baselineWatermark, 2*time.Second)
	preFailureState := stablePathWaitForTrustedCandidates(t, clientStack, peerStack, publicPeerAddr, privatePeerAddr, publicDiscoveryStarted, trustUDPAddrDuration-500*time.Millisecond)
	underlayAtFailure := underlayRoundTrips.Load()
	gatewayHandler.publicDropped.Store(0)
	gatewayHandler.publicWireGuardDropped.Store(0)

	gatewayHandler.publicBlocked.Store(true)
	failureStarted := mono.Now()
	if _, err := underlaySender.WriteTo([]byte{1}, underlayDst); err != nil {
		t.Fatalf("send private-underlay probe at failure: %v", err)
	}
	mustSendPing()
	stablePathWaitForDrop(t, &gatewayHandler.publicWireGuardDropped, time.Second)
	action(clientStack.conn)
	// Force peer discovery only to prove that the alternate path remains
	// bidirectionally healthy. This does not clear bestAddr or its trust timer.
	stablePathForceFullDiscovery(t, clientStack, peerStack)
	pongState := stablePathWaitForFreshPong(t, clientStack, peerStack, privatePeerAddr, failureStarted, 2*time.Second)
	postPongSequence := mustSendPing()

	selectedAt := stablePathWaitForPeerAddr(t, clientStack, peerStack, privatePeerAddr, trustUDPAddrDuration+2*time.Second)
	firstOverlayAfterPong := stablePathWaitForDelivery(t, deliveries, postPongSequence-1, 2*time.Second)
	postSelectionSequence := mustSendPing()
	postSelectionDelivery := stablePathWaitForDelivery(t, deliveries, postSelectionSequence-1, 2*time.Second)
	stablePathWaitForUnderlay(t, &underlayRoundTrips, underlayAtFailure, 2*time.Second)

	discoDelay := pongState.at.Sub(failureStarted)
	selectionDelay := selectedAt.Sub(failureStarted)
	postDiscoLag := firstOverlayAfterPong.at.Sub(pongState.at)
	overlayGap := firstOverlayAfterPong.at.Sub(lastBeforeFailure.at)
	underlayDuringFailure := underlayRoundTrips.Load() - underlayAtFailure
	t.Logf("stable peer disco=%v port=%d; private disco pong after %v while best=%v; private selected after %v (%v from original trust deadline); overlay resumed %v after pong (%v total gap); private-underlay round trips=%d", peerDiscoKey.ShortString(), peerPort, discoDelay, pongState.bestAddr, selectionDelay, selectedAt.Sub(preFailureState.trustUntil), postDiscoLag, overlayGap, underlayDuringFailure)

	if discoDelay > maxStablePathFailover {
		t.Errorf("private endpoint disco round-trip took %v; want at most %v", discoDelay, maxStablePathFailover)
	}
	if !selectedAt.Before(preFailureState.trustUntil) {
		t.Errorf("private endpoint was selected after %v, but only after trust in the failed public endpoint expired", selectionDelay)
	}
	if postDiscoLag > maxStablePathFailover {
		t.Errorf("overlay traffic remained stalled for %v after a successful private disco round-trip; want at most %v", postDiscoLag, maxStablePathFailover)
	}
	if overlayGap > maxStablePathFailover {
		t.Errorf("public path failure interrupted overlay traffic for %v; want at most %v", overlayGap, maxStablePathFailover)
	}
	if selectionDelay > maxStablePathFailover {
		trustDelta := selectedAt.Sub(preFailureState.trustUntil)
		if trustDelta < -500*time.Millisecond || trustDelta > 500*time.Millisecond {
			t.Errorf("slow failover occurred %v from the original trust deadline; want within 500ms", trustDelta)
		}
	}
	if postSelectionDelivery.at.Before(selectedAt) {
		t.Errorf("post-selection ping sequence %d was delivered before the private endpoint was selected", postSelectionDelivery.sequence)
	}
	if dropped := gatewayHandler.publicDropped.Load(); dropped == 0 {
		t.Error("gateway did not blackhole any packets to the public peer endpoint")
	}
	if dropped := gatewayHandler.publicWireGuardDropped.Load(); dropped == 0 {
		t.Error("gateway did not blackhole WireGuard data on the public peer endpoint")
	}
	if underlayDuringFailure == 0 {
		t.Error("private underlay completed no round trips during public path failure")
	}
	if want := uint64(selectionDelay / (250 * time.Millisecond)); underlayDuringFailure < want {
		t.Errorf("private underlay completed %d round trips during failure; want at least %d", underlayDuringFailure, want)
	}
	if last := mono.Time(lastUnderlayRoundTrip.Load()); last == 0 || mono.Now().Sub(last) > time.Second {
		t.Error("private-underlay probes stopped during public path failure")
	}
	if clientObserver.wrongInterface.Load() != 0 {
		t.Errorf("client sent endpoint traffic through an interface other than %v", clientIF)
	}
	if clientObserver.publicPackets.Load() == 0 || clientObserver.privatePackets.Load() == 0 {
		t.Errorf("client did not exercise both endpoint routes: public=%d private=%d", clientObserver.publicPackets.Load(), clientObserver.privatePackets.Load())
	}
	if gatewayHandler.badRoute.Load() != 0 {
		t.Errorf("gateway routed %d endpoint packets through the wrong upstream path", gatewayHandler.badRoute.Load())
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
	wgPeerAfter, ok := clientStack.dev.LookupActivePeer(peerStack.Public().Raw32())
	if !ok {
		t.Error("WireGuard peer is not active after path failure")
	} else if wgPeerAfter != wgPeerBefore {
		t.Error("WireGuard peer was replaced during path failure")
	}
}

type stablePathGateway struct {
	clientIF, publicIF, privateIF *natlab.Interface
	clientAddr                    netip.Addr
	publicPeer, privatePeer       netip.AddrPort
	privateDelay                  time.Duration
	publicNAT, privateNAT         *natlab.SNAT44

	publicBlocked          atomic.Bool
	publicDropped          atomic.Int64
	publicWireGuardDropped atomic.Int64
	publicPackets          atomic.Int64
	privatePackets         atomic.Int64
	badRoute               atomic.Int64
}

func (g *stablePathGateway) HandleIn(p *natlab.Packet, iif *natlab.Interface) *natlab.Packet {
	switch iif {
	case g.publicIF:
		if g.publicBlocked.Load() && p.Src == g.publicPeer {
			g.notePublicDrop(p)
			return nil
		}
		return g.publicNAT.HandleIn(p, iif)
	case g.privateIF:
		return g.privateNAT.HandleIn(p, iif)
	default:
		return p
	}
}

func (g *stablePathGateway) HandleOut(p *natlab.Packet, _ *natlab.Interface) *natlab.Packet {
	return p
}

func (g *stablePathGateway) HandleForward(p *natlab.Packet, iif, oif *natlab.Interface) *natlab.Packet {
	if iif == g.clientIF && p.Src.Addr() == g.clientAddr {
		switch p.Dst {
		case g.publicPeer:
			g.publicPackets.Add(1)
			if oif != g.publicIF {
				g.badRoute.Add(1)
			}
			if g.publicBlocked.Load() {
				g.notePublicDrop(p)
				return nil
			}
		case g.privatePeer:
			g.privatePackets.Add(1)
			if oif != g.privateIF {
				g.badRoute.Add(1)
			}
			time.Sleep(g.privateDelay)
		}
	}

	switch {
	case iif == g.publicIF || oif == g.publicIF:
		return g.publicNAT.HandleForward(p, iif, oif)
	case iif == g.privateIF || oif == g.privateIF:
		return g.privateNAT.HandleForward(p, iif, oif)
	default:
		return p
	}
}

func (g *stablePathGateway) notePublicDrop(p *natlab.Packet) {
	g.publicDropped.Add(1)
	if !disco.LooksLikeDiscoWrapper(p.Payload) {
		g.publicWireGuardDropped.Add(1)
	}
}

type stablePathClientObserver struct {
	clientIF                *natlab.Interface
	publicPeer, privatePeer netip.AddrPort
	publicPackets           atomic.Int64
	privatePackets          atomic.Int64
	wrongInterface          atomic.Int64
}

func (o *stablePathClientObserver) HandleIn(p *natlab.Packet, _ *natlab.Interface) *natlab.Packet {
	return p
}

func (o *stablePathClientObserver) HandleOut(p *natlab.Packet, oif *natlab.Interface) *natlab.Packet {
	switch p.Dst {
	case o.publicPeer:
		o.publicPackets.Add(1)
	case o.privatePeer:
		o.privatePackets.Add(1)
	default:
		return p
	}
	if oif != o.clientIF || p.Src.Addr() != o.clientIF.V4() {
		o.wrongInterface.Add(1)
	}
	return p
}

func (o *stablePathClientObserver) HandleForward(p *natlab.Packet, _, _ *natlab.Interface) *natlab.Packet {
	return p
}

type stablePathDelivery struct {
	sequence uint16
	at       mono.Time
}

func stablePathPing(dst, src netip.Addr, sequence uint16) []byte {
	p := tuntest.Ping(dst, src)
	binary.BigEndian.PutUint16(p[26:28], sequence)
	binary.BigEndian.PutUint16(p[22:24], 0)
	binary.BigEndian.PutUint16(p[22:24], stablePathInternetChecksum(p[20:]))
	return p
}

func stablePathPingSequence(p []byte) (uint16, bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 1 || p[20] != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint16(p[26:28]), true
}

func stablePathInternetChecksum(p []byte) uint16 {
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

func stablePathWaitForDelivery(t *testing.T, deliveries <-chan stablePathDelivery, after uint16, timeout time.Duration) stablePathDelivery {
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

func stablePathWaitForDrop(t *testing.T, dropped *atomic.Int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for dropped.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a WireGuard packet to hit the public-path blackhole")
		}
		time.Sleep(time.Millisecond)
	}
}

func stablePathWaitForUnderlay(t *testing.T, roundTrips *atomic.Uint64, after uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for roundTrips.Load() <= after {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a private-underlay round trip during public path failure")
		}
		time.Sleep(time.Millisecond)
	}
}

func stablePathPeerCurAddr(from, to *magicStack) string {
	peer, ok := from.Status().Peer[to.Public()]
	if !ok {
		return ""
	}
	return peer.CurAddr
}

func stablePathWaitForPeerAddr(t *testing.T, from, to *magicStack, want netip.AddrPort, timeout time.Duration) mono.Time {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := stablePathPeerCurAddr(from, to); got == want.String() {
			return mono.Now()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for endpoint %q; got %q", want, stablePathPeerCurAddr(from, to))
	return 0
}

func stablePathWaitForPeerEndpoint(t *testing.T, from, to *magicStack, timeout time.Duration) {
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

func stablePathForceFullDiscovery(t *testing.T, from, to *magicStack) {
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

type stablePathState struct {
	publicLatency  time.Duration
	privateLatency time.Duration
	trustUntil     mono.Time
}

func stablePathWaitForTrustedCandidates(t *testing.T, from, to *magicStack, public, private netip.AddrPort, discoveryStarted mono.Time, minTrustRemaining time.Duration) stablePathState {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last stablePathState
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
		last = stablePathState{
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
			if remaining := last.trustUntil.Sub(mono.Now()); remaining < minTrustRemaining {
				t.Fatalf("public endpoint trust remaining = %v; want at least %v", remaining, minTrustRemaining)
			}
			return last
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("public endpoint is not trusted with fresh public and private candidates; last state: %+v", last)
	return stablePathState{}
}

type stablePathPongState struct {
	at       mono.Time
	bestAddr netip.AddrPort
}

func stablePathWaitForFreshPong(t *testing.T, from, to *magicStack, endpoint netip.AddrPort, after mono.Time, timeout time.Duration) stablePathPongState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		from.conn.mu.Lock()
		de, ok := from.conn.peerMap.endpointForNodeKey(to.Public())
		from.conn.mu.Unlock()
		if ok {
			de.mu.Lock()
			state, found := de.endpointState[endpoint]
			if found && len(state.recentPongs) > 0 {
				pong := state.recentPongs[state.recentPong]
				if !pong.pongAt.Before(after) && pong.from == endpoint {
					result := stablePathPongState{at: pong.pongAt, bestAddr: de.bestAddr.ap}
					de.mu.Unlock()
					return result
				}
			}
			de.mu.Unlock()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for fresh disco Pong from %v", endpoint)
	return stablePathPongState{}
}
