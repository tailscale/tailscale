// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

// TestPeerEndpointMigrationDoesNotInterruptTraffic models a peer restart that
// rotates its disco key and UDP port. The public and private networks remain
// available, an independent public UDP probe runs throughout, and no NATLab
// packet handler drops traffic during the measured migration.
func TestPeerEndpointMigrationDoesNotInterruptTraffic(t *testing.T) {
	tstest.ResourceCheck(t)

	clientHandler := &dualPathClientHandler{}
	peerHandler := &dualPathPeerHandler{privatePathDelay: 20 * time.Millisecond}
	client := &natlab.Machine{Name: "client", PacketHandler: clientHandler}
	peer := &natlab.Machine{Name: "peer", PacketHandler: peerHandler}
	stunMachine := &natlab.Machine{Name: "stun"}
	inet := natlab.NewInternet()
	lan := &natlab.Network{
		Name:    "private",
		Prefix4: netip.MustParsePrefix("10.17.65.0/24"),
	}
	stunIF := stunMachine.Attach("eth0", inet)
	client.Attach("public", inet)
	peerPublicIF := peer.Attach("public", inet)
	clientPrivateIF := client.Attach("private", lan)
	peerPrivateIF := peer.Attach("private", lan)

	clientHandler.publicPeer = peerPublicIF.V4()
	peerHandler.privatePeer = clientPrivateIF.V4()

	derpMap, cleanupDERP := runDERPAndStun(t, t.Logf, stunMachine, stunIF.V4())
	defer cleanupDERP()

	clientStack := newMagicStack(t, logger.WithPrefix(t.Logf, "client: "), client, derpMap)
	defer clientStack.Close()
	peerStack := newMagicStack(t, logger.WithPrefix(t.Logf, "peer: "), peer, derpMap)
	defer peerStack.Close()

	privatePeerAddr := netip.AddrPortFrom(peerPrivateIF.V4(), peerStack.conn.LocalPort())
	peerStack.conn.SetStaticEndpoints(views.SliceOf([]netip.AddrPort{privatePeerAddr}))

	var withoutDERP atomic.Bool
	cleanupMesh := meshStacks(t.Logf, func(_ int, nm *netmap.NetworkMap) {
		if !withoutDERP.Load() {
			return
		}
		for i, peer := range nm.Peers {
			n := peer.AsStruct()
			n.HomeDERP = 0
			nm.Peers[i] = n.View()
		}
	}, clientStack, peerStack)
	defer cleanupMesh()

	trafficCtx, stopTraffic := context.WithCancel(context.Background())
	var trafficWG sync.WaitGroup
	var nextSequence atomic.Uint32
	deliveries := make(chan deliveredPing, 256)
	underlayReceiver, err := peer.ListenPacket(trafficCtx, "udp4", ":0")
	if err != nil {
		t.Fatalf("listen for underlay probes: %v", err)
	}
	underlaySender, err := client.ListenPacket(trafficCtx, "udp4", ":0")
	if err != nil {
		underlayReceiver.Close()
		t.Fatalf("create underlay probe sender: %v", err)
	}
	var underlayRoundTrips atomic.Uint64
	var lastUnderlayRoundTrip atomic.Int64
	underlayPort := uint16(underlayReceiver.LocalAddr().(*net.UDPAddr).Port)
	trafficWG.Add(5)
	go func() {
		defer trafficWG.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-trafficCtx.Done():
				return
			case <-ticker.C:
				sequence := uint16(nextSequence.Add(1))
				select {
				case clientStack.tun.Outbound <- sequencedPing(peerStack.IP(), clientStack.IP(), sequence):
				case <-trafficCtx.Done():
					return
				}
			}
		}
	}()
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
				case deliveries <- deliveredPing{sequence: sequence, at: time.Now()}:
				case <-trafficCtx.Done():
					return
				}
			}
		}
	}()
	go func() {
		defer trafficWG.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerPublicIF.V4(), underlayPort))
		for {
			select {
			case <-trafficCtx.Done():
				return
			case <-ticker.C:
				if _, err := underlaySender.WriteTo([]byte{1}, dst); err != nil {
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
			lastUnderlayRoundTrip.Store(time.Now().UnixNano())
		}
	}()
	defer func() {
		stopTraffic()
		underlaySender.Close()
		underlayReceiver.Close()
		trafficWG.Wait()
	}()

	// Initially block the public route so discovery establishes the known-good
	// private route first.
	waitForPeerEndpoint(t, clientStack, peerStack, 5*time.Second)
	forceFullDirectDiscovery(t, clientStack, peerStack)
	waitForPeerAddr(t, clientStack, peerStack, privatePeerAddr, 10*time.Second)
	waitForPingDelivery(t, deliveries, 0, 5*time.Second)
	t.Logf("baseline: private direct path %v is selected and carrying traffic", privatePeerAddr)

	// Remove DERP before the failure. Recovery must come from the working
	// private candidate, not relay fallback.
	withoutDERP.Store(true)
	forceEndpointUpdate(t, clientStack)
	waitForPeerWithoutDERP(t, clientStack, peerStack, 5*time.Second)
	t.Log("DERP fallback disabled; recovery must use the advertised private direct path")

	clientHandler.mode.Store(int32(dualPathPublicAllowed))
	forceFullDirectDiscovery(t, clientStack, peerStack)
	publicPeerAddr := netip.AddrPortFrom(peerPublicIF.V4(), peerStack.conn.LocalPort())
	waitForPeerAddr(t, clientStack, peerStack, publicPeerAddr, 5*time.Second)
	waitForPingDelivery(t, deliveries, 0, 2*time.Second)
	t.Logf("public path %v wins discovery over the slower private path", publicPeerAddr)

	for {
		select {
		case <-deliveries:
		default:
			goto deliveriesDrained
		}
	}

deliveriesDrained:
	clientHandler.publicPacketsDropped.Store(0)
	underlayAtMigration := underlayRoundTrips.Load()
	migrationStarted := time.Now()
	oldPort := peerStack.conn.LocalPort()
	newPort := oldPort + 1
	if newPort == 0 {
		newPort = oldPort - 1
	}
	oldDiscoKey := peerStack.conn.DiscoPublicKey()
	peerStack.conn.RotateDiscoKey()
	peerStack.conn.SetPreferredPort(newPort)
	if got := peerStack.conn.LocalPort(); got != newPort {
		t.Fatalf("peer UDP listener did not migrate: got port %d, want %d", got, newPort)
	}
	peerStack.conn.SetStaticEndpoints(views.SliceOf([]netip.AddrPort{
		netip.AddrPortFrom(peerPrivateIF.V4(), newPort),
	}))
	sequenceAtMigration := uint16(nextSequence.Load())
	newDiscoKey := peerStack.conn.DiscoPublicKey()
	waitForPeerDiscoKey(t, clientStack, peerStack, newDiscoKey, 5*time.Second)

	recovery := waitForPingDelivery(t, deliveries, sequenceAtMigration, trustUDPAddrDuration+2*time.Second)
	gap := recovery.at.Sub(migrationStarted)
	missing := uint16(recovery.sequence - sequenceAtMigration - 1)
	underlayDuringMigration := underlayRoundTrips.Load() - underlayAtMigration
	t.Logf("peer migrated from disco key %v port %d to %v port %d; ping sequence %d was first delivered after %v (%d packets missing); %d independent underlay probes completed round trips", oldDiscoKey.ShortString(), oldPort, newDiscoKey.ShortString(), newPort, recovery.sequence, gap, missing, underlayDuringMigration)
	if dropped := clientHandler.publicPacketsDropped.Load(); dropped != 0 {
		t.Fatalf("NATLab packet handler dropped %d packets during endpoint migration", dropped)
	}
	if want := uint64(gap / (250 * time.Millisecond)); underlayDuringMigration < want {
		t.Fatalf("only %d independent underlay probes completed round trips during migration; want at least %d", underlayDuringMigration, want)
	}
	if last := lastUnderlayRoundTrip.Load(); last == 0 || time.Since(time.Unix(0, last)) > 300*time.Millisecond {
		t.Fatal("independent public-underlay probes stopped during endpoint migration")
	}
	if gap > time.Second {
		t.Fatalf("peer endpoint migration on a lossless underlay interrupted TUN delivery for %v; want at most 1s", gap)
	}
}

type deliveredPing struct {
	sequence uint16
	at       time.Time
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
			if after == 0 || delivery.sequence > after {
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
)

// dualPathClientHandler initially suppresses the public path so the test can
// establish a working private path before allowing both paths without loss.
type dualPathClientHandler struct {
	publicPeer           netip.Addr
	mode                 atomic.Int32
	publicPacketsDropped atomic.Int64
}

func (h *dualPathClientHandler) HandleIn(p *natlab.Packet, _ *natlab.Interface) *natlab.Packet {
	if p.Src.Addr() != h.publicPeer {
		return p
	}
	if h.mode.Load() != int32(dualPathPublicAllowed) {
		h.publicPacketsDropped.Add(1)
		return nil
	}
	return p
}

func (h *dualPathClientHandler) HandleOut(p *natlab.Packet, _ *natlab.Interface) *natlab.Packet {
	if p.Dst.Addr() == h.publicPeer && h.mode.Load() == int32(dualPathPrivateOnly) {
		h.publicPacketsDropped.Add(1)
		return nil
	}
	return p
}

func (h *dualPathClientHandler) HandleForward(p *natlab.Packet, _, _ *natlab.Interface) *natlab.Packet {
	return p
}

// dualPathPeerHandler makes the public path win the latency comparison while
// preserving a usable, slower private path for recovery.
type dualPathPeerHandler struct {
	privatePeer      netip.Addr
	privatePathDelay time.Duration
}

func (h *dualPathPeerHandler) delayPrivate(p *natlab.Packet) {
	if p.Src.Addr() == h.privatePeer || p.Dst.Addr() == h.privatePeer {
		time.Sleep(h.privatePathDelay)
	}
}

func (h *dualPathPeerHandler) HandleIn(p *natlab.Packet, _ *natlab.Interface) *natlab.Packet {
	h.delayPrivate(p)
	return p
}

func (h *dualPathPeerHandler) HandleOut(p *natlab.Packet, _ *natlab.Interface) *natlab.Packet {
	h.delayPrivate(p)
	return p
}

func (h *dualPathPeerHandler) HandleForward(p *natlab.Packet, _, _ *natlab.Interface) *natlab.Packet {
	return p
}

func peerCurAddr(from, to *magicStack) string {
	peer, ok := from.Status().Peer[to.Public()]
	if !ok {
		return ""
	}
	return peer.CurAddr
}

func waitForPeerAddr(t *testing.T, from, to *magicStack, want netip.AddrPort, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := peerCurAddr(from, to); got == want.String() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for endpoint %q; got %q", want, peerCurAddr(from, to))
}

func waitForPeerDiscoKey(t *testing.T, from, to *magicStack, want key.DiscoPublic, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		from.conn.mu.Lock()
		de, ok := from.conn.peerMap.endpointForNodeKey(to.Public())
		from.conn.mu.Unlock()
		if ok {
			if disco := de.disco.Load(); disco != nil && disco.key == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for peer disco key %v", want.ShortString())
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

func forceEndpointUpdate(t *testing.T, s *magicStack) {
	t.Helper()
	s.conn.mu.Lock()
	eps := slices.Clone(s.conn.lastEndpoints)
	s.conn.mu.Unlock()
	s.epCh <- eps
}

func waitForPeerWithoutDERP(t *testing.T, from, to *magicStack, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		from.conn.mu.Lock()
		de, ok := from.conn.peerMap.endpointForNodeKey(to.Public())
		from.conn.mu.Unlock()
		if ok {
			de.mu.Lock()
			noDERP := !de.derpAddr.IsValid()
			de.mu.Unlock()
			if noDERP {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out removing the peer's DERP route")
}
