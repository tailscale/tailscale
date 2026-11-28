// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/udprelay"
	"tailscale.com/net/udprelay/status"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netlogtype"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/filter/filtertype"
	"tailscale.com/wgengine/wgcfg/nmcfg"
)

// relayedMeshForTest is a mesh of three magicStacks where m1 and m2 are peer
// relay clients, and relay is a peer relay server node running an in-process
// [udprelay.Server]. Direct UDP paths between all nodes are disabled via
// TS_DEBUG_NEVER_DIRECT_UDP, so the only viable m1<->m2 data paths are DERP
// and the Geneve-encapsulated path through the relay server.
type relayedMeshForTest struct {
	m1, m2 *magicStack
	relay  *magicStack
	server *udprelay.Server

	// serverAddrPort is the [udprelay.Server]'s advertised loopback
	// IP:port.
	serverAddrPort netip.AddrPort

	// pathReady receives one event per peer relay path installed as an
	// endpoint bestAddr on m1 and m2, via
	// [Conn.testOnlyRelayEndpointReadyHook].
	pathReady map[*magicStack]chan relayPathReadyEvent

	mu          sync.Mutex
	serverDisco key.DiscoPublic // captured from the first endpoint allocation, zero value until then
}

// relayPathReadyEvent records a peer relay path installation as an endpoint
// bestAddr, observed via [Conn.testOnlyRelayEndpointReadyHook].
type relayPathReadyEvent struct {
	peer key.NodePublic
	addr addrQuality
}

// getServerDisco returns the relay server's disco key as captured from the
// first endpoint allocation, or the zero value if no allocation has happened
// yet.
func (m *relayedMeshForTest) getServerDisco() key.DiscoPublic {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.serverDisco
}

// newUDPRelayServerForTest constructs a [udprelay.Server] bound to a free UDP
// port on 127.0.0.1, advertising that same loopback address as its only
// (static) endpoint. It is closed when the test ends.
func newUDPRelayServerForTest(t *testing.T, logf logger.Logf) (*udprelay.Server, netip.AddrPort) {
	t.Helper()
	for range 5 {
		// udprelay.Server does not expose its bound port, so find a free
		// one and ask the server to bind to it. The free port may be taken
		// by the time the server binds; retry on error. Note that the
		// server binds with SO_REUSEPORT where available, so a colliding
		// binder that also set SO_REUSEPORT would not surface as a bind
		// error; that's acceptable for in-process tests, where no such
		// binder shares the port range.
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to find free UDP port: %v", err)
		}
		port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		pc.Close()
		server, err := udprelay.NewServer(logf, port, true, new(usermetric.Registry), nil)
		if err != nil {
			t.Logf("udprelay.NewServer on port %d: %v (retrying)", port, err)
			continue
		}
		t.Cleanup(func() { server.Close() })
		ap := netip.AddrPortFrom(netaddr.IPv4(127, 0, 0, 1), port)
		server.SetStaticAddrPorts(views.SliceOf([]netip.AddrPort{ap}))
		return server, ap
	}
	t.Fatal("failed to bind a udprelay.Server")
	return nil, netip.AddrPort{}
}

// relayCapFilterForTest returns a [*filter.Filter] granting
// [tailcfg.PeerCapabilityRelayTarget] from relay towards the clients (which
// makes relay a candidate peer relay server from the clients' perspective,
// see [Conn.updateRelayServersSet]), and [tailcfg.PeerCapabilityRelay] from
// the clients towards relay (which permits the clients to allocate endpoints
// on relay's server, evaluated by the relay server node at
// [disco.AllocateUDPRelayEndpointRequest] reception time).
func relayCapFilterForTest(relay netip.Prefix, clients ...netip.Prefix) *filter.Filter {
	var relayTargetCaps []filtertype.CapMatch
	for _, client := range clients {
		relayTargetCaps = append(relayTargetCaps, filtertype.CapMatch{
			Dst: client,
			Cap: tailcfg.PeerCapabilityRelayTarget,
		})
	}
	matches := []filtertype.Match{
		{
			Srcs: []netip.Prefix{relay},
			Caps: relayTargetCaps,
		},
		{
			Srcs: clients,
			Caps: []filtertype.CapMatch{{
				Dst: relay,
				Cap: tailcfg.PeerCapabilityRelay,
			}},
		},
	}
	return filter.New(matches, nil, nil, nil, nil, nil)
}

// setMeshNetmapsForTest plumbs netmaps and WireGuard configs into the given
// stacks, forming a full mesh in the same shape meshStacks produces (overlay
// addresses 1.0.0.<idx+1>/32, HomeDERP 1), but synchronously: when it
// returns, every stack is fully configured and no background plumbing
// remains. Unlike meshStacks it does not propagate endpoint updates; the
// peer relay tests disable direct UDP paths, so peer endpoints are never
// dialed and DERP/relay reachability is independent of them. Peers advertise
// a relay-capable [tailcfg.CapabilityVersion], which relay clients require
// of their peers (see capVerIsRelayCapable).
func setMeshNetmapsForTest(t *testing.T, logf logger.Logf, stacks ...*magicStack) {
	t.Helper()

	// Nothing consumes the stacks' endpoint update channels (meshStacks
	// normally does); drain them so magicsock's EndpointsFunc callback can
	// never block on a full channel, e.g. in longer-running tests spanning
	// multiple netcheck/STUN rounds.
	stopDrain := make(chan struct{})
	t.Cleanup(func() { close(stopDrain) })
	for _, m := range stacks {
		go func(ch chan []tailcfg.Endpoint) {
			for {
				select {
				case <-ch:
				case <-stopDrain:
					return
				}
			}
		}(m.epCh)
	}

	for myIdx, me := range stacks {
		nm := &netmap.NetworkMap{
			NodeKey: me.privateKey.Public(),
			SelfNode: (&tailcfg.Node{
				Addresses: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(1, 0, 0, byte(myIdx+1)), 32)},
			}).View(),
		}
		for i, peer := range stacks {
			if i == myIdx {
				continue
			}
			addrs := []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(1, 0, 0, byte(i+1)), 32)}
			nm.Peers = append(nm.Peers, (&tailcfg.Node{
				ID:         tailcfg.NodeID(i + 1),
				Name:       fmt.Sprintf("node%d", i+1),
				Key:        peer.privateKey.Public(),
				DiscoKey:   peer.conn.DiscoPublicKey(),
				Addresses:  addrs,
				AllowedIPs: addrs,
				HomeDERP:   1,
				Cap:        tailcfg.CurrentCapabilityVersion,
			}).View())
		}
		me.conn.SetNetworkMap(nm.SelfNode, nm.Peers)
		peerSet := make(set.Set[key.NodePublic], len(nm.Peers))
		for _, p := range nm.Peers {
			peerSet.Add(p.Key())
		}
		me.conn.UpdatePeers(peerSet)
		wg, err := nmcfg.WGCfg(me.privateKey, nm, logf, 0, "")
		if err != nil {
			t.Fatalf("failed to construct wgcfg from netmap: %v", err)
		}
		if err := me.Reconfig(wg); err != nil {
			t.Fatalf("device reconfig failed: %v", err)
		}
	}
}

// newRelayedMeshForTest builds a [relayedMeshForTest]: three meshed
// magicStacks where the third runs an in-process [udprelay.Server], wired
// into its [Conn] over the eventbus exactly like
// feature/relayserver.extension wires it in production: it subscribes to
// [UDPRelayAllocReq] published by [Conn], allocates on the
// [udprelay.Server], and publishes a [UDPRelayAllocResp] back towards
// [Conn].
//
// Direct UDP paths are suppressed via TS_DEBUG_NEVER_DIRECT_UDP for the
// duration of the test, forcing relay path usage for peer-to-peer traffic
// while leaving DERP available for disco signaling.
//
// All plumbing is synchronous: when newRelayedMeshForTest returns, every
// stack is fully configured. Relay path installation on m1 and m2 is
// observable as events via the pathReady channels (see mustPeerRelay).
func newRelayedMeshForTest(t *testing.T, logf logger.Logf) *relayedMeshForTest {
	t.Helper()
	tstest.AssertNotParallel(t) // envknob.Setenv is process-wide

	prevNeverDirectUDP := envknob.String("TS_DEBUG_NEVER_DIRECT_UDP")
	envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", "1")
	t.Cleanup(func() { envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", prevNeverDirectUDP) })

	derpMap, derpCleanup := runDERPAndStun(t, logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	t.Cleanup(derpCleanup)

	mesh := &relayedMeshForTest{
		m1:    newMagicStack(t, logger.WithPrefix(logf, "conn1: "), localhostListener{}, derpMap),
		m2:    newMagicStack(t, logger.WithPrefix(logf, "conn2: "), localhostListener{}, derpMap),
		relay: newMagicStack(t, logger.WithPrefix(logf, "relay: "), localhostListener{}, derpMap),
	}
	t.Cleanup(mesh.m1.Close)
	t.Cleanup(mesh.m2.Close)
	t.Cleanup(mesh.relay.Close)

	mesh.server, mesh.serverAddrPort = newUDPRelayServerForTest(t, logger.WithPrefix(logf, "relayserver: "))

	// Observe peer relay path installation on the clients as events,
	// rather than polling endpoint state.
	mesh.pathReady = make(map[*magicStack]chan relayPathReadyEvent)
	for _, m := range []*magicStack{mesh.m1, mesh.m2} {
		ch := make(chan relayPathReadyEvent, 16)
		m.conn.testOnlyRelayEndpointReadyHook.Store(func(peer key.NodePublic, addr addrQuality) {
			select {
			case ch <- relayPathReadyEvent{peer: peer, addr: addr}:
			default: // the hook must never block magicsock internals
			}
		})
		mesh.pathReady[m] = ch
	}

	// Wire the udprelay.Server into the relay node's Conn over the
	// eventbus, mirroring feature/relayserver's extension. This is the
	// production seam: Conn publishes UDPRelayAllocReq upon
	// disco.AllocateUDPRelayEndpointRequest reception, and subscribes to
	// UDPRelayAllocResp for transmission back to the requesting client
	// over DERP.
	ec := mesh.relay.conn.eventBus.Client("relayserver.extension.test")
	respPub := eventbus.Publish[UDPRelayAllocResp](ec)
	eventbus.SubscribeFunc(ec, func(req UDPRelayAllocReq) {
		se, err := mesh.server.AllocateEndpoint(req.Message.ClientDisco[0], req.Message.ClientDisco[1])
		if err != nil {
			logf("relayserver: error allocating endpoint: %v", err)
			return
		}
		mesh.mu.Lock()
		mesh.serverDisco = se.ServerDisco
		mesh.mu.Unlock()
		// Publish from a separate goroutine, mirroring
		// feature/relayserver. Publishing from within an
		// eventbus.SubscribeFunc is potentially unsafe if publisher and
		// subscriber share a lock. See tailscale/tailscale#17830.
		go respPub.Publish(UDPRelayAllocResp{
			ReqRxFromNodeKey:  req.RxFromNodeKey,
			ReqRxFromDiscoKey: req.RxFromDiscoKey,
			Message: &disco.AllocateUDPRelayEndpointResponse{
				Generation: req.Message.Generation,
				UDPRelayEndpoint: disco.UDPRelayEndpoint{
					ServerDisco:         se.ServerDisco,
					ClientDisco:         se.ClientDisco,
					LamportID:           se.LamportID,
					VNI:                 se.VNI,
					BindLifetime:        se.BindLifetime.Duration,
					SteadyStateLifetime: se.SteadyStateLifetime.Duration,
					AddrPorts:           se.AddrPorts,
				},
			},
		})
	})
	t.Cleanup(ec.Close)

	// The addresses setMeshNetmapsForTest assigns, in stack order.
	m1Prefix := netip.PrefixFrom(netaddr.IPv4(1, 0, 0, 1), 32)
	m2Prefix := netip.PrefixFrom(netaddr.IPv4(1, 0, 0, 2), 32)
	relayPrefix := netip.PrefixFrom(netaddr.IPv4(1, 0, 0, 3), 32)

	filt := relayCapFilterForTest(relayPrefix, m1Prefix, m2Prefix)
	mesh.m1.conn.SetFilter(filt)
	mesh.m2.conn.SetFilter(filt)
	mesh.relay.conn.SetFilter(filt)

	// Synchronously plumb netmaps and WireGuard configs; when this
	// returns, all stacks know all peers and are ready to move traffic,
	// with no need to wait for asynchronous netmap propagation.
	setMeshNetmapsForTest(t, logf, mesh.m1, mesh.m2, mesh.relay)

	return mesh
}

// bestRelayAddr returns src's bestAddr for dst if it is a peer relay path
// (VNI set), otherwise ok is false. It is a single locked read, not a wait.
func bestRelayAddr(src *magicStack, dst key.NodePublic) (_ addrQuality, ok bool) {
	src.conn.mu.Lock()
	ep, ok := src.conn.peerMap.endpointForNodeKey(dst)
	src.conn.mu.Unlock()
	if !ok {
		return addrQuality{}, false
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if !ep.bestAddr.vni.IsSet() {
		return addrQuality{}, false
	}
	return ep.bestAddr, true
}

// mustPeerRelay blocks until src's endpoint for dst installs a path through
// mesh's relay server as its bestAddr, observed via the pathReady event
// channel fed by [Conn.testOnlyRelayEndpointReadyHook], and validates that
// path's details against the relay server. It fails the test fatally on
// timeout or validation error, and returns the installed [addrQuality].
func mustPeerRelay(t *testing.T, logf logger.Logf, mesh *relayedMeshForTest, src, dst *magicStack) addrQuality {
	t.Helper()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case ev := <-mesh.pathReady[src]:
			if ev.peer != dst.Public() {
				continue // relay path to some other peer; keep waiting
			}
			best := ev.addr
			if best.ap != mesh.serverAddrPort {
				t.Fatalf("peer relay path %s->%s addr = %v, want %v", src, dst, best.ap, mesh.serverAddrPort)
			}
			if want := mesh.getServerDisco(); best.relayServerDisco.Compare(want) != 0 {
				t.Fatalf("peer relay path %s->%s server disco = %v, want %v", src, dst, best.relayServerDisco, want)
			}
			logf("peer relay path %s->%s established via %v vni=%d", src, dst, best.ap, best.vni.Get())
			return best
		case <-timeout.C:
			t.Fatalf("timed out waiting for a peer relay path from %s to %s", src, dst)
		}
	}
}

// relaySessionWithBothClientsBound returns the relay server's sole session
// once both clients are bound and have nonzero forwarded counters, otherwise
// an error.
func relaySessionWithBothClientsBound(server *udprelay.Server) (status.ServerSession, error) {
	sessions := server.GetSessions()
	if len(sessions) != 1 {
		return status.ServerSession{}, fmt.Errorf("got %d relay server sessions, want 1: %+v", len(sessions), sessions)
	}
	session := sessions[0]
	for _, client := range []status.ClientInfo{session.Client1, session.Client2} {
		if !client.Endpoint.IsValid() {
			return status.ServerSession{}, fmt.Errorf("relay server session client %s is not bound: %+v", client.ShortDisco, session)
		}
		if client.PacketsTx == 0 || client.BytesTx == 0 {
			return status.ServerSession{}, fmt.Errorf("relay server session client %s has zero forwarded counters: %+v", client.ShortDisco, session)
		}
	}
	return session, nil
}

// drainTunInbound discards any buffered packets on ch without blocking.
func drainTunInbound(ch chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// mustPingTun sends a ping from src to dst through the tun devices and
// blocks until a matching packet is delivered, failing t after a deadline.
// The caller must own both tun channels (no concurrent pingers). Delivery is
// the event waited on; there is no retransmit loop, which the caller must
// only rely on once paths are established (WireGuard stages outbound
// packets across its own handshake, so this also holds for a first packet
// over a fresh tunnel with configured peers).
func mustPingTun(t *testing.T, src, dst *magicStack) {
	t.Helper()
	pkt := tuntest.Ping(dst.IP(), src.IP())
	select {
	case src.tun.Outbound <- pkt:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out sending ping %s->%s", src, dst)
	}
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case recv := <-dst.tun.Inbound:
			if !bytes.Equal(recv, pkt) {
				continue // not our ping (e.g. a stale in-flight packet); keep waiting
			}
			return
		case <-timeout.C:
			t.Fatalf("timed out waiting for ping to transit %s->%s", src, dst)
		}
	}
}

// TestPeerRelayE2E exercises the peer relay data path end to end with real
// magicsock + wireguard-go stacks: two relay clients and a relay server node
// (running an in-process udprelay.Server) are meshed together, direct UDP
// paths are administratively disabled (TS_DEBUG_NEVER_DIRECT_UDP), and
// traffic is verified to transit a Geneve-encapsulated path through the
// relay server in both directions.
func TestPeerRelayE2E(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	mesh := newRelayedMeshForTest(t, logf)

	// Track per-connection statistics so we can later assert that overlay
	// traffic was physically transmitted towards the relay server.
	mesh.m1.conn.SetConnectionCounter(mesh.m1.counts.Add)
	mesh.m2.conn.SetConnectionCounter(mesh.m2.counts.Add)

	// Continuously ping in both directions, asserting zero loss. The
	// initial pings transit DERP; the traffic also keeps endpoint
	// heartbeats (and with them UDP relay path discovery) running.
	stopPing1 := newPinger(t, logf, mesh.m1, mesh.m2)
	stopPing2 := newPinger(t, logf, mesh.m2, mesh.m1)
	pingersStopped := false
	stopPingers := func() {
		if !pingersStopped {
			pingersStopped = true
			stopPing1()
			stopPing2()
		}
	}
	defer stopPingers()

	// Block until both sides upgrade from DERP to a path through the relay
	// server, as signaled by Conn.testOnlyRelayEndpointReadyHook.
	ready1 := mustPeerRelay(t, logf, mesh, mesh.m1, mesh.m2)
	ready2 := mustPeerRelay(t, logf, mesh, mesh.m2, mesh.m1)

	// Each pathReady event was triggered by a disco pong received through
	// the relay server. The server only forwards between two bound
	// clients, and it counts a forwarded packet before transmitting it, so
	// by now it must already report exactly one session with both clients
	// bound and nonzero forwarded packet/byte counters; a single
	// (poll-free) check suffices.
	baseline, err := relaySessionWithBothClientsBound(mesh.server)
	if err != nil {
		t.Fatal(err)
	}

	// The hook events, magicsock's current endpoint state (single locked
	// reads), and the relay server's session view must all agree.
	for _, pair := range []struct {
		src, dst *magicStack
		ready    addrQuality
	}{
		{mesh.m1, mesh.m2, ready1},
		{mesh.m2, mesh.m1, ready2},
	} {
		best, ok := bestRelayAddr(pair.src, pair.dst.Public())
		if !ok {
			t.Fatalf("peer relay path %s->%s went away", pair.src, pair.dst)
		}
		if best.ap != pair.ready.ap || best.vni.Get() != pair.ready.vni.Get() {
			t.Fatalf("peer relay path %s->%s = %v, want %v", pair.src, pair.dst, best.epAddr, pair.ready.epAddr)
		}
		if best.vni.Get() != baseline.VNI {
			t.Fatalf("peer relay path %s->%s vni = %d, want %d", pair.src, pair.dst, best.vni.Get(), baseline.VNI)
		}
	}

	// Stop the continuous pingers (their zero-loss job across the
	// DERP->relay migration is done) and snapshot the per-connection
	// statistics for the connections with the relay server's addr:port as
	// the physical destination; growth beyond this snapshot is asserted
	// below.
	stopPingers()
	wantConns := []struct {
		m    *magicStack
		conn netlogtype.Connection
	}{
		{mesh.m1, netlogtype.Connection{Src: netip.MustParseAddrPort("1.0.0.2:0"), Dst: mesh.serverAddrPort}},
		{mesh.m2, netlogtype.Connection{Src: netip.MustParseAddrPort("1.0.0.1:0"), Dst: mesh.serverAddrPort}},
	}
	baselineConnCounts := make([]netlogtype.Counts, len(wantConns))
	for i, want := range wantConns {
		baselineConnCounts[i] = want.m.counts.Clone()[want.conn]
	}

	// Push a few more pings through the established relay path in both
	// directions, blocking on each delivery (an event) rather than
	// retrying on a timer. Drain any stragglers from the stopped pingers
	// first so deliveries below are attributable to these pings (at most
	// one in-flight straggler per direction can survive the pingers'
	// cleanup; three pings leave margin for it).
	drainTunInbound(mesh.m1.tun.Inbound)
	drainTunInbound(mesh.m2.tun.Inbound)
	const numPings = 3
	for range numPings {
		mustPingTun(t, mesh.m1, mesh.m2)
		mustPingTun(t, mesh.m2, mesh.m1)
	}

	// Both stacks must have transmitted overlay (post-WireGuard) packets
	// with the relay server's addr:port as the physical destination,
	// beyond the baseline snapshot. Growth (rather than nonzero) is
	// asserted because the relay server's session counters alone cannot
	// distinguish WireGuard data from non-handshake disco (e.g. heartbeat
	// ping/pong), which transits relay paths without the Geneve control
	// bit set; the per-connection statistics only count WireGuard data, so
	// their growth proves data kept flowing via the relay through the end
	// of the test. No waiting is required: WireGuard sends to a peer
	// sequentially and the per-connection counter update for ping N
	// completes before ping N+1 is transmitted, so the deliveries observed
	// above guarantee all but (at most) the final ping have already been
	// counted.
	for i, want := range wantConns {
		counts := want.m.counts.Clone()[want.conn]
		if counts.TxPackets <= baselineConnCounts[i].TxPackets {
			t.Fatalf("%s overlay tx counts to relay connection %v did not grow beyond %+v: %+v",
				want.m, want.conn, baselineConnCounts[i], counts)
		}
	}

	// The relay server's forwarded counters for both clients must also
	// grow beyond the baseline session snapshot. The server counts a
	// forwarded packet before transmitting it, so the ping deliveries
	// observed above already imply growth; the deadline poll (which does
	// not sleep when the first check passes, the common case) is purely
	// defensive for the pathological case where a delivery transited a
	// DERP duplicate sent during a bestAddr trust expiry, e.g. under an
	// extreme scheduler stall, while the relay copy is still in flight.
	// The server offers no notification seam for its counters.
	if err := tstest.WaitFor(10*time.Second, func() error {
		session, err := relaySessionWithBothClientsBound(mesh.server)
		if err != nil {
			return err
		}
		if session.VNI != baseline.VNI {
			return fmt.Errorf("relay server session VNI changed: got %d, want %d", session.VNI, baseline.VNI)
		}
		if session.Client1.PacketsTx <= baseline.Client1.PacketsTx {
			return fmt.Errorf("client %s forwarded packets did not grow beyond %d", session.Client1.ShortDisco, baseline.Client1.PacketsTx)
		}
		if session.Client2.PacketsTx <= baseline.Client2.PacketsTx {
			return fmt.Errorf("client %s forwarded packets did not grow beyond %d", session.Client2.ShortDisco, baseline.Client2.PacketsTx)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
