// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	qt "github.com/frankban/quicktest"
	wgconn "github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"go4.org/mem"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/control/controlknobs"
	"tailscale.com/derp/derpserver"
	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/connstats"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/ping"
	"tailscale.com/net/stun"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netlogtype"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/types/ptr"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
	"tailscale.com/util/racebuild"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/filter/filtertype"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgcfg/nmcfg"
	"tailscale.com/wgengine/wglog"
)

func init() {
	os.Setenv("IN_TS_TEST", "1")

	// Some of these tests lose a disco pong before establishing a
	// direct connection, so instead of waiting 5 seconds in the
	// test, reduce the wait period.
	// (In particular, TestActiveDiscovery.)
	discoPingInterval = 100 * time.Millisecond
	pingTimeoutDuration = 100 * time.Millisecond
}

// WaitReady waits until the magicsock is entirely initialized and connected
// to its home DERP server. This is normally not necessary, since magicsock
// is intended to be entirely asynchronous, but it helps eliminate race
// conditions in tests. In particular, you can't expect two test magicsocks
// to be able to connect to each other through a test DERP unless they are
// both fully initialized before you try.
func (c *Conn) WaitReady(t testing.TB) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-c.derpStarted:
		return
	case <-c.connCtx.Done():
		t.Fatalf("magicsock.Conn closed while waiting for readiness")
	case <-timer.C:
		t.Fatalf("timeout waiting for readiness")
	}
}

func runDERPAndStun(t *testing.T, logf logger.Logf, l nettype.PacketListener, stunIP netip.Addr) (derpMap *tailcfg.DERPMap, cleanup func()) {
	d := derpserver.New(key.NewNode(), logf)

	httpsrv := httptest.NewUnstartedServer(derpserver.Handler(d))
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()

	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, l)

	m := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "t1",
						RegionID:         1,
						HostName:         "test-node.unused",
						IPv4:             "127.0.0.1",
						IPv6:             "none",
						STUNPort:         stunAddr.Port,
						DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
						InsecureForTests: true,
						STUNTestIP:       stunIP.String(),
					},
				},
			},
		},
	}

	cleanup = func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
	}

	return m, cleanup
}

// magicStack is a magicsock, plus all the stuff around it that's
// necessary to send and receive packets to test e2e wireguard
// happiness.
type magicStack struct {
	privateKey key.NodePrivate
	epCh       chan []tailcfg.Endpoint // endpoint updates produced by this peer
	stats      *connstats.Statistics   // per-connection statistics
	conn       *Conn                   // the magicsock itself
	tun        *tuntest.ChannelTUN     // TUN device to send/receive packets
	tsTun      *tstun.Wrapper          // wrapped tun that implements filtering and wgengine hooks
	dev        *device.Device          // the wireguard-go Device that connects the previous things
	wgLogger   *wglog.Logger           // wireguard-go log wrapper
	netMon     *netmon.Monitor         // always non-nil
	metrics    *usermetric.Registry
}

// newMagicStack builds and initializes an idle magicsock and
// friends. You need to call conn.onNodeViewsUpdate and dev.Reconfig
// before anything interesting happens.
func newMagicStack(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap) *magicStack {
	privateKey := key.NewNode()
	return newMagicStackWithKey(t, logf, l, derpMap, privateKey)
}

func newMagicStackWithKey(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap, privateKey key.NodePrivate) *magicStack {
	t.Helper()

	bus := eventbustest.NewBus(t)

	netMon, err := netmon.New(bus, logf)
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	ht := health.NewTracker(bus)

	var reg usermetric.Registry
	epCh := make(chan []tailcfg.Endpoint, 100) // arbitrary
	conn, err := NewConn(Options{
		NetMon:                 netMon,
		EventBus:               bus,
		Metrics:                &reg,
		Logf:                   logf,
		HealthTracker:          ht,
		DisablePortMapper:      true,
		TestOnlyPacketListener: l,
		EndpointsFunc: func(eps []tailcfg.Endpoint) {
			epCh <- eps
		},
	})
	if err != nil {
		t.Fatalf("constructing magicsock: %v", err)
	}
	conn.SetDERPMap(derpMap)
	if err := conn.SetPrivateKey(privateKey); err != nil {
		t.Fatalf("setting private key in magicsock: %v", err)
	}

	tun := tuntest.NewChannelTUN()
	tsTun := tstun.Wrap(logf, tun.TUN(), &reg)
	tsTun.SetFilter(filter.NewAllowAllForTest(logf))
	tsTun.Start()

	wgLogger := wglog.NewLogger(logf)
	dev := wgcfg.NewDevice(tsTun, conn.Bind(), wgLogger.DeviceLogger)
	dev.Up()

	// Wait for magicsock to connect up to DERP.
	conn.WaitReady(t)

	// Wait for first endpoint update to be available
	deadline := time.Now().Add(2 * time.Second)
	for len(epCh) == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}

	return &magicStack{
		privateKey: privateKey,
		epCh:       epCh,
		conn:       conn,
		tun:        tun,
		tsTun:      tsTun,
		dev:        dev,
		wgLogger:   wgLogger,
		netMon:     netMon,
		metrics:    &reg,
	}
}

func (s *magicStack) Reconfig(cfg *wgcfg.Config) error {
	s.tsTun.SetWGConfig(cfg)
	s.wgLogger.SetPeers(cfg.Peers)
	return wgcfg.ReconfigDevice(s.dev, cfg, s.conn.logf)
}

func (s *magicStack) String() string {
	pub := s.Public()
	return pub.ShortString()
}

func (s *magicStack) Close() {
	s.dev.Close()
	s.conn.Close()
	s.netMon.Close()
}

func (s *magicStack) Public() key.NodePublic {
	return s.privateKey.Public()
}

// Status returns a subset of the ipnstate.Status, only involving
// the magicsock-specific parts.
func (s *magicStack) Status() *ipnstate.Status {
	var sb ipnstate.StatusBuilder
	sb.WantPeers = true
	s.conn.UpdateStatus(&sb)
	return sb.Status()
}

// IP returns the Tailscale IP address assigned to this magicStack.
//
// Something external needs to provide a NetworkMap and WireGuard
// configs to the magicStack in order for it to acquire an IP
// address. See meshStacks for one possible source of netmaps and IPs.
func (s *magicStack) IP() netip.Addr {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		s.conn.mu.Lock()
		var addr netip.Addr
		if s.conn.self.Valid() && s.conn.self.Addresses().Len() > 0 {
			addr = s.conn.self.Addresses().At(0).Addr()
		}
		s.conn.mu.Unlock()
		if addr.IsValid() {
			return addr
		}
	}
	panic("timed out waiting for magicstack to get an IP assigned")
}

// meshStacks monitors epCh on all given ms, and plumbs network maps
// and WireGuard configs into everyone to form a full mesh that has up
// to date endpoint info. Think of it as an extremely stripped down
// and purpose-built Tailscale control plane.
func meshStacks(logf logger.Logf, mutateNetmap func(idx int, nm *netmap.NetworkMap), ms ...*magicStack) (cleanup func()) {
	ctx, cancel := context.WithCancel(context.Background())

	// Serialize all reconfigurations globally, just to keep things
	// simpler.
	var (
		mu  sync.Mutex
		eps = make([][]tailcfg.Endpoint, len(ms))
	)

	buildNetmapLocked := func(myIdx int) *netmap.NetworkMap {
		me := ms[myIdx]
		nm := &netmap.NetworkMap{
			PrivateKey: me.privateKey,
			NodeKey:    me.privateKey.Public(),
			SelfNode: (&tailcfg.Node{
				Addresses: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(1, 0, 0, byte(myIdx+1)), 32)},
			}).View(),
		}
		for i, peer := range ms {
			if i == myIdx {
				continue
			}
			addrs := []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(1, 0, 0, byte(i+1)), 32)}
			peer := &tailcfg.Node{
				ID:         tailcfg.NodeID(i + 1),
				Name:       fmt.Sprintf("node%d", i+1),
				Key:        peer.privateKey.Public(),
				DiscoKey:   peer.conn.DiscoPublicKey(),
				Addresses:  addrs,
				AllowedIPs: addrs,
				Endpoints:  epFromTyped(eps[i]),
				HomeDERP:   1,
			}
			nm.Peers = append(nm.Peers, peer.View())
		}

		if mutateNetmap != nil {
			mutateNetmap(myIdx, nm)
		}
		return nm
	}

	updateEps := func(idx int, newEps []tailcfg.Endpoint) {
		mu.Lock()
		defer mu.Unlock()

		eps[idx] = newEps

		for i, m := range ms {
			nm := buildNetmapLocked(i)
			nv := NodeViewsUpdate{
				SelfNode: nm.SelfNode,
				Peers:    nm.Peers,
			}
			m.conn.onNodeViewsUpdate(nv)
			peerSet := make(set.Set[key.NodePublic], len(nv.Peers))
			for _, peer := range nv.Peers {
				peerSet.Add(peer.Key())
			}
			m.conn.UpdatePeers(peerSet)
			wg, err := nmcfg.WGCfg(nm, logf, 0, "")
			if err != nil {
				// We're too far from the *testing.T to be graceful,
				// blow up. Shouldn't happen anyway.
				panic(fmt.Sprintf("failed to construct wgcfg from netmap: %v", err))
			}
			if err := m.Reconfig(wg); err != nil {
				if ctx.Err() != nil || errors.Is(err, errConnClosed) {
					// shutdown race, don't care.
					return
				}
				panic(fmt.Sprintf("device reconfig failed: %v", err))
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(len(ms))
	for i := range ms {
		go func(myIdx int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case eps := <-ms[myIdx].epCh:
					logf("conn%d endpoints update", myIdx+1)
					updateEps(myIdx, eps)
				}
			}
		}(i)
	}

	return func() {
		cancel()
		wg.Wait()
	}
}

func TestNewConn(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	epCh := make(chan string, 16)
	epFunc := func(endpoints []tailcfg.Endpoint) {
		for _, ep := range endpoints {
			epCh <- ep.Addr.String()
		}
	}

	bus := eventbus.New()
	t.Cleanup(bus.Close)

	netMon, err := netmon.New(bus, logger.WithPrefix(t.Logf, "... netmon: "))
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	defer netMon.Close()

	stunAddr, stunCleanupFn := stuntest.Serve(t)
	defer stunCleanupFn()

	port := pickPort(t)
	conn, err := NewConn(Options{
		Port:              port,
		DisablePortMapper: true,
		EndpointsFunc:     epFunc,
		Logf:              t.Logf,
		NetMon:            netMon,
		EventBus:          bus,
		Metrics:           new(usermetric.Registry),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDERPMap(stuntest.DERPMapOf(stunAddr.String()))
	conn.SetPrivateKey(key.NewNode())

	go func() {
		pkts := make([][]byte, 1)
		sizes := make([]int, 1)
		eps := make([]wgconn.Endpoint, 1)
		pkts[0] = make([]byte, 64<<10)
		receiveIPv4 := conn.receiveIPv4()
		for {
			_, err := receiveIPv4(pkts, sizes, eps)
			if err != nil {
				return
			}
		}
	}()

	timeout := time.After(10 * time.Second)
	var endpoints []string
	suffix := fmt.Sprintf(":%d", port)
collectEndpoints:
	for {
		select {
		case ep := <-epCh:
			t.Logf("TestNewConn: got endpoint: %v", ep)
			endpoints = append(endpoints, ep)
			if strings.HasSuffix(ep, suffix) {
				break collectEndpoints
			}
		case <-timeout:
			t.Fatalf("timeout with endpoints: %v", endpoints)
		}
	}
}

func pickPort(t testing.TB) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestPickDERPFallback(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	c := newConn(t.Logf)
	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {},
			2: {},
			3: {},
			4: {},
			5: {},
			6: {},
			7: {},
			8: {},
		},
	}
	c.derpMap = dm
	a := c.pickDERPFallback()
	if a == 0 {
		t.Fatalf("pickDERPFallback returned 0")
	}

	// Test that it's consistent.
	for range 50 {
		b := c.pickDERPFallback()
		if a != b {
			t.Fatalf("got inconsistent %d vs %d values", a, b)
		}
	}

	// Test that that the pointer value of c is blended in and
	// distribution over nodes works.
	got := map[int]int{}
	for range 50 {
		c = newConn(t.Logf)
		c.derpMap = dm
		got[c.pickDERPFallback()]++
	}
	t.Logf("distribution: %v", got)
	if len(got) < 2 {
		t.Errorf("expected more than 1 node; got %v", got)
	}

	// Test that stickiness works.
	const someNode = 123456
	c.myDerp = someNode
	if got := c.pickDERPFallback(); got != someNode {
		t.Errorf("not sticky: got %v; want %v", got, someNode)
	}

	// TODO: test that disco-based clients changing to a new DERP
	// region causes this fallback to also move, once disco clients
	// have fixed DERP fallback logic.
}

// TestDeviceStartStop exercises the startup and shutdown logic of
// wireguard-go, which is intimately intertwined with magicsock's own
// lifecycle. We seem to be good at generating deadlocks here, so if
// this test fails you should suspect a deadlock somewhere in startup
// or shutdown. It may be an infrequent flake, so run with
// -count=10000 to be sure.
func TestDeviceStartStop(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	bus := eventbus.New()
	t.Cleanup(bus.Close)

	netMon, err := netmon.New(bus, logger.WithPrefix(t.Logf, "... netmon: "))
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	defer netMon.Close()

	conn, err := NewConn(Options{
		EndpointsFunc: func(eps []tailcfg.Endpoint) {},
		Logf:          t.Logf,
		NetMon:        netMon,
		EventBus:      bus,
		Metrics:       new(usermetric.Registry),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tun := tuntest.NewChannelTUN()
	wgLogger := wglog.NewLogger(t.Logf)
	dev := wgcfg.NewDevice(tun.TUN(), conn.Bind(), wgLogger.DeviceLogger)
	dev.Up()
	dev.Close()
}

// Exercise a code path in sendDiscoMessage if the connection has been closed.
func TestConnClosed(t *testing.T) {
	mstun := &natlab.Machine{Name: "stun"}
	m1 := &natlab.Machine{Name: "m1"}
	m2 := &natlab.Machine{Name: "m2"}
	inet := natlab.NewInternet()
	sif := mstun.Attach("eth0", inet)
	m1if := m1.Attach("eth0", inet)
	m2if := m2.Attach("eth0", inet)

	d := &devices{
		m1:     m1,
		m1IP:   m1if.V4(),
		m2:     m2,
		m2IP:   m2if.V4(),
		stun:   mstun,
		stunIP: sif.V4(),
	}

	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	derpMap, cleanup := runDERPAndStun(t, logf, d.stun, d.stunIP)
	defer cleanup()

	ms1 := newMagicStack(t, logger.WithPrefix(logf, "conn1: "), d.m1, derpMap)
	defer ms1.Close()
	ms2 := newMagicStack(t, logger.WithPrefix(logf, "conn2: "), d.m2, derpMap)
	defer ms2.Close()

	cleanup = meshStacks(t.Logf, nil, ms1, ms2)
	defer cleanup()

	pkt := tuntest.Ping(ms2.IP(), ms1.IP())

	if len(ms1.conn.activeDerp) == 0 {
		t.Errorf("unexpected DERP empty got: %v want: >0", len(ms1.conn.activeDerp))
	}

	ms1.conn.Close()
	ms2.conn.Close()

	// This should hit a c.closed conditional in sendDiscoMessage() and return immediately.
	ms1.tun.Outbound <- pkt
	select {
	case <-ms2.tun.Inbound:
		t.Error("unexpected response with connection closed")
	case <-time.After(100 * time.Millisecond):
	}

	if len(ms1.conn.activeDerp) > 0 {
		t.Errorf("unexpected DERP active got: %v want:0", len(ms1.conn.activeDerp))
	}
}

func makeNestable(t *testing.T) (logf logger.Logf, setT func(t *testing.T)) {
	var mu sync.RWMutex
	cur := t

	setT = func(t *testing.T) {
		mu.Lock()
		cur = t
		mu.Unlock()
	}

	logf = func(s string, args ...any) {
		mu.RLock()
		t := cur

		t.Helper()
		t.Logf(s, args...)
		mu.RUnlock()
	}

	return logf, setT
}

// localhostOnlyListener is a nettype.PacketListener that listens on
// localhost (127.0.0.1 or ::1, depending on the requested network)
// when asked to listen on the unspecified address.
//
// It's used in tests where we set up localhost-to-localhost
// communication, because if you listen on the unspecified address on
// macOS and Windows, you get an interactive firewall consent prompt
// to allow the binding, which breaks our CIs.
type localhostListener struct{}

func (localhostListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	switch network {
	case "udp4":
		switch host {
		case "", "0.0.0.0":
			host = "127.0.0.1"
		case "127.0.0.1":
		default:
			return nil, fmt.Errorf("localhostListener cannot be asked to listen on %q", address)
		}
	case "udp6":
		switch host {
		case "", "::":
			host = "::1"
		case "::1":
		default:
			return nil, fmt.Errorf("localhostListener cannot be asked to listen on %q", address)
		}
	}
	var conf net.ListenConfig
	return conf.ListenPacket(ctx, network, net.JoinHostPort(host, port))
}

func TestTwoDevicePing(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/11762")
	l, ip := localhostListener{}, netaddr.IPv4(127, 0, 0, 1)
	n := &devices{
		m1:     l,
		m1IP:   ip,
		m2:     l,
		m2IP:   ip,
		stun:   l,
		stunIP: ip,
	}
	testTwoDevicePing(t, n)
}

func TestDiscokeyChange(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	m1Key := key.NewNode()
	m1 := newMagicStackWithKey(t, t.Logf, localhostListener{}, derpMap, m1Key)
	defer m1.Close()
	m2 := newMagicStack(t, t.Logf, localhostListener{}, derpMap)
	defer m2.Close()

	var (
		mu sync.Mutex
		// Start with some random discoKey that isn't actually m1's key,
		// to simulate m2 coming up with knowledge of an old, expired
		// discokey. We'll switch to the correct one later in the test.
		m1DiscoKey = key.NewDisco().Public()
	)
	setm1Key := func(idx int, nm *netmap.NetworkMap) {
		if idx != 1 {
			// only mutate m2's netmap
			return
		}
		if len(nm.Peers) != 1 {
			// m1 not in netmap yet.
			return
		}
		mu.Lock()
		defer mu.Unlock()
		mut := nm.Peers[0].AsStruct()
		mut.DiscoKey = m1DiscoKey
		nm.Peers[0] = mut.View()
	}

	cleanupMesh := meshStacks(t.Logf, setm1Key, m1, m2)
	defer cleanupMesh()

	// Wait for both peers to know about each other.
	for {
		if s1 := m1.Status(); len(s1.Peer) != 1 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if s2 := m2.Status(); len(s2.Peer) != 1 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		break
	}

	mu.Lock()
	m1DiscoKey = m1.conn.DiscoPublicKey()
	mu.Unlock()

	// Manually trigger an endpoint update to meshStacks, so it hands
	// m2 a new netmap.
	m1.conn.mu.Lock()
	m1.epCh <- m1.conn.lastEndpoints
	m1.conn.mu.Unlock()

	cleanup = newPinger(t, t.Logf, m1, m2)
	defer cleanup()

	mustDirect(t, t.Logf, m1, m2)
	mustDirect(t, t.Logf, m2, m1)
}

func TestActiveDiscovery(t *testing.T) {
	tstest.ResourceCheck(t)

	t.Run("simple_internet", func(t *testing.T) {
		t.Parallel()
		mstun := &natlab.Machine{Name: "stun"}
		m1 := &natlab.Machine{Name: "m1"}
		m2 := &natlab.Machine{Name: "m2"}
		inet := natlab.NewInternet()
		sif := mstun.Attach("eth0", inet)
		m1if := m1.Attach("eth0", inet)
		m2if := m2.Attach("eth0", inet)

		n := &devices{
			m1:     m1,
			m1IP:   m1if.V4(),
			m2:     m2,
			m2IP:   m2if.V4(),
			stun:   mstun,
			stunIP: sif.V4(),
		}
		testActiveDiscovery(t, n)
	})

	t.Run("facing_easy_firewalls", func(t *testing.T) {
		mstun := &natlab.Machine{Name: "stun"}
		m1 := &natlab.Machine{
			Name:          "m1",
			PacketHandler: &natlab.Firewall{},
		}
		m2 := &natlab.Machine{
			Name:          "m2",
			PacketHandler: &natlab.Firewall{},
		}
		inet := natlab.NewInternet()
		sif := mstun.Attach("eth0", inet)
		m1if := m1.Attach("eth0", inet)
		m2if := m2.Attach("eth0", inet)

		n := &devices{
			m1:     m1,
			m1IP:   m1if.V4(),
			m2:     m2,
			m2IP:   m2if.V4(),
			stun:   mstun,
			stunIP: sif.V4(),
		}
		testActiveDiscovery(t, n)
	})

	t.Run("facing_nats", func(t *testing.T) {
		mstun := &natlab.Machine{Name: "stun"}
		m1 := &natlab.Machine{
			Name:          "m1",
			PacketHandler: &natlab.Firewall{},
		}
		nat1 := &natlab.Machine{
			Name: "nat1",
		}
		m2 := &natlab.Machine{
			Name:          "m2",
			PacketHandler: &natlab.Firewall{},
		}
		nat2 := &natlab.Machine{
			Name: "nat2",
		}

		inet := natlab.NewInternet()
		lan1 := &natlab.Network{
			Name:    "lan1",
			Prefix4: netip.MustParsePrefix("192.168.0.0/24"),
		}
		lan2 := &natlab.Network{
			Name:    "lan2",
			Prefix4: netip.MustParsePrefix("192.168.1.0/24"),
		}

		sif := mstun.Attach("eth0", inet)
		nat1WAN := nat1.Attach("wan", inet)
		nat1LAN := nat1.Attach("lan1", lan1)
		nat2WAN := nat2.Attach("wan", inet)
		nat2LAN := nat2.Attach("lan2", lan2)
		m1if := m1.Attach("eth0", lan1)
		m2if := m2.Attach("eth0", lan2)
		lan1.SetDefaultGateway(nat1LAN)
		lan2.SetDefaultGateway(nat2LAN)

		nat1.PacketHandler = &natlab.SNAT44{
			Machine:           nat1,
			ExternalInterface: nat1WAN,
			Firewall: &natlab.Firewall{
				TrustedInterface: nat1LAN,
			},
		}
		nat2.PacketHandler = &natlab.SNAT44{
			Machine:           nat2,
			ExternalInterface: nat2WAN,
			Firewall: &natlab.Firewall{
				TrustedInterface: nat2LAN,
			},
		}

		n := &devices{
			m1:     m1,
			m1IP:   m1if.V4(),
			m2:     m2,
			m2IP:   m2if.V4(),
			stun:   mstun,
			stunIP: sif.V4(),
		}
		testActiveDiscovery(t, n)
	})
}

type devices struct {
	m1   nettype.PacketListener
	m1IP netip.Addr

	m2   nettype.PacketListener
	m2IP netip.Addr

	stun   nettype.PacketListener
	stunIP netip.Addr
}

// newPinger starts continuously sending test packets from srcM to
// dstM, until cleanup is invoked to stop it. Each ping has 1 second
// to transit the network. It is a test failure to lose a ping.
func newPinger(t *testing.T, logf logger.Logf, src, dst *magicStack) (cleanup func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	one := func() bool {
		// TODO(danderson): requiring exactly zero packet loss
		// will probably be too strict for some tests we'd like to
		// run (e.g. discovery switching to a new path on
		// failure). Figure out what kind of thing would be
		// acceptable to test instead of "every ping must
		// transit".
		pkt := tuntest.Ping(dst.IP(), src.IP())
		select {
		case src.tun.Outbound <- pkt:
		case <-ctx.Done():
			return false
		}
		select {
		case <-dst.tun.Inbound:
			return true
		case <-time.After(10 * time.Second):
			// Very generous timeout here because depending on
			// magicsock setup races, the first handshake might get
			// eaten by the receiving end (if wireguard-go hasn't been
			// configured quite yet), so we have to wait for at least
			// the first retransmit from wireguard before we declare
			// failure.
			t.Errorf("timed out waiting for ping to transit")
			return true
		case <-ctx.Done():
			// Try a little bit longer to consume the packet we're
			// waiting for. This is to deal with shutdown races, where
			// natlab may still be delivering a packet to us from a
			// goroutine.
			select {
			case <-dst.tun.Inbound:
			case <-time.After(time.Second):
			}
			return false
		}
	}

	cleanup = func() {
		cancel()
		<-done
	}

	// Synchronously transit one ping to get things started. This is
	// nice because it means that newPinger returning means we've
	// worked through initial connectivity.
	if !one() {
		cleanup()
		return
	}

	go func() {
		logf("sending ping stream from %s (%s) to %s (%s)", src, src.IP(), dst, dst.IP())
		defer close(done)
		for one() {
		}
	}()

	return cleanup
}

// testActiveDiscovery verifies that two magicStacks tied to the given
// devices can establish a direct p2p connection with each other. See
// TestActiveDiscovery for the various configurations of devices that
// get exercised.
func testActiveDiscovery(t *testing.T, d *devices) {
	tstest.PanicOnLog()

	tlogf, setT := makeNestable(t)
	setT(t)

	start := time.Now()
	wlogf := func(msg string, args ...any) {
		t.Helper()
		msg = fmt.Sprintf("%s: %s", time.Since(start).Truncate(time.Microsecond), msg)
		tlogf(msg, args...)
	}
	logf, closeLogf := logger.LogfCloser(wlogf)
	defer closeLogf()

	derpMap, cleanup := runDERPAndStun(t, logf, d.stun, d.stunIP)
	defer cleanup()

	m1 := newMagicStack(t, logger.WithPrefix(logf, "conn1: "), d.m1, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, logger.WithPrefix(logf, "conn2: "), d.m2, derpMap)
	defer m2.Close()

	cleanup = meshStacks(logf, nil, m1, m2)
	defer cleanup()

	m1IP := m1.IP()
	m2IP := m2.IP()
	logf("IPs: %s %s", m1IP, m2IP)

	cleanup = newPinger(t, logf, m1, m2)
	defer cleanup()

	// Everything is now up and running, active discovery should find
	// a direct path between our peers. Wait for it to switch away
	// from DERP.
	mustDirect(t, logf, m1, m2)
	mustDirect(t, logf, m2, m1)

	logf("starting cleanup")
}

func mustDirect(t *testing.T, logf logger.Logf, m1, m2 *magicStack) {
	lastLog := time.Now().Add(-time.Minute)
	// See https://github.com/tailscale/tailscale/issues/654
	// and https://github.com/tailscale/tailscale/issues/3247 for discussions of this deadline.
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		pst := m1.Status().Peer[m2.Public()]
		if pst.CurAddr != "" {
			logf("direct link %s->%s found with addr %s", m1, m2, pst.CurAddr)
			return
		}
		if now := time.Now(); now.Sub(lastLog) > time.Second {
			logf("no direct path %s->%s yet, addrs %v", m1, m2, pst.Addrs)
			lastLog = now
		}
	}
	t.Errorf("magicsock did not find a direct path from %s to %s", m1, m2)
}

func testTwoDevicePing(t *testing.T, d *devices) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	// This gets reassigned inside every test, so that the connections
	// all log using the "current" t.Logf function. Sigh.
	nestedLogf, setT := makeNestable(t)

	logf, closeLogf := logger.LogfCloser(nestedLogf)
	defer closeLogf()

	derpMap, cleanup := runDERPAndStun(t, logf, d.stun, d.stunIP)
	defer cleanup()

	m1 := newMagicStack(t, logf, d.m1, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, logf, d.m2, derpMap)
	defer m2.Close()

	cleanupMesh := meshStacks(logf, nil, m1, m2)
	defer cleanupMesh()

	// Wait for magicsock to be told about peers from meshStacks.
	tstest.WaitFor(10*time.Second, func() error {
		if p := m1.Status().Peer[m2.Public()]; p == nil || !p.InMagicSock {
			return errors.New("m1 not ready")
		}
		if p := m2.Status().Peer[m1.Public()]; p == nil || !p.InMagicSock {
			return errors.New("m2 not ready")
		}
		return nil
	})

	m1cfg := &wgcfg.Config{
		Name:       "peer1",
		PrivateKey: m1.privateKey,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("1.0.0.1/32")},
		Peers: []wgcfg.Peer{
			{
				PublicKey:  m2.privateKey.Public(),
				DiscoKey:   m2.conn.DiscoPublicKey(),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("1.0.0.2/32")},
			},
		},
	}
	m2cfg := &wgcfg.Config{
		Name:       "peer2",
		PrivateKey: m2.privateKey,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("1.0.0.2/32")},
		Peers: []wgcfg.Peer{
			{
				PublicKey:  m1.privateKey.Public(),
				DiscoKey:   m1.conn.DiscoPublicKey(),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("1.0.0.1/32")},
			},
		},
	}

	if err := m1.Reconfig(m1cfg); err != nil {
		t.Fatal(err)
	}
	if err := m2.Reconfig(m2cfg); err != nil {
		t.Fatal(err)
	}

	// In the normal case, pings succeed immediately.
	// However, in the case of a handshake race, we need to retry.
	// With very bad luck, we can need to retry multiple times.
	allowedRetries := 3
	if cibuild.On() {
		// Allow extra retries on small/flaky/loaded CI machines.
		allowedRetries *= 2
	}
	// Retries take 5s each. Add 1s for some processing time.
	pingTimeout := 5*time.Second*time.Duration(allowedRetries) + time.Second

	// sendWithTimeout sends msg using send, checking that it is received unchanged from in.
	// It resends once per second until the send succeeds, or pingTimeout time has elapsed.
	sendWithTimeout := func(msg []byte, in chan []byte, send func()) error {
		start := time.Now()
		for time.Since(start) < pingTimeout {
			send()
			select {
			case recv := <-in:
				if !bytes.Equal(msg, recv) {
					return errors.New("ping did not transit correctly")
				}
				return nil
			case <-time.After(time.Second):
				// try again
			}
		}
		return errors.New("ping timed out")
	}

	ping1 := func(t *testing.T) {
		msg2to1 := tuntest.Ping(netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("1.0.0.2"))
		send := func() {
			m2.tun.Outbound <- msg2to1
			t.Log("ping1 sent")
		}
		in := m1.tun.Inbound
		if err := sendWithTimeout(msg2to1, in, send); err != nil {
			t.Error(err)
		}
	}
	ping2 := func(t *testing.T) {
		msg1to2 := tuntest.Ping(netip.MustParseAddr("1.0.0.2"), netip.MustParseAddr("1.0.0.1"))
		send := func() {
			m1.tun.Outbound <- msg1to2
			t.Log("ping2 sent")
		}
		in := m2.tun.Inbound
		if err := sendWithTimeout(msg1to2, in, send); err != nil {
			t.Error(err)
		}
	}

	m1.stats = connstats.NewStatistics(0, 0, nil)
	defer m1.stats.Shutdown(context.Background())
	m1.conn.SetStatistics(m1.stats)
	m2.stats = connstats.NewStatistics(0, 0, nil)
	defer m2.stats.Shutdown(context.Background())
	m2.conn.SetStatistics(m2.stats)

	checkStats := func(t *testing.T, m *magicStack, wantConns []netlogtype.Connection) {
		_, stats := m.stats.TestExtract()
		for _, conn := range wantConns {
			if _, ok := stats[conn]; ok {
				return
			}
		}
		t.Helper()
		t.Errorf("missing any connection to %s from %s", wantConns, slicesx.MapKeys(stats))
	}

	addrPort := netip.MustParseAddrPort
	m1Conns := []netlogtype.Connection{
		{Src: addrPort("1.0.0.2:0"), Dst: m2.conn.pconn4.LocalAddr().AddrPort()},
		{Src: addrPort("1.0.0.2:0"), Dst: addrPort("127.3.3.40:1")},
	}
	m2Conns := []netlogtype.Connection{
		{Src: addrPort("1.0.0.1:0"), Dst: m1.conn.pconn4.LocalAddr().AddrPort()},
		{Src: addrPort("1.0.0.1:0"), Dst: addrPort("127.3.3.40:1")},
	}

	outerT := t
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		ping1(t)
		checkStats(t, m1, m1Conns)
		checkStats(t, m2, m2Conns)
	})

	t.Run("ping 1.0.0.2", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		ping2(t)
		checkStats(t, m1, m1Conns)
		checkStats(t, m2, m2Conns)
	})

	t.Run("ping 1.0.0.2 via SendPacket", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		msg1to2 := tuntest.Ping(netip.MustParseAddr("1.0.0.2"), netip.MustParseAddr("1.0.0.1"))
		send := func() {
			if err := m1.tsTun.InjectOutbound(msg1to2); err != nil {
				t.Fatal(err)
			}
			t.Log("SendPacket sent")
		}
		in := m2.tun.Inbound
		if err := sendWithTimeout(msg1to2, in, send); err != nil {
			t.Error(err)
		}
		checkStats(t, m1, m1Conns)
		checkStats(t, m2, m2Conns)
	})

	t.Run("no-op dev1 reconfig", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		if err := m1.Reconfig(m1cfg); err != nil {
			t.Fatal(err)
		}
		ping1(t)
		ping2(t)
		checkStats(t, m1, m1Conns)
		checkStats(t, m2, m2Conns)
	})
	t.Run("compare-metrics-stats", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		m1.conn.resetMetricsForTest()
		m1.stats.TestExtract()
		m2.conn.resetMetricsForTest()
		m2.stats.TestExtract()
		t.Logf("Metrics before: %s\n", m1.metrics.String())
		ping1(t)
		ping2(t)
		assertConnStatsAndUserMetricsEqual(t, m1)
		assertConnStatsAndUserMetricsEqual(t, m2)
		t.Logf("Metrics after: %s\n", m1.metrics.String())
	})
}

func (c *Conn) resetMetricsForTest() {
	c.metrics.inboundBytesIPv4Total.Set(0)
	c.metrics.inboundPacketsIPv4Total.Set(0)
	c.metrics.outboundBytesIPv4Total.Set(0)
	c.metrics.outboundPacketsIPv4Total.Set(0)
	c.metrics.inboundBytesIPv6Total.Set(0)
	c.metrics.inboundPacketsIPv6Total.Set(0)
	c.metrics.outboundBytesIPv6Total.Set(0)
	c.metrics.outboundPacketsIPv6Total.Set(0)
	c.metrics.inboundBytesDERPTotal.Set(0)
	c.metrics.inboundPacketsDERPTotal.Set(0)
	c.metrics.outboundBytesDERPTotal.Set(0)
	c.metrics.outboundPacketsDERPTotal.Set(0)
}

func assertConnStatsAndUserMetricsEqual(t *testing.T, ms *magicStack) {
	_, phys := ms.stats.TestExtract()

	physIPv4RxBytes := int64(0)
	physIPv4TxBytes := int64(0)
	physDERPRxBytes := int64(0)
	physDERPTxBytes := int64(0)
	physIPv4RxPackets := int64(0)
	physIPv4TxPackets := int64(0)
	physDERPRxPackets := int64(0)
	physDERPTxPackets := int64(0)
	for conn, count := range phys {
		t.Logf("physconn src: %s, dst: %s", conn.Src.String(), conn.Dst.String())
		if conn.Dst.String() == "127.3.3.40:1" {
			physDERPRxBytes += int64(count.RxBytes)
			physDERPTxBytes += int64(count.TxBytes)
			physDERPRxPackets += int64(count.RxPackets)
			physDERPTxPackets += int64(count.TxPackets)
		} else {
			physIPv4RxBytes += int64(count.RxBytes)
			physIPv4TxBytes += int64(count.TxBytes)
			physIPv4RxPackets += int64(count.RxPackets)
			physIPv4TxPackets += int64(count.TxPackets)
		}
	}

	metricIPv4RxBytes := ms.conn.metrics.inboundBytesIPv4Total.Value()
	metricIPv4RxPackets := ms.conn.metrics.inboundPacketsIPv4Total.Value()
	metricIPv4TxBytes := ms.conn.metrics.outboundBytesIPv4Total.Value()
	metricIPv4TxPackets := ms.conn.metrics.outboundPacketsIPv4Total.Value()

	metricDERPRxBytes := ms.conn.metrics.inboundBytesDERPTotal.Value()
	metricDERPRxPackets := ms.conn.metrics.inboundPacketsDERPTotal.Value()
	metricDERPTxBytes := ms.conn.metrics.outboundBytesDERPTotal.Value()
	metricDERPTxPackets := ms.conn.metrics.outboundPacketsDERPTotal.Value()

	c := qt.New(t)
	c.Assert(physDERPRxBytes, qt.Equals, metricDERPRxBytes)
	c.Assert(physDERPTxBytes, qt.Equals, metricDERPTxBytes)
	c.Assert(physIPv4RxBytes, qt.Equals, metricIPv4RxBytes)
	c.Assert(physIPv4TxBytes, qt.Equals, metricIPv4TxBytes)
	c.Assert(physDERPRxPackets, qt.Equals, metricDERPRxPackets)
	c.Assert(physDERPTxPackets, qt.Equals, metricDERPTxPackets)
	c.Assert(physIPv4RxPackets, qt.Equals, metricIPv4RxPackets)
	c.Assert(physIPv4TxPackets, qt.Equals, metricIPv4TxPackets)

	// Validate that the usermetrics and clientmetrics are in sync
	// Note: the clientmetrics are global, this means that when they are registering with the
	// wgengine, multiple in-process nodes used by this test will be updating the same metrics. This is why we need to multiply
	// the metrics by 2 to get the expected value.
	// TODO(kradalby): https://github.com/tailscale/tailscale/issues/13420
	c.Assert(metricSendUDP.Value(), qt.Equals, metricIPv4TxPackets*2)
	c.Assert(metricRecvDataPacketsIPv4.Value(), qt.Equals, metricIPv4RxPackets*2)
	c.Assert(metricRecvDataPacketsDERP.Value(), qt.Equals, metricDERPRxPackets*2)
}

// tests that having a endpoint.String prevents wireguard-go's
// log.Printf("%v") of its conn.Endpoint values from using reflect to
// walk into read mutex while they're being used and then causing data
// races.
func TestDiscoStringLogRace(t *testing.T) {
	de := new(endpoint)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		fmt.Fprintf(io.Discard, "%v", de)
	}()
	go func() {
		defer wg.Done()
		de.mu.Lock()
	}()
	wg.Wait()
}

func Test32bitAlignment(t *testing.T) {
	// Need an associated conn with non-nil noteRecvActivity to
	// trigger interesting work on the atomics in endpoint.
	called := 0
	de := endpoint{
		c: &Conn{
			noteRecvActivity: func(key.NodePublic) { called++ },
		},
	}

	if off := unsafe.Offsetof(de.lastRecvWG); off%8 != 0 {
		t.Fatalf("endpoint.lastRecvWG is not 8-byte aligned")
	}

	de.noteRecvActivity(epAddr{}, mono.Now()) // verify this doesn't panic on 32-bit
	if called != 1 {
		t.Fatal("expected call to noteRecvActivity")
	}
	de.noteRecvActivity(epAddr{}, mono.Now())
	if called != 1 {
		t.Error("expected no second call to noteRecvActivity")
	}
}

// newTestConn returns a new Conn.
func newTestConn(t testing.TB) *Conn {
	t.Helper()
	port := pickPort(t)

	bus := eventbustest.NewBus(t)

	netMon, err := netmon.New(bus, logger.WithPrefix(t.Logf, "... netmon: "))
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	t.Cleanup(func() { netMon.Close() })

	conn, err := NewConn(Options{
		NetMon:                 netMon,
		EventBus:               bus,
		HealthTracker:          health.NewTracker(bus),
		Metrics:                new(usermetric.Registry),
		DisablePortMapper:      true,
		Logf:                   t.Logf,
		Port:                   port,
		TestOnlyPacketListener: localhostListener{},
		EndpointsFunc: func(eps []tailcfg.Endpoint) {
			t.Logf("endpoints: %q", eps)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// addTestEndpoint sets conn's node views to a single peer expected
// to receive packets from sendConn (or DERP), and returns that peer's
// nodekey and discokey.
func addTestEndpoint(tb testing.TB, conn *Conn, sendConn net.PacketConn) (key.NodePublic, key.DiscoPublic) {
	// Give conn just enough state that it'll recognize sendConn as a
	// valid peer and not fall through to the legacy magicsock
	// codepath.
	discoKey := key.DiscoPublicFromRaw32(mem.B([]byte{31: 1}))
	nodeKey := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 31: 0}))
	conn.onNodeViewsUpdate(NodeViewsUpdate{
		Peers: nodeViews([]*tailcfg.Node{
			{
				ID:        1,
				Key:       nodeKey,
				DiscoKey:  discoKey,
				Endpoints: eps(sendConn.LocalAddr().String()),
			},
		}),
	})
	conn.SetPrivateKey(key.NodePrivateFromRaw32(mem.B([]byte{0: 1, 31: 0})))
	_, err := conn.ParseEndpoint(nodeKey.UntypedHexString())
	if err != nil {
		tb.Fatal(err)
	}
	conn.addValidDiscoPathForTest(nodeKey, netip.MustParseAddrPort(sendConn.LocalAddr().String()))
	return nodeKey, discoKey
}

func setUpReceiveFrom(tb testing.TB) (roundTrip func()) {
	if b, ok := tb.(*testing.B); ok {
		b.ReportAllocs()
	}

	conn := newTestConn(tb)
	tb.Cleanup(func() { conn.Close() })
	conn.logf = logger.Discard

	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { sendConn.Close() })

	addTestEndpoint(tb, conn, sendConn)

	var dstAddr net.Addr = conn.pconn4.LocalAddr()
	sendBuf := make([]byte, 1<<10)
	for i := range sendBuf {
		sendBuf[i] = 'x'
	}
	buffs := make([][]byte, 1)
	buffs[0] = make([]byte, 2<<10)
	sizes := make([]int, 1)
	eps := make([]wgconn.Endpoint, 1)
	receiveIPv4 := conn.receiveIPv4()
	return func() {
		if _, err := sendConn.WriteTo(sendBuf, dstAddr); err != nil {
			tb.Fatalf("WriteTo: %v", err)
		}
		n, err := receiveIPv4(buffs, sizes, eps)
		if err != nil {
			tb.Fatal(err)
		}
		_ = n
		_ = eps
	}
}

// goMajorVersion reports the major Go version and whether it is a Tailscale fork.
// If parsing fails, goMajorVersion returns 0, false.
func goMajorVersion(s string) (version int, isTS bool) {
	if !strings.HasPrefix(s, "go1.") {
		return 0, false
	}
	mm := s[len("go1."):]
	var major, rest string
	for _, sep := range []string{".", "rc", "beta", "-"} {
		i := strings.Index(mm, sep)
		if i > 0 {
			major, rest = mm[:i], mm[i:]
			break
		}
	}
	if major == "" {
		major = mm
	}
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0, false
	}
	return n, strings.Contains(rest, "ts")
}

func TestGoMajorVersion(t *testing.T) {
	tests := []struct {
		version string
		wantN   int
		wantTS  bool
	}{
		{"go1.15.8", 15, false},
		{"go1.16rc1", 16, false},
		{"go1.16rc1", 16, false},
		{"go1.15.5-ts3bd89195a3", 15, true},
		{"go1.15", 15, false},
		{"go1.18-ts0d07ed810a", 18, true},
	}

	for _, tt := range tests {
		n, ts := goMajorVersion(tt.version)
		if tt.wantN != n || tt.wantTS != ts {
			t.Errorf("goMajorVersion(%s) = %v, %v, want %v, %v", tt.version, n, ts, tt.wantN, tt.wantTS)
		}
	}

	// Ensure that the current Go version is parseable.
	n, _ := goMajorVersion(runtime.Version())
	if n == 0 {
		t.Fatalf("unable to parse %v", runtime.Version())
	}
}

func TestReceiveFromAllocs(t *testing.T) {
	// TODO(jwhited): we are back to nonzero alloc due to our use of x/net until
	//  https://github.com/golang/go/issues/45886 is implemented.
	t.Skip("alloc tests are skipped until https://github.com/golang/go/issues/45886 is implemented and plumbed.")
	if racebuild.On {
		t.Skip("alloc tests are unreliable with -race")
	}
	// Go 1.16 and before: allow 3 allocs.
	// Go 1.17: allow 2 allocs.
	// Go 1.17, Tailscale fork: allow 1 alloc.
	// Go 1.18+: allow 0 allocs.
	// Go 2.0: allow -1 allocs (projected).
	major, ts := goMajorVersion(runtime.Version())
	maxAllocs := 3
	switch {
	case major == 17 && !ts:
		maxAllocs = 2
	case major == 17 && ts:
		maxAllocs = 1
	case major >= 18:
		maxAllocs = 0
	}
	t.Logf("allowing %d allocs for Go version %q", maxAllocs, runtime.Version())
	roundTrip := setUpReceiveFrom(t)
	err := tstest.MinAllocsPerRun(t, uint64(maxAllocs), roundTrip)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkReceiveFrom(b *testing.B) {
	roundTrip := setUpReceiveFrom(b)
	for range b.N {
		roundTrip()
	}
}

func BenchmarkReceiveFrom_Native(b *testing.B) {
	b.ReportAllocs()
	recvConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer recvConn.Close()
	recvConnUDP := recvConn.(*net.UDPConn)

	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer sendConn.Close()

	var dstAddr net.Addr = recvConn.LocalAddr()
	sendBuf := make([]byte, 1<<10)
	for i := range sendBuf {
		sendBuf[i] = 'x'
	}

	buf := make([]byte, 2<<10)
	for range b.N {
		if _, err := sendConn.WriteTo(sendBuf, dstAddr); err != nil {
			b.Fatalf("WriteTo: %v", err)
		}
		if _, _, err := recvConnUDP.ReadFromUDP(buf); err != nil {
			b.Fatalf("ReadFromUDP: %v", err)
		}
	}
}

func nodeViews(v []*tailcfg.Node) []tailcfg.NodeView {
	nv := make([]tailcfg.NodeView, len(v))
	for i, n := range v {
		nv[i] = n.View()
	}
	return nv
}

// Test that a node views update where node changes its node key but
// doesn't change its disco key doesn't result in a broken state.
//
// https://github.com/tailscale/tailscale/issues/1391
func TestOnNodeViewsUpdateChangingNodeKey(t *testing.T) {
	conn := newTestConn(t)
	t.Cleanup(func() { conn.Close() })
	var buf tstest.MemLogger
	conn.logf = buf.Logf

	conn.SetPrivateKey(key.NodePrivateFromRaw32(mem.B([]byte{0: 1, 31: 0})))

	discoKey := key.DiscoPublicFromRaw32(mem.B([]byte{31: 1}))
	nodeKey1 := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 2: '1', 31: 0}))
	nodeKey2 := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 2: '2', 31: 0}))

	conn.onNodeViewsUpdate(NodeViewsUpdate{
		Peers: nodeViews([]*tailcfg.Node{
			{
				ID:        1,
				Key:       nodeKey1,
				DiscoKey:  discoKey,
				Endpoints: eps("192.168.1.2:345"),
			},
		}),
	})
	_, err := conn.ParseEndpoint(nodeKey1.UntypedHexString())
	if err != nil {
		t.Fatal(err)
	}

	for range 3 {
		conn.onNodeViewsUpdate(NodeViewsUpdate{
			Peers: nodeViews([]*tailcfg.Node{
				{
					ID:        2,
					Key:       nodeKey2,
					DiscoKey:  discoKey,
					Endpoints: eps("192.168.1.2:345"),
				},
			}),
		})
	}

	de, ok := conn.peerMap.endpointForNodeKey(nodeKey2)
	if ok && de.publicKey != nodeKey2 {
		t.Fatalf("discoEndpoint public key = %q; want %q", de.publicKey, nodeKey2)
	}
	deDisco := de.disco.Load()
	if deDisco == nil {
		t.Fatalf("discoEndpoint disco is nil")
	}
	if deDisco.key != discoKey {
		t.Errorf("discoKey = %v; want %v", deDisco.key, discoKey)
	}
	if _, ok := conn.peerMap.endpointForNodeKey(nodeKey1); ok {
		t.Errorf("didn't expect to find node for key1")
	}

	log := buf.String()
	wantSub := map[string]int{
		"magicsock: got updated network map; 1 peers": 2,
	}
	for sub, want := range wantSub {
		got := strings.Count(log, sub)
		if got != want {
			t.Errorf("in log, count of substring %q = %v; want %v", sub, got, want)
		}
	}
	if t.Failed() {
		t.Logf("log output: %s", log)
	}
}

func TestRebindStress(t *testing.T) {
	conn := newTestConn(t)

	var buf tstest.MemLogger
	conn.logf = buf.Logf

	closed := false
	t.Cleanup(func() {
		if !closed {
			conn.Close()
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)
	go func() {
		buffs := make([][]byte, 1)
		sizes := make([]int, 1)
		eps := make([]wgconn.Endpoint, 1)
		buffs[0] = make([]byte, 1500)
		receiveIPv4 := conn.receiveIPv4()
		for {
			_, err := receiveIPv4(buffs, sizes, eps)
			if ctx.Err() != nil {
				errc <- nil
				return
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 2000 {
			conn.Rebind()
		}
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			conn.Rebind()
		}
	}()
	wg.Wait()

	cancel()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true

	err := <-errc
	if err != nil {
		t.Fatalf("Got ReceiveIPv4 error: %v (is closed = %v). Log:\n%s", err, errors.Is(err, net.ErrClosed), buf.String())
	}
}

func TestEndpointSetsEqual(t *testing.T) {
	s := func(ports ...uint16) (ret []tailcfg.Endpoint) {
		for _, port := range ports {
			ret = append(ret, tailcfg.Endpoint{
				Addr: netip.AddrPortFrom(netip.Addr{}, port),
			})
		}
		return
	}
	tests := []struct {
		a, b []tailcfg.Endpoint
		want bool
	}{
		{
			want: true,
		},
		{
			a:    s(1, 2, 3),
			b:    s(1, 2, 3),
			want: true,
		},
		{
			a:    s(1, 2),
			b:    s(2, 1),
			want: true,
		},
		{
			a:    s(1, 2),
			b:    s(2, 1, 1),
			want: true,
		},
		{
			a:    s(1, 2, 2),
			b:    s(2, 1),
			want: true,
		},
		{
			a:    s(1, 2, 2),
			b:    s(2, 1, 1),
			want: true,
		},
		{
			a:    s(1, 2, 2, 3),
			b:    s(2, 1, 1),
			want: false,
		},
		{
			a:    s(1, 2, 2),
			b:    s(2, 1, 1, 3),
			want: false,
		},
	}
	for _, tt := range tests {
		if got := endpointSetsEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("%q vs %q = %v; want %v", tt.a, tt.b, got, tt.want)
		}
	}

}

func TestBetterAddr(t *testing.T) {
	const ms = time.Millisecond
	al := func(ipps string, d time.Duration) addrQuality {
		return addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort(ipps)}, latency: d}
	}
	almtu := func(ipps string, d time.Duration, mtu tstun.WireMTU) addrQuality {
		return addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort(ipps)}, latency: d, wireMTU: mtu}
	}
	avl := func(ipps string, vni uint32, d time.Duration) addrQuality {
		q := al(ipps, d)
		q.vni.Set(vni)
		return q
	}
	zero := addrQuality{}

	const (
		publicV4   = "1.2.3.4:555"
		publicV4_2 = "5.6.7.8:999"
		publicV6   = "[2001::5]:123"

		privateV4 = "10.0.0.2:123"
	)

	tests := []struct {
		a, b addrQuality
		want bool // whether a is better than b
	}{
		{a: zero, b: zero, want: false},
		{a: al(publicV4, 5*ms), b: zero, want: true},
		{a: zero, b: al(publicV4, 5*ms), want: false},
		{a: al(publicV4, 5*ms), b: al(publicV4_2, 10*ms), want: true},
		{a: al(publicV4, 5*ms), b: al(publicV4, 10*ms), want: false}, // same IPPort

		// Don't prefer b to a if it's not substantially better.
		{a: al(publicV4, 100*ms), b: al(publicV4_2, 100*ms), want: false},
		{a: al(publicV4, 100*ms), b: al(publicV4_2, 101*ms), want: false},
		{a: al(publicV4, 100*ms), b: al(publicV4_2, 103*ms), want: true},

		// Latencies of zero don't result in a divide-by-zero
		{a: al(publicV4, 0), b: al(publicV4_2, 0), want: false},

		// Prefer private IPs to public IPs if roughly equivalent...
		{
			a:    al(privateV4, 100*ms),
			b:    al(publicV4, 91*ms),
			want: true,
		},
		{
			a:    al(publicV4, 91*ms),
			b:    al(privateV4, 100*ms),
			want: false,
		},
		// ... but not if the private IP is slower.
		{
			a:    al(privateV4, 100*ms),
			b:    al(publicV4, 30*ms),
			want: false,
		},
		{
			a:    al(publicV4, 30*ms),
			b:    al(privateV4, 100*ms),
			want: true,
		},

		// Prefer IPv6 if roughly equivalent:
		{
			a:    al(publicV6, 100*ms),
			b:    al(publicV4, 91*ms),
			want: true,
		},
		{
			a:    al(publicV4, 91*ms),
			b:    al(publicV6, 100*ms),
			want: false,
		},
		// But not if IPv4 is much faster:
		{
			a:    al(publicV6, 100*ms),
			b:    al(publicV4, 30*ms),
			want: false,
		},
		{
			a:    al(publicV4, 30*ms),
			b:    al(publicV6, 100*ms),
			want: true,
		},
		// If addresses are equal, prefer larger MTU
		{
			a:    almtu(publicV4, 30*ms, 1500),
			b:    almtu(publicV4, 30*ms, 0),
			want: true,
		},
		// Private IPs are preferred over public IPs even if the public
		// IP is IPv6.
		{
			a:    al("192.168.0.1:555", 100*ms),
			b:    al("[2001::5]:123", 101*ms),
			want: true,
		},
		{
			a:    al("[2001::5]:123", 101*ms),
			b:    al("192.168.0.1:555", 100*ms),
			want: false,
		},

		// Link-local unicast addresses are preferred over other
		// private IPs, but not as much as localhost addresses.
		{
			a:    al("[fe80::ce8:474a:a27e:113b]:555", 101*ms),
			b:    al("[fd89:1a8a:8888:9999:aaaa:bbbb:cccc:dddd]:555", 100*ms),
			want: true,
		},
		{
			a:    al("[fe80::ce8:474a:a27e:113b]:555", 101*ms),
			b:    al("[::1]:555", 100*ms),
			want: false,
		},

		// Prefer non-Geneve over Geneve-encapsulated
		{
			a:    al(publicV4, 100*ms),
			b:    avl(publicV4, 1, 100*ms),
			want: true,
		},
		{
			a:    avl(publicV4, 1, 100*ms),
			b:    al(publicV4, 100*ms),
			want: false,
		},
	}
	for i, tt := range tests {
		got := betterAddr(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("[%d] betterAddr(%+v, %+v) = %v; want %v", i, tt.a, tt.b, got, tt.want)
			continue
		}
		gotBack := betterAddr(tt.b, tt.a)
		if got && gotBack {
			t.Errorf("[%d] betterAddr(%+v, %+v) and betterAddr(%+v, %+v) both unexpectedly true", i, tt.a, tt.b, tt.b, tt.a)
		}
	}

}

func epFromTyped(eps []tailcfg.Endpoint) (ret []netip.AddrPort) {
	for _, ep := range eps {
		ret = append(ret, ep.Addr)
	}
	return
}

func eps(s ...string) []netip.AddrPort {
	var eps []netip.AddrPort
	for _, ep := range s {
		eps = append(eps, netip.MustParseAddrPort(ep))
	}
	return eps
}

func TestStressOnNodeViewsUpdate(t *testing.T) {
	t.Parallel()

	conn := newTestConn(t)
	t.Cleanup(func() { conn.Close() })
	var buf tstest.MemLogger
	conn.logf = buf.Logf

	conn.SetPrivateKey(key.NewNode())

	const npeers = 5
	present := make([]bool, npeers)
	allPeers := make([]*tailcfg.Node, npeers)
	for i := range allPeers {
		present[i] = true
		allPeers[i] = &tailcfg.Node{
			ID:        tailcfg.NodeID(i) + 1,
			DiscoKey:  randDiscoKey(),
			Key:       randNodeKey(),
			Endpoints: eps(fmt.Sprintf("192.168.1.2:%d", i)),
		}
	}

	// Get a PRNG seed. If not provided, generate a new one to get extra coverage.
	seed, err := strconv.ParseUint(os.Getenv("TS_STRESS_SET_NETWORK_MAP_SEED"), 10, 64)
	if err != nil {
		var buf [8]byte
		crand.Read(buf[:])
		seed = binary.LittleEndian.Uint64(buf[:])
	}
	t.Logf("TS_STRESS_SET_NETWORK_MAP_SEED=%d", seed)
	prng := rand.New(rand.NewSource(int64(seed)))

	const iters = 1000 // approx 0.5s on an m1 mac
	for range iters {
		for j := 0; j < npeers; j++ {
			// Randomize which peers are present.
			if prng.Int()&1 == 0 {
				present[j] = !present[j]
			}
			// Randomize some peer disco keys and node keys.
			if prng.Int()&1 == 0 {
				allPeers[j].DiscoKey = randDiscoKey()
			}
			if prng.Int()&1 == 0 {
				allPeers[j].Key = randNodeKey()
			}
		}
		// Clone existing peers.
		peers := make([]*tailcfg.Node, 0, len(allPeers))
		for peerIdx, p := range allPeers {
			if present[peerIdx] {
				peers = append(peers, p.Clone())
			}
		}
		// Set the node views.
		conn.onNodeViewsUpdate(NodeViewsUpdate{
			Peers: nodeViews(peers),
		})
		// Check invariants.
		if err := conn.peerMap.validate(); err != nil {
			t.Error(err)
		}
	}
}

func randDiscoKey() (k key.DiscoPublic) { return key.NewDisco().Public() }
func randNodeKey() (k key.NodePublic)   { return key.NewNode().Public() }

// validate checks m for internal consistency and reports the first error encountered.
// It is used in tests only, so it doesn't need to be efficient.
func (m *peerMap) validate() error {
	seenEps := make(map[*endpoint]bool)
	for pub, pi := range m.byNodeKey {
		if got := pi.ep.publicKey; got != pub {
			return fmt.Errorf("byNodeKey[%v].publicKey = %v", pub, got)
		}
		if _, ok := seenEps[pi.ep]; ok {
			return fmt.Errorf("duplicate endpoint present: %v", pi.ep.publicKey)
		}
		seenEps[pi.ep] = true
		for addr := range pi.epAddrs {
			if got := m.byEpAddr[addr]; got != pi {
				return fmt.Errorf("m.byEpAddr[%v] = %v, want %v", addr, got, pi)
			}
		}
	}
	if len(m.byNodeKey) != len(m.byNodeID) {
		return fmt.Errorf("len(m.byNodeKey)=%d != len(m.byNodeID)=%d", len(m.byNodeKey), len(m.byNodeID))
	}
	for nodeID, pi := range m.byNodeID {
		ep := pi.ep
		if pi2, ok := m.byNodeKey[ep.publicKey]; !ok {
			return fmt.Errorf("nodeID %d in map with publicKey %v that's missing from map", nodeID, ep.publicKey)
		} else if pi2 != pi {
			return fmt.Errorf("nodeID %d in map with publicKey %v that points to different endpoint", nodeID, ep.publicKey)
		}
	}

	for addr, pi := range m.byEpAddr {
		if !pi.epAddrs.Contains(addr) {
			return fmt.Errorf("epAddrs[%v] for %v is false", addr, pi.ep.publicKey)
		}
		pi2 := m.byNodeKey[pi.ep.publicKey]
		if pi != pi2 {
			return fmt.Errorf("byNodeKey[%v]=%p doesn't match byEpAddr[%v]=%p", pi, pi, pi.ep.publicKey, pi2)
		}
	}

	publicToDisco := make(map[key.NodePublic]key.DiscoPublic)
	for disco, nodes := range m.nodesOfDisco {
		for pub := range nodes {
			if _, ok := m.byNodeKey[pub]; !ok {
				return fmt.Errorf("nodesOfDisco refers to public key %v, which is not present in byNodeKey", pub)
			}
			if _, ok := publicToDisco[pub]; ok {
				return fmt.Errorf("publicKey %v refers to multiple disco keys", pub)
			}
			publicToDisco[pub] = disco
		}
	}

	return nil
}

func TestBlockForeverConnUnblocks(t *testing.T) {
	c := newBlockForeverConn()
	done := make(chan error, 1)
	go func() {
		defer close(done)
		_, _, err := c.ReadFromUDPAddrPort(make([]byte, 1))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // give ReadFrom time to get blocked
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Errorf("got %v; want net.ErrClosed", err)
		}
	case <-timer.C:
		t.Fatal("timeout")
	}
}

func TestDiscoMagicMatches(t *testing.T) {
	// Convert our disco magic number into a uint32 and uint16 to test
	// against. We panic on an incorrect length here rather than try to be
	// generic with our BPF instructions below.
	//
	// Note that BPF uses network byte order (big-endian) when loading data
	// from a packet, so that is what we use to generate our magic numbers.
	if len(disco.Magic) != 6 {
		t.Fatalf("expected disco.Magic to be of length 6")
	}
	if m1 := binary.BigEndian.Uint32([]byte(disco.Magic[:4])); m1 != discoMagic1 {
		t.Errorf("first 4 bytes of disco magic don't match, got %v want %v", discoMagic1, m1)
	}
	if m2 := binary.BigEndian.Uint16([]byte(disco.Magic[4:6])); m2 != discoMagic2 {
		t.Errorf("last 2 bytes of disco magic don't match, got %v want %v", discoMagic2, m2)
	}
}

func TestRebindingUDPConn(t *testing.T) {
	// Test that RebindingUDPConn can be re-bound to different connection
	// types.
	c := RebindingUDPConn{}
	realConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer realConn.Close()
	c.setConnLocked(realConn.(nettype.PacketConn), "udp4", 1)
	c.setConnLocked(newBlockForeverConn(), "", 1)
}

// https://github.com/tailscale/tailscale/issues/6680: don't ignore
// onNodeViewsUpdate calls when there are no peers. (A too aggressive fast path was
// previously bailing out early, thinking there were no changes since all zero
// peers didn't change, but the node views has non-peer info in it too we shouldn't discard)
func TestOnNodeViewsUpdateWithNoPeers(t *testing.T) {
	var c Conn
	knobs := &controlknobs.Knobs{}
	c.logf = logger.Discard
	c.controlKnobs = knobs // TODO(bradfitz): move silent disco bool to controlknobs

	for i := 1; i <= 3; i++ {
		v := !debugEnableSilentDisco()
		envknob.Setenv("TS_DEBUG_ENABLE_SILENT_DISCO", fmt.Sprint(v))
		nv := NodeViewsUpdate{}
		c.onNodeViewsUpdate(nv)
		t.Logf("ptr %d: %p", i, nv)
		if c.lastFlags.heartbeatDisabled != v {
			t.Fatalf("call %d: didn't store netmap", i)
		}
	}
}

// newWireguard starts up a new wireguard-go device attached to a test tun, and
// returns the device, tun and endpoint port. To add peers call device.IpcSet with UAPI instructions.
func newWireguard(t *testing.T, uapi string, aips []netip.Prefix) (*device.Device, *tuntest.ChannelTUN, uint16) {
	wgtun := tuntest.NewChannelTUN()
	wglogf := func(f string, args ...any) {
		t.Logf("wg-go: "+f, args...)
	}
	wglog := device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   wglogf,
	}
	wgdev := wgcfg.NewDevice(wgtun.TUN(), wgconn.NewDefaultBind(), &wglog)

	if err := wgdev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}

	if err := wgdev.Up(); err != nil {
		t.Fatal(err)
	}

	var port uint16
	s, err := wgdev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if k == "listen_port" {
			p, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				panic(err)
			}
			port = uint16(p)
			break
		}
	}

	return wgdev, wgtun, port
}

func TestIsWireGuardOnlyPeer(t *testing.T) {
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	tskey := key.NewNode()
	tsaip := netip.MustParsePrefix("100.111.222.111/32")

	wgkey := key.NewNode()
	wgaip := netip.MustParsePrefix("100.222.111.222/32")

	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s\n\n",
		wgkey.UntypedHexString(), tskey.Public().UntypedHexString(), tsaip.String())
	wgdev, wgtun, port := newWireguard(t, uapi, []netip.Prefix{wgaip})
	defer wgdev.Close()
	wgEp := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)

	m := newMagicStackWithKey(t, t.Logf, localhostListener{}, derpMap, tskey)
	defer m.Close()

	nm := &netmap.NetworkMap{
		Name:       "ts",
		PrivateKey: m.privateKey,
		NodeKey:    m.privateKey.Public(),
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{tsaip},
		}).View(),
		Peers: nodeViews([]*tailcfg.Node{
			{
				ID:              1,
				Key:             wgkey.Public(),
				Endpoints:       []netip.AddrPort{wgEp},
				IsWireGuardOnly: true,
				Addresses:       []netip.Prefix{wgaip},
				AllowedIPs:      []netip.Prefix{wgaip},
			},
		}),
	}
	nv := NodeViewsUpdate{
		SelfNode: nm.SelfNode,
		Peers:    nm.Peers,
	}
	m.conn.onNodeViewsUpdate(nv)

	cfg, err := nmcfg.WGCfg(nm, t.Logf, netmap.AllowSubnetRoutes, "")
	if err != nil {
		t.Fatal(err)
	}
	m.Reconfig(cfg)

	pbuf := tuntest.Ping(wgaip.Addr(), tsaip.Addr())
	m.tun.Outbound <- pbuf

	select {
	case p := <-wgtun.Inbound:
		if !bytes.Equal(p, pbuf) {
			t.Errorf("got unexpected packet: %x", p)
		}
	case <-time.After(time.Second):
		t.Fatal("no packet after 1s")
	}
}

func TestIsWireGuardOnlyPeerWithMasquerade(t *testing.T) {
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	tskey := key.NewNode()
	tsaip := netip.MustParsePrefix("100.111.222.111/32")

	wgkey := key.NewNode()
	wgaip := netip.MustParsePrefix("10.64.0.1/32")

	// the ip that the wireguard peer has in allowed ips and expects as a masq source
	masqip := netip.MustParsePrefix("10.64.0.2/32")

	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s\n\n",
		wgkey.UntypedHexString(), tskey.Public().UntypedHexString(), masqip.String())
	wgdev, wgtun, port := newWireguard(t, uapi, []netip.Prefix{wgaip})
	defer wgdev.Close()
	wgEp := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)

	m := newMagicStackWithKey(t, t.Logf, localhostListener{}, derpMap, tskey)
	defer m.Close()

	nm := &netmap.NetworkMap{
		Name:       "ts",
		PrivateKey: m.privateKey,
		NodeKey:    m.privateKey.Public(),
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{tsaip},
		}).View(),
		Peers: nodeViews([]*tailcfg.Node{
			{
				ID:                            1,
				Key:                           wgkey.Public(),
				Endpoints:                     []netip.AddrPort{wgEp},
				IsWireGuardOnly:               true,
				Addresses:                     []netip.Prefix{wgaip},
				AllowedIPs:                    []netip.Prefix{wgaip},
				SelfNodeV4MasqAddrForThisPeer: ptr.To(masqip.Addr()),
			},
		}),
	}
	nv := NodeViewsUpdate{
		SelfNode: nm.SelfNode,
		Peers:    nm.Peers,
	}
	m.conn.onNodeViewsUpdate(nv)

	cfg, err := nmcfg.WGCfg(nm, t.Logf, netmap.AllowSubnetRoutes, "")
	if err != nil {
		t.Fatal(err)
	}
	m.Reconfig(cfg)

	pbuf := tuntest.Ping(wgaip.Addr(), tsaip.Addr())
	m.tun.Outbound <- pbuf

	select {
	case p := <-wgtun.Inbound:

		// TODO(raggi): move to a bytes.Equal based test later, once
		// tuntest.Ping produces correct checksums!

		var pkt packet.Parsed
		pkt.Decode(p)
		if pkt.ICMP4Header().Type != packet.ICMP4EchoRequest {
			t.Fatalf("unexpected packet: %x", p)
		}
		if pkt.Src.Addr() != masqip.Addr() {
			t.Fatalf("bad source IP, got %s, want %s", pkt.Src.Addr(), masqip.Addr())
		}
		if pkt.Dst.Addr() != wgaip.Addr() {
			t.Fatalf("bad source IP, got %s, want %s", pkt.Src.Addr(), masqip.Addr())
		}
	case <-time.After(time.Second):
		t.Fatal("no packet after 1s")
	}
}

// applyNetworkMap is a test helper that sets the network map and
// configures WG.
func applyNetworkMap(t *testing.T, m *magicStack, nm *netmap.NetworkMap) {
	t.Helper()
	nv := NodeViewsUpdate{
		SelfNode: nm.SelfNode,
		Peers:    nm.Peers,
	}
	m.conn.onNodeViewsUpdate(nv)
	// Make sure we can't use v6 to avoid test failures.
	m.conn.noV6.Store(true)

	// Turn the network map into a wireguard config (for the tailscale internal wireguard device).
	cfg, err := nmcfg.WGCfg(nm, t.Logf, netmap.AllowSubnetRoutes, "")
	if err != nil {
		t.Fatal(err)
	}
	// Apply the wireguard config to the tailscale internal wireguard device.
	if err := m.Reconfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestIsWireGuardOnlyPickEndpointByPing(t *testing.T) {
	t.Skip("This test is flaky; see https://github.com/tailscale/tailscale/issues/8037")

	clock := &tstest.Clock{}
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	// Create a TS client.
	tskey := key.NewNode()
	tsaip := netip.MustParsePrefix("100.111.222.111/32")

	// Create a WireGuard only client.
	wgkey := key.NewNode()
	wgaip := netip.MustParsePrefix("100.222.111.222/32")

	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s\n\n",
		wgkey.UntypedHexString(), tskey.Public().UntypedHexString(), tsaip.String())

	wgdev, wgtun, port := newWireguard(t, uapi, []netip.Prefix{wgaip})
	defer wgdev.Close()
	wgEp := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	wgEp2 := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), port)

	m := newMagicStackWithKey(t, t.Logf, localhostListener{}, derpMap, tskey)
	defer m.Close()

	pr := newPingResponder(t)
	// Get a destination address which includes a port, so that UDP packets flow
	// to the correct place, the mockPinger will use this to direct port-less
	// pings to this place.
	pingDest := pr.LocalAddr()

	// Create and start the pinger that is used for the
	// wireguard only endpoint pings
	p, closeP := mockPinger(t, clock, pingDest)
	defer closeP()
	m.conn.wgPinger.Set(p)

	// Create an IPv6 endpoint which should not receive any traffic.
	v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	badEpRecv := make(chan []byte)
	go func() {
		defer v6.Close()
		for {
			b := make([]byte, 1500)
			n, _, err := v6.ReadFrom(b)
			if err != nil {
				close(badEpRecv)
				return
			}
			badEpRecv <- b[:n]
		}
	}()
	wgEpV6 := netip.MustParseAddrPort(v6.LocalAddr().String())

	nm := &netmap.NetworkMap{
		Name:       "ts",
		PrivateKey: m.privateKey,
		NodeKey:    m.privateKey.Public(),
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{tsaip},
		}).View(),
		Peers: nodeViews([]*tailcfg.Node{
			{
				Key:             wgkey.Public(),
				Endpoints:       []netip.AddrPort{wgEp, wgEp2, wgEpV6},
				IsWireGuardOnly: true,
				Addresses:       []netip.Prefix{wgaip},
				AllowedIPs:      []netip.Prefix{wgaip},
			},
		}),
	}

	applyNetworkMap(t, m, nm)

	buf := tuntest.Ping(wgaip.Addr(), tsaip.Addr())
	m.tun.Outbound <- buf

	select {
	case p := <-wgtun.Inbound:
		if !bytes.Equal(p, buf) {
			t.Errorf("got unexpected packet: %x", p)
		}
	case <-badEpRecv:
		t.Fatal("got packet on bad endpoint")
	case <-time.After(5 * time.Second):
		t.Fatal("no packet after 1s")
	}

	pi, ok := m.conn.peerMap.byNodeKey[wgkey.Public()]
	if !ok {
		t.Fatal("wgkey doesn't exist in peer map")
	}

	// Check that we got a valid address set on the first send - this
	// will be randomly selected, but because we have noV6 set to true,
	// it will be the IPv4 address.
	if !pi.ep.bestAddr.ap.Addr().IsValid() {
		t.Fatal("bestaddr was nil")
	}

	if pi.ep.trustBestAddrUntil.Before(mono.Now().Add(14 * time.Second)) {
		t.Errorf("trustBestAddrUntil time wasn't set to 15 seconds in the future: got %v", pi.ep.trustBestAddrUntil)
	}

	for ipp, state := range pi.ep.endpointState {
		if ipp == wgEp {
			if len(state.recentPongs) != 1 {
				t.Errorf("IPv4 address did not have a recentPong entry: got %v, want %v", len(state.recentPongs), 1)
			}
			// Set the latency extremely low so we choose this endpoint during the next
			// addrForSendLocked call.
			state.recentPongs[state.recentPong].latency = time.Nanosecond
		}

		if ipp == wgEp2 {
			if len(state.recentPongs) != 1 {
				t.Errorf("IPv4 address did not have a recentPong entry: got %v, want %v", len(state.recentPongs), 1)
			}
			// Set the latency extremely high so we dont choose endpoint during the next
			// addrForSendLocked call.
			state.recentPongs[state.recentPong].latency = time.Second
		}

		if ipp == wgEpV6 && len(state.recentPongs) != 0 {
			t.Fatal("IPv6 should not have recentPong: IPv6 is not useable")
		}
	}

	// Set trustBestAddrUnitl to now, so addrForSendLocked goes through the
	// latency selection flow.
	pi.ep.trustBestAddrUntil = mono.Now().Add(-time.Second)

	buf = tuntest.Ping(wgaip.Addr(), tsaip.Addr())
	m.tun.Outbound <- buf

	select {
	case p := <-wgtun.Inbound:
		if !bytes.Equal(p, buf) {
			t.Errorf("got unexpected packet: %x", p)
		}
	case <-badEpRecv:
		t.Fatal("got packet on bad endpoint")
	case <-time.After(5 * time.Second):
		t.Fatal("no packet after 1s")
	}

	// Check that we have responded to a WireGuard only ping twice.
	if pr.responseCount != 2 {
		t.Fatal("pingresponder response count was not 2", pr.responseCount)
	}

	pi, ok = m.conn.peerMap.byNodeKey[wgkey.Public()]
	if !ok {
		t.Fatal("wgkey doesn't exist in peer map")
	}

	if !pi.ep.bestAddr.ap.Addr().IsValid() {
		t.Error("no bestAddr address was set")
	}

	if pi.ep.bestAddr.ap.Addr() != wgEp.Addr() {
		t.Errorf("bestAddr was not set to the expected IPv4 address: got %v, want %v", pi.ep.bestAddr.ap.Addr().String(), wgEp.Addr())
	}

	if pi.ep.trustBestAddrUntil.IsZero() {
		t.Fatal("trustBestAddrUntil was not set")
	}

	if pi.ep.trustBestAddrUntil.Before(mono.Now().Add(55 * time.Minute)) {
		// Set to 55 minutes incase of sloooow tests.
		t.Errorf("trustBestAddrUntil time wasn't set to an hour in the future: got %v", pi.ep.trustBestAddrUntil)
	}
}

// udpingPacketConn will convert potentially ICMP destination addrs to UDP
// destination addrs in WriteTo so that a test that is intending to send ICMP
// traffic will instead send UDP traffic, without the higher level Pinger being
// aware of this difference.
type udpingPacketConn struct {
	net.PacketConn
	// destPort will be configured by the test to be the peer expected to respond to a ping.
	destPort uint16
}

func (u *udpingPacketConn) WriteTo(body []byte, dest net.Addr) (int, error) {
	switch d := dest.(type) {
	case *net.IPAddr:
		udpAddr := &net.UDPAddr{
			IP:   d.IP,
			Port: int(u.destPort),
			Zone: d.Zone,
		}
		return u.PacketConn.WriteTo(body, udpAddr)
	}
	return 0, fmt.Errorf("unimplemented udpingPacketConn for %T", dest)
}

type mockListenPacketer struct {
	conn4 net.PacketConn
	conn6 net.PacketConn
}

func (mlp *mockListenPacketer) ListenPacket(ctx context.Context, typ string, addr string) (net.PacketConn, error) {
	switch typ {
	case "ip4:icmp":
		return mlp.conn4, nil
	case "ip6:icmp":
		return mlp.conn6, nil
	}
	return nil, fmt.Errorf("unimplemented ListenPacketForTesting for %s", typ)
}

func mockPinger(t *testing.T, clock *tstest.Clock, dest net.Addr) (*ping.Pinger, func()) {
	ctx := context.Background()

	dIPP := netip.MustParseAddrPort(dest.String())
	// In tests, we use UDP so that we can test without being root; this
	// doesn't matter because we mock out the ICMP reply below to be a real
	// ICMP echo reply packet.
	conn4, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket: %v", err)
	}
	conn6, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		t.Fatalf("net.ListenPacket: %v", err)
	}

	conn4 = &udpingPacketConn{
		PacketConn: conn4,
		destPort:   dIPP.Port(),
	}

	conn6 = &udpingPacketConn{
		PacketConn: conn6,
		destPort:   dIPP.Port(),
	}

	p := ping.New(ctx, t.Logf, &mockListenPacketer{conn4: conn4, conn6: conn6})

	done := func() {
		if err := p.Close(); err != nil {
			t.Errorf("error on close: %v", err)
		}
	}

	return p, done
}

type pingResponder struct {
	net.PacketConn
	running       atomic.Bool
	responseCount int
}

func (p *pingResponder) start() {
	buf := make([]byte, 1500)
	for p.running.Load() {
		n, addr, err := p.PacketConn.ReadFrom(buf)
		if err != nil {
			return
		}

		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			panic("got a non-ICMP message:" + fmt.Sprintf("%x", m))
		}

		r := icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Code: m.Code,
			Body: m.Body,
		}

		b, err := r.Marshal(nil)
		if err != nil {
			panic(err)
		}

		if _, err := p.PacketConn.WriteTo(b, addr); err != nil {
			panic(err)
		}
		p.responseCount++
	}
}

func (p *pingResponder) stop() {
	p.running.Store(false)
	p.Close()
}

func newPingResponder(t *testing.T) *pingResponder {
	t.Helper()
	// global binds should be both IPv4 and IPv6 (if our test platforms don't,
	// we might need to bind two sockets instead)
	conn, err := net.ListenPacket("udp", ":")
	if err != nil {
		t.Fatal(err)
	}
	pr := &pingResponder{PacketConn: conn}
	pr.running.Store(true)
	go pr.start()
	t.Cleanup(pr.stop)
	return pr
}

func TestAddrForSendLockedForWireGuardOnly(t *testing.T) {
	testTime := mono.Now()
	secondPingTime := testTime.Add(10 * time.Second)

	type endpointDetails struct {
		addrPort netip.AddrPort
		latency  time.Duration
	}

	wgTests := []struct {
		name             string
		sendInitialPing  bool
		validAddr        bool
		sendFollowUpPing bool
		pingTime         mono.Time
		ep               []endpointDetails
		want             epAddr
	}{
		{
			name:             "no endpoints",
			sendInitialPing:  false,
			validAddr:        false,
			sendFollowUpPing: false,
			pingTime:         testTime,
			ep:               []endpointDetails{},
			want:             epAddr{},
		},
		{
			name:             "singular endpoint does not request ping",
			sendInitialPing:  false,
			validAddr:        true,
			sendFollowUpPing: false,
			pingTime:         testTime,
			ep: []endpointDetails{
				{
					addrPort: netip.MustParseAddrPort("1.1.1.1:111"),
					latency:  100 * time.Millisecond,
				},
			},
			want: epAddr{ap: netip.MustParseAddrPort("1.1.1.1:111")},
		},
		{
			name:             "ping sent within wireguardPingInterval should not request ping",
			sendInitialPing:  true,
			validAddr:        true,
			sendFollowUpPing: false,
			pingTime:         testTime.Add(7 * time.Second),
			ep: []endpointDetails{
				{
					addrPort: netip.MustParseAddrPort("1.1.1.1:111"),
					latency:  100 * time.Millisecond,
				},
				{
					addrPort: netip.MustParseAddrPort("[2345:0425:2CA1:0000:0000:0567:5673:23b5]:222"),
					latency:  2000 * time.Millisecond,
				},
			},
			want: epAddr{ap: netip.MustParseAddrPort("1.1.1.1:111")},
		},
		{
			name:             "ping sent outside of wireguardPingInterval should request ping",
			sendInitialPing:  true,
			validAddr:        true,
			sendFollowUpPing: true,
			pingTime:         testTime.Add(3 * time.Second),
			ep: []endpointDetails{
				{
					addrPort: netip.MustParseAddrPort("1.1.1.1:111"),
					latency:  100 * time.Millisecond,
				},
				{
					addrPort: netip.MustParseAddrPort("[2345:0425:2CA1:0000:0000:0567:5673:23b5]:222"),
					latency:  150 * time.Millisecond,
				},
			},
			want: epAddr{ap: netip.MustParseAddrPort("1.1.1.1:111")},
		},
		{
			name:             "choose lowest latency for useable IPv4 and IPv6",
			sendInitialPing:  true,
			validAddr:        true,
			sendFollowUpPing: false,
			pingTime:         secondPingTime,
			ep: []endpointDetails{
				{
					addrPort: netip.MustParseAddrPort("1.1.1.1:111"),
					latency:  100 * time.Millisecond,
				},
				{
					addrPort: netip.MustParseAddrPort("[2345:0425:2CA1:0000:0000:0567:5673:23b5]:222"),
					latency:  10 * time.Millisecond,
				},
			},
			want: epAddr{ap: netip.MustParseAddrPort("[2345:0425:2CA1:0000:0000:0567:5673:23b5]:222")},
		},
		{
			name:             "choose IPv6 address when latency is the same for v4 and v6",
			sendInitialPing:  true,
			validAddr:        true,
			sendFollowUpPing: false,
			pingTime:         secondPingTime,
			ep: []endpointDetails{
				{
					addrPort: netip.MustParseAddrPort("1.1.1.1:111"),
					latency:  100 * time.Millisecond,
				},
				{
					addrPort: netip.MustParseAddrPort("[1::1]:567"),
					latency:  100 * time.Millisecond,
				},
			},
			want: epAddr{ap: netip.MustParseAddrPort("[1::1]:567")},
		},
	}

	for _, test := range wgTests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := &endpoint{
				isWireguardOnly: true,
				endpointState:   map[netip.AddrPort]*endpointState{},
				c: &Conn{
					logf: t.Logf,
					noV4: atomic.Bool{},
					noV6: atomic.Bool{},
				},
			}

			for _, epd := range test.ep {
				endpoint.endpointState[epd.addrPort] = &endpointState{}
			}
			udpAddr, _, shouldPing := endpoint.addrForSendLocked(testTime)
			if udpAddr.ap.IsValid() != test.validAddr {
				t.Errorf("udpAddr validity is incorrect; got %v, want %v", udpAddr.ap.IsValid(), test.validAddr)
			}
			if shouldPing != test.sendInitialPing {
				t.Errorf("addrForSendLocked did not indiciate correct ping state; got %v, want %v", shouldPing, test.sendInitialPing)
			}

			// Update the endpointState to simulate a ping having been
			// sent and a pong received.
			for _, epd := range test.ep {
				state, ok := endpoint.endpointState[epd.addrPort]
				if !ok {
					t.Errorf("addr does not exist in endpoint state map")
				}
				state.lastPing = test.pingTime

				latency, ok := state.latencyLocked()
				if ok {
					t.Errorf("latency was set for %v: %v", epd.addrPort, latency)
				}
				state.recentPongs = append(state.recentPongs, pongReply{
					latency: epd.latency,
				})
				state.recentPong = 0
			}

			udpAddr, _, shouldPing = endpoint.addrForSendLocked(secondPingTime)
			if udpAddr != test.want {
				t.Errorf("udpAddr returned is not expected: got %v, want %v", udpAddr, test.want)
			}
			if shouldPing != test.sendFollowUpPing {
				t.Errorf("addrForSendLocked did not indiciate correct ping state; got %v, want %v", shouldPing, test.sendFollowUpPing)
			}
			if endpoint.bestAddr.epAddr != test.want {
				t.Errorf("bestAddr.epAddr is not as expected: got %v, want %v", endpoint.bestAddr.epAddr, test.want)
			}
		})
	}
}

func TestAddrForPingSizeLocked(t *testing.T) {
	testTime := mono.Now()

	validUdpAddr := netip.MustParseAddrPort("1.1.1.1:111")
	validDerpAddr := netip.MustParseAddrPort("2.2.2.2:222")

	pingTests := []struct {
		desc            string
		size            int           // size of ping payload
		mtu             tstun.WireMTU // The MTU of the path to bestAddr, if any
		bestAddr        bool          // If the endpoint should have a valid bestAddr
		bestAddrTrusted bool          // If the bestAddr has not yet expired
		wantUDP         bool          // Non-zero UDP addr means send to UDP; zero means start discovery
		wantDERP        bool          // Non-zero DERP addr means send to DERP
	}{
		{
			desc:            "ping_size_0_and_invalid_UDP_addr_should_start_discovery_and_send_to_DERP",
			size:            0,
			bestAddr:        false,
			bestAddrTrusted: false,
			wantUDP:         false,
			wantDERP:        true,
		},
		{
			desc:            "ping_size_0_and_valid_trusted_UDP_addr_should_send_to_UDP_and_not_send_to_DERP",
			size:            0,
			bestAddr:        true,
			bestAddrTrusted: true,
			wantUDP:         true,
			wantDERP:        false,
		},
		{
			desc:            "ping_size_0_and_valid_but_expired_UDP_addr_should_send_to_both_UDP_and_DERP",
			size:            0,
			bestAddr:        true,
			bestAddrTrusted: false,
			wantUDP:         true,
			wantDERP:        true,
		},
		{
			desc:            "ping_size_too_big_for_trusted_UDP_addr_should_start_discovery_and_send_to_DERP",
			size:            pktLenToPingSize(1501, validUdpAddr.Addr().Is6()),
			mtu:             1500,
			bestAddr:        true,
			bestAddrTrusted: true,
			wantUDP:         false,
			wantDERP:        true,
		},
		{
			desc:            "ping_size_too_big_for_untrusted_UDP_addr_should_start_discovery_and_send_to_DERP",
			size:            pktLenToPingSize(1501, validUdpAddr.Addr().Is6()),
			mtu:             1500,
			bestAddr:        true,
			bestAddrTrusted: false,
			wantUDP:         false,
			wantDERP:        true,
		},
		{
			desc:            "ping_size_small_enough_for_trusted_UDP_addr_should_send_to_UDP_and_not_DERP",
			size:            pktLenToPingSize(1500, validUdpAddr.Addr().Is6()),
			mtu:             1500,
			bestAddr:        true,
			bestAddrTrusted: true,
			wantUDP:         true,
			wantDERP:        false,
		},
		{
			desc:            "ping_size_small_enough_for_untrusted_UDP_addr_should_send_to_UDP_and_DERP",
			size:            pktLenToPingSize(1500, validUdpAddr.Addr().Is6()),
			mtu:             1500,
			bestAddr:        true,
			bestAddrTrusted: false,
			wantUDP:         true,
			wantDERP:        true,
		},
	}

	for _, test := range pingTests {
		t.Run(test.desc, func(t *testing.T) {
			bestAddr := addrQuality{wireMTU: test.mtu}
			if test.bestAddr {
				bestAddr.epAddr.ap = validUdpAddr
			}
			ep := &endpoint{
				derpAddr: validDerpAddr,
				bestAddr: bestAddr,
			}
			if test.bestAddrTrusted {
				ep.trustBestAddrUntil = testTime.Add(1 * time.Second)
			}

			udpAddr, derpAddr := ep.addrForPingSizeLocked(testTime, test.size)

			if test.wantUDP && !udpAddr.ap.IsValid() {
				t.Errorf("%s: udpAddr returned is not valid, won't be sent to UDP address", test.desc)
			}
			if !test.wantUDP && udpAddr.ap.IsValid() {
				t.Errorf("%s: udpAddr returned is valid, discovery will not start", test.desc)
			}
			if test.wantDERP && !derpAddr.IsValid() {
				t.Errorf("%s: derpAddr returned is not valid, won't be sent to DERP", test.desc)
			}
			if !test.wantDERP && derpAddr.IsValid() {
				t.Errorf("%s: derpAddr returned is valid, will be sent to DERP", test.desc)
			}
		})
	}
}

func TestMaybeSetNearestDERP(t *testing.T) {
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "t1",
						RegionID: 1,
						HostName: "test-node.unused",
						IPv4:     "127.0.0.1",
						IPv6:     "none",
					},
				},
			},
			21: {
				RegionID:   21,
				RegionCode: "tor",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "21b",
						RegionID: 21,
						HostName: "tor.test-node.unused",
						IPv4:     "127.0.0.1",
						IPv6:     "none",
					},
				},
			},
			31: {
				RegionID:   31,
				RegionCode: "fallback",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "31b",
						RegionID: 31,
						HostName: "fallback.test-node.unused",
						IPv4:     "127.0.0.1",
						IPv6:     "none",
					},
				},
			},
		},
	}

	// Ensure that our fallback code always picks a deterministic value.
	tstest.Replace(t, &pickDERPFallbackForTests, func() int { return 31 })

	// Actually test this code path.
	tstest.Replace(t, &checkControlHealthDuringNearestDERPInTests, true)

	testCases := []struct {
		name               string
		old                int
		reportDERP         int
		connectedToControl bool
		want               int
	}{
		{
			name:               "connected_with_report_derp",
			old:                1,
			reportDERP:         21,
			connectedToControl: true,
			want:               21,
		},
		{
			name:               "not_connected_with_report_derp",
			old:                1,
			reportDERP:         21,
			connectedToControl: false,
			want:               1, // no change
		},
		{
			name:               "not_connected_with_report_derp_and_no_current",
			old:                0,     // no current DERP
			reportDERP:         21,    // have new DERP
			connectedToControl: false, // not connected...
			want:               21,    // ... but want to change to new DERP
		},
		{
			name:               "not_connected_with_fallback_and_no_current",
			old:                0,     // no current DERP
			reportDERP:         0,     // no new DERP
			connectedToControl: false, // not connected...
			want:               31,    // ... but we fallback to deterministic value
		},
		{
			name:               "connected_no_derp",
			old:                1,
			reportDERP:         0,
			connectedToControl: true,
			want:               1, // no change
		},
		{
			name:               "connected_no_derp_fallback",
			old:                0,
			reportDERP:         0,
			connectedToControl: true,
			want:               31, // deterministic fallback
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ht := health.NewTracker(eventbustest.NewBus(t))
			c := newConn(t.Logf)
			c.myDerp = tt.old
			c.derpMap = derpMap
			c.health = ht

			report := &netcheck.Report{PreferredDERP: tt.reportDERP}

			oldConnected := ht.GetInPollNetMap()
			if tt.connectedToControl != oldConnected {
				if tt.connectedToControl {
					ht.GotStreamedMapResponse()
					t.Cleanup(ht.SetOutOfPollNetMap)
				} else {
					ht.SetOutOfPollNetMap()
					t.Cleanup(ht.GotStreamedMapResponse)
				}
			}

			got := c.maybeSetNearestDERP(report)
			if got != tt.want {
				t.Errorf("got new DERP region %d, want %d", got, tt.want)
			}
		})
	}
}

func TestShouldRebind(t *testing.T) {
	tests := []struct {
		err    error
		ok     bool
		reason string
	}{
		{nil, false, ""},
		{io.EOF, false, ""},
		{io.ErrUnexpectedEOF, false, ""},
		{io.ErrShortBuffer, false, ""},
		{&net.OpError{Err: syscall.EPERM}, true, "operation-not-permitted"},
		{&net.OpError{Err: syscall.EPIPE}, true, "broken-pipe"},
		{&net.OpError{Err: syscall.ENOTCONN}, true, "broken-pipe"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s-%v", tt.err, tt.ok), func(t *testing.T) {
			if got, reason := shouldRebind(tt.err); got != tt.ok || reason != tt.reason {
				t.Errorf("errShouldRebind(%v) = %v, %q; want %v, %q", tt.err, got, reason, tt.ok, tt.reason)
			}
		})
	}
}

func TestMaybeRebindOnError(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	var rebindErrs []error
	if runtime.GOOS != "plan9" {
		rebindErrs = append(rebindErrs,
			&net.OpError{Err: syscall.EPERM},
			&net.OpError{Err: syscall.EPIPE},
			&net.OpError{Err: syscall.ENOTCONN},
		)
	}

	for _, rebindErr := range rebindErrs {
		t.Run(fmt.Sprintf("rebind-%s", rebindErr), func(t *testing.T) {
			conn := newTestConn(t)
			defer conn.Close()

			before := metricRebindCalls.Value()
			conn.maybeRebindOnError(rebindErr)
			after := metricRebindCalls.Value()
			if before+1 != after {
				t.Errorf("should rebind on %#v", rebindErr)
			}
		})
	}

	t.Run("no-frequent-rebind", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			if runtime.GOOS != "plan9" {
				err := fmt.Errorf("outer err: %w", syscall.EPERM)
				conn := newTestConn(t)
				defer conn.Close()
				lastRebindTime := time.Now().Add(-1 * time.Second)
				conn.lastErrRebind.Store(lastRebindTime)
				before := metricRebindCalls.Value()
				conn.maybeRebindOnError(err)
				after := metricRebindCalls.Value()
				if before != after {
					t.Errorf("should not rebind within 5 seconds of last")
				}

				// ensure that rebinds are performed and store an updated last
				// rebind time.
				time.Sleep(6 * time.Second)

				conn.maybeRebindOnError(err)
				newTime := conn.lastErrRebind.Load()
				if newTime == lastRebindTime {
					t.Errorf("expected a rebind to occur")
				}
				if newTime.Sub(lastRebindTime) < 5*time.Second {
					t.Errorf("expected at least 5 seconds between %s and %s", lastRebindTime, newTime)
				}
			}

		})
	})
}

func newTestConnAndRegistry(t *testing.T) (*Conn, *usermetric.Registry, func()) {
	t.Helper()
	bus := eventbus.New()
	netMon := must.Get(netmon.New(bus, t.Logf))

	reg := new(usermetric.Registry)

	conn := must.Get(NewConn(Options{
		DisablePortMapper: true,
		Logf:              t.Logf,
		NetMon:            netMon,
		EventBus:          bus,
		Metrics:           reg,
	}))

	return conn, reg, func() {
		bus.Close()
		netMon.Close()
		conn.Close()
	}
}

func TestNetworkSendErrors(t *testing.T) {
	t.Run("network-down", func(t *testing.T) {
		// TODO(alexc): This test case fails on Windows because it never
		// successfully sends the first packet:
		//
		// 	   expected successful Send, got err: "write udp4 0.0.0.0:57516->127.0.0.1:9999:
		// 	   wsasendto: The requested address is not valid in its context."
		//
		// It would be nice to run this test on Windows, but I was already
		// on a side quest and it was unclear if this test has ever worked
		// correctly on Windows.
		if runtime.GOOS == "windows" {
			t.Skipf("skipping on %s", runtime.GOOS)
		}

		conn, reg, close := newTestConnAndRegistry(t)
		defer close()

		buffs := [][]byte{{00, 00, 00, 00, 00, 00, 00, 00}}
		ep := &lazyEndpoint{
			src: epAddr{ap: netip.MustParseAddrPort("127.0.0.1:9999")},
		}
		offset := 8

		// Check this is a valid payload to send when the network is up
		conn.SetNetworkUp(true)
		if err := conn.Send(buffs, ep, offset); err != nil {
			t.Errorf("expected successful Send, got err: %q", err)
		}

		// Now we know the payload would be sent if the network is up,
		// send it again when the network is down
		conn.SetNetworkUp(false)
		err := conn.Send(buffs, ep, offset)
		if err == nil {
			t.Error("expected error, got nil")
		}
		resp := httptest.NewRecorder()
		reg.Handler(resp, new(http.Request))
		if !strings.Contains(resp.Body.String(), `tailscaled_outbound_dropped_packets_total{reason="error"} 1`) {
			t.Errorf("expected NetworkDown to increment packet dropped metric; got %q", resp.Body.String())
		}
	})

	t.Run("invalid-payload", func(t *testing.T) {
		conn, reg, close := newTestConnAndRegistry(t)
		defer close()

		conn.SetNetworkUp(false)
		err := conn.Send([][]byte{{00}}, &lazyEndpoint{}, 0)
		if err == nil {
			t.Error("expected error, got nil")
		}
		resp := httptest.NewRecorder()
		reg.Handler(resp, new(http.Request))
		if !strings.Contains(resp.Body.String(), `tailscaled_outbound_dropped_packets_total{reason="error"} 1`) {
			t.Errorf("expected invalid payload to increment packet dropped metric; got %q", resp.Body.String())
		}
	})
}

func Test_packetLooksLike(t *testing.T) {
	discoPub := key.DiscoPublicFromRaw32(mem.B([]byte{1: 1, 30: 30, 31: 31}))
	nakedDisco := make([]byte, 0, 512)
	nakedDisco = append(nakedDisco, disco.Magic...)
	nakedDisco = discoPub.AppendTo(nakedDisco)

	geneveEncapDisco := make([]byte, packet.GeneveFixedHeaderLength+len(nakedDisco))
	gh := packet.GeneveHeader{
		Version:  0,
		Protocol: packet.GeneveProtocolDisco,
		Control:  true,
	}
	gh.VNI.Set(1)
	err := gh.Encode(geneveEncapDisco)
	if err != nil {
		t.Fatal(err)
	}
	copy(geneveEncapDisco[packet.GeneveFixedHeaderLength:], nakedDisco)

	nakedWireGuardInitiation := make([]byte, len(geneveEncapDisco))
	binary.LittleEndian.PutUint32(nakedWireGuardInitiation, device.MessageInitiationType)
	nakedWireGuardResponse := make([]byte, len(geneveEncapDisco))
	binary.LittleEndian.PutUint32(nakedWireGuardResponse, device.MessageResponseType)
	nakedWireGuardCookieReply := make([]byte, len(geneveEncapDisco))
	binary.LittleEndian.PutUint32(nakedWireGuardCookieReply, device.MessageCookieReplyType)
	nakedWireGuardTransport := make([]byte, len(geneveEncapDisco))
	binary.LittleEndian.PutUint32(nakedWireGuardTransport, device.MessageTransportType)

	geneveEncapWireGuard := make([]byte, packet.GeneveFixedHeaderLength+len(nakedWireGuardInitiation))
	gh = packet.GeneveHeader{
		Version:  0,
		Protocol: packet.GeneveProtocolWireGuard,
		Control:  true,
	}
	gh.VNI.Set(1)
	err = gh.Encode(geneveEncapWireGuard)
	if err != nil {
		t.Fatal(err)
	}
	copy(geneveEncapWireGuard[packet.GeneveFixedHeaderLength:], nakedWireGuardInitiation)

	geneveEncapDiscoNonZeroGeneveVersion := make([]byte, packet.GeneveFixedHeaderLength+len(nakedDisco))
	gh = packet.GeneveHeader{
		Version:  1,
		Protocol: packet.GeneveProtocolDisco,
		Control:  true,
	}
	gh.VNI.Set(1)
	err = gh.Encode(geneveEncapDiscoNonZeroGeneveVersion)
	if err != nil {
		t.Fatal(err)
	}
	copy(geneveEncapDiscoNonZeroGeneveVersion[packet.GeneveFixedHeaderLength:], nakedDisco)

	geneveEncapDiscoNonZeroGeneveReservedBits := make([]byte, packet.GeneveFixedHeaderLength+len(nakedDisco))
	gh = packet.GeneveHeader{
		Version:  0,
		Protocol: packet.GeneveProtocolDisco,
		Control:  true,
	}
	gh.VNI.Set(1)
	err = gh.Encode(geneveEncapDiscoNonZeroGeneveReservedBits)
	if err != nil {
		t.Fatal(err)
	}
	geneveEncapDiscoNonZeroGeneveReservedBits[1] |= 0x3F
	copy(geneveEncapDiscoNonZeroGeneveReservedBits[packet.GeneveFixedHeaderLength:], nakedDisco)

	geneveEncapDiscoNonZeroGeneveVNILSB := make([]byte, packet.GeneveFixedHeaderLength+len(nakedDisco))
	gh = packet.GeneveHeader{
		Version:  0,
		Protocol: packet.GeneveProtocolDisco,
		Control:  true,
	}
	gh.VNI.Set(1)
	err = gh.Encode(geneveEncapDiscoNonZeroGeneveVNILSB)
	if err != nil {
		t.Fatal(err)
	}
	geneveEncapDiscoNonZeroGeneveVNILSB[7] |= 0xFF
	copy(geneveEncapDiscoNonZeroGeneveVNILSB[packet.GeneveFixedHeaderLength:], nakedDisco)

	tests := []struct {
		name                    string
		msg                     []byte
		wantPacketLooksLikeType packetLooksLikeType
		wantIsGeneveEncap       bool
	}{
		{
			name:                    "STUN binding success response",
			msg:                     stun.Response(stun.NewTxID(), netip.MustParseAddrPort("127.0.0.1:1")),
			wantPacketLooksLikeType: packetLooksLikeSTUNBinding,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "naked disco",
			msg:                     nakedDisco,
			wantPacketLooksLikeType: packetLooksLikeDisco,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "geneve encap disco",
			msg:                     geneveEncapDisco,
			wantPacketLooksLikeType: packetLooksLikeDisco,
			wantIsGeneveEncap:       true,
		},
		{
			name:                    "geneve encap too short disco",
			msg:                     geneveEncapDisco[:len(geneveEncapDisco)-key.DiscoPublicRawLen],
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "geneve encap disco nonzero geneve version",
			msg:                     geneveEncapDiscoNonZeroGeneveVersion,
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "geneve encap disco nonzero geneve reserved bits",
			msg:                     geneveEncapDiscoNonZeroGeneveReservedBits,
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "geneve encap disco nonzero geneve vni lsb",
			msg:                     geneveEncapDiscoNonZeroGeneveVNILSB,
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "geneve encap wireguard",
			msg:                     geneveEncapWireGuard,
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       true,
		},
		{
			name:                    "naked WireGuard Initiation type",
			msg:                     nakedWireGuardInitiation,
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "naked WireGuard Response type",
			msg:                     nakedWireGuardResponse,
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "naked WireGuard Cookie Reply type",
			msg:                     nakedWireGuardCookieReply,
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       false,
		},
		{
			name:                    "naked WireGuard Transport type",
			msg:                     nakedWireGuardTransport,
			wantPacketLooksLikeType: packetLooksLikeWireGuard,
			wantIsGeneveEncap:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPacketLooksLikeType, gotIsGeneveEncap := packetLooksLike(tt.msg)
			if gotPacketLooksLikeType != tt.wantPacketLooksLikeType {
				t.Errorf("packetLooksLike() gotPacketLooksLikeType = %v, want %v", gotPacketLooksLikeType, tt.wantPacketLooksLikeType)
			}
			if gotIsGeneveEncap != tt.wantIsGeneveEncap {
				t.Errorf("packetLooksLike() gotIsGeneveEncap = %v, want %v", gotIsGeneveEncap, tt.wantIsGeneveEncap)
			}
		})
	}
}

func Test_looksLikeInitiationMsg(t *testing.T) {
	// initMsg was captured as the first packet from a WireGuard "session"
	initMsg, err := hex.DecodeString("01000000d9205f67915a500e377b409e0c3d97ca91e68654b95952de965e75df491000cce00632678cd9e8c8525556aa8daf24e6cfc44c48812bb560ff3c1c5dee061b3f833dfaa48acf13b64bd1e0027aa4d977a3721b82fd6072338702fc3193651404980ad46dae2869ba6416cc0eb38621a4140b5b918eb6402b697202adb3002a6d00000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if len(initMsg) != device.MessageInitiationSize {
		t.Fatalf("initMsg is not %d bytes long", device.MessageInitiationSize)
	}
	initMsgSizeTransportType := make([]byte, len(initMsg))
	copy(initMsgSizeTransportType, initMsg)
	binary.LittleEndian.PutUint32(initMsgSizeTransportType, device.MessageTransportType)
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{
			name: "valid initiation",
			b:    initMsg,
			want: true,
		},
		{
			name: "invalid message type field",
			b:    initMsgSizeTransportType,
			want: false,
		},
		{
			name: "too small",
			b:    initMsg[:device.MessageInitiationSize-1],
			want: false,
		},
		{
			name: "too big",
			b:    append(initMsg, 0),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeInitiationMsg(tt.b); got != tt.want {
				t.Errorf("looksLikeInitiationMsg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_nodeHasCap(t *testing.T) {
	nodeAOnlyIPv4 := &tailcfg.Node{
		ID: 1,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("1.1.1.1/32"),
		},
	}
	nodeBOnlyIPv6 := nodeAOnlyIPv4.Clone()
	nodeBOnlyIPv6.Addresses[0] = netip.MustParsePrefix("::1/128")

	nodeCOnlyIPv4 := &tailcfg.Node{
		ID: 2,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("2.2.2.2/32"),
		},
	}
	nodeDOnlyIPv6 := nodeCOnlyIPv4.Clone()
	nodeDOnlyIPv6.Addresses[0] = netip.MustParsePrefix("::2/128")

	tests := []struct {
		name string
		filt *filter.Filter
		src  tailcfg.NodeView
		dst  tailcfg.NodeView
		cap  tailcfg.PeerCapability
		want bool
	}{
		{
			name: "match v4",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("2.2.2.2/32")},
					Caps: []filtertype.CapMatch{
						{
							Dst: netip.MustParsePrefix("1.1.1.1/32"),
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			src:  nodeCOnlyIPv4.View(),
			dst:  nodeAOnlyIPv4.View(),
			cap:  tailcfg.PeerCapabilityRelayTarget,
			want: true,
		},
		{
			name: "match v6",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("::2/128")},
					Caps: []filtertype.CapMatch{
						{
							Dst: netip.MustParsePrefix("::1/128"),
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			src:  nodeDOnlyIPv6.View(),
			dst:  nodeBOnlyIPv6.View(),
			cap:  tailcfg.PeerCapabilityRelayTarget,
			want: true,
		},
		{
			name: "no match CapMatch Dst",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("::2/128")},
					Caps: []filtertype.CapMatch{
						{
							Dst: netip.MustParsePrefix("::3/128"),
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			src:  nodeDOnlyIPv6.View(),
			dst:  nodeBOnlyIPv6.View(),
			cap:  tailcfg.PeerCapabilityRelayTarget,
			want: false,
		},
		{
			name: "no match peer cap",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("::2/128")},
					Caps: []filtertype.CapMatch{
						{
							Dst: netip.MustParsePrefix("::1/128"),
							Cap: tailcfg.PeerCapabilityIngress,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			src:  nodeDOnlyIPv6.View(),
			dst:  nodeBOnlyIPv6.View(),
			cap:  tailcfg.PeerCapabilityRelayTarget,
			want: false,
		},
		{
			name: "nil src",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("2.2.2.2/32")},
					Caps: []filtertype.CapMatch{
						{
							Dst: netip.MustParsePrefix("1.1.1.1/32"),
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			src:  tailcfg.NodeView{},
			dst:  nodeAOnlyIPv4.View(),
			cap:  tailcfg.PeerCapabilityRelayTarget,
			want: false,
		},
		{
			name: "nil dst",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("2.2.2.2/32")},
					Caps: []filtertype.CapMatch{
						{
							Dst: netip.MustParsePrefix("1.1.1.1/32"),
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			src:  nodeCOnlyIPv4.View(),
			dst:  tailcfg.NodeView{},
			cap:  tailcfg.PeerCapabilityRelayTarget,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nodeHasCap(tt.filt, tt.src, tt.dst, tt.cap); got != tt.want {
				t.Errorf("nodeHasCap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConn_onNodeViewsUpdate_updateRelayServersSet(t *testing.T) {
	peerNodeCandidateRelay := &tailcfg.Node{
		Cap: 121,
		ID:  1,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("1.1.1.1/32"),
		},
		HomeDERP: 1,
		Key:      key.NewNode().Public(),
		DiscoKey: key.NewDisco().Public(),
	}

	peerNodeNotCandidateRelayCapVer := &tailcfg.Node{
		Cap: 120, // intentionally lower to fail capVer check
		ID:  1,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("1.1.1.1/32"),
		},
		HomeDERP: 1,
		Key:      key.NewNode().Public(),
		DiscoKey: key.NewDisco().Public(),
	}

	selfNode := &tailcfg.Node{
		Cap: 120, // intentionally lower than capVerIsRelayCapable to verify self check
		ID:  2,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("2.2.2.2/32"),
		},
		HomeDERP: 2,
		Key:      key.NewNode().Public(),
		DiscoKey: key.NewDisco().Public(),
	}

	selfNodeNodeAttrDisableRelayClient := selfNode.Clone()
	selfNodeNodeAttrDisableRelayClient.CapMap = make(tailcfg.NodeCapMap)
	selfNodeNodeAttrDisableRelayClient.CapMap[tailcfg.NodeAttrDisableRelayClient] = nil

	selfNodeNodeAttrOnlyTCP443 := selfNode.Clone()
	selfNodeNodeAttrOnlyTCP443.CapMap = make(tailcfg.NodeCapMap)
	selfNodeNodeAttrOnlyTCP443.CapMap[tailcfg.NodeAttrOnlyTCP443] = nil

	tests := []struct {
		name                   string
		filt                   *filter.Filter
		self                   tailcfg.NodeView
		peers                  []tailcfg.NodeView
		wantRelayServers       set.Set[candidatePeerRelay]
		wantRelayClientEnabled bool
	}{
		{
			name: "candidate relay server",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: peerNodeCandidateRelay.Addresses,
					Caps: []filtertype.CapMatch{
						{
							Dst: selfNode.Addresses[0],
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			self:  selfNode.View(),
			peers: []tailcfg.NodeView{peerNodeCandidateRelay.View()},
			wantRelayServers: set.SetOf([]candidatePeerRelay{
				{
					nodeKey:          peerNodeCandidateRelay.Key,
					discoKey:         peerNodeCandidateRelay.DiscoKey,
					derpHomeRegionID: 1,
				},
			}),
			wantRelayClientEnabled: true,
		},
		{
			name: "no candidate relay server because self has tailcfg.NodeAttrDisableRelayClient",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: peerNodeCandidateRelay.Addresses,
					Caps: []filtertype.CapMatch{
						{
							Dst: selfNodeNodeAttrDisableRelayClient.Addresses[0],
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			self:                   selfNodeNodeAttrDisableRelayClient.View(),
			peers:                  []tailcfg.NodeView{peerNodeCandidateRelay.View()},
			wantRelayServers:       make(set.Set[candidatePeerRelay]),
			wantRelayClientEnabled: false,
		},
		{
			name: "no candidate relay server because self has tailcfg.NodeAttrOnlyTCP443",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: peerNodeCandidateRelay.Addresses,
					Caps: []filtertype.CapMatch{
						{
							Dst: selfNodeNodeAttrOnlyTCP443.Addresses[0],
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			self:                   selfNodeNodeAttrOnlyTCP443.View(),
			peers:                  []tailcfg.NodeView{peerNodeCandidateRelay.View()},
			wantRelayServers:       make(set.Set[candidatePeerRelay]),
			wantRelayClientEnabled: false,
		},
		{
			name: "self candidate relay server",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: selfNode.Addresses,
					Caps: []filtertype.CapMatch{
						{
							Dst: selfNode.Addresses[0],
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			self:  selfNode.View(),
			peers: []tailcfg.NodeView{selfNode.View()},
			wantRelayServers: set.SetOf([]candidatePeerRelay{
				{
					nodeKey:          selfNode.Key,
					discoKey:         selfNode.DiscoKey,
					derpHomeRegionID: 2,
				},
			}),
			wantRelayClientEnabled: true,
		},
		{
			name: "no candidate relay server",
			filt: filter.New([]filtertype.Match{
				{
					Srcs: peerNodeNotCandidateRelayCapVer.Addresses,
					Caps: []filtertype.CapMatch{
						{
							Dst: selfNode.Addresses[0],
							Cap: tailcfg.PeerCapabilityRelayTarget,
						},
					},
				},
			}, nil, nil, nil, nil, nil),
			self:                   selfNode.View(),
			peers:                  []tailcfg.NodeView{peerNodeNotCandidateRelayCapVer.View()},
			wantRelayServers:       make(set.Set[candidatePeerRelay]),
			wantRelayClientEnabled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newConn(t.Logf)
			c.filt = tt.filt
			if len(tt.wantRelayServers) == 0 {
				// So we can verify it gets flipped back.
				c.hasPeerRelayServers.Store(true)
			}

			c.onNodeViewsUpdate(NodeViewsUpdate{
				SelfNode: tt.self,
				Peers:    tt.peers,
			})
			got := c.relayManager.getServers()
			if !got.Equal(tt.wantRelayServers) {
				t.Fatalf("got: %v != want: %v", got, tt.wantRelayServers)
			}
			if len(tt.wantRelayServers) > 0 != c.hasPeerRelayServers.Load() {
				t.Fatalf("c.hasPeerRelayServers: %v != len(tt.wantRelayServers) > 0: %v", c.hasPeerRelayServers.Load(), len(tt.wantRelayServers) > 0)
			}
			if c.relayClientEnabled != tt.wantRelayClientEnabled {
				t.Fatalf("c.relayClientEnabled: %v != wantRelayClientEnabled: %v", c.relayClientEnabled, tt.wantRelayClientEnabled)
			}
		})
	}
}

func TestConn_receiveIP(t *testing.T) {
	looksLikeNakedDisco := make([]byte, 0, len(disco.Magic)+key.DiscoPublicRawLen)
	looksLikeNakedDisco = append(looksLikeNakedDisco, disco.Magic...)
	looksLikeNakedDisco = looksLikeNakedDisco[:cap(looksLikeNakedDisco)]

	looksLikeGeneveDisco := make([]byte, packet.GeneveFixedHeaderLength+len(looksLikeNakedDisco))
	gh := packet.GeneveHeader{
		Protocol: packet.GeneveProtocolDisco,
	}
	gh.VNI.Set(1)
	err := gh.Encode(looksLikeGeneveDisco)
	if err != nil {
		t.Fatal(err)
	}
	copy(looksLikeGeneveDisco[packet.GeneveFixedHeaderLength:], looksLikeNakedDisco)

	looksLikeSTUNBinding := stun.Response(stun.NewTxID(), netip.MustParseAddrPort("127.0.0.1:7777"))

	findMetricByName := func(name string) *clientmetric.Metric {
		for _, metric := range clientmetric.Metrics() {
			if metric.Name() == name {
				return metric
			}
		}
		t.Fatalf("failed to find metric with name: %v", name)
		return nil
	}

	looksLikeNakedWireGuardInit := make([]byte, device.MessageInitiationSize)
	binary.LittleEndian.PutUint32(looksLikeNakedWireGuardInit, device.MessageInitiationType)

	looksLikeGeneveWireGuardInit := make([]byte, packet.GeneveFixedHeaderLength+device.MessageInitiationSize)
	gh = packet.GeneveHeader{
		Protocol: packet.GeneveProtocolWireGuard,
	}
	gh.VNI.Set(1)
	err = gh.Encode(looksLikeGeneveWireGuardInit)
	if err != nil {
		t.Fatal(err)
	}
	copy(looksLikeGeneveWireGuardInit[packet.GeneveFixedHeaderLength:], looksLikeNakedWireGuardInit)

	newPeerMapInsertableEndpoint := func(lastRecvWG mono.Time) *endpoint {
		ep := &endpoint{
			nodeID:     1,
			publicKey:  key.NewNode().Public(),
			lastRecvWG: lastRecvWG,
		}
		ep.disco.Store(&endpointDisco{
			key: key.NewDisco().Public(),
		})
		return ep
	}

	tests := []struct {
		name string
		// A copy of b is used as input, tests may re-use the same value.
		b   []byte
		ipp netip.AddrPort
		// cache must be non-nil, and must not be reused across tests. If
		// cache.de is non-nil after receiveIP(), then we verify it is equal to
		// wantEndpointType.
		cache *epAddrEndpointCache
		// If true, wantEndpointType is inserted into the [peerMap].
		insertWantEndpointTypeInPeerMap bool
		// If insertWantEndpointTypeInPeerMap is true, use this [epAddr] for it
		// in the [peerMap.setNodeKeyForEpAddr] call.
		peerMapEpAddr epAddr
		// If [*endpoint] then we expect 'got' to be the same [*endpoint]. If
		// [*lazyEndpoint] and [*lazyEndpoint.maybeEP] is non-nil, we expect
		// got.maybeEP to also be non-nil. Must not be reused across tests.
		wantEndpointType           wgconn.Endpoint
		wantSize                   int
		wantIsGeneveEncap          bool
		wantOk                     bool
		wantMetricInc              *clientmetric.Metric
		wantNoteRecvActivityCalled bool
	}{
		{
			name:                       "naked disco",
			b:                          looksLikeNakedDisco,
			ipp:                        netip.MustParseAddrPort("127.0.0.1:7777"),
			cache:                      &epAddrEndpointCache{},
			wantEndpointType:           nil,
			wantSize:                   0,
			wantIsGeneveEncap:          false,
			wantOk:                     false,
			wantMetricInc:              metricRecvDiscoBadPeer,
			wantNoteRecvActivityCalled: false,
		},
		{
			name:                       "geneve encap disco",
			b:                          looksLikeGeneveDisco,
			ipp:                        netip.MustParseAddrPort("127.0.0.1:7777"),
			cache:                      &epAddrEndpointCache{},
			wantEndpointType:           nil,
			wantSize:                   0,
			wantIsGeneveEncap:          false,
			wantOk:                     false,
			wantMetricInc:              metricRecvDiscoBadPeer,
			wantNoteRecvActivityCalled: false,
		},
		{
			name:                       "STUN binding",
			b:                          looksLikeSTUNBinding,
			ipp:                        netip.MustParseAddrPort("127.0.0.1:7777"),
			cache:                      &epAddrEndpointCache{},
			wantEndpointType:           nil,
			wantSize:                   0,
			wantIsGeneveEncap:          false,
			wantOk:                     false,
			wantMetricInc:              findMetricByName("netcheck_stun_recv_ipv4"),
			wantNoteRecvActivityCalled: false,
		},
		{
			name:                       "naked WireGuard init lazyEndpoint empty peerMap",
			b:                          looksLikeNakedWireGuardInit,
			ipp:                        netip.MustParseAddrPort("127.0.0.1:7777"),
			cache:                      &epAddrEndpointCache{},
			wantEndpointType:           &lazyEndpoint{},
			wantSize:                   len(looksLikeNakedWireGuardInit),
			wantIsGeneveEncap:          false,
			wantOk:                     true,
			wantMetricInc:              nil,
			wantNoteRecvActivityCalled: false,
		},
		{
			name:                            "naked WireGuard init endpoint matching peerMap entry",
			b:                               looksLikeNakedWireGuardInit,
			ipp:                             netip.MustParseAddrPort("127.0.0.1:7777"),
			cache:                           &epAddrEndpointCache{},
			insertWantEndpointTypeInPeerMap: true,
			peerMapEpAddr:                   epAddr{ap: netip.MustParseAddrPort("127.0.0.1:7777")},
			wantEndpointType:                newPeerMapInsertableEndpoint(0),
			wantSize:                        len(looksLikeNakedWireGuardInit),
			wantIsGeneveEncap:               false,
			wantOk:                          true,
			wantMetricInc:                   nil,
			wantNoteRecvActivityCalled:      true,
		},
		{
			name:                       "geneve WireGuard init lazyEndpoint empty peerMap",
			b:                          looksLikeGeneveWireGuardInit,
			ipp:                        netip.MustParseAddrPort("127.0.0.1:7777"),
			cache:                      &epAddrEndpointCache{},
			wantEndpointType:           &lazyEndpoint{},
			wantSize:                   len(looksLikeGeneveWireGuardInit) - packet.GeneveFixedHeaderLength,
			wantIsGeneveEncap:          true,
			wantOk:                     true,
			wantMetricInc:              nil,
			wantNoteRecvActivityCalled: false,
		},
		{
			name:                            "geneve WireGuard init lazyEndpoint matching peerMap activity noted",
			b:                               looksLikeGeneveWireGuardInit,
			ipp:                             netip.MustParseAddrPort("127.0.0.1:7777"),
			cache:                           &epAddrEndpointCache{},
			insertWantEndpointTypeInPeerMap: true,
			peerMapEpAddr:                   epAddr{ap: netip.MustParseAddrPort("127.0.0.1:7777"), vni: gh.VNI},
			wantEndpointType: &lazyEndpoint{
				maybeEP: newPeerMapInsertableEndpoint(0),
			},
			wantSize:                   len(looksLikeGeneveWireGuardInit) - packet.GeneveFixedHeaderLength,
			wantIsGeneveEncap:          true,
			wantOk:                     true,
			wantMetricInc:              nil,
			wantNoteRecvActivityCalled: true,
		},
		{
			name:                            "geneve WireGuard init lazyEndpoint matching peerMap no activity noted",
			b:                               looksLikeGeneveWireGuardInit,
			ipp:                             netip.MustParseAddrPort("127.0.0.1:7777"),
			cache:                           &epAddrEndpointCache{},
			insertWantEndpointTypeInPeerMap: true,
			peerMapEpAddr:                   epAddr{ap: netip.MustParseAddrPort("127.0.0.1:7777"), vni: gh.VNI},
			wantEndpointType: &lazyEndpoint{
				maybeEP: newPeerMapInsertableEndpoint(mono.Now().Add(time.Hour * 24)),
			},
			wantSize:                   len(looksLikeGeneveWireGuardInit) - packet.GeneveFixedHeaderLength,
			wantIsGeneveEncap:          true,
			wantOk:                     true,
			wantMetricInc:              nil,
			wantNoteRecvActivityCalled: false,
		},
		// TODO(jwhited): verify cache.de is used when conditions permit
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noteRecvActivityCalled := false
			metricBefore := int64(0)
			if tt.wantMetricInc != nil {
				metricBefore = tt.wantMetricInc.Value()
			}

			// Init Conn.
			c := &Conn{
				privateKey: key.NewNode(),
				netChecker: &netcheck.Client{},
				peerMap:    newPeerMap(),
			}
			c.havePrivateKey.Store(true)
			c.noteRecvActivity = func(public key.NodePublic) {
				noteRecvActivityCalled = true
			}
			c.SetStatistics(connstats.NewStatistics(0, 0, nil))

			if tt.insertWantEndpointTypeInPeerMap {
				var insertEPIntoPeerMap *endpoint
				switch ep := tt.wantEndpointType.(type) {
				case *endpoint:
					insertEPIntoPeerMap = ep
				case *lazyEndpoint:
					insertEPIntoPeerMap = ep.maybeEP
				default:
					t.Fatal("unexpected tt.wantEndpointType concrete type")
				}
				insertEPIntoPeerMap.c = c
				c.peerMap.upsertEndpoint(insertEPIntoPeerMap, key.DiscoPublic{})
				c.peerMap.setNodeKeyForEpAddr(tt.peerMapEpAddr, insertEPIntoPeerMap.publicKey)
			}

			// Allow the same input packet to be used across tests, receiveIP()
			// may mutate.
			inputPacket := make([]byte, len(tt.b))
			copy(inputPacket, tt.b)

			got, gotSize, gotIsGeneveEncap, gotOk := c.receiveIP(inputPacket, tt.ipp, tt.cache)
			if (tt.wantEndpointType == nil) != (got == nil) {
				t.Errorf("receiveIP() (tt.wantEndpointType == nil): %v != (got == nil): %v", tt.wantEndpointType == nil, got == nil)
			}
			if tt.wantEndpointType != nil && reflect.TypeOf(got).String() != reflect.TypeOf(tt.wantEndpointType).String() {
				t.Errorf("receiveIP() got = %v, want %v", reflect.TypeOf(got).String(), reflect.TypeOf(tt.wantEndpointType).String())
			} else {
				switch ep := tt.wantEndpointType.(type) {
				case *endpoint:
					if ep != got.(*endpoint) {
						t.Errorf("receiveIP() want [*endpoint]: %p != got [*endpoint]: %p", ep, got)
					}
				case *lazyEndpoint:
					if ep.maybeEP != nil && ep.maybeEP != got.(*lazyEndpoint).maybeEP {
						t.Errorf("receiveIP() want [*lazyEndpoint.maybeEP]: %p != got [*lazyEndpoint.maybeEP] %p", ep, got)
					}
				}
			}

			if gotSize != tt.wantSize {
				t.Errorf("receiveIP() gotSize = %v, want %v", gotSize, tt.wantSize)
			}
			if gotIsGeneveEncap != tt.wantIsGeneveEncap {
				t.Errorf("receiveIP() gotIsGeneveEncap = %v, want %v", gotIsGeneveEncap, tt.wantIsGeneveEncap)
			}
			if gotOk != tt.wantOk {
				t.Errorf("receiveIP() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
			if tt.wantMetricInc != nil && tt.wantMetricInc.Value() != metricBefore+1 {
				t.Errorf("receiveIP() metric %v not incremented", tt.wantMetricInc.Name())
			}
			if tt.wantNoteRecvActivityCalled != noteRecvActivityCalled {
				t.Errorf("receiveIP() noteRecvActivityCalled = %v, want %v", noteRecvActivityCalled, tt.wantNoteRecvActivityCalled)
			}

			if tt.cache.de != nil {
				switch ep := got.(type) {
				case *endpoint:
					if tt.cache.de != ep {
						t.Errorf("receiveIP() cache populated with [*endpoint] %p, want %p", tt.cache.de, ep)
					}
				case *lazyEndpoint:
					if tt.cache.de != ep.maybeEP {
						t.Errorf("receiveIP() cache populated with [*endpoint] %p, want (lazyEndpoint.maybeEP) %p", tt.cache.de, ep.maybeEP)
					}
				default:
					t.Fatal("receiveIP() unexpected [conn.Endpoint] type")
				}
			}

			// Verify physical rx stats
			stats := c.stats.Load()
			_, gotPhy := stats.TestExtract()
			wantNonzeroRxStats := false
			switch ep := tt.wantEndpointType.(type) {
			case *lazyEndpoint:
				if ep.maybeEP != nil {
					wantNonzeroRxStats = true
				}
			case *endpoint:
				wantNonzeroRxStats = true
			}
			if tt.wantOk && wantNonzeroRxStats {
				wantRxBytes := uint64(tt.wantSize)
				if tt.wantIsGeneveEncap {
					wantRxBytes += packet.GeneveFixedHeaderLength
				}
				wantPhy := map[netlogtype.Connection]netlogtype.Counts{
					{Dst: tt.ipp}: {
						RxPackets: 1,
						RxBytes:   wantRxBytes,
					},
				}
				if !reflect.DeepEqual(gotPhy, wantPhy) {
					t.Errorf("receiveIP() got physical conn stats = %v, want %v", gotPhy, wantPhy)
				}
			} else {
				if len(gotPhy) != 0 {
					t.Errorf("receiveIP() unexpected nonzero physical count stats: %+v", gotPhy)
				}
			}
		})
	}
}

func Test_lazyEndpoint_InitiationMessagePublicKey(t *testing.T) {
	tests := []struct {
		name                       string
		callWithPeerMapKey         bool
		maybeEPMatchingKey         bool
		wantNoteRecvActivityCalled bool
	}{
		{
			name:                       "noteRecvActivity called",
			callWithPeerMapKey:         true,
			maybeEPMatchingKey:         false,
			wantNoteRecvActivityCalled: true,
		},
		{
			name:                       "maybeEP early return",
			callWithPeerMapKey:         true,
			maybeEPMatchingKey:         true,
			wantNoteRecvActivityCalled: false,
		},
		{
			name:                       "not in peerMap early return",
			callWithPeerMapKey:         false,
			maybeEPMatchingKey:         false,
			wantNoteRecvActivityCalled: false,
		},
		{
			name:                       "not in peerMap maybeEP early return",
			callWithPeerMapKey:         false,
			maybeEPMatchingKey:         true,
			wantNoteRecvActivityCalled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &endpoint{
				nodeID:    1,
				publicKey: key.NewNode().Public(),
			}
			ep.disco.Store(&endpointDisco{
				key: key.NewDisco().Public(),
			})

			var noteRecvActivityCalledFor key.NodePublic
			conn := newConn(t.Logf)
			conn.noteRecvActivity = func(public key.NodePublic) {
				// wireguard-go will call into ParseEndpoint if the "real"
				// noteRecvActivity ends up JIT configuring the peer. Mimic that
				// to ensure there are no deadlocks around conn.mu.
				// See tailscale/tailscale#16651 & http://go/corp#30836
				_, err := conn.ParseEndpoint(ep.publicKey.UntypedHexString())
				if err != nil {
					t.Fatalf("ParseEndpoint() err: %v", err)
				}
				noteRecvActivityCalledFor = public
			}
			ep.c = conn

			var pubKey [32]byte
			if tt.callWithPeerMapKey {
				copy(pubKey[:], ep.publicKey.AppendTo(nil))
			}
			conn.peerMap.upsertEndpoint(ep, key.DiscoPublic{})

			le := &lazyEndpoint{
				c: conn,
			}
			if tt.maybeEPMatchingKey {
				le.maybeEP = ep
			}
			le.InitiationMessagePublicKey(pubKey)
			want := key.NodePublic{}
			if tt.wantNoteRecvActivityCalled {
				want = ep.publicKey
			}
			if noteRecvActivityCalledFor.Compare(want) != 0 {
				t.Fatalf("noteRecvActivityCalledFor = %v, want %v", noteRecvActivityCalledFor, want)
			}
		})
	}
}

func Test_lazyEndpoint_FromPeer(t *testing.T) {
	tests := []struct {
		name                string
		callWithPeerMapKey  bool
		maybeEPMatchingKey  bool
		wantEpAddrInPeerMap bool
	}{
		{
			name:                "epAddr in peerMap",
			callWithPeerMapKey:  true,
			maybeEPMatchingKey:  false,
			wantEpAddrInPeerMap: true,
		},
		{
			name:                "maybeEP early return",
			callWithPeerMapKey:  true,
			maybeEPMatchingKey:  true,
			wantEpAddrInPeerMap: false,
		},
		{
			name:                "not in peerMap early return",
			callWithPeerMapKey:  false,
			maybeEPMatchingKey:  false,
			wantEpAddrInPeerMap: false,
		},
		{
			name:                "not in peerMap maybeEP early return",
			callWithPeerMapKey:  false,
			maybeEPMatchingKey:  true,
			wantEpAddrInPeerMap: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := &endpoint{
				nodeID:    1,
				publicKey: key.NewNode().Public(),
			}
			ep.disco.Store(&endpointDisco{
				key: key.NewDisco().Public(),
			})
			conn := newConn(t.Logf)
			ep.c = conn

			var pubKey [32]byte
			if tt.callWithPeerMapKey {
				copy(pubKey[:], ep.publicKey.AppendTo(nil))
			}
			conn.peerMap.upsertEndpoint(ep, key.DiscoPublic{})

			le := &lazyEndpoint{
				c:   conn,
				src: epAddr{ap: netip.MustParseAddrPort("127.0.0.1:7777")},
			}
			if tt.maybeEPMatchingKey {
				le.maybeEP = ep
			}
			le.FromPeer(pubKey)
			if tt.wantEpAddrInPeerMap {
				gotEP, ok := conn.peerMap.endpointForEpAddr(le.src)
				if !ok {
					t.Errorf("lazyEndpoint epAddr not found in peerMap")
				} else if gotEP != ep {
					t.Errorf("gotEP: %p != ep: %p", gotEP, ep)
				}
			} else if len(conn.peerMap.byEpAddr) != 0 {
				t.Errorf("unexpected epAddr in peerMap")
			}
		})
	}
}
