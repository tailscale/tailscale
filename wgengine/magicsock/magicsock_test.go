// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"go4.org/mem"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/disco"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/racebuild"
	"tailscale.com/wgengine/filter"
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
	d := derp.NewServer(key.NewNode(), logf)

	httpsrv := httptest.NewUnstartedServer(derphttp.Handler(d))
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
	conn       *Conn                   // the magicsock itself
	tun        *tuntest.ChannelTUN     // TUN device to send/receive packets
	tsTun      *tstun.Wrapper          // wrapped tun that implements filtering and wgengine hooks
	dev        *device.Device          // the wireguard-go Device that connects the previous things
	wgLogger   *wglog.Logger           // wireguard-go log wrapper
}

// newMagicStack builds and initializes an idle magicsock and
// friends. You need to call conn.SetNetworkMap and dev.Reconfig
// before anything interesting happens.
func newMagicStack(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap) *magicStack {
	privateKey := key.NewNode()
	return newMagicStackWithKey(t, logf, l, derpMap, privateKey)
}

func newMagicStackWithKey(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap, privateKey key.NodePrivate) *magicStack {
	t.Helper()

	epCh := make(chan []tailcfg.Endpoint, 100) // arbitrary
	conn, err := NewConn(Options{
		Logf:                   logf,
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
	tsTun := tstun.Wrap(logf, tun.TUN())
	tsTun.SetFilter(filter.NewAllowAllForTest(logf))

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
	}
}

func (s *magicStack) Reconfig(cfg *wgcfg.Config) error {
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
}

func (s *magicStack) Public() key.NodePublic {
	return s.privateKey.Public()
}

func (s *magicStack) Status() *ipnstate.Status {
	var sb ipnstate.StatusBuilder
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
		st := s.Status()
		if len(st.TailscaleIPs) > 0 {
			return st.TailscaleIPs[0]
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
			Addresses:  []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(1, 0, 0, byte(myIdx+1)), 32)},
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
				Endpoints:  epStrings(eps[i]),
				DERP:       "127.3.3.40:1",
			}
			nm.Peers = append(nm.Peers, peer)
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
			m.conn.SetNetworkMap(nm)
			peerSet := make(map[key.NodePublic]struct{}, len(nm.Peers))
			for _, peer := range nm.Peers {
				peerSet[peer.Key] = struct{}{}
			}
			m.conn.UpdatePeers(peerSet)
			wg, err := nmcfg.WGCfg(nm, logf, netmap.AllowSingleHosts, "")
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

	stunAddr, stunCleanupFn := stuntest.Serve(t)
	defer stunCleanupFn()

	port := pickPort(t)
	conn, err := NewConn(Options{
		Port:          port,
		EndpointsFunc: epFunc,
		Logf:          t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDERPMap(stuntest.DERPMapOf(stunAddr.String()))
	conn.SetPrivateKey(key.NewNode())

	go func() {
		var pkt [64 << 10]byte
		for {
			_, _, err := conn.receiveIPv4(pkt[:])
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

	c := newConn()
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
	for i := 0; i < 50; i++ {
		b := c.pickDERPFallback()
		if a != b {
			t.Fatalf("got inconsistent %d vs %d values", a, b)
		}
	}

	// Test that the pointer value of c is blended in and
	// distribution over nodes works.
	got := map[int]int{}
	for i := 0; i < 50; i++ {
		c = newConn()
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

	conn, err := NewConn(Options{
		EndpointsFunc: func(eps []tailcfg.Endpoint) {},
		Logf:          t.Logf,
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

// Legacy clients appear to new code as peers that know about DERP and
// WireGuard, but don't have a disco key. Check that we can still
// communicate successfully with such peers.
func TestNoDiscoKey(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	m1 := newMagicStack(t, t.Logf, localhostListener{}, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, t.Logf, localhostListener{}, derpMap)
	defer m2.Close()

	removeDisco := func(idx int, nm *netmap.NetworkMap) {
		for _, p := range nm.Peers {
			p.DiscoKey = key.DiscoPublic{}
		}
	}

	cleanupMesh := meshStacks(t.Logf, removeDisco, m1, m2)
	defer cleanupMesh()

	// Wait for both peers to know about each other before we try to
	// ping.
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

	pkt := tuntest.Ping(m2.IP(), m1.IP())
	m1.tun.Outbound <- pkt
	select {
	case <-m2.tun.Inbound:
		t.Logf("ping m1>m2 ok")
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for ping to transit")
	}
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
		nm.Peers[0].DiscoKey = m1DiscoKey
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
	tstest.ResourceCheck(t)

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

	outerT := t
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		ping1(t)
	})

	t.Run("ping 1.0.0.2", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		ping2(t)
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
	})

	t.Run("no-op dev1 reconfig", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		if err := m1.Reconfig(m1cfg); err != nil {
			t.Fatal(err)
		}
		ping1(t)
		ping2(t)
	})
}

func TestDiscoMessage(t *testing.T) {
	c := newConn()
	c.logf = t.Logf
	c.privateKey = key.NewNode()

	peer1Pub := c.DiscoPublicKey()
	peer1Priv := c.discoPrivate
	n := &tailcfg.Node{
		Key:      key.NewNode().Public(),
		DiscoKey: peer1Pub,
	}
	c.peerMap.upsertEndpoint(&endpoint{
		publicKey: n.Key,
		discoKey:  n.DiscoKey,
	}, key.DiscoPublic{})

	const payload = "why hello"

	var nonce [24]byte
	crand.Read(nonce[:])

	pkt := peer1Pub.AppendTo([]byte("TS💬"))

	box := peer1Priv.Shared(c.discoPrivate.Public()).Seal([]byte(payload))
	pkt = append(pkt, box...)
	got := c.handleDiscoMessage(pkt, netip.AddrPort{}, key.NodePublic{})
	if !got {
		t.Error("failed to open it")
	}
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

	if off := unsafe.Offsetof(de.lastRecv); off%8 != 0 {
		t.Fatalf("endpoint.lastRecv is not 8-byte aligned")
	}

	de.noteRecvActivity() // verify this doesn't panic on 32-bit
	if called != 1 {
		t.Fatal("expected call to noteRecvActivity")
	}
	de.noteRecvActivity()
	if called != 1 {
		t.Error("expected no second call to noteRecvActivity")
	}
}

// newTestConn returns a new Conn.
func newTestConn(t testing.TB) *Conn {
	t.Helper()
	port := pickPort(t)
	conn, err := NewConn(Options{
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

// addTestEndpoint sets conn's network map to a single peer expected
// to receive packets from sendConn (or DERP), and returns that peer's
// nodekey and discokey.
func addTestEndpoint(tb testing.TB, conn *Conn, sendConn net.PacketConn) (key.NodePublic, key.DiscoPublic) {
	// Give conn just enough state that it'll recognize sendConn as a
	// valid peer and not fall through to the legacy magicsock
	// codepath.
	discoKey := key.DiscoPublicFromRaw32(mem.B([]byte{31: 1}))
	nodeKey := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 31: 0}))
	conn.SetNetworkMap(&netmap.NetworkMap{
		Peers: []*tailcfg.Node{
			{
				Key:       nodeKey,
				DiscoKey:  discoKey,
				Endpoints: []string{sendConn.LocalAddr().String()},
			},
		},
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
	buf := make([]byte, 2<<10)
	return func() {
		if _, err := sendConn.WriteTo(sendBuf, dstAddr); err != nil {
			tb.Fatalf("WriteTo: %v", err)
		}
		n, ep, err := conn.receiveIPv4(buf)
		if err != nil {
			tb.Fatal(err)
		}
		_ = n
		_ = ep
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
	for i := 0; i < b.N; i++ {
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
	for i := 0; i < b.N; i++ {
		if _, err := sendConn.WriteTo(sendBuf, dstAddr); err != nil {
			b.Fatalf("WriteTo: %v", err)
		}
		if _, _, err := recvConnUDP.ReadFromUDP(buf); err != nil {
			b.Fatalf("ReadFromUDP: %v", err)
		}
	}
}

// Test that a netmap update where node changes its node key but
// doesn't change its disco key doesn't result in a broken state.
//
// https://github.com/tailscale/tailscale/issues/1391
func TestSetNetworkMapChangingNodeKey(t *testing.T) {
	conn := newTestConn(t)
	t.Cleanup(func() { conn.Close() })
	var buf tstest.MemLogger
	conn.logf = buf.Logf

	conn.SetPrivateKey(key.NodePrivateFromRaw32(mem.B([]byte{0: 1, 31: 0})))

	discoKey := key.DiscoPublicFromRaw32(mem.B([]byte{31: 1}))
	nodeKey1 := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 2: '1', 31: 0}))
	nodeKey2 := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 2: '2', 31: 0}))

	conn.SetNetworkMap(&netmap.NetworkMap{
		Peers: []*tailcfg.Node{
			{
				Key:       nodeKey1,
				DiscoKey:  discoKey,
				Endpoints: []string{"192.168.1.2:345"},
			},
		},
	})
	_, err := conn.ParseEndpoint(nodeKey1.UntypedHexString())
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		conn.SetNetworkMap(&netmap.NetworkMap{
			Peers: []*tailcfg.Node{
				{
					Key:       nodeKey2,
					DiscoKey:  discoKey,
					Endpoints: []string{"192.168.1.2:345"},
				},
			},
		})
	}

	de, ok := conn.peerMap.endpointForNodeKey(nodeKey2)
	if ok && de.publicKey != nodeKey2 {
		t.Fatalf("discoEndpoint public key = %q; want %q", de.publicKey, nodeKey2)
	}
	if de.discoKey != discoKey {
		t.Errorf("discoKey = %v; want %v", de.discoKey, discoKey)
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
		buf := make([]byte, 1500)
		for {
			_, _, err := conn.receiveIPv4(buf)
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
		for i := 0; i < 2000; i++ {
			conn.Rebind()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
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
	al := func(ipps string, d time.Duration) addrLatency {
		return addrLatency{netip.MustParseAddrPort(ipps), d}
	}
	zero := addrLatency{}
	tests := []struct {
		a, b addrLatency
		want bool
	}{
		{a: zero, b: zero, want: false},
		{a: al("10.0.0.2:123", 5*ms), b: zero, want: true},
		{a: zero, b: al("10.0.0.2:123", 5*ms), want: false},
		{a: al("10.0.0.2:123", 5*ms), b: al("1.2.3.4:555", 6*ms), want: true},
		{a: al("10.0.0.2:123", 5*ms), b: al("10.0.0.2:123", 10*ms), want: false}, // same IPPort

		// Prefer IPv6 if roughly equivalent:
		{
			a:    al("[2001::5]:123", 100*ms),
			b:    al("1.2.3.4:555", 91*ms),
			want: true,
		},
		{
			a:    al("1.2.3.4:555", 91*ms),
			b:    al("[2001::5]:123", 100*ms),
			want: false,
		},
		// But not if IPv4 is much faster:
		{
			a:    al("[2001::5]:123", 100*ms),
			b:    al("1.2.3.4:555", 30*ms),
			want: false,
		},
		{
			a:    al("1.2.3.4:555", 30*ms),
			b:    al("[2001::5]:123", 100*ms),
			want: true,
		},
	}
	for _, tt := range tests {
		got := betterAddr(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("betterAddr(%+v, %+v) = %v; want %v", tt.a, tt.b, got, tt.want)
			continue
		}
		gotBack := betterAddr(tt.b, tt.a)
		if got && gotBack {
			t.Errorf("betterAddr(%+v, %+v) and betterAddr(%+v, %+v) both unexpectedly true", tt.a, tt.b, tt.b, tt.a)
		}
	}

}

func epStrings(eps []tailcfg.Endpoint) (ret []string) {
	for _, ep := range eps {
		ret = append(ret, ep.Addr.String())
	}
	return
}

func TestStressSetNetworkMap(t *testing.T) {
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
			DiscoKey:  randDiscoKey(),
			Key:       randNodeKey(),
			Endpoints: []string{fmt.Sprintf("192.168.1.2:%d", i)},
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
	for i := 0; i < iters; i++ {
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
		// Clone existing peers into a new netmap.
		peers := make([]*tailcfg.Node, 0, len(allPeers))
		for peerIdx, p := range allPeers {
			if present[peerIdx] {
				peers = append(peers, p.Clone())
			}
		}
		// Set the netmap.
		conn.SetNetworkMap(&netmap.NetworkMap{
			Peers: peers,
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
		if got, want := pi.ep.wgEndpoint, pub.UntypedHexString(); got != want {
			return fmt.Errorf("byNodeKey[%v].wgEndpoint = %q, want %q", pub, got, want)
		}
		if _, ok := seenEps[pi.ep]; ok {
			return fmt.Errorf("duplicate endpoint present: %v", pi.ep.publicKey)
		}
		seenEps[pi.ep] = true
		for ipp, v := range pi.ipPorts {
			if !v {
				return fmt.Errorf("m.byIPPort[%v] is false, expected map to be set-like", ipp)
			}
			if got := m.byIPPort[ipp]; got != pi {
				return fmt.Errorf("m.byIPPort[%v] = %v, want %v", ipp, got, pi)
			}
		}
	}

	for ipp, pi := range m.byIPPort {
		if !pi.ipPorts[ipp] {
			return fmt.Errorf("ipPorts[%v] for %v is false", ipp, pi.ep.publicKey)
		}
		pi2 := m.byNodeKey[pi.ep.publicKey]
		if pi != pi2 {
			return fmt.Errorf("byNodeKey[%v]=%p doesn't match byIPPort[%v]=%p", pi, pi, pi.ep.publicKey, pi2)
		}
	}

	publicToDisco := make(map[key.NodePublic]key.DiscoPublic)
	for disco, nodes := range m.nodesOfDisco {
		for pub, v := range nodes {
			if !v {
				return fmt.Errorf("m.nodeOfDisco[%v][%v] is false, expected map to be set-like", disco, pub)
			}
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
		_, _, err := c.ReadFrom(make([]byte, 1))
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
