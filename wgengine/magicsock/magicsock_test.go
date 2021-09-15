// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"inet.af/netaddr"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/types/wgkey"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/racebuild"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgcfg/nmcfg"
	"tailscale.com/wgengine/wglog"
)

func init() {
	os.Setenv("IN_TS_TEST", "1")
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

func runDERPAndStun(t *testing.T, logf logger.Logf, l nettype.PacketListener, stunIP netaddr.IP) (derpMap *tailcfg.DERPMap, cleanup func()) {
	var serverPrivateKey key.Private
	if _, err := crand.Read(serverPrivateKey[:]); err != nil {
		t.Fatal(err)
	}
	d := derp.NewServer(serverPrivateKey, logf)

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
	privateKey wgkey.Private
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
	t.Helper()

	privateKey, err := wgkey.NewPrivate()
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}

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
	dev := device.NewDevice(tsTun, conn.Bind(), wgLogger.DeviceLogger)
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

func (s *magicStack) Public() key.Public {
	return key.Public(s.privateKey.Public())
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
func (s *magicStack) IP() netaddr.IP {
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
			NodeKey:    tailcfg.NodeKey(me.privateKey.Public()),
			Addresses:  []netaddr.IPPrefix{netaddr.IPPrefixFrom(netaddr.IPv4(1, 0, 0, byte(myIdx+1)), 32)},
		}
		for i, peer := range ms {
			if i == myIdx {
				continue
			}
			addrs := []netaddr.IPPrefix{netaddr.IPPrefixFrom(netaddr.IPv4(1, 0, 0, byte(i+1)), 32)}
			peer := &tailcfg.Node{
				ID:         tailcfg.NodeID(i + 1),
				Name:       fmt.Sprintf("node%d", i+1),
				Key:        tailcfg.NodeKey(peer.privateKey.Public()),
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
			peerSet := make(map[key.Public]struct{}, len(nm.Peers))
			for _, peer := range nm.Peers {
				peerSet[key.Public(peer.Key)] = struct{}{}
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
	conn.SetPrivateKey(wgkey.Private(key.NewPrivate()))

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
			1: &tailcfg.DERPRegion{},
			2: &tailcfg.DERPRegion{},
			3: &tailcfg.DERPRegion{},
			4: &tailcfg.DERPRegion{},
			5: &tailcfg.DERPRegion{},
			6: &tailcfg.DERPRegion{},
			7: &tailcfg.DERPRegion{},
			8: &tailcfg.DERPRegion{},
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

	// Test that that the pointer value of c is blended in and
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
	dev := device.NewDevice(tun.TUN(), conn.Bind(), wgLogger.DeviceLogger)
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

	pkt := tuntest.Ping(ms2.IP().IPAddr().IP, ms1.IP().IPAddr().IP)

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

	logf = func(s string, args ...interface{}) {
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
			p.DiscoKey = tailcfg.DiscoKey{}
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

	pkt := tuntest.Ping(m2.IP().IPAddr().IP, m1.IP().IPAddr().IP)
	m1.tun.Outbound <- pkt
	select {
	case <-m2.tun.Inbound:
		t.Logf("ping m1>m2 ok")
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for ping to transit")
	}
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
			Prefix4: netaddr.MustParseIPPrefix("192.168.0.0/24"),
		}
		lan2 := &natlab.Network{
			Name:    "lan2",
			Prefix4: netaddr.MustParseIPPrefix("192.168.1.0/24"),
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
	m1IP netaddr.IP

	m2   nettype.PacketListener
	m2IP netaddr.IP

	stun   nettype.PacketListener
	stunIP netaddr.IP
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
		pkt := tuntest.Ping(dst.IP().IPAddr().IP, src.IP().IPAddr().IP)
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
	wlogf := func(msg string, args ...interface{}) {
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

	mustDirect := func(m1, m2 *magicStack) {
		lastLog := time.Now().Add(-time.Minute)
		// See https://github.com/tailscale/tailscale/issues/654 for a discussion of this deadline.
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
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

	mustDirect(m1, m2)
	mustDirect(m2, m1)

	logf("starting cleanup")
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
		if p := m1.Status().Peer[key.Public(m2.privateKey.Public())]; p == nil || !p.InMagicSock {
			return errors.New("m1 not ready")
		}
		if p := m2.Status().Peer[key.Public(m1.privateKey.Public())]; p == nil || !p.InMagicSock {
			return errors.New("m2 not ready")
		}
		return nil
	})

	m1cfg := &wgcfg.Config{
		Name:       "peer1",
		PrivateKey: m1.privateKey,
		Addresses:  []netaddr.IPPrefix{netaddr.MustParseIPPrefix("1.0.0.1/32")},
		Peers: []wgcfg.Peer{
			wgcfg.Peer{
				PublicKey:  m2.privateKey.Public(),
				DiscoKey:   m2.conn.DiscoPublicKey(),
				AllowedIPs: []netaddr.IPPrefix{netaddr.MustParseIPPrefix("1.0.0.2/32")},
			},
		},
	}
	m2cfg := &wgcfg.Config{
		Name:       "peer2",
		PrivateKey: m2.privateKey,
		Addresses:  []netaddr.IPPrefix{netaddr.MustParseIPPrefix("1.0.0.2/32")},
		Peers: []wgcfg.Peer{
			wgcfg.Peer{
				PublicKey:  m1.privateKey.Public(),
				DiscoKey:   m1.conn.DiscoPublicKey(),
				AllowedIPs: []netaddr.IPPrefix{netaddr.MustParseIPPrefix("1.0.0.1/32")},
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
		msg2to1 := tuntest.Ping(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2"))
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
		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
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
		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
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
	c.privateKey = key.NewPrivate()

	peer1Pub := c.DiscoPublicKey()
	peer1Priv := c.discoPrivate
	n := &tailcfg.Node{
		Key:      tailcfg.NodeKey(key.NewPrivate().Public()),
		DiscoKey: peer1Pub,
	}
	c.peerMap.upsertDiscoEndpoint(&endpoint{
		publicKey: n.Key,
		discoKey:  n.DiscoKey,
	})

	const payload = "why hello"

	var nonce [24]byte
	crand.Read(nonce[:])

	pkt := append([]byte("TS💬"), peer1Pub[:]...)
	pkt = append(pkt, nonce[:]...)

	pkt = box.Seal(pkt, []byte(payload), &nonce, c.discoPrivate.Public().B32(), peer1Priv.B32())
	got := c.handleDiscoMessage(pkt, netaddr.IPPort{})
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
		fmt.Fprintf(ioutil.Discard, "%v", de)
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
			noteRecvActivity: func(tailcfg.NodeKey) { called++ },
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
func addTestEndpoint(tb testing.TB, conn *Conn, sendConn net.PacketConn) (tailcfg.NodeKey, tailcfg.DiscoKey) {
	// Give conn just enough state that it'll recognize sendConn as a
	// valid peer and not fall through to the legacy magicsock
	// codepath.
	discoKey := tailcfg.DiscoKey{31: 1}
	nodeKey := tailcfg.NodeKey{0: 'N', 1: 'K'}
	conn.SetNetworkMap(&netmap.NetworkMap{
		Peers: []*tailcfg.Node{
			{
				Key:       nodeKey,
				DiscoKey:  discoKey,
				Endpoints: []string{sendConn.LocalAddr().String()},
			},
		},
	})
	conn.SetPrivateKey(wgkey.Private{0: 1})
	_, err := conn.ParseEndpoint(wgkey.Key(nodeKey).HexString())
	if err != nil {
		tb.Fatal(err)
	}
	conn.addValidDiscoPathForTest(discoKey, netaddr.MustParseIPPort(sendConn.LocalAddr().String()))
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
	for _, sep := range []string{".", "rc", "beta"} {
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
	}

	for _, tt := range tests {
		n, ts := goMajorVersion(tt.version)
		if tt.wantN != n || tt.wantTS != ts {
			t.Errorf("goMajorVersion(%s) = %v, %v, want %v, %v", tt.version, n, ts, tt.wantN, tt.wantTS)
		}
	}
}

func TestReceiveFromAllocs(t *testing.T) {
	if racebuild.On {
		t.Skip("alloc tests are unreliable with -race")
	}
	// Go 1.16 and before: allow 3 allocs.
	// Go Tailscale fork, Go 1.17+: only allow 2 allocs.
	major, ts := goMajorVersion(runtime.Version())
	maxAllocs := 3
	if major >= 17 || ts {
		maxAllocs = 2
	}
	t.Logf("allowing %d allocs for Go version %q", maxAllocs, runtime.Version())
	roundTrip := setUpReceiveFrom(t)
	avg := int(testing.AllocsPerRun(1000, roundTrip))
	if avg > maxAllocs {
		t.Fatalf("expected %d allocs in ReceiveFrom, got %v", maxAllocs, avg)
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

	conn.SetPrivateKey(wgkey.Private{0: 1})

	discoKey := tailcfg.DiscoKey{31: 1}
	nodeKey1 := tailcfg.NodeKey{0: 'N', 1: 'K', 2: '1'}
	nodeKey2 := tailcfg.NodeKey{0: 'N', 1: 'K', 2: '2'}

	conn.SetNetworkMap(&netmap.NetworkMap{
		Peers: []*tailcfg.Node{
			{
				Key:       nodeKey1,
				DiscoKey:  discoKey,
				Endpoints: []string{"192.168.1.2:345"},
			},
		},
	})
	_, err := conn.ParseEndpoint(wgkey.Key(nodeKey1).HexString())
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

	de, ok := conn.peerMap.endpointForDiscoKey(discoKey)
	if ok && de.publicKey != nodeKey2 {
		t.Fatalf("discoEndpoint public key = %q; want %q", de.publicKey[:], nodeKey2[:])
	}

	log := buf.String()
	wantSub := map[string]int{
		"magicsock: got updated network map; 1 peers": 2,
		"magicsock: disco key discokey:0000000000000000000000000000000000000000000000000000000000000001 changed from node key [TksxA] to [TksyA]": 1,
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
				Addr: netaddr.IPPortFrom(netaddr.IP{}, port),
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
		return addrLatency{netaddr.MustParseIPPort(ipps), d}
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
