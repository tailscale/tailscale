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
	"encoding/json"
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
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"golang.org/x/crypto/nacl/box"
	"inet.af/netaddr"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/derp/derpmap"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/types/wgkey"
	"tailscale.com/util/cibuild"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/tstun"
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
			1: &tailcfg.DERPRegion{
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:         "t1",
						RegionID:     1,
						HostName:     "test-node.unused",
						IPv4:         "127.0.0.1",
						IPv6:         "none",
						STUNPort:     stunAddr.Port,
						DERPTestPort: httpsrv.Listener.Addr().(*net.TCPAddr).Port,
						STUNTestIP:   stunIP.String(),
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
	epCh       chan []string       // endpoint updates produced by this peer
	conn       *Conn               // the magicsock itself
	tun        *tuntest.ChannelTUN // TUN device to send/receive packets
	tsTun      *tstun.TUN          // wrapped tun that implements filtering and wgengine hooks
	dev        *device.Device      // the wireguard-go Device that connects the previous things
	wgLogger   *wglog.Logger       // wireguard-go log wrapper
}

// newMagicStack builds and initializes an idle magicsock and
// friends. You need to call conn.SetNetworkMap and dev.Reconfig
// before anything interesting happens.
func newMagicStack(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap, disableLegacy bool) *magicStack {
	t.Helper()

	privateKey, err := wgkey.NewPrivate()
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	epCh := make(chan []string, 100) // arbitrary
	conn, err := NewConn(Options{
		Logf:           logf,
		PacketListener: l,
		EndpointsFunc: func(eps []string) {
			epCh <- eps
		},
		SimulatedNetwork:        l != nettype.Std{},
		DisableLegacyNetworking: disableLegacy,
	})
	if err != nil {
		t.Fatalf("constructing magicsock: %v", err)
	}
	conn.Start()
	conn.SetDERPMap(derpMap)
	if err := conn.SetPrivateKey(privateKey); err != nil {
		t.Fatalf("setting private key in magicsock: %v", err)
	}

	tun := tuntest.NewChannelTUN()
	tsTun := tstun.WrapTUN(logf, tun.TUN())
	tsTun.SetFilter(filter.NewAllowAllForTest(logf))

	wgLogger := wglog.NewLogger(logf)
	dev := device.NewDevice(tsTun, &device.DeviceOptions{
		Logger:         wgLogger.DeviceLogger,
		CreateEndpoint: conn.CreateEndpoint,
		CreateBind:     conn.CreateBind,
		SkipBindUpdate: true,
	})
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
func (s *magicStack) IP(t *testing.T) netaddr.IP {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		st := s.Status()
		if len(st.TailscaleIPs) > 0 {
			return st.TailscaleIPs[0]
		}
	}
	t.Fatal("timed out waiting for magicstack to get an IP assigned")
	panic("unreachable") // compiler doesn't know t.Fatal panics
}

// meshStacks monitors epCh on all given ms, and plumbs network maps
// and WireGuard configs into everyone to form a full mesh that has up
// to date endpoint info. Think of it as an extremely stripped down
// and purpose-built Tailscale control plane.
//
// meshStacks only supports disco connections, not legacy logic.
func meshStacks(logf logger.Logf, ms []*magicStack) (cleanup func()) {
	ctx, cancel := context.WithCancel(context.Background())

	// Serialize all reconfigurations globally, just to keep things
	// simpler.
	var (
		mu  sync.Mutex
		eps = make([][]string, len(ms))
	)

	buildNetmapLocked := func(myIdx int) *netmap.NetworkMap {
		me := ms[myIdx]
		nm := &netmap.NetworkMap{
			PrivateKey: me.privateKey,
			NodeKey:    tailcfg.NodeKey(me.privateKey.Public()),
			Addresses:  []netaddr.IPPrefix{{IP: netaddr.IPv4(1, 0, 0, byte(myIdx+1)), Bits: 32}},
		}
		for i, peer := range ms {
			if i == myIdx {
				continue
			}
			addrs := []netaddr.IPPrefix{{IP: netaddr.IPv4(1, 0, 0, byte(i+1)), Bits: 32}}
			peer := &tailcfg.Node{
				ID:         tailcfg.NodeID(i + 1),
				Name:       fmt.Sprintf("node%d", i+1),
				Key:        tailcfg.NodeKey(peer.privateKey.Public()),
				DiscoKey:   peer.conn.DiscoPublicKey(),
				Addresses:  addrs,
				AllowedIPs: addrs,
				Endpoints:  eps[i],
				DERP:       "127.3.3.40:1",
			}
			nm.Peers = append(nm.Peers, peer)
		}

		return nm
	}

	updateEps := func(idx int, newEps []string) {
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
			wg, err := nmcfg.WGCfg(nm, logf, netmap.AllowSingleHosts)
			if err != nil {
				// We're too far from the *testing.T to be graceful,
				// blow up. Shouldn't happen anyway.
				panic(fmt.Sprintf("failed to construct wgcfg from netmap: %v", err))
			}
			if err := m.Reconfig(wg); err != nil {
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
	epFunc := func(endpoints []string) {
		for _, ep := range endpoints {
			epCh <- ep
		}
	}

	stunAddr, stunCleanupFn := stuntest.Serve(t)
	defer stunCleanupFn()

	port := pickPort(t)
	conn, err := NewConn(Options{
		Port:                    port,
		EndpointsFunc:           epFunc,
		Logf:                    t.Logf,
		DisableLegacyNetworking: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDERPMap(stuntest.DERPMapOf(stunAddr.String()))
	conn.SetPrivateKey(wgkey.Private(key.NewPrivate()))
	conn.Start()

	go func() {
		var pkt [64 << 10]byte
		for {
			_, _, err := conn.ReceiveIPv4(pkt[:])
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

func TestDerpIPConstant(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	if DerpMagicIP != derpMagicIP.String() {
		t.Errorf("str %q != IP %v", DerpMagicIP, derpMagicIP)
	}
	if len(derpMagicIP) != 4 {
		t.Errorf("derpMagicIP is len %d; want 4", len(derpMagicIP))
	}
}

func TestPickDERPFallback(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	c := newConn()
	c.derpMap = derpmap.Prod()
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
		c.derpMap = derpmap.Prod()
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

	// But move if peers are elsewhere.
	const otherNode = 789
	c.addrsByKey = map[key.Public]*addrSet{
		key.Public{1}: &addrSet{addrs: []net.UDPAddr{{IP: derpMagicIP, Port: otherNode}}},
	}
	if got := c.pickDERPFallback(); got != otherNode {
		t.Errorf("didn't join peers: got %v; want %v", got, someNode)
	}
}

func makeConfigs(t *testing.T, addrs []netaddr.IPPort) []wgcfg.Config {
	t.Helper()

	var privKeys []wgcfg.PrivateKey
	var addresses [][]netaddr.IPPrefix

	for i := range addrs {
		privKey, err := wgkey.NewPrivate()
		if err != nil {
			t.Fatal(err)
		}
		privKeys = append(privKeys, wgcfg.PrivateKey(privKey))

		addresses = append(addresses, []netaddr.IPPrefix{
			parseCIDR(t, fmt.Sprintf("1.0.0.%d/32", i+1)),
		})
	}

	var cfgs []wgcfg.Config
	for i, addr := range addrs {
		cfg := wgcfg.Config{
			Name:       fmt.Sprintf("peer%d", i+1),
			PrivateKey: privKeys[i],
			Addresses:  addresses[i],
			ListenPort: addr.Port,
		}
		for peerNum, addr := range addrs {
			if peerNum == i {
				continue
			}
			peer := wgcfg.Peer{
				PublicKey:           privKeys[peerNum].Public(),
				AllowedIPs:          addresses[peerNum],
				Endpoints:           addr.String(),
				PersistentKeepalive: 25,
			}
			cfg.Peers = append(cfg.Peers, peer)
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs
}

func parseCIDR(t *testing.T, addr string) netaddr.IPPrefix {
	t.Helper()
	cidr, err := netaddr.ParseIPPrefix(addr)
	if err != nil {
		t.Fatal(err)
	}
	return cidr
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
		EndpointsFunc:           func(eps []string) {},
		Logf:                    t.Logf,
		DisableLegacyNetworking: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Start()
	defer conn.Close()

	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), &device.DeviceOptions{
		Logger:         wglog.NewLogger(t.Logf).DeviceLogger,
		CreateEndpoint: conn.CreateEndpoint,
		CreateBind:     conn.CreateBind,
		SkipBindUpdate: true,
	})
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

	ms1 := newMagicStack(t, logger.WithPrefix(logf, "conn1: "), d.m1, derpMap, true)
	defer ms1.Close()
	ms2 := newMagicStack(t, logger.WithPrefix(logf, "conn2: "), d.m2, derpMap, true)
	defer ms2.Close()

	cleanup = meshStacks(t.Logf, []*magicStack{ms1, ms2})
	defer cleanup()

	pkt := tuntest.Ping(ms2.IP(t).IPAddr().IP, ms1.IP(t).IPAddr().IP)

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

func TestTwoDevicePing(t *testing.T) {
	l, ip := nettype.Std{}, netaddr.IPv4(127, 0, 0, 1)
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
			Prefix4: mustPrefix("192.168.0.0/24"),
		}
		lan2 := &natlab.Network{
			Name:    "lan2",
			Prefix4: mustPrefix("192.168.1.0/24"),
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

func mustPrefix(s string) netaddr.IPPrefix {
	pfx, err := netaddr.ParseIPPrefix(s)
	if err != nil {
		panic(err)
	}
	return pfx
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
		pkt := tuntest.Ping(dst.IP(t).IPAddr().IP, src.IP(t).IPAddr().IP)
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
		logf("sending ping stream from %s (%s) to %s (%s)", src, src.IP(t), dst, dst.IP(t))
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

	m1 := newMagicStack(t, logger.WithPrefix(logf, "conn1: "), d.m1, derpMap, true)
	defer m1.Close()
	m2 := newMagicStack(t, logger.WithPrefix(logf, "conn2: "), d.m2, derpMap, true)
	defer m2.Close()

	cleanup = meshStacks(logf, []*magicStack{m1, m2})
	defer cleanup()

	m1IP := m1.IP(t)
	m2IP := m2.IP(t)
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

	m1 := newMagicStack(t, logf, d.m1, derpMap, false)
	defer m1.Close()
	m2 := newMagicStack(t, logf, d.m2, derpMap, false)
	defer m2.Close()

	addrs := []netaddr.IPPort{
		{IP: d.m1IP, Port: m1.conn.LocalPort()},
		{IP: d.m2IP, Port: m2.conn.LocalPort()},
	}
	cfgs := makeConfigs(t, addrs)

	if err := m1.Reconfig(&cfgs[0]); err != nil {
		t.Fatal(err)
	}
	if err := m2.Reconfig(&cfgs[1]); err != nil {
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

	ping1 := func(t *testing.T) {
		msg2to1 := tuntest.Ping(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2"))
		m2.tun.Outbound <- msg2to1
		t.Log("ping1 sent")
		select {
		case msgRecv := <-m1.tun.Inbound:
			if !bytes.Equal(msg2to1, msgRecv) {
				t.Error("ping did not transit correctly")
			}
		case <-time.After(pingTimeout):
			t.Error("ping did not transit")
		}
	}
	ping2 := func(t *testing.T) {
		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
		m1.tun.Outbound <- msg1to2
		t.Log("ping2 sent")
		select {
		case msgRecv := <-m2.tun.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-time.After(pingTimeout):
			t.Error("return ping did not transit")
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
		if err := m1.tsTun.InjectOutbound(msg1to2); err != nil {
			t.Fatal(err)
		}
		t.Log("SendPacket sent")
		select {
		case msgRecv := <-m2.tun.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-time.After(pingTimeout):
			t.Error("return ping did not transit")
		}
	})

	t.Run("no-op dev1 reconfig", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		if err := m1.Reconfig(&cfgs[0]); err != nil {
			t.Fatal(err)
		}
		ping1(t)
		ping2(t)
	})

	// TODO: Remove this once the following tests are reliable.
	if run, _ := strconv.ParseBool(os.Getenv("RUN_CURSED_TESTS")); !run {
		t.Skip("skipping following tests because RUN_CURSED_TESTS is not set.")
	}

	pingSeq := func(t *testing.T, count int, totalTime time.Duration, strict bool) {
		msg := func(i int) []byte {
			b := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
			b[len(b)-1] = byte(i) // set seq num
			return b
		}

		// Space out ping transmissions so that the overall
		// transmission happens in totalTime.
		//
		// We do this because the packet spray logic in magicsock is
		// time-based to allow for reliable NAT traversal. However,
		// for the packet spraying test further down, there needs to
		// be at least 1 sprayed packet that is not the handshake, in
		// case the handshake gets eaten by the race resolution logic.
		//
		// This is an inherent "race by design" in our current
		// magicsock+wireguard-go codebase: sometimes, racing
		// handshakes will result in a sub-optimal path for a few
		// hundred milliseconds, until a subsequent spray corrects the
		// issue. In order for the test to reflect that magicsock
		// works as designed, we have to space out packet transmission
		// here.
		interPacketGap := totalTime / time.Duration(count)
		if interPacketGap < 1*time.Millisecond {
			interPacketGap = 0
		}

		for i := 0; i < count; i++ {
			b := msg(i)
			m1.tun.Outbound <- b
			time.Sleep(interPacketGap)
		}

		for i := 0; i < count; i++ {
			b := msg(i)
			select {
			case msgRecv := <-m2.tun.Inbound:
				if !bytes.Equal(b, msgRecv) {
					if strict {
						t.Errorf("return ping %d did not transit correctly: %s", i, cmp.Diff(b, msgRecv))
					}
				}
			case <-time.After(pingTimeout):
				if strict {
					t.Errorf("return ping %d did not transit", i)
				}
			}
		}
	}

	t.Run("ping 1.0.0.1 x50", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		pingSeq(t, 50, 0, true)
	})

	// Add DERP relay.
	derpEp := "127.3.3.40:1"
	ep0 := cfgs[0].Peers[0].Endpoints
	ep0 = derpEp + "," + ep0
	cfgs[0].Peers[0].Endpoints = ep0
	ep1 := cfgs[1].Peers[0].Endpoints
	ep1 = derpEp + "," + ep1
	cfgs[1].Peers[0].Endpoints = ep1
	if err := m1.Reconfig(&cfgs[0]); err != nil {
		t.Fatal(err)
	}
	if err := m2.Reconfig(&cfgs[1]); err != nil {
		t.Fatal(err)
	}

	t.Run("add DERP", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		pingSeq(t, 20, 0, true)
	})

	// Disable real route.
	cfgs[0].Peers[0].Endpoints = derpEp
	cfgs[1].Peers[0].Endpoints = derpEp
	if err := m1.Reconfig(&cfgs[0]); err != nil {
		t.Fatal(err)
	}
	if err := m2.Reconfig(&cfgs[1]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond) // TODO remove

	t.Run("all traffic over DERP", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		defer func() {
			if t.Failed() || true {
				logf("cfg0: %v", stringifyConfig(cfgs[0]))
				logf("cfg1: %v", stringifyConfig(cfgs[1]))
			}
		}()
		pingSeq(t, 20, 0, true)
	})

	m1.dev.RemoveAllPeers()
	m2.dev.RemoveAllPeers()

	// Give one peer a non-DERP endpoint. We expect the other to
	// accept it via roamAddr.
	cfgs[0].Peers[0].Endpoints = ep0
	if ep2 := cfgs[1].Peers[0].Endpoints; len(ep2) != 1 {
		t.Errorf("unexpected peer endpoints in dev2: %v", ep2)
	}
	if err := m2.Reconfig(&cfgs[1]); err != nil {
		t.Fatal(err)
	}
	if err := m1.Reconfig(&cfgs[0]); err != nil {
		t.Fatal(err)
	}
	// Dear future human debugging a test failure here: this test is
	// flaky, and very infrequently will drop 1-2 of the 50 ping
	// packets. This does not affect normal operation of tailscaled,
	// but makes this test fail.
	//
	// TODO(danderson): finish root-causing and de-flake this test.
	t.Run("one real route is enough thanks to spray", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		pingSeq(t, 50, 700*time.Millisecond, false)

		cfg, err := wgcfg.DeviceConfig(m2.dev)
		if err != nil {
			t.Fatal(err)
		}
		ep2 := cfg.Peers[0].Endpoints
		if len(ep2) != 2 {
			t.Error("handshake spray failed to find real route")
		}
	})
}

// TestAddrSet tests addrSet appendDests and updateDst.
func TestAddrSet(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	mustIPPortPtr := func(s string) *netaddr.IPPort {
		t.Helper()
		ipp, err := netaddr.ParseIPPort(s)
		if err != nil {
			t.Fatal(err)
		}
		return &ipp
	}
	mustUDPAddr := func(s string) *net.UDPAddr {
		return mustIPPortPtr(s).UDPAddr()
	}
	udpAddrs := func(ss ...string) (ret []net.UDPAddr) {
		t.Helper()
		for _, s := range ss {
			ret = append(ret, *mustUDPAddr(s))
		}
		return ret
	}
	joinUDPs := func(in []netaddr.IPPort) string {
		var sb strings.Builder
		for i, ua := range in {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(ua.String())
		}
		return sb.String()
	}
	var (
		regPacket   = []byte("some regular packet")
		sprayPacket = []byte("0000")
	)
	binary.LittleEndian.PutUint32(sprayPacket[:4], device.MessageInitiationType)
	if !shouldSprayPacket(sprayPacket) {
		t.Fatal("sprayPacket should be classified as a spray packet for testing")
	}

	// A step is either a b+want appendDests tests, or an
	// UpdateDst call, depending on which fields are set.
	type step struct {
		// advance is the time to advance the fake clock
		// before the step.
		advance time.Duration

		// updateDst, if set, does an UpdateDst call and
		// b+want are ignored.
		updateDst *net.UDPAddr

		b    []byte
		want string // comma-separated
	}
	tests := []struct {
		name     string
		as       *addrSet
		steps    []step
		logCheck func(t *testing.T, logged []byte)
	}{
		{
			name: "reg_packet_no_curaddr",
			as: &addrSet{
				addrs:    udpAddrs("127.3.3.40:1", "123.45.67.89:123", "10.0.0.1:123"),
				curAddr:  -1, // unknown
				roamAddr: nil,
			},
			steps: []step{
				{b: regPacket, want: "127.3.3.40:1"},
			},
		},
		{
			name: "reg_packet_have_curaddr",
			as: &addrSet{
				addrs:    udpAddrs("127.3.3.40:1", "123.45.67.89:123", "10.0.0.1:123"),
				curAddr:  1, // global IP
				roamAddr: nil,
			},
			steps: []step{
				{b: regPacket, want: "123.45.67.89:123"},
			},
		},
		{
			name: "reg_packet_have_roamaddr",
			as: &addrSet{
				addrs:    udpAddrs("127.3.3.40:1", "123.45.67.89:123", "10.0.0.1:123"),
				curAddr:  2, // should be ignored
				roamAddr: mustIPPortPtr("5.6.7.8:123"),
			},
			steps: []step{
				{b: regPacket, want: "5.6.7.8:123"},
				{updateDst: mustUDPAddr("10.0.0.1:123")}, // no more roaming
				{b: regPacket, want: "10.0.0.1:123"},
			},
		},
		{
			name: "start_roaming",
			as: &addrSet{
				addrs:   udpAddrs("127.3.3.40:1", "123.45.67.89:123", "10.0.0.1:123"),
				curAddr: 2,
			},
			steps: []step{
				{b: regPacket, want: "10.0.0.1:123"},
				{updateDst: mustUDPAddr("4.5.6.7:123")},
				{b: regPacket, want: "4.5.6.7:123"},
				{updateDst: mustUDPAddr("5.6.7.8:123")},
				{b: regPacket, want: "5.6.7.8:123"},
				{updateDst: mustUDPAddr("123.45.67.89:123")}, // end roaming
				{b: regPacket, want: "123.45.67.89:123"},
			},
		},
		{
			name: "spray_packet",
			as: &addrSet{
				addrs:    udpAddrs("127.3.3.40:1", "123.45.67.89:123", "10.0.0.1:123"),
				curAddr:  2, // should be ignored
				roamAddr: mustIPPortPtr("5.6.7.8:123"),
			},
			steps: []step{
				{b: sprayPacket, want: "127.3.3.40:1,123.45.67.89:123,10.0.0.1:123,5.6.7.8:123"},
				{advance: 300 * time.Millisecond, b: regPacket, want: "127.3.3.40:1,123.45.67.89:123,10.0.0.1:123,5.6.7.8:123"},
				{advance: 300 * time.Millisecond, b: regPacket, want: "127.3.3.40:1,123.45.67.89:123,10.0.0.1:123,5.6.7.8:123"},
				{advance: 3, b: regPacket, want: "5.6.7.8:123"},
				{advance: 2 * time.Millisecond, updateDst: mustUDPAddr("10.0.0.1:123")},
				{advance: 3, b: regPacket, want: "10.0.0.1:123"},
			},
		},
		{
			name: "low_pri",
			as: &addrSet{
				addrs:   udpAddrs("127.3.3.40:1", "123.45.67.89:123", "10.0.0.1:123"),
				curAddr: 2,
			},
			steps: []step{
				{updateDst: mustUDPAddr("123.45.67.89:123")},
				{updateDst: mustUDPAddr("123.45.67.89:123")},
			},
			logCheck: func(t *testing.T, logged []byte) {
				if n := bytes.Count(logged, []byte(", keeping current ")); n != 1 {
					t.Errorf("low-prio keeping current logged %d times; want 1", n)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			faket := time.Unix(0, 0)
			var logBuf bytes.Buffer
			tt.as.Logf = func(format string, args ...interface{}) {
				fmt.Fprintf(&logBuf, format, args...)
				t.Logf(format, args...)
			}
			tt.as.clock = func() time.Time { return faket }
			initAddrSet(tt.as)
			for i, st := range tt.steps {
				faket = faket.Add(st.advance)

				if st.updateDst != nil {
					if err := tt.as.updateDst(st.updateDst); err != nil {
						t.Fatal(err)
					}
					continue
				}
				got, _ := tt.as.appendDests(nil, st.b)
				if gotStr := joinUDPs(got); gotStr != st.want {
					t.Errorf("step %d: got %v; want %v", i, gotStr, st.want)
				}
			}
			if tt.logCheck != nil {
				tt.logCheck(t, logBuf.Bytes())
			}
		})
	}
}

// initAddrSet initializes fields in the provided incomplete addrSet
// to satisfying invariants within magicsock.
func initAddrSet(as *addrSet) {
	if as.roamAddr != nil && as.roamAddrStd == nil {
		as.roamAddrStd = as.roamAddr.UDPAddr()
	}
	if len(as.ipPorts) == 0 {
		for _, ua := range as.addrs {
			ipp, ok := netaddr.FromStdAddr(ua.IP, ua.Port, ua.Zone)
			if !ok {
				panic(fmt.Sprintf("bogus UDPAddr %+v", ua))
			}
			as.ipPorts = append(as.ipPorts, ipp)
		}
	}
}

func TestDiscoMessage(t *testing.T) {
	c := newConn()
	c.logf = t.Logf
	c.privateKey = key.NewPrivate()

	peer1Pub := c.DiscoPublicKey()
	peer1Priv := c.discoPrivate
	c.endpointOfDisco = map[tailcfg.DiscoKey]*discoEndpoint{
		tailcfg.DiscoKey(peer1Pub): &discoEndpoint{
			// ... (enough for this test)
		},
	}
	c.nodeOfDisco = map[tailcfg.DiscoKey]*tailcfg.Node{
		tailcfg.DiscoKey(peer1Pub): &tailcfg.Node{
			// ... (enough for this test)
		},
	}

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

// tests that having a discoEndpoint.String prevents wireguard-go's
// log.Printf("%v") of its conn.Endpoint values from using reflect to
// walk into read mutex while they're being used and then causing data
// races.
func TestDiscoStringLogRace(t *testing.T) {
	de := new(discoEndpoint)
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

func stringifyConfig(cfg wgcfg.Config) string {
	j, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	return string(j)
}

func Test32bitAlignment(t *testing.T) {
	var de discoEndpoint
	off := unsafe.Offsetof(de.lastRecvUnixAtomic)
	if off%8 != 0 {
		t.Fatalf("lastRecvUnixAtomic is not 8-byte aligned")
	}
	if !de.isFirstRecvActivityInAwhile() { // verify this doesn't panic on 32-bit
		t.Error("expected true")
	}
	if de.isFirstRecvActivityInAwhile() {
		t.Error("expected false on second call")
	}
	var c Conn
	atomic.AddInt64(&c.derpRecvCountAtomic, 1)
}

// newNonLegacyTestConn returns a new Conn with DisableLegacyNetworking set true.
func newNonLegacyTestConn(t testing.TB) *Conn {
	t.Helper()
	port := pickPort(t)
	conn, err := NewConn(Options{
		Logf: t.Logf,
		Port: port,
		EndpointsFunc: func(eps []string) {
			t.Logf("endpoints: %q", eps)
		},
		DisableLegacyNetworking: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// Tests concurrent DERP readers pushing DERP data into ReceiveIPv4
// (which should blend all DERP reads into UDP reads).
func TestDerpReceiveFromIPv4(t *testing.T) {
	conn := newNonLegacyTestConn(t)
	defer conn.Close()

	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sendConn.Close()
	nodeKey, _ := addTestEndpoint(conn, sendConn)

	var sends int = 250e3 // takes about a second
	if testing.Short() {
		sends /= 10
	}
	senders := runtime.NumCPU()
	sends -= (sends % senders)
	var wg sync.WaitGroup
	defer wg.Wait()
	t.Logf("doing %v sends over %d senders", sends, senders)

	ctx, cancel := context.WithCancel(context.Background())
	defer conn.Close()
	defer cancel()

	doneCtx, cancelDoneCtx := context.WithCancel(context.Background())
	cancelDoneCtx()

	for i := 0; i < senders; i++ {
		wg.Add(1)
		regionID := i + 1
		go func() {
			defer wg.Done()
			for i := 0; i < sends/senders; i++ {
				res := derpReadResult{
					regionID: regionID,
					n:        123,
					src:      key.Public(nodeKey),
					copyBuf:  func(dst []byte) int { return 123 },
				}
				// First send with the closed context. ~50% of
				// these should end up going through the
				// send-a-zero-derpReadResult path, returning
				// true, in which case we don't want to send again.
				// We test later that we hit the other path.
				if conn.sendDerpReadResult(doneCtx, res) {
					continue
				}

				if !conn.sendDerpReadResult(ctx, res) {
					t.Error("unexpected false")
					return
				}
			}
		}()
	}

	zeroSendsStart := testCounterZeroDerpReadResultSend.Value()

	buf := make([]byte, 1500)
	for i := 0; i < sends; i++ {
		n, ep, err := conn.ReceiveIPv4(buf)
		if err != nil {
			t.Fatal(err)
		}
		_ = n
		_ = ep
	}

	t.Logf("did %d ReceiveIPv4 calls", sends)

	zeroSends, zeroRecv := testCounterZeroDerpReadResultSend.Value(), testCounterZeroDerpReadResultRecv.Value()
	if zeroSends != zeroRecv {
		t.Errorf("did %d zero sends != %d corresponding receives", zeroSends, zeroRecv)
	}
	zeroSendDelta := zeroSends - zeroSendsStart
	if zeroSendDelta == 0 {
		t.Errorf("didn't see any sends of derpReadResult zero value")
	}
	if zeroSendDelta == int64(sends) {
		t.Errorf("saw %v sends of the derpReadResult zero value which was unexpectedly high (100%% of our %v sends)", zeroSendDelta, sends)
	}
}

// addTestEndpoint sets conn's network map to a single peer expected
// to receive packets from sendConn (or DERP), and returns that peer's
// nodekey and discokey.
func addTestEndpoint(conn *Conn, sendConn net.PacketConn) (tailcfg.NodeKey, tailcfg.DiscoKey) {
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
	conn.CreateEndpoint([32]byte(nodeKey), "0000000000000000000000000000000000000000000000000000000000000001.disco.tailscale:12345")
	conn.addValidDiscoPathForTest(discoKey, netaddr.MustParseIPPort(sendConn.LocalAddr().String()))
	return nodeKey, discoKey
}

func BenchmarkReceiveFrom(b *testing.B) {
	conn := newNonLegacyTestConn(b)
	defer conn.Close()

	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer sendConn.Close()

	addTestEndpoint(conn, sendConn)

	var dstAddr net.Addr = conn.pconn4.LocalAddr()
	sendBuf := make([]byte, 1<<10)
	for i := range sendBuf {
		sendBuf[i] = 'x'
	}

	buf := make([]byte, 2<<10)
	for i := 0; i < b.N; i++ {
		if _, err := sendConn.WriteTo(sendBuf, dstAddr); err != nil {
			b.Fatalf("WriteTo: %v", err)
		}
		n, ep, err := conn.ReceiveIPv4(buf)
		if err != nil {
			b.Fatal(err)
		}
		_ = n
		_ = ep
	}
}

func BenchmarkReceiveFrom_Native(b *testing.B) {
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
