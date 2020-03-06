// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/stun"
	"tailscale.com/types/key"
)

func TestListen(t *testing.T) {
	// TODO(crawshaw): when offline this test spends a while trying to connect to real derp servers.

	epCh := make(chan string, 16)
	epFunc := func(endpoints []string) {
		for _, ep := range endpoints {
			epCh <- ep
		}
	}

	stunAddr, stunCleanupFn := serveSTUN(t)
	defer stunCleanupFn()

	port := pickPort(t)
	conn, err := Listen(Options{
		Port:          port,
		STUN:          []string{stunAddr.String()},
		EndpointsFunc: epFunc,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() {
		var pkt [64 << 10]byte
		for {
			_, _, _, err := conn.ReceiveIPv4(pkt[:])
			if err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
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
		case <-ctx.Done():
			t.Fatalf("timeout with endpoints: %v", endpoints)
		}
	}
}

func pickPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestDerpIPConstant(t *testing.T) {
	if DerpMagicIP != derpMagicIP.String() {
		t.Errorf("str %q != IP %v", DerpMagicIP, derpMagicIP)
	}
	if len(derpMagicIP) != 4 {
		t.Errorf("derpMagicIP is len %d; want 4", len(derpMagicIP))
	}
}

func TestPickDERPFallback(t *testing.T) {
	if len(derpNodeID) == 0 {
		t.Fatal("no DERP nodes registered; this test needs an update after DERP node runtime discovery")
	}

	c := new(Conn)
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
		c = new(Conn)
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
}

type stunStats struct {
	mu       sync.Mutex
	readIPv4 int
	readIPv6 int
}

func serveSTUN(t *testing.T) (addr net.Addr, cleanupFn func()) {
	t.Helper()

	// TODO(crawshaw): use stats to test re-STUN logic
	var stats stunStats

	pc, err := net.ListenPacket("udp4", ":3478")
	if err != nil {
		t.Fatalf("failed to open STUN listener: %v", err)
	}

	go runSTUN(pc, &stats)
	return pc.LocalAddr(), func() { pc.Close() }
}

func runSTUN(pc net.PacketConn, stats *stunStats) {
	var buf [64 << 10]byte
	for {
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			if strings.Contains(err.Error(), "closed network connection") {
				log.Printf("STUN server shutdown")
				return
			}
			continue
		}
		ua := addr.(*net.UDPAddr)
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			continue
		}

		stats.mu.Lock()
		if ua.IP.To4() != nil {
			stats.readIPv4++
		} else {
			stats.readIPv6++
		}
		stats.mu.Unlock()

		res := stun.Response(txid, ua.IP, uint16(ua.Port))
		if _, err := pc.WriteTo(res, addr); err != nil {
			log.Printf("STUN server write failed: %v", err)
		}
	}
}

func makeConfigs(t *testing.T, ports []uint16) []wgcfg.Config {
	t.Helper()

	var privKeys []wgcfg.PrivateKey
	var addresses [][]wgcfg.CIDR

	for i := range ports {
		privKey, err := wgcfg.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		privKeys = append(privKeys, privKey)

		addresses = append(addresses, []wgcfg.CIDR{
			parseCIDR(t, fmt.Sprintf("1.0.0.%d/32", i+1)),
		})
	}

	var cfgs []wgcfg.Config
	for i, port := range ports {
		cfg := wgcfg.Config{
			Name:       fmt.Sprintf("peer%d", i+1),
			PrivateKey: privKeys[i],
			Addresses:  addresses[i],
			ListenPort: port,
		}
		for peerNum, port := range ports {
			if peerNum == i {
				continue
			}
			peer := wgcfg.Peer{
				PublicKey:  privKeys[peerNum].Public(),
				AllowedIPs: addresses[peerNum],
				Endpoints: []wgcfg.Endpoint{{
					Host: "127.0.0.1",
					Port: port,
				}},
				PersistentKeepalive: 25,
			}
			cfg.Peers = append(cfg.Peers, peer)
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs
}

func parseCIDR(t *testing.T, addr string) wgcfg.CIDR {
	t.Helper()
	cidr, err := wgcfg.ParseCIDR(addr)
	if err != nil {
		t.Fatal(err)
	}
	return *cidr
}

func runDERP(t *testing.T) (s *derp.Server, addr string, cleanupFn func()) {
	var serverPrivateKey key.Private
	if _, err := crand.Read(serverPrivateKey[:]); err != nil {
		t.Fatal(err)
	}

	s = derp.NewServer(serverPrivateKey, t.Logf)
	// TODO: cleanup httpsrv.CloseClientConnections / Close

	httpsrv := httptest.NewUnstartedServer(derphttp.Handler(s))
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()
	t.Logf("DERP server URL: %s", httpsrv.URL)

	addr = strings.TrimPrefix(httpsrv.URL, "https://")
	cleanupFn = func() {
		s.Close()
	}

	return s, addr, cleanupFn
}

func stashDerpers() (cleanupFn func()) {
	origDerpHostOfIndex := derpHostOfIndex
	origDerpIndexOfHost := derpIndexOfHost
	origDerpNodeID := derpNodeID
	derpHostOfIndex = map[int]string{}
	derpIndexOfHost = map[string]int{}
	derpNodeID = nil
	return func() {
		derpHostOfIndex = origDerpHostOfIndex
		derpIndexOfHost = origDerpIndexOfHost
		derpNodeID = origDerpNodeID
	}
}

func TestTwoDevicePing(t *testing.T) {
	// Wipe default DERP list, add local server.
	// (Do it now, or derpHost will try to connect to derp1.tailscale.com.)
	derpServer, derpAddr, derpCleanupFn := runDERP(t)
	defer derpCleanupFn()
	defer stashDerpers()()

	addDerper(1, derpAddr)

	stunAddr, stunCleanupFn := serveSTUN(t)
	defer stunCleanupFn()

	epCh1 := make(chan []string, 16)
	conn1, err := Listen(Options{
		STUN: []string{stunAddr.String()},
		EndpointsFunc: func(eps []string) {
			epCh1 <- eps
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	conn1.derpMu.Lock()
	conn1.derpTLSConfig = &tls.Config{InsecureSkipVerify: true}
	conn1.derpMu.Unlock()

	epCh2 := make(chan []string, 16)
	conn2, err := Listen(Options{
		STUN: []string{stunAddr.String()},
		EndpointsFunc: func(eps []string) {
			epCh2 <- eps
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	conn2.derpMu.Lock()
	conn2.derpTLSConfig = &tls.Config{InsecureSkipVerify: true}
	conn2.derpMu.Unlock()

	ports := []uint16{conn1.LocalPort(), conn2.LocalPort()}
	cfgs := makeConfigs(t, ports)

	if err := conn1.SetPrivateKey(cfgs[0].PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := conn2.SetPrivateKey(cfgs[1].PrivateKey); err != nil {
		t.Fatal(err)
	}

	tun1 := tuntest.NewChannelTUN()
	dev1 := device.NewDevice(tun1.TUN(), &device.DeviceOptions{
		Logger:         device.NewLogger(device.LogLevelDebug, "dev1: "),
		CreateEndpoint: conn1.CreateEndpoint,
		CreateBind:     conn1.CreateBind,
		SkipBindUpdate: true,
	})
	dev1.Up()
	//defer dev1.Close() TODO(crawshaw): this hangs
	if err := dev1.Reconfig(&cfgs[0]); err != nil {
		t.Fatal(err)
	}

	tun2 := tuntest.NewChannelTUN()
	dev2 := device.NewDevice(tun2.TUN(), &device.DeviceOptions{
		Logger:         device.NewLogger(device.LogLevelDebug, "dev2: "),
		CreateEndpoint: conn2.CreateEndpoint,
		CreateBind:     conn2.CreateBind,
		SkipBindUpdate: true,
	})
	dev2.Up()
	//defer dev2.Close() TODO(crawshaw): this hangs

	if err := dev2.Reconfig(&cfgs[1]); err != nil {
		t.Fatal(err)
	}

	ping1 := func(t *testing.T) {
		t.Helper()

		msg2to1 := tuntest.Ping(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2"))
		tun2.Outbound <- msg2to1
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		select {
		case msgRecv := <-tun1.Inbound:
			if !bytes.Equal(msg2to1, msgRecv) {
				t.Error("ping did not transit correctly")
			}
		case <-ctx.Done():
			t.Error("ping did not transit")
		}
	}
	ping2 := func(t *testing.T) {
		t.Helper()

		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
		tun1.Outbound <- msg1to2
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		select {
		case msgRecv := <-tun2.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-ctx.Done():
			t.Error("return ping did not transit")
		}
	}

	t.Run("ping 1.0.0.1", func(t *testing.T) { ping1(t) })
	t.Run("ping 1.0.0.2", func(t *testing.T) { ping2(t) })
	t.Run("ping 1.0.0.2 via SendPacket", func(t *testing.T) {
		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
		if err := dev1.SendPacket(msg1to2); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		select {
		case msgRecv := <-tun2.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-ctx.Done():
			t.Error("return ping did not transit")
		}
	})

	t.Run("no-op dev1 reconfig", func(t *testing.T) {
		if err := dev1.Reconfig(&cfgs[0]); err != nil {
			t.Fatal(err)
		}
		ping1(t)
		ping2(t)
	})

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
			tun1.Outbound <- b
			time.Sleep(interPacketGap)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for i := 0; i < count; i++ {
			b := msg(i)
			select {
			case msgRecv := <-tun2.Inbound:
				if !bytes.Equal(b, msgRecv) {
					if strict {
						t.Errorf("return ping %d did not transit correctly: %s", i, cmp.Diff(b, msgRecv))
					}
				}
			case <-ctx.Done():
				if strict {
					t.Fatalf("return ping %d did not transit", i)
				}
			}
		}

	}

	t.Run("ping 1.0.0.1 x50", func(t *testing.T) {
		pingSeq(t, 50, 0, true)
	})

	// Add DERP relay.
	derpEp := wgcfg.Endpoint{Host: "127.3.3.40", Port: 1}
	ep0 := cfgs[0].Peers[0].Endpoints
	ep0 = append([]wgcfg.Endpoint{derpEp}, ep0...)
	cfgs[0].Peers[0].Endpoints = ep0
	ep1 := cfgs[1].Peers[0].Endpoints
	ep1 = append([]wgcfg.Endpoint{derpEp}, ep1...)
	cfgs[1].Peers[0].Endpoints = ep1
	if err := dev1.Reconfig(&cfgs[0]); err != nil {
		t.Fatal(err)
	}
	if err := dev2.Reconfig(&cfgs[1]); err != nil {
		t.Fatal(err)
	}

	t.Run("add DERP", func(t *testing.T) {
		defer func() {
			t.Logf("DERP vars: %s", derpServer.ExpVar().String())
		}()
		pingSeq(t, 20, 0, true)
	})

	// Disable real route.
	cfgs[0].Peers[0].Endpoints = []wgcfg.Endpoint{derpEp}
	cfgs[1].Peers[0].Endpoints = []wgcfg.Endpoint{derpEp}
	if err := dev1.Reconfig(&cfgs[0]); err != nil {
		t.Fatal(err)
	}
	if err := dev2.Reconfig(&cfgs[1]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond) // TODO remove

	t.Run("all traffic over DERP", func(t *testing.T) {
		defer func() {
			t.Logf("DERP vars: %s", derpServer.ExpVar().String())
			if t.Failed() || true {
				uapi1, _ := cfgs[0].ToUAPI()
				t.Logf("cfg0: %v", uapi1)
				uapi2, _ := cfgs[1].ToUAPI()
				t.Logf("cfg1: %v", uapi2)
			}
		}()
		pingSeq(t, 20, 0, true)
	})

	dev1.RemoveAllPeers()
	dev2.RemoveAllPeers()

	// Give one peer a non-DERP endpoint. We expect the other to
	// accept it via roamAddr.
	cfgs[0].Peers[0].Endpoints = ep0
	if ep2 := cfgs[1].Peers[0].Endpoints; len(ep2) != 1 {
		t.Errorf("unexpected peer endpoints in dev2: %v", ep2)
	}
	if err := dev2.Reconfig(&cfgs[1]); err != nil {
		t.Fatal(err)
	}
	if err := dev1.Reconfig(&cfgs[0]); err != nil {
		t.Fatal(err)
	}
	// Dear future human debugging a test failure here: this test is
	// flaky, and very infrequently will drop 1-2 of the 50 ping
	// packets. This does not affect normal operation of tailscaled,
	// but makes this test fail.
	//
	// TODO(danderson): finish root-causing and de-flake this test.
	t.Run("one real route is enough thanks to spray", func(t *testing.T) {
		pingSeq(t, 50, 700*time.Millisecond, false)

		ep2 := dev2.Config().Peers[0].Endpoints
		if len(ep2) != 2 {
			t.Error("handshake spray failed to find real route")
		}
	})
}
