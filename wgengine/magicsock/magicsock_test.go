// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/stun"
)

func TestListen(t *testing.T) {
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

func TestTwoDevicePing(t *testing.T) {
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

	ports := []uint16{conn1.LocalPort(), conn2.LocalPort()}
	cfgs := makeConfigs(t, ports)

	uapi1, _ := cfgs[0].ToUAPI()
	t.Logf("cfg0: %v", uapi1)
	uapi2, _ := cfgs[1].ToUAPI()
	t.Logf("cfg1: %v", uapi2)

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
		select {
		case msgRecv := <-tun1.Inbound:
			if !bytes.Equal(msg2to1, msgRecv) {
				t.Error("ping did not transit correctly")
			}
		case <-time.After(1 * time.Second):
			t.Error("ping did not transit")
		}
	}
	ping2 := func(t *testing.T) {
		t.Helper()

		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
		tun1.Outbound <- msg1to2
		select {
		case msgRecv := <-tun2.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-time.After(1 * time.Second):
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
		select {
		case msgRecv := <-tun2.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-time.After(1 * time.Second):
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
}
