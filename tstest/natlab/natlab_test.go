// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package natlab

import (
	"context"
	"fmt"
	"testing"
	"time"

	"inet.af/netaddr"
	"tailscale.com/tstest"
)

func TestAllocIPs(t *testing.T) {
	n := NewInternet()
	saw := map[netaddr.IP]bool{}
	for i := 0; i < 255; i++ {
		for _, f := range []func(*Interface) netaddr.IP{n.allocIPv4, n.allocIPv6} {
			ip := f(nil)
			if saw[ip] {
				t.Fatalf("got duplicate %v", ip)
			}
			saw[ip] = true
		}
	}

	// This should work:
	n.allocIPv6(nil)

	// But allocating another IPv4 should panic, exhausting the
	// limited /24 range:
	defer func() {
		if e := recover(); fmt.Sprint(e) != "pool exhausted" {
			t.Errorf("unexpected panic: %v", e)
		}
	}()
	n.allocIPv4(nil)
	t.Fatalf("expected panic from IPv4")
}

func TestSendPacket(t *testing.T) {
	internet := NewInternet()

	foo := &Machine{Name: "foo"}
	bar := &Machine{Name: "bar"}
	ifFoo := foo.Attach("eth0", internet)
	ifBar := bar.Attach("enp0s1", internet)

	fooAddr := netaddr.IPPort{IP: ifFoo.V4(), Port: 123}
	barAddr := netaddr.IPPort{IP: ifBar.V4(), Port: 456}

	ctx := context.Background()
	fooPC, err := foo.ListenPacket(ctx, "udp4", fooAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	barPC, err := bar.ListenPacket(ctx, "udp4", barAddr.String())
	if err != nil {
		t.Fatal(err)
	}

	const msg = "some message"
	if _, err := fooPC.WriteTo([]byte(msg), barAddr.UDPAddr()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500) // TODO: care about MTUs in the natlab package somewhere
	n, addr, err := barPC.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf = buf[:n]
	if string(buf) != msg {
		t.Errorf("read %q; want %q", buf, msg)
	}
	if addr.String() != fooAddr.String() {
		t.Errorf("addr = %q; want %q", addr, fooAddr)
	}
}

func TestMultiNetwork(t *testing.T) {
	lan := &Network{
		Name:    "lan",
		Prefix4: mustPrefix("192.168.0.0/24"),
	}
	internet := NewInternet()

	client := &Machine{Name: "client"}
	nat := &Machine{Name: "nat"}
	server := &Machine{Name: "server"}

	ifClient := client.Attach("eth0", lan)
	ifNATWAN := nat.Attach("ethwan", internet)
	ifNATLAN := nat.Attach("ethlan", lan)
	ifServer := server.Attach("eth0", internet)

	ctx := context.Background()
	clientPC, err := client.ListenPacket(ctx, "udp", ":123")
	if err != nil {
		t.Fatal(err)
	}
	natPC, err := nat.ListenPacket(ctx, "udp", ":456")
	if err != nil {
		t.Fatal(err)
	}
	serverPC, err := server.ListenPacket(ctx, "udp", ":789")
	if err != nil {
		t.Fatal(err)
	}

	clientAddr := netaddr.IPPort{IP: ifClient.V4(), Port: 123}
	natLANAddr := netaddr.IPPort{IP: ifNATLAN.V4(), Port: 456}
	natWANAddr := netaddr.IPPort{IP: ifNATWAN.V4(), Port: 456}
	serverAddr := netaddr.IPPort{IP: ifServer.V4(), Port: 789}

	const msg1, msg2 = "hello", "world"
	if _, err := natPC.WriteTo([]byte(msg1), clientAddr.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := natPC.WriteTo([]byte(msg2), serverAddr.UDPAddr()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	n, addr, err := clientPC.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != msg1 {
		t.Errorf("read %q; want %q", buf[:n], msg1)
	}
	if addr.String() != natLANAddr.String() {
		t.Errorf("addr = %q; want %q", addr, natLANAddr)
	}

	n, addr, err = serverPC.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != msg2 {
		t.Errorf("read %q; want %q", buf[:n], msg2)
	}
	if addr.String() != natWANAddr.String() {
		t.Errorf("addr = %q; want %q", addr, natLANAddr)
	}
}

type trivialNAT struct {
	clientIP     netaddr.IP
	lanIf, wanIf *Interface
}

func (n *trivialNAT) HandleIn(p *Packet, iface *Interface) *Packet {
	if iface == n.wanIf && p.Dst.IP == n.wanIf.V4() {
		p.Dst.IP = n.clientIP
	}
	return p
}

func (n trivialNAT) HandleOut(p *Packet, iface *Interface) *Packet {
	return p
}

func (n *trivialNAT) HandleForward(p *Packet, iif, oif *Interface) *Packet {
	// Outbound from LAN -> apply NAT, continue
	if iif == n.lanIf && oif == n.wanIf {
		if p.Src.IP == n.clientIP {
			p.Src.IP = n.wanIf.V4()
		}
		return p
	}
	// Return traffic to LAN, allow if right dst.
	if iif == n.wanIf && oif == n.lanIf && p.Dst.IP == n.clientIP {
		return p
	}
	// Else drop.
	return nil
}

func TestPacketHandler(t *testing.T) {
	lan := &Network{
		Name:    "lan",
		Prefix4: mustPrefix("192.168.0.0/24"),
		Prefix6: mustPrefix("fd00:916::/64"),
	}
	internet := NewInternet()

	client := &Machine{Name: "client"}
	nat := &Machine{Name: "nat"}
	server := &Machine{Name: "server"}

	ifClient := client.Attach("eth0", lan)
	ifNATWAN := nat.Attach("wan", internet)
	ifNATLAN := nat.Attach("lan", lan)
	ifServer := server.Attach("server", internet)

	lan.SetDefaultGateway(ifNATLAN)

	nat.PacketHandler = &trivialNAT{
		clientIP: ifClient.V4(),
		lanIf:    ifNATLAN,
		wanIf:    ifNATWAN,
	}

	ctx := context.Background()
	clientPC, err := client.ListenPacket(ctx, "udp4", ":123")
	if err != nil {
		t.Fatal(err)
	}
	serverPC, err := server.ListenPacket(ctx, "udp4", ":456")
	if err != nil {
		t.Fatal(err)
	}

	const msg = "some message"
	serverAddr := netaddr.IPPort{IP: ifServer.V4(), Port: 456}
	if _, err := clientPC.WriteTo([]byte(msg), serverAddr.UDPAddr()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500) // TODO: care about MTUs in the natlab package somewhere
	n, addr, err := serverPC.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf = buf[:n]
	if string(buf) != msg {
		t.Errorf("read %q; want %q", buf, msg)
	}
	mappedAddr := netaddr.IPPort{IP: ifNATWAN.V4(), Port: 123}
	if addr.String() != mappedAddr.String() {
		t.Errorf("addr = %q; want %q", addr, mappedAddr)
	}
}

func TestFirewall(t *testing.T) {
	wan := NewInternet()
	lan := &Network{
		Name:    "lan",
		Prefix4: mustPrefix("10.0.0.0/8"),
	}
	m := &Machine{Name: "test"}
	trust := m.Attach("trust", lan)
	untrust := m.Attach("untrust", wan)

	client := ipp("192.168.0.2:1234")
	serverA := ipp("2.2.2.2:5678")
	serverB1 := ipp("7.7.7.7:9012")
	serverB2 := ipp("7.7.7.7:3456")

	t.Run("ip_port_dependent", func(t *testing.T) {
		f := &Firewall{
			TrustedInterface: trust,
			SessionTimeout:   30 * time.Second,
			Type:             AddressAndPortDependentFirewall,
		}
		testFirewall(t, f, []fwTest{
			// client -> A authorizes A -> client
			{trust, untrust, client, serverA, true},
			{untrust, trust, serverA, client, true},
			{untrust, trust, serverA, client, true},

			// B1 -> client fails until client -> B1
			{untrust, trust, serverB1, client, false},
			{trust, untrust, client, serverB1, true},
			{untrust, trust, serverB1, client, true},

			// B2 -> client still fails
			{untrust, trust, serverB2, client, false},
		})
	})
	t.Run("ip_dependent", func(t *testing.T) {
		f := &Firewall{
			TrustedInterface: trust,
			SessionTimeout:   30 * time.Second,
			Type:             AddressDependentFirewall,
		}
		testFirewall(t, f, []fwTest{
			// client -> A authorizes A -> client
			{trust, untrust, client, serverA, true},
			{untrust, trust, serverA, client, true},
			{untrust, trust, serverA, client, true},

			// B1 -> client fails until client -> B1
			{untrust, trust, serverB1, client, false},
			{trust, untrust, client, serverB1, true},
			{untrust, trust, serverB1, client, true},

			// B2 -> client also works now
			{untrust, trust, serverB2, client, true},
		})
	})
	t.Run("endpoint_independent", func(t *testing.T) {
		f := &Firewall{
			TrustedInterface: trust,
			SessionTimeout:   30 * time.Second,
			Type:             EndpointIndependentFirewall,
		}
		testFirewall(t, f, []fwTest{
			// client -> A authorizes A -> client
			{trust, untrust, client, serverA, true},
			{untrust, trust, serverA, client, true},
			{untrust, trust, serverA, client, true},

			// B1 -> client also works
			{untrust, trust, serverB1, client, true},

			// B2 -> client also works
			{untrust, trust, serverB2, client, true},
		})
	})
}

type fwTest struct {
	iif, oif *Interface
	src, dst netaddr.IPPort
	ok       bool
}

func testFirewall(t *testing.T, f *Firewall, tests []fwTest) {
	t.Helper()
	clock := &tstest.Clock{}
	f.TimeNow = clock.Now
	for _, test := range tests {
		clock.Advance(time.Second)
		p := &Packet{
			Src:     test.src,
			Dst:     test.dst,
			Payload: []byte{},
		}
		got := f.HandleForward(p, test.iif, test.oif)
		gotOK := got != nil
		if gotOK != test.ok {
			t.Errorf("iif=%s oif=%s src=%s dst=%s got ok=%v, want ok=%v", test.iif, test.oif, test.src, test.dst, gotOK, test.ok)
		}
	}
}

func ipp(str string) netaddr.IPPort {
	ipp, err := netaddr.ParseIPPort(str)
	if err != nil {
		panic(err)
	}
	return ipp
}

func TestNAT(t *testing.T) {
	internet := NewInternet()
	lan := &Network{
		Name:    "LAN",
		Prefix4: mustPrefix("192.168.0.0/24"),
	}
	m := &Machine{Name: "NAT"}
	wanIf := m.Attach("wan", internet)
	lanIf := m.Attach("lan", lan)

	t.Run("endpoint_independent_mapping", func(t *testing.T) {
		n := &SNAT44{
			Machine:           m,
			ExternalInterface: wanIf,
			Type:              EndpointIndependentNAT,
			Firewall: &Firewall{
				TrustedInterface: lanIf,
			},
		}
		testNAT(t, n, lanIf, wanIf, []natTest{
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("2.2.2.2:5678"),
				wantNewMapping: true,
			},
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("7.7.7.7:9012"),
				wantNewMapping: false,
			},
			{
				src:            ipp("192.168.0.20:2345"),
				dst:            ipp("7.7.7.7:9012"),
				wantNewMapping: true,
			},
		})
	})

	t.Run("address_dependent_mapping", func(t *testing.T) {
		n := &SNAT44{
			Machine:           m,
			ExternalInterface: wanIf,
			Type:              AddressDependentNAT,
			Firewall: &Firewall{
				TrustedInterface: lanIf,
			},
		}
		testNAT(t, n, lanIf, wanIf, []natTest{
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("2.2.2.2:5678"),
				wantNewMapping: true,
			},
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("2.2.2.2:9012"),
				wantNewMapping: false,
			},
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("7.7.7.7:9012"),
				wantNewMapping: true,
			},
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("7.7.7.7:1234"),
				wantNewMapping: false,
			},
		})
	})

	t.Run("address_and_port_dependent_mapping", func(t *testing.T) {
		n := &SNAT44{
			Machine:           m,
			ExternalInterface: wanIf,
			Type:              AddressAndPortDependentNAT,
			Firewall: &Firewall{
				TrustedInterface: lanIf,
			},
		}
		testNAT(t, n, lanIf, wanIf, []natTest{
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("2.2.2.2:5678"),
				wantNewMapping: true,
			},
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("2.2.2.2:9012"),
				wantNewMapping: true,
			},
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("7.7.7.7:9012"),
				wantNewMapping: true,
			},
			{
				src:            ipp("192.168.0.20:1234"),
				dst:            ipp("7.7.7.7:1234"),
				wantNewMapping: true,
			},
		})
	})
}

type natTest struct {
	src, dst       netaddr.IPPort
	wantNewMapping bool
}

func testNAT(t *testing.T, n *SNAT44, lanIf, wanIf *Interface, tests []natTest) {
	clock := &tstest.Clock{}
	n.TimeNow = clock.Now

	mappings := map[netaddr.IPPort]bool{}
	for _, test := range tests {
		clock.Advance(time.Second)
		p := &Packet{
			Src:     test.src,
			Dst:     test.dst,
			Payload: []byte("foo"),
		}
		gotPacket := n.HandleForward(p.Clone(), lanIf, wanIf)
		if gotPacket == nil {
			t.Errorf("n.HandleForward(%v) dropped packet", p)
			continue
		}

		if gotPacket.Dst != p.Dst {
			t.Errorf("n.HandleForward(%v) mutated dest ip:port, got %v", p, gotPacket.Dst)
		}
		gotNewMapping := !mappings[gotPacket.Src]
		if gotNewMapping != test.wantNewMapping {
			t.Errorf("n.HandleForward(%v) mapping was new=%v, want %v", p, gotNewMapping, test.wantNewMapping)
		}
		mappings[gotPacket.Src] = true

		// Check that the return path works and translates back
		// correctly.
		clock.Advance(time.Second)
		p2 := &Packet{
			Src:     test.dst,
			Dst:     gotPacket.Src,
			Payload: []byte("bar"),
		}
		gotPacket2 := n.HandleIn(p2.Clone(), wanIf)

		if gotPacket2 == nil {
			t.Errorf("return packet was dropped")
			continue
		}

		if gotPacket2.Src != test.dst {
			t.Errorf("return packet has src=%v, want %v", gotPacket2.Src, test.dst)
		}
		if gotPacket2.Dst != test.src {
			t.Errorf("return packet has dst=%v, want %v", gotPacket2.Dst, test.src)
		}
	}
}
