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

	// This HandlePacket implements a basic (some might say "broken")
	// 1:1 NAT, where client's IP gets replaced with the NAT's WAN IP,
	// and vice versa.
	//
	// This NAT is not suitable for actual use, since it doesn't do
	// port remappings or any other things that NATs usually to. But
	// it works as a demonstrator for a single client behind the NAT,
	// where the NAT box itself doesn't also make PacketConns.
	nat.HandlePacket = func(p []byte, iface *Interface, dst, src netaddr.IPPort) PacketVerdict {
		switch {
		case dst.IP.Is6():
			return Continue // no NAT for ipv6
		case iface == ifNATLAN && src.IP == ifClient.V4():
			nat.Inject(p, dst, netaddr.IPPort{IP: ifNATWAN.V4(), Port: src.Port})
			return Drop
		case iface == ifNATWAN && dst.IP == ifNATWAN.V4():
			nat.Inject(p, netaddr.IPPort{IP: ifClient.V4(), Port: dst.Port}, src)
			return Drop
		default:
			return Continue
		}
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
	clock := &tstest.Clock{}

	wan := NewInternet()
	lan := &Network{
		Name:    "lan",
		Prefix4: mustPrefix("10.0.0.0/8"),
	}
	m := &Machine{Name: "test"}
	trust := m.Attach("trust", lan)
	untrust := m.Attach("untrust", wan)

	f := &Firewall{
		TrustedInterface: trust,
		SessionTimeout:   30 * time.Second,
		TimeNow:          clock.Now,
	}

	client := ipp("192.168.0.2:1234")
	serverA := ipp("2.2.2.2:5678")
	serverB := ipp("7.7.7.7:9012")
	tests := []struct {
		iface    *Interface
		src, dst netaddr.IPPort
		want     PacketVerdict
	}{
		{trust, client, serverA, Continue},
		{untrust, serverA, client, Continue},
		{untrust, serverA, client, Continue},
		{untrust, serverB, client, Drop},
		{trust, client, serverB, Continue},
		{untrust, serverB, client, Continue},
	}

	for _, test := range tests {
		clock.Advance(time.Second)
		got := f.HandlePacket(nil, test.iface, test.dst, test.src)
		if got != test.want {
			t.Errorf("iface=%s src=%s dst=%s got %v, want %v", test.iface.name, test.src, test.dst, got, test.want)
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
