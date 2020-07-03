// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package natlab

import (
	"fmt"
	"testing"

	"inet.af/netaddr"
)

func TestAllocIPs(t *testing.T) {
	n := NewInternet()
	saw := map[netaddr.IP]bool{}
	for i := 0; i < 255; i++ {
		for _, f := range []func(*Machine) netaddr.IP{n.allocIPv4, n.allocIPv6} {
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

	foo := NewMachine("foo")
	bar := NewMachine("bar")
	ifFoo := foo.Attach("eth0", internet)
	ifBar := bar.Attach("enp0s1", internet)

	fooAddr := netaddr.IPPort{IP: ifFoo.V4(), Port: 123}
	barAddr := netaddr.IPPort{IP: ifBar.V4(), Port: 456}

	fooPC, err := foo.ListenPacket("udp4", fooAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	barPC, err := bar.ListenPacket("udp4", barAddr.String())
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

	client := NewMachine("client")
	nat := NewMachine("nat")
	server := NewMachine("server")

	ifClient := client.Attach("eth0", lan)
	ifNATWAN := nat.Attach("ethwan", internet)
	ifNATLAN := nat.Attach("ethlan", lan)
	ifServer := server.Attach("eth0", internet)

	clientPC, err := client.ListenPacket("udp", ":123")
	if err != nil {
		t.Fatal(err)
	}
	natPC, err := nat.ListenPacket("udp", ":456")
	if err != nil {
		t.Fatal(err)
	}
	serverPC, err := server.ListenPacket("udp", ":789")
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
