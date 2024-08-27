// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TestPacketSideEffects tests that upon receiving certain
// packets, other packets and/or log statements are generated.
func TestPacketSideEffects(t *testing.T) {
	type netTest struct {
		name  string
		pkt   []byte // to send
		check func(*sideEffects) error
	}
	tests := []struct {
		netName string // name of the Server returned by setup
		setup   func() (*Server, error)
		tests   []netTest // to run against setup's Server
	}{
		{
			netName: "basic",
			setup: func() (*Server, error) {
				var c Config
				nw := c.AddNetwork("192.168.0.1/24")
				c.AddNode(nw)
				c.AddNode(nw)
				return New(&c)
			},
			tests: []netTest{
				{
					name: "drop-rando-ethertype",
					pkt:  mkEth(nodeMac(2), nodeMac(1), 0x4321, []byte("hello")),
					check: all(
						logSubstr("Dropping non-IP packet"),
					),
				},
				{
					name: "dst-mac-between-nodes",
					pkt:  mkEth(nodeMac(2), nodeMac(1), testingEthertype, []byte("hello")),
					check: all(
						numPkts(1),
						pktSubstr("SrcMAC=52:cc:cc:cc:cc:01 DstMAC=52:cc:cc:cc:cc:02 EthernetType=UnknownEthernetType"),
						pktSubstr("Unable to decode EthernetType 4660"),
					),
				},
				{
					name: "broadcast-mac",
					pkt:  mkEth(macBroadcast, nodeMac(1), testingEthertype, []byte("hello")),
					check: all(
						numPkts(1),
						pktSubstr("SrcMAC=52:cc:cc:cc:cc:01 DstMAC=ff:ff:ff:ff:ff:ff EthernetType=UnknownEthernetType"),
						pktSubstr("Unable to decode EthernetType 4660"),
					),
				},
			},
		},
		{
			netName: "v6",
			setup: func() (*Server, error) {
				var c Config
				c.AddNode(c.AddNetwork("2000:52::1/64"))
				return New(&c)
			},
			tests: []netTest{
				{
					name: "router-solicit",
					pkt:  mkIPv6RouterSolicit(nodeMac(1), netip.MustParseAddr("fe80::50cc:ccff:fecc:cc01")),
					check: all(
						logSubstr("sending IPv6 router advertisement to 52:cc:cc:cc:cc:01 from 52:ee:ee:ee:ee:01"),
						numPkts(1),
						pktSubstr("TypeCode=RouterAdvertisement"),
						pktSubstr("= ICMPv6RouterAdvertisement"),
						pktSubstr("SrcMAC=52:ee:ee:ee:ee:01 DstMAC=52:cc:cc:cc:cc:01 EthernetType=IPv6"),
					),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.netName, func(t *testing.T) {
			s, err := tt.setup()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			for _, tt := range tt.tests {
				t.Run(tt.name, func(t *testing.T) {
					se := &sideEffects{}
					s.SetLoggerForTest(se.logf)
					for mac := range s.MACs() {
						s.RegisterSinkForTest(mac, func(eth []byte) {
							se.got = append(se.got, eth)
						})
					}

					s.handleEthernetFrameFromVM(tt.pkt)
					if tt.check != nil {
						if err := tt.check(se); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		})
	}

}

// mkEth encodes an ethernet frame with the given payload.
func mkEth(dst, src MAC, ethType layers.EthernetType, payload []byte) []byte {
	ret := make([]byte, 0, 14+len(payload))
	ret = append(ret, dst.HWAddr()...)
	ret = append(ret, src.HWAddr()...)
	ret = binary.BigEndian.AppendUint16(ret, uint16(ethType))
	return append(ret, payload...)
}

// mkIPv6RouterSolicit makes a IPv6 router solicitation packet
// ethernet frame.
func mkIPv6RouterSolicit(srcMAC MAC, srcIP netip.Addr) []byte {
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      srcIP.AsSlice(),
		DstIP:      net.ParseIP("ff02::2"), // all routers
	}
	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0),
	}

	ra := &layers.ICMPv6RouterSolicitation{
		Options: []layers.ICMPv6Option{{
			Type: layers.ICMPv6OptSourceAddress,
			Data: srcMAC.HWAddr(),
		}},
	}
	icmp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, options, ip, icmp, ra); err != nil {
		panic(fmt.Sprintf("serializing ICMPv6 RA: %v", err))
	}

	return mkEth(macAllRouters, srcMAC, layers.EthernetTypeIPv6, buf.Bytes())
}

// sideEffects gathers side effects as a result of sending a packet and tests
// whether those effects were as desired.
type sideEffects struct {
	logs []string
	got  [][]byte // ethernet packets received
}

func (se *sideEffects) logf(format string, args ...any) {
	se.logs = append(se.logs, fmt.Sprintf(format, args...))
}

// all aggregates several side effects checkers into one.
func all(checks ...func(*sideEffects) error) func(*sideEffects) error {
	return func(se *sideEffects) error {
		var errs []error
		for _, check := range checks {
			if err := check(se); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
}

// logSubstr returns a side effect checker func that checks
// whether a log statement was output containing substring sub.
func logSubstr(sub string) func(*sideEffects) error {
	return func(se *sideEffects) error {
		for _, log := range se.logs {
			if strings.Contains(log, sub) {
				return nil
			}
		}
		return fmt.Errorf("expected log substring %q not found; log statements were %q", sub, se.logs)
	}
}

// pkgSubstr returns a side effect checker func that checks whether an ethernet
// packet was received that, once decoded and stringified by gopacket, contains
// substring sub.
func pktSubstr(sub string) func(*sideEffects) error {
	return func(se *sideEffects) error {
		var pkts bytes.Buffer
		for i, pkt := range se.got {
			pkt := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Lazy)
			got := pkt.String()
			fmt.Fprintf(&pkts, "[pkt%d]:\n%s\n", i, got)
			if strings.Contains(got, sub) {
				return nil
			}
		}
		return fmt.Errorf("packet summary with substring %q not found; packets were:\n%s", sub, pkts.Bytes())
	}
}

// numPkts returns a side effect checker func that checks whether
// the received number of ethernet packets was the given number.
func numPkts(want int) func(*sideEffects) error {
	return func(se *sideEffects) error {
		if len(se.got) == want {
			return nil
		}
		var pkts bytes.Buffer
		for i, pkt := range se.got {
			pkt := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Lazy)
			got := pkt.String()
			fmt.Fprintf(&pkts, "[pkt%d]:\n%s\n", i, got)
		}
		return fmt.Errorf("got %d packets, want %d. packets were:\n%s", len(se.got), want, pkts.Bytes())
	}
}
