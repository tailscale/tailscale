// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/appctype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
)

func TestProtoPortRangesAllow(t *testing.T) {
	// ppr builds the grant values a peer holds for an app.
	ppr := func(ss ...string) views.Slice[tailcfg.ProtoPortRange] {
		var out []tailcfg.ProtoPortRange
		for _, s := range ss {
			var p tailcfg.ProtoPortRange
			if err := p.UnmarshalText([]byte(s)); err != nil {
				t.Fatalf("parsing %q: %v", s, err)
			}
			out = append(out, p)
		}
		return views.SliceOf(out)
	}

	src := netip.MustParseAddr("100.64.0.1")
	dst := netip.MustParseAddr("169.254.0.1")

	pkt := func(ver uint8, proto ipproto.Proto, port uint16, flags packet.TCPFlag) packet.Parsed {
		return packet.Parsed{
			IPVersion: ver,
			IPProto:   proto,
			Src:       netip.AddrPortFrom(src, 12345),
			Dst:       netip.AddrPortFrom(dst, port),
			TCPFlags:  flags,
		}
	}
	tcpSyn := func(port uint16) packet.Parsed { return pkt(4, ipproto.TCP, port, packet.TCPSyn) }
	tcp := func(port uint16, flags packet.TCPFlag) packet.Parsed { return pkt(4, ipproto.TCP, port, flags) }
	udp := func(port uint16) packet.Parsed { return pkt(4, ipproto.UDP, port, 0) }
	sctp := func(port uint16) packet.Parsed { return pkt(4, ipproto.SCTP, port, 0) }

	// IsEchoResponse and IsError read the packet body, so ICMP cases need real
	// bytes rather than a hand-built [packet.Parsed].
	icmp4 := func(typ packet.ICMP4Type) packet.Parsed {
		buf := packet.Generate(packet.ICMP4Header{
			IP4Header: packet.IP4Header{Src: src, Dst: dst},
			Type:      typ,
			Code:      packet.ICMP4NoCode,
		}, []byte("payload!!"))
		var p packet.Parsed
		p.Decode(buf)
		if p.IPProto != ipproto.ICMPv4 {
			t.Fatalf("test setup error: built an %v packet, want ICMPv4", p.IPProto)
		}
		return p
	}

	// gre is a protocol that carries no port and gets no special handling.
	const gre = ipproto.Proto(47)

	tests := []struct {
		name       string
		ranges     views.Slice[tailcfg.ProtoPortRange]
		p          packet.Parsed
		want       bool
		wantReason string
	}{
		{"tcp-syn-match", ppr("tcp:443"), tcpSyn(443), true, connectorTCPReason},
		{"tcp-syn-wrong-port", ppr("tcp:443"), tcpSyn(80), false, ""},
		{"tcp-syn-wrong-proto", ppr("udp:443"), tcpSyn(443), false, ""},
		{"tcp-syn-protoless", ppr("80"), tcpSyn(80), true, connectorTCPReason},
		{"tcp-syn-wildcard", ppr("*"), tcpSyn(1), true, connectorTCPReason},
		{"tcp-syn-any-port", ppr("tcp:*"), tcpSyn(9999), true, connectorTCPReason},
		{"tcp-syn-range-first", ppr("tcp:80-90"), tcpSyn(80), true, connectorTCPReason},
		{"tcp-syn-range-last", ppr("tcp:80-90"), tcpSyn(90), true, connectorTCPReason},
		{"tcp-syn-range-low", ppr("tcp:80-90"), tcpSyn(79), false, ""},
		{"tcp-syn-range-high", ppr("tcp:80-90"), tcpSyn(91), false, ""},
		{"tcp-syn-empty-grant", ppr(), tcpSyn(443), false, ""},
		{"tcp-syn-union-first", ppr("tcp:443", "udp:53"), tcpSyn(443), true, connectorTCPReason},
		{"tcp-syn-union-neither", ppr("tcp:443", "udp:53"), tcpSyn(53), false, ""},

		// Inherited from RunIn: anything that is not a lone SYN is admitted,
		// including to a port the grant does not name, and with no grant at
		// all. On a connector that packet then gets DNATed on to the app.
		{"tcp-ack-ungranted-port", ppr("tcp:443"), tcp(22, packet.TCPAck), true, connectorTCPNonSynReason},
		{"tcp-ack-empty-grant", ppr(), tcp(22, packet.TCPAck), true, connectorTCPNonSynReason},
		{"tcp-syn-ack-is-not-a-syn", ppr(), tcp(22, packet.TCPSynAck), true, connectorTCPNonSynReason},

		{"udp-match", ppr("udp:53"), udp(53), true, connectorPortReason},
		{"udp-wrong-port", ppr("udp:53"), udp(54), false, ""},
		{"udp-protoless", ppr("80"), udp(80), true, connectorPortReason},
		{"udp-empty-grant", ppr(), udp(53), false, ""},
		{"sctp-match", ppr("132:9"), sctp(9), true, connectorPortReason},
		{"sctp-wrong-port", ppr("132:9"), sctp(10), false, ""},
		// A range naming no protocol covers UDP but not SCTP.
		{"sctp-protoless-denied", ppr("9"), sctp(9), false, ""},
		{"udp-protoless-allowed", ppr("9"), udp(9), true, connectorPortReason},

		{"icmp4-request-with-grant", ppr("tcp:443"), icmp4(packet.ICMP4EchoRequest), true, connectorICMPReason},
		{"icmp4-request-empty-grant", ppr(), icmp4(packet.ICMP4EchoRequest), false, ""},
		// Responses are admitted even with no grant at all.
		{"icmp4-echo-reply-empty-grant", ppr(), icmp4(packet.ICMP4EchoReply), true, connectorICMPResponseReason},
		{"icmp4-unreachable-empty-grant", ppr(), icmp4(packet.ICMP4Unreachable), true, connectorICMPResponseReason},
		// An ICMP protocol that disagrees with the packet's IP version is
		// refused rather than falling through to the default case.
		{"icmp6-on-ipv4", ppr("*"), pkt(4, ipproto.ICMPv6, 0, 0), false, ""},
		{"icmp4-on-ipv6", ppr("*"), pkt(6, ipproto.ICMPv4, 0, 0), false, ""},

		// A protocol that carries no port has to be granted by name, in full.
		{"gre-all-ports", ppr("47:*"), pkt(4, gre, 0, 0), true, connectorPortlessReason},
		{"gre-narrow-ports", ppr("47:80"), pkt(4, gre, 0, 0), false, ""},
		{"gre-protoless-grant", ppr("*"), pkt(4, gre, 0, 0), false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotReason := protoPortRangesAllow(tt.ranges, tt.p)
			if got != tt.want || gotReason != tt.wantReason {
				t.Errorf("protoPortRangesAllow(%v, %v) = (%v, %q), want (%v, %q)",
					tt.ranges, &tt.p, got, gotReason, tt.want, tt.wantReason)
			}
		})
	}
}

// TestConnectorIngressAllow checks that [connector.ingressAllow] holds peers
// to the protocols and ports their grant for the app permits, that a transit
// IP with no registered mapping still gets through so the datapath can answer
// with the re-registration TSMP, and that addresses outside the transit pools
// are refused outright.
//
// The per-protocol matching itself is covered in more detail by [TestProtoPortRangesAllow].
func TestConnectorIngressAllow(t *testing.T) {
	const appName = "app"

	peerIP := netip.MustParseAddr("100.64.0.1")
	peerNode := (&tailcfg.Node{ID: 1, Addresses: []netip.Prefix{netip.PrefixFrom(peerIP, 32)}}).View()
	otherPeerIP := netip.MustParseAddr("100.64.0.2")

	transitIP := netip.MustParseAddr("192.0.2.1")
	unmappedTransitIP := netip.MustParseAddr("192.0.2.2")
	outsidePoolIP := netip.MustParseAddr("100.64.0.42")

	type probe struct {
		proto ipproto.Proto
		port  uint16
		// flags are the packet's TCP flags. A TCP probe that names none is
		// sent as a lone SYN, the case the grant is actually consulted for.
		flags packet.TCPFlag
		dst   netip.Addr // defaults to transitIP
		src   netip.Addr // defaults to peerIP
		want  bool
	}

	tests := []struct {
		name  string
		grant []tailcfg.RawMessage
		// noRegister skips registering the transit IP mapping, leaving the
		// connector with nothing to look up for it.
		noRegister bool
		probes     []probe
	}{
		{
			name:  "wildcard",
			grant: []tailcfg.RawMessage{`"*"`},
			probes: []probe{
				{proto: ipproto.TCP, port: 443, want: true},
				{proto: ipproto.TCP, port: 80, want: true},
				{proto: ipproto.UDP, port: 53, want: true},
				{proto: ipproto.ICMPv4, want: true},
			},
		},
		{
			name:  "tcp-443",
			grant: []tailcfg.RawMessage{`"tcp:443"`},
			probes: []probe{
				{proto: ipproto.TCP, port: 443, want: true},
				{proto: ipproto.TCP, port: 80, want: false},
				{proto: ipproto.TCP, port: 442, want: false},
				{proto: ipproto.TCP, port: 444, want: false},
				{proto: ipproto.UDP, port: 443, want: false},
				// ICMP has no port, so any grant at all permits it.
				{proto: ipproto.ICMPv4, want: true},
			},
		},
		{
			name:  "protoless-port",
			grant: []tailcfg.RawMessage{`"80"`},
			probes: []probe{
				{proto: ipproto.TCP, port: 80, want: true},
				{proto: ipproto.UDP, port: 80, want: true},
				{proto: ipproto.TCP, port: 443, want: false},
				// A protocol-less range covers TCP and UDP, not SCTP.
				{proto: ipproto.SCTP, port: 80, want: false},
			},
		},
		{
			// Following the packet filter, only a lone SYN is held to the
			// grant's ports; continuations of an existing session are let
			// through so that return traffic arrives. See
			// [protoPortRangesAllow].
			name:  "tcp-non-syn-not-held-to-ports",
			grant: []tailcfg.RawMessage{`"tcp:443"`},
			probes: []probe{
				{proto: ipproto.TCP, port: 22, flags: packet.TCPAck, want: true},
				{proto: ipproto.TCP, port: 22, flags: packet.TCPSynAck, want: true},
				{proto: ipproto.TCP, port: 22, flags: packet.TCPSyn, want: false},
			},
		},
		{
			name:  "port-range",
			grant: []tailcfg.RawMessage{`"tcp:8000-8100"`},
			probes: []probe{
				{proto: ipproto.TCP, port: 7999, want: false},
				{proto: ipproto.TCP, port: 8000, want: true},
				{proto: ipproto.TCP, port: 8050, want: true},
				{proto: ipproto.TCP, port: 8100, want: true},
				{proto: ipproto.TCP, port: 8101, want: false},
			},
		},
		{
			name:  "union-of-values",
			grant: []tailcfg.RawMessage{`"tcp:443"`, `"udp:53"`},
			probes: []probe{
				{proto: ipproto.TCP, port: 443, want: true},
				{proto: ipproto.UDP, port: 53, want: true},
				{proto: ipproto.UDP, port: 443, want: false},
				{proto: ipproto.TCP, port: 53, want: false},
			},
		},
		{
			name:  "empty-grant-permits-nothing",
			grant: []tailcfg.RawMessage{},
			probes: []probe{
				{proto: ipproto.TCP, port: 443, want: false},
				{proto: ipproto.UDP, port: 53, want: false},
				{proto: ipproto.ICMPv4, want: false},
			},
		},
		{
			name:  "outside-transit-pool",
			grant: []tailcfg.RawMessage{`"*"`},
			probes: []probe{
				{proto: ipproto.TCP, port: 443, dst: outsidePoolIP, want: false},
			},
		},
		{
			// Without a mapping the connector has no grant to judge the
			// packet by, so it passes the filter and the datapath drops it
			// and tells the client to re-register.
			name:       "no-mapping-registered",
			grant:      []tailcfg.RawMessage{`"tcp:443"`},
			noRegister: true,
			probes: []probe{
				{proto: ipproto.TCP, port: 443, dst: unmappedTransitIP, want: true},
				{proto: ipproto.TCP, port: 80, dst: unmappedTransitIP, want: true},
			},
		},
		{
			// A mapping registered by one peer says nothing about another,
			// which lands in the no-mapping case above.
			name:  "different-peer",
			grant: []tailcfg.RawMessage{`"tcp:443"`},
			probes: []probe{
				{proto: ipproto.TCP, port: 80, src: otherPeerIP, want: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newConn25(t.Logf)
			c.reconfig(&config{
				isConfigured: true,
				appsByName:   map[string]appctype.AppConnectorAttr{appName: {}},
				ipSets:       ipSets{v4Transit: mustIPSetFromPrefix("192.0.2.0/24")},
			})

			if !tt.noRegister {
				peerCap := tailcfg.PeerCapMap{
					peercap.Conn25Prefix.ToAttribute(appName): tt.grant,
				}
				resp := c.handleConnectorTransitIPRequest(peerNode, peerCap, ConnectorTransitIPRequest{
					TransitIPs: []TransitIPRequest{withValidDstToken(t, c.connector, TransitIPRequest{
						TransitIP:     transitIP,
						DestinationIP: netip.MustParseAddr("203.0.113.1"),
						App:           appName,
					})},
				})
				if len(resp.TransitIPs) != 1 || resp.TransitIPs[0].Code != OK {
					t.Fatalf("registration failed: %+v", resp.TransitIPs)
				}
			}

			for _, p := range tt.probes {
				src, dst := p.src, p.dst
				if !src.IsValid() {
					src = peerIP
				}
				if !dst.IsValid() {
					dst = transitIP
				}
				flags := p.flags
				if p.proto == ipproto.TCP && flags == 0 {
					flags = packet.TCPSyn
				}
				got, _ := c.connector.ingressAllow(packet.Parsed{
					IPVersion: 4,
					IPProto:   p.proto,
					TCPFlags:  flags,
					Src:       netip.AddrPortFrom(src, 12345),
					Dst:       netip.AddrPortFrom(dst, p.port),
				})
				if got != p.want {
					t.Errorf("ingressAllow(%v %v -> %v:%d) = %v, want %v",
						p.proto, src, dst, p.port, got, p.want)
				}
			}
		})
	}
}

// TestConnectorGrantRegistration checks that the grant's values are decoded
// and stored with the mapping, and that a grant that cannot be decoded is
// refused outright rather than registered under a partial interpretation.
func TestConnectorGrantRegistration(t *testing.T) {
	const appName = "app"

	peerIP := netip.MustParseAddr("100.64.0.1")
	peerNode := (&tailcfg.Node{ID: 1, Addresses: []netip.Prefix{netip.PrefixFrom(peerIP, 32)}}).View()
	transitIP := netip.MustParseAddr("192.0.2.1")

	tests := []struct {
		name      string
		grant     []tailcfg.RawMessage
		omitCap   bool
		wantCode  TransitIPResponseCode
		wantMsg   string
		wantPorts []tailcfg.ProtoPortRange
	}{
		{
			name:      "proto-and-port",
			grant:     []tailcfg.RawMessage{`"tcp:443"`},
			wantCode:  OK,
			wantPorts: []tailcfg.ProtoPortRange{{Proto: int(ipproto.TCP), Ports: tailcfg.PortRange{First: 443, Last: 443}}},
		},
		{
			name:      "wildcard",
			grant:     []tailcfg.RawMessage{`"*"`},
			wantCode:  OK,
			wantPorts: []tailcfg.ProtoPortRange{{Ports: tailcfg.PortRangeAny}},
		},
		{
			name:      "empty",
			grant:     []tailcfg.RawMessage{},
			wantCode:  OK,
			wantPorts: []tailcfg.ProtoPortRange{},
		},
		{
			name:     "unparseable",
			grant:    []tailcfg.RawMessage{`"not-a-port"`},
			wantCode: MissingAppPermission,
			wantMsg:  unparseableAppPermissionMessage,
		},
		{
			name:     "no-capability",
			omitCap:  true,
			wantCode: MissingAppPermission,
			wantMsg:  missingAppPermissionMessage,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newConn25(t.Logf)
			c.reconfig(&config{
				isConfigured: true,
				appsByName:   map[string]appctype.AppConnectorAttr{appName: {}},
				ipSets:       ipSets{v4Transit: mustIPSetFromPrefix("192.0.2.0/24")},
			})

			peerCap := tailcfg.PeerCapMap{}
			if !tt.omitCap {
				peerCap[peercap.Conn25Prefix.ToAttribute(appName)] = tt.grant
			}
			resp := c.handleConnectorTransitIPRequest(peerNode, peerCap, ConnectorTransitIPRequest{
				TransitIPs: []TransitIPRequest{withValidDstToken(t, c.connector, TransitIPRequest{
					TransitIP:     transitIP,
					DestinationIP: netip.MustParseAddr("203.0.113.1"),
					App:           appName,
				})},
			})
			if len(resp.TransitIPs) != 1 {
				t.Fatalf("got %d responses, want 1", len(resp.TransitIPs))
			}
			if got := resp.TransitIPs[0].Code; got != tt.wantCode {
				t.Errorf("code = %d, want %d", got, tt.wantCode)
			}
			if got := resp.TransitIPs[0].Message; got != tt.wantMsg {
				t.Errorf("message = %q, want %q", got, tt.wantMsg)
			}

			c.connector.mu.Lock()
			defer c.connector.mu.Unlock()
			aa, ok := c.connector.lookupAppAddrBySrcIPAndTransitIPLocked(peerIP, transitIP)
			if tt.wantCode != OK {
				// A refused request must not leave a mapping behind.
				if ok {
					t.Errorf("mapping was registered for a refused request: %+v", aa)
				}
				return
			}
			if !ok {
				t.Fatal("no mapping registered")
			}
			if diff := cmp.Diff(tt.wantPorts, aa.ports.AsSlice()); diff != "" {
				t.Errorf("stored ports mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
