// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package filter

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime/rate"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
)

// testAllowedProto is an IP protocol number we treat as allowed for
// these tests.
const (
	testAllowedProto ipproto.Proto = 116
	testDeniedProto  ipproto.Proto = 127 // CRUDP, appropriately cruddy
)

func m(srcs []netip.Prefix, dsts []NetPortRange, protos ...ipproto.Proto) Match {
	if protos == nil {
		protos = defaultProtos
	}
	return Match{
		IPProto: protos,
		Srcs:    srcs,
		Dsts:    dsts,
	}
}

func newFilter(logf logger.Logf) *Filter {
	matches := []Match{
		m(nets("8.1.1.1", "8.2.2.2"), netports("1.2.3.4:22", "5.6.7.8:23-24")),
		m(nets("9.1.1.1", "9.2.2.2"), netports("1.2.3.4:22", "5.6.7.8:23-24"), ipproto.SCTP),
		m(nets("8.1.1.1", "8.2.2.2"), netports("5.6.7.8:27-28")),
		m(nets("2.2.2.2"), netports("8.1.1.1:22")),
		m(nets("0.0.0.0/0"), netports("100.122.98.50:*")),
		m(nets("0.0.0.0/0"), netports("0.0.0.0/0:443")),
		m(nets("153.1.1.1", "153.1.1.2", "153.3.3.3"), netports("1.2.3.4:999")),
		m(nets("::1", "::2"), netports("2001::1:22", "2001::2:22")),
		m(nets("::/0"), netports("::/0:443")),
		m(nets("0.0.0.0/0"), netports("0.0.0.0/0:*"), testAllowedProto),
		m(nets("::/0"), netports("::/0:*"), testAllowedProto),
	}

	// Expects traffic to 100.122.98.50, 1.2.3.4, 5.6.7.8,
	// 102.102.102.102, 119.119.119.119, 8.1.0.0/16
	var localNets netipx.IPSetBuilder
	for _, n := range nets("100.122.98.50", "1.2.3.4", "5.6.7.8", "102.102.102.102", "119.119.119.119", "8.1.0.0/16", "2001::/16") {
		localNets.AddPrefix(n)
	}

	var logB netipx.IPSetBuilder
	logB.Complement()
	localNetsSet, _ := localNets.IPSet()
	logBSet, _ := logB.IPSet()

	return New(matches, localNetsSet, logBSet, nil, logf)
}

func TestFilter(t *testing.T) {
	acl := newFilter(t.Logf)

	type InOut struct {
		want Response
		p    packet.Parsed
	}
	tests := []InOut{
		// allow 8.1.1.1 => 1.2.3.4:22
		{Accept, parsed(ipproto.TCP, "8.1.1.1", "1.2.3.4", 999, 22)},
		{Accept, parsed(ipproto.ICMPv4, "8.1.1.1", "1.2.3.4", 0, 0)},
		{Drop, parsed(ipproto.TCP, "8.1.1.1", "1.2.3.4", 0, 0)},
		{Accept, parsed(ipproto.TCP, "8.1.1.1", "1.2.3.4", 0, 22)},
		{Drop, parsed(ipproto.TCP, "8.1.1.1", "1.2.3.4", 0, 21)},
		// allow 8.2.2.2. => 1.2.3.4:22
		{Accept, parsed(ipproto.TCP, "8.2.2.2", "1.2.3.4", 0, 22)},
		{Drop, parsed(ipproto.TCP, "8.2.2.2", "1.2.3.4", 0, 23)},
		{Drop, parsed(ipproto.TCP, "8.3.3.3", "1.2.3.4", 0, 22)},
		// allow 8.1.1.1 => 5.6.7.8:23-24
		{Accept, parsed(ipproto.TCP, "8.1.1.1", "5.6.7.8", 0, 23)},
		{Accept, parsed(ipproto.TCP, "8.1.1.1", "5.6.7.8", 0, 24)},
		{Drop, parsed(ipproto.TCP, "8.1.1.3", "5.6.7.8", 0, 24)},
		{Drop, parsed(ipproto.TCP, "8.1.1.1", "5.6.7.8", 0, 22)},
		// allow * => *:443
		{Accept, parsed(ipproto.TCP, "17.34.51.68", "8.1.34.51", 0, 443)},
		{Drop, parsed(ipproto.TCP, "17.34.51.68", "8.1.34.51", 0, 444)},
		// allow * => 100.122.98.50:*
		{Accept, parsed(ipproto.TCP, "17.34.51.68", "100.122.98.50", 0, 999)},
		{Accept, parsed(ipproto.TCP, "17.34.51.68", "100.122.98.50", 0, 0)},

		// allow ::1, ::2 => [2001::1]:22
		{Accept, parsed(ipproto.TCP, "::1", "2001::1", 0, 22)},
		{Accept, parsed(ipproto.ICMPv6, "::1", "2001::1", 0, 0)},
		{Accept, parsed(ipproto.TCP, "::2", "2001::1", 0, 22)},
		{Accept, parsed(ipproto.TCP, "::2", "2001::2", 0, 22)},
		{Drop, parsed(ipproto.TCP, "::1", "2001::1", 0, 23)},
		{Drop, parsed(ipproto.TCP, "::1", "2001::3", 0, 22)},
		{Drop, parsed(ipproto.TCP, "::3", "2001::1", 0, 22)},
		// allow * => *:443
		{Accept, parsed(ipproto.TCP, "::1", "2001::1", 0, 443)},
		{Drop, parsed(ipproto.TCP, "::1", "2001::1", 0, 444)},

		// localNets prefilter - accepted by policy filter, but
		// unexpected dst IP.
		{Drop, parsed(ipproto.TCP, "8.1.1.1", "16.32.48.64", 0, 443)},
		{Drop, parsed(ipproto.TCP, "1::", "2602::1", 0, 443)},

		// Don't allow protocols not specified by filter
		{Drop, parsed(ipproto.SCTP, "8.1.1.1", "1.2.3.4", 999, 22)},
		// But SCTP is allowed for 9.1.1.1
		{Accept, parsed(ipproto.SCTP, "9.1.1.1", "1.2.3.4", 999, 22)},

		// Unknown protocol is allowed if all its ports are allowed.
		{Accept, parsed(testAllowedProto, "1.2.3.4", "5.6.7.8", 0, 0)},
		{Accept, parsed(testAllowedProto, "2001::1", "2001::2", 0, 0)},
		{Drop, parsed(testDeniedProto, "1.2.3.4", "5.6.7.8", 0, 0)},
		{Drop, parsed(testDeniedProto, "2001::1", "2001::2", 0, 0)},
	}
	for i, test := range tests {
		aclFunc := acl.runIn4
		if test.p.IPVersion == 6 {
			aclFunc = acl.runIn6
		}
		if got, why := aclFunc(&test.p); test.want != got {
			t.Errorf("#%d runIn got=%v want=%v why=%q packet:%v", i, got, test.want, why, test.p)
		}
		if test.p.IPProto == ipproto.TCP {
			var got Response
			if test.p.IPVersion == 4 {
				got = acl.CheckTCP(test.p.Src.Addr(), test.p.Dst.Addr(), test.p.Dst.Port())
			} else {
				got = acl.CheckTCP(test.p.Src.Addr(), test.p.Dst.Addr(), test.p.Dst.Port())
			}
			if test.want != got {
				t.Errorf("#%d CheckTCP got=%v want=%v packet:%v", i, got, test.want, test.p)
			}
			// TCP and UDP are treated equivalently in the filter - verify that.
			test.p.IPProto = ipproto.UDP
			if got, why := aclFunc(&test.p); test.want != got {
				t.Errorf("#%d runIn (UDP) got=%v want=%v why=%q packet:%v", i, got, test.want, why, test.p)
			}
		}
		// Update UDP state
		_, _ = acl.runOut(&test.p)
	}
}

func TestUDPState(t *testing.T) {
	acl := newFilter(t.Logf)
	flags := LogDrops | LogAccepts

	a4 := parsed(ipproto.UDP, "119.119.119.119", "102.102.102.102", 4242, 4343)
	b4 := parsed(ipproto.UDP, "102.102.102.102", "119.119.119.119", 4343, 4242)

	// Unsolicited UDP traffic gets dropped
	if got := acl.RunIn(&a4, flags); got != Drop {
		t.Fatalf("incoming initial packet not dropped, got=%v: %v", got, a4)
	}
	// We talk to that peer
	if got := acl.RunOut(&b4, flags); got != Accept {
		t.Fatalf("outbound packet didn't egress, got=%v: %v", got, b4)
	}
	// Now, the same packet as before is allowed back.
	if got := acl.RunIn(&a4, flags); got != Accept {
		t.Fatalf("incoming response packet not accepted, got=%v: %v", got, a4)
	}

	a6 := parsed(ipproto.UDP, "2001::2", "2001::1", 4242, 4343)
	b6 := parsed(ipproto.UDP, "2001::1", "2001::2", 4343, 4242)

	// Unsolicited UDP traffic gets dropped
	if got := acl.RunIn(&a6, flags); got != Drop {
		t.Fatalf("incoming initial packet not dropped: %v", a4)
	}
	// We talk to that peer
	if got := acl.RunOut(&b6, flags); got != Accept {
		t.Fatalf("outbound packet didn't egress: %v", b4)
	}
	// Now, the same packet as before is allowed back.
	if got := acl.RunIn(&a6, flags); got != Accept {
		t.Fatalf("incoming response packet not accepted: %v", a4)
	}
}

func TestNoAllocs(t *testing.T) {
	acl := newFilter(t.Logf)

	tcp4Packet := raw4(ipproto.TCP, "8.1.1.1", "1.2.3.4", 999, 22, 0)
	udp4Packet := raw4(ipproto.UDP, "8.1.1.1", "1.2.3.4", 999, 22, 0)
	tcp6Packet := raw6(ipproto.TCP, "2001::1", "2001::2", 999, 22, 0)
	udp6Packet := raw6(ipproto.UDP, "2001::1", "2001::2", 999, 22, 0)

	tests := []struct {
		name   string
		dir    direction
		packet []byte
	}{
		{"tcp4_in", in, tcp4Packet},
		{"tcp6_in", in, tcp6Packet},
		{"tcp4_out", out, tcp4Packet},
		{"tcp6_out", out, tcp6Packet},
		{"udp4_in", in, udp4Packet},
		{"udp6_in", in, udp6Packet},
		{"udp4_out", out, udp4Packet},
		{"udp6_out", out, udp6Packet},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := tstest.MinAllocsPerRun(t, 0, func() {
				q := &packet.Parsed{}
				q.Decode(test.packet)
				switch test.dir {
				case in:
					acl.RunIn(q, 0)
				case out:
					acl.RunOut(q, 0)
				}
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestParseIPSet(t *testing.T) {
	tests := []struct {
		host    string
		bits    int
		want    []netip.Prefix
		wantErr string
	}{
		{"8.8.8.8", 24, pfx("8.8.8.8/24"), ""},
		{"2601:1234::", 64, pfx("2601:1234::/64"), ""},
		{"8.8.8.8", 33, nil, `invalid CIDR size 33 for IP "8.8.8.8"`},
		{"8.8.8.8", -1, pfx("8.8.8.8/32"), ""},
		{"8.8.8.8", 32, pfx("8.8.8.8/32"), ""},
		{"8.8.8.8/24", -1, nil, "8.8.8.8/24 contains non-network bits set"},
		{"8.8.8.0/24", 18, pfx("8.8.8.0/24"), ""}, // the 18 is ignored
		{"1.0.0.0-1.255.255.255", 5, pfx("1.0.0.0/8"), ""},
		{"1.0.0.0-2.1.2.3", 5, pfx("1.0.0.0/8", "2.0.0.0/16", "2.1.0.0/23", "2.1.2.0/30"), ""},
		{"1.0.0.2-1.0.0.1", -1, nil, "invalid IP range \"1.0.0.2-1.0.0.1\""},
		{"2601:1234::", 129, nil, `invalid CIDR size 129 for IP "2601:1234::"`},
		{"0.0.0.0", 24, pfx("0.0.0.0/24"), ""},
		{"::", 64, pfx("::/64"), ""},
		{"*", 24, pfx("0.0.0.0/0", "::/0"), ""},
	}
	for _, tt := range tests {
		var bits *int
		if tt.bits != -1 {
			bits = &tt.bits
		}
		got, err := parseIPSet(tt.host, bits)
		if err != nil {
			if err.Error() == tt.wantErr {
				continue
			}
			t.Errorf("parseIPSet(%q, %v) error: %v; want error %q", tt.host, tt.bits, err, tt.wantErr)
		}
		compareIP := cmp.Comparer(func(a, b netip.Addr) bool { return a == b })
		compareIPPrefix := cmp.Comparer(func(a, b netip.Prefix) bool { return a == b })
		if diff := cmp.Diff(got, tt.want, compareIP, compareIPPrefix); diff != "" {
			t.Errorf("parseIPSet(%q, %v) = %s; want %s", tt.host, tt.bits, got, tt.want)
			continue
		}
	}
}

func BenchmarkFilter(b *testing.B) {
	tcp4Packet := raw4(ipproto.TCP, "8.1.1.1", "1.2.3.4", 999, 22, 0)
	udp4Packet := raw4(ipproto.UDP, "8.1.1.1", "1.2.3.4", 999, 22, 0)
	icmp4Packet := raw4(ipproto.ICMPv4, "8.1.1.1", "1.2.3.4", 0, 0, 0)

	tcp6Packet := raw6(ipproto.TCP, "::1", "2001::1", 999, 22, 0)
	udp6Packet := raw6(ipproto.UDP, "::1", "2001::1", 999, 22, 0)
	icmp6Packet := raw6(ipproto.ICMPv6, "::1", "2001::1", 0, 0, 0)

	benches := []struct {
		name   string
		dir    direction
		packet []byte
	}{
		// Non-SYN TCP and ICMP have similar code paths in and out.
		{"icmp4", in, icmp4Packet},
		{"tcp4_syn_in", in, tcp4Packet},
		{"tcp4_syn_out", out, tcp4Packet},
		{"udp4_in", in, udp4Packet},
		{"udp4_out", out, udp4Packet},
		{"icmp6", in, icmp6Packet},
		{"tcp6_syn_in", in, tcp6Packet},
		{"tcp6_syn_out", out, tcp6Packet},
		{"udp6_in", in, udp6Packet},
		{"udp6_out", out, udp6Packet},
	}

	for _, bench := range benches {
		b.Run(bench.name, func(b *testing.B) {
			acl := newFilter(b.Logf)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				q := &packet.Parsed{}
				q.Decode(bench.packet)
				// This branch seems to have no measurable impact on performance.
				if bench.dir == in {
					acl.RunIn(q, 0)
				} else {
					acl.RunOut(q, 0)
				}
			}
		})
	}
}

func TestPreFilter(t *testing.T) {
	packets := []struct {
		desc string
		want Response
		b    []byte
	}{
		{"empty", Accept, []byte{}},
		{"short", Drop, []byte("short")},
		{"junk", Drop, raw4default(ipproto.Unknown, 10)},
		{"fragment", Accept, raw4default(ipproto.Fragment, 40)},
		{"tcp", noVerdict, raw4default(ipproto.TCP, 0)},
		{"udp", noVerdict, raw4default(ipproto.UDP, 0)},
		{"icmp", noVerdict, raw4default(ipproto.ICMPv4, 0)},
	}
	f := NewAllowNone(t.Logf, &netipx.IPSet{})
	for _, testPacket := range packets {
		p := &packet.Parsed{}
		p.Decode(testPacket.b)
		got := f.pre(p, LogDrops|LogAccepts, in)
		if got != testPacket.want {
			t.Errorf("%q got=%v want=%v packet:\n%s", testPacket.desc, got, testPacket.want, packet.Hexdump(testPacket.b))
		}
	}
}

func TestOmitDropLogging(t *testing.T) {
	tests := []struct {
		name string
		pkt  *packet.Parsed
		dir  direction
		want bool
	}{
		{
			name: "v4_tcp_out",
			pkt:  &packet.Parsed{IPVersion: 4, IPProto: ipproto.TCP},
			dir:  out,
			want: false,
		},
		{
			name: "v6_icmp_out", // as seen on Linux
			pkt:  parseHexPkt(t, "60 00 00 00 00 00 3a 00   fe800000000000000000000000000000 ff020000000000000000000000000002"),
			dir:  out,
			want: true,
		},
		{
			name: "v6_to_MLDv2_capable_routers", // as seen on Windows
			pkt:  parseHexPkt(t, "60 00 00 00 00 24 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff 02 00 00 00 00 00 00 00 00 00 00 00 00 00 16 3a 00 05 02 00 00 01 00 8f 00 6e 80 00 00 00 01 04 00 00 00 ff 02 00 00 00 00 00 00 00 00 00 00 00 00 00 0c"),
			dir:  out,
			want: true,
		},
		{
			name: "v4_igmp_out", // on Windows, from https://github.com/tailscale/tailscale/issues/618
			pkt:  parseHexPkt(t, "46 00 00 30 37 3a 00 00 01 02 10 0e a9 fe 53 6b e0 00 00 16 94 04 00 00 22 00 14 05 00 00 00 02 04 00 00 00 e0 00 00 fb 04 00 00 00 e0 00 00 fc"),
			dir:  out,
			want: true,
		},
		{
			name: "v6_udp_multicast",
			pkt:  parseHexPkt(t, "60 00 00 00 00 00 11 00  fe800000000000007dc6bc04499262a3 ff120000000000000000000000008384"),
			dir:  out,
			want: true,
		},
		{
			name: "v4_multicast_out_low",
			pkt:  &packet.Parsed{IPVersion: 4, Dst: mustIPPort("224.0.0.0:0")},
			dir:  out,
			want: true,
		},
		{
			name: "v4_multicast_out_high",
			pkt:  &packet.Parsed{IPVersion: 4, Dst: mustIPPort("239.255.255.255:0")},
			dir:  out,
			want: true,
		},
		{
			name: "v4_link_local_unicast",
			pkt:  &packet.Parsed{IPVersion: 4, Dst: mustIPPort("169.254.1.2:0")},
			dir:  out,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := omitDropLogging(tt.pkt, tt.dir)
			if got != tt.want {
				t.Errorf("got %v; want %v\npacket: %#v\n%s", got, tt.want, tt.pkt, packet.Hexdump(tt.pkt.Buffer()))
			}
		})
	}
}

func TestLoggingPrivacy(t *testing.T) {
	oldDrop := dropBucket
	oldAccept := acceptBucket
	dropBucket = rate.NewLimiter(2^32, 2^32)
	acceptBucket = dropBucket
	defer func() {
		dropBucket = oldDrop
		acceptBucket = oldAccept
	}()

	var (
		logged     bool
		testLogger logger.Logf
	)
	logf := func(format string, args ...any) {
		testLogger(format, args...)
		logged = true
	}

	var logB netipx.IPSetBuilder
	logB.AddPrefix(netip.MustParsePrefix("100.64.0.0/10"))
	logB.AddPrefix(tsaddr.TailscaleULARange())
	f := newFilter(logf)
	f.logIPs, _ = logB.IPSet()

	var (
		ts4       = netip.AddrPortFrom(tsaddr.CGNATRange().Addr().Next(), 1234)
		internet4 = netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 1234)
		ts6       = netip.AddrPortFrom(tsaddr.TailscaleULARange().Addr().Next(), 1234)
		internet6 = netip.AddrPortFrom(netip.MustParseAddr("2001::1"), 1234)
	)

	tests := []struct {
		name   string
		pkt    *packet.Parsed
		dir    direction
		logged bool
	}{
		{
			name:   "ts_to_ts_v4_out",
			pkt:    &packet.Parsed{IPVersion: 4, IPProto: ipproto.TCP, Src: ts4, Dst: ts4},
			dir:    out,
			logged: true,
		},
		{
			name:   "ts_to_internet_v4_out",
			pkt:    &packet.Parsed{IPVersion: 4, IPProto: ipproto.TCP, Src: ts4, Dst: internet4},
			dir:    out,
			logged: false,
		},
		{
			name:   "internet_to_ts_v4_out",
			pkt:    &packet.Parsed{IPVersion: 4, IPProto: ipproto.TCP, Src: internet4, Dst: ts4},
			dir:    out,
			logged: false,
		},
		{
			name:   "ts_to_ts_v4_in",
			pkt:    &packet.Parsed{IPVersion: 4, IPProto: ipproto.TCP, Src: ts4, Dst: ts4},
			dir:    in,
			logged: true,
		},
		{
			name:   "ts_to_internet_v4_in",
			pkt:    &packet.Parsed{IPVersion: 4, IPProto: ipproto.TCP, Src: ts4, Dst: internet4},
			dir:    in,
			logged: false,
		},
		{
			name:   "internet_to_ts_v4_in",
			pkt:    &packet.Parsed{IPVersion: 4, IPProto: ipproto.TCP, Src: internet4, Dst: ts4},
			dir:    in,
			logged: false,
		},
		{
			name:   "ts_to_ts_v6_out",
			pkt:    &packet.Parsed{IPVersion: 6, IPProto: ipproto.TCP, Src: ts6, Dst: ts6},
			dir:    out,
			logged: true,
		},
		{
			name:   "ts_to_internet_v6_out",
			pkt:    &packet.Parsed{IPVersion: 6, IPProto: ipproto.TCP, Src: ts6, Dst: internet6},
			dir:    out,
			logged: false,
		},
		{
			name:   "internet_to_ts_v6_out",
			pkt:    &packet.Parsed{IPVersion: 6, IPProto: ipproto.TCP, Src: internet6, Dst: ts6},
			dir:    out,
			logged: false,
		},
		{
			name:   "ts_to_ts_v6_in",
			pkt:    &packet.Parsed{IPVersion: 6, IPProto: ipproto.TCP, Src: ts6, Dst: ts6},
			dir:    in,
			logged: true,
		},
		{
			name:   "ts_to_internet_v6_in",
			pkt:    &packet.Parsed{IPVersion: 6, IPProto: ipproto.TCP, Src: ts6, Dst: internet6},
			dir:    in,
			logged: false,
		},
		{
			name:   "internet_to_ts_v6_in",
			pkt:    &packet.Parsed{IPVersion: 6, IPProto: ipproto.TCP, Src: internet6, Dst: ts6},
			dir:    in,
			logged: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.pkt.StuffForTesting(1024)
			logged = false
			testLogger = t.Logf
			switch test.dir {
			case out:
				f.RunOut(test.pkt, LogDrops|LogAccepts)
			case in:
				f.RunIn(test.pkt, LogDrops|LogAccepts)
			default:
				panic("unknown direction")
			}
			if logged != test.logged {
				t.Errorf("logged = %v, want %v", logged, test.logged)
			}
		})
	}
}

var mustIP = netip.MustParseAddr

func parsed(proto ipproto.Proto, src, dst string, sport, dport uint16) packet.Parsed {
	sip, dip := mustIP(src), mustIP(dst)

	var ret packet.Parsed
	ret.Decode(dummyPacket)
	ret.IPProto = proto
	ret.Src = netip.AddrPortFrom(sip, sport)
	ret.Dst = netip.AddrPortFrom(dip, dport)
	ret.TCPFlags = packet.TCPSyn

	if sip.Is4() {
		ret.IPVersion = 4
	} else {
		ret.IPVersion = 6
	}

	return ret
}

func raw6(proto ipproto.Proto, src, dst string, sport, dport uint16, trimLen int) []byte {
	u := packet.UDP6Header{
		IP6Header: packet.IP6Header{
			Src: mustIP(src),
			Dst: mustIP(dst),
		},
		SrcPort: sport,
		DstPort: dport,
	}

	payload := make([]byte, 12)
	// Set the right bit to look like a TCP SYN, if the packet ends up interpreted as TCP
	payload[5] = byte(packet.TCPSyn)

	b := packet.Generate(&u, payload) // payload large enough to possibly be TCP

	// UDP marshaling clobbers IPProto, so override it here.
	u.IP6Header.IPProto = proto
	if err := u.IP6Header.Marshal(b); err != nil {
		panic(err)
	}

	if trimLen > 0 {
		return b[:trimLen]
	} else {
		return b
	}
}

func raw4(proto ipproto.Proto, src, dst string, sport, dport uint16, trimLength int) []byte {
	u := packet.UDP4Header{
		IP4Header: packet.IP4Header{
			Src: mustIP(src),
			Dst: mustIP(dst),
		},
		SrcPort: sport,
		DstPort: dport,
	}

	payload := make([]byte, 12)
	// Set the right bit to look like a TCP SYN, if the packet ends up interpreted as TCP
	payload[5] = byte(packet.TCPSyn)

	b := packet.Generate(&u, payload) // payload large enough to possibly be TCP

	// UDP marshaling clobbers IPProto, so override it here.
	switch proto {
	case ipproto.Unknown, ipproto.Fragment:
	default:
		u.IP4Header.IPProto = proto
	}
	if err := u.IP4Header.Marshal(b); err != nil {
		panic(err)
	}

	if proto == ipproto.Fragment {
		// Set some fragment offset. This makes the IP
		// checksum wrong, but we don't validate the checksum
		// when parsing.
		b[7] = 255
	}

	if trimLength > 0 {
		return b[:trimLength]
	} else {
		return b
	}
}

func raw4default(proto ipproto.Proto, trimLength int) []byte {
	return raw4(proto, "8.8.8.8", "8.8.8.8", 53, 53, trimLength)
}

func parseHexPkt(t *testing.T, h string) *packet.Parsed {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
	if err != nil {
		t.Fatalf("failed to read hex %q: %v", h, err)
	}
	p := new(packet.Parsed)
	p.Decode(b)
	return p
}

func mustIPPort(s string) netip.AddrPort {
	ipp, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ipp
}

func pfx(strs ...string) (ret []netip.Prefix) {
	for _, s := range strs {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			panic(err)
		}
		ret = append(ret, pfx)
	}
	return ret
}

func nets(nets ...string) (ret []netip.Prefix) {
	for _, s := range nets {
		if !strings.Contains(s, "/") {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				panic(err)
			}
			bits := uint8(32)
			if ip.Is6() {
				bits = 128
			}
			ret = append(ret, netip.PrefixFrom(ip, int(bits)))
		} else {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				panic(err)
			}
			ret = append(ret, pfx)
		}
	}
	return ret
}

func ports(s string) PortRange {
	if s == "*" {
		return allPorts
	}

	var fs, ls string
	i := strings.IndexByte(s, '-')
	if i == -1 {
		fs = s
		ls = fs
	} else {
		fs = s[:i]
		ls = s[i+1:]
	}
	first, err := strconv.ParseInt(fs, 10, 16)
	if err != nil {
		panic(fmt.Sprintf("invalid NetPortRange %q", s))
	}
	last, err := strconv.ParseInt(ls, 10, 16)
	if err != nil {
		panic(fmt.Sprintf("invalid NetPortRange %q", s))
	}
	return PortRange{uint16(first), uint16(last)}
}

func netports(netPorts ...string) (ret []NetPortRange) {
	for _, s := range netPorts {
		i := strings.LastIndexByte(s, ':')
		if i == -1 {
			panic(fmt.Sprintf("invalid NetPortRange %q", s))
		}

		npr := NetPortRange{
			Net:   nets(s[:i])[0],
			Ports: ports(s[i+1:]),
		}
		ret = append(ret, npr)
	}
	return ret
}

func TestMatchesFromFilterRules(t *testing.T) {
	tests := []struct {
		name string
		in   []tailcfg.FilterRule
		want []Match
	}{
		{
			name: "empty",
			want: []Match{},
		},
		{
			name: "implicit_protos",
			in: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.1.1"},
					DstPorts: []tailcfg.NetPortRange{{
						IP:    "*",
						Ports: tailcfg.PortRange{First: 22, Last: 22},
					}},
				},
			},
			want: []Match{
				{
					IPProto: []ipproto.Proto{
						ipproto.TCP,
						ipproto.UDP,
						ipproto.ICMPv4,
						ipproto.ICMPv6,
					},
					Dsts: []NetPortRange{
						{
							Net:   netip.MustParsePrefix("0.0.0.0/0"),
							Ports: PortRange{22, 22},
						},
						{
							Net:   netip.MustParsePrefix("::0/0"),
							Ports: PortRange{22, 22},
						},
					},
					Srcs: []netip.Prefix{
						netip.MustParsePrefix("100.64.1.1/32"),
					},
					Caps: []CapMatch{},
				},
			},
		},
		{
			name: "explicit_protos",
			in: []tailcfg.FilterRule{
				{
					IPProto: []int{int(ipproto.TCP)},
					SrcIPs:  []string{"100.64.1.1"},
					DstPorts: []tailcfg.NetPortRange{{
						IP:    "1.2.0.0/16",
						Ports: tailcfg.PortRange{First: 22, Last: 22},
					}},
				},
			},
			want: []Match{
				{
					IPProto: []ipproto.Proto{
						ipproto.TCP,
					},
					Dsts: []NetPortRange{
						{
							Net:   netip.MustParsePrefix("1.2.0.0/16"),
							Ports: PortRange{22, 22},
						},
					},
					Srcs: []netip.Prefix{
						netip.MustParsePrefix("100.64.1.1/32"),
					},
					Caps: []CapMatch{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MatchesFromFilterRules(tt.in)
			if err != nil {
				t.Fatal(err)
			}

			compareIP := cmp.Comparer(func(a, b netip.Addr) bool { return a == b })
			compareIPPrefix := cmp.Comparer(func(a, b netip.Prefix) bool { return a == b })
			if diff := cmp.Diff(got, tt.want, compareIP, compareIPPrefix); diff != "" {
				t.Errorf("wrong (-got+want)\n%s", diff)
			}
		})
	}
}

func TestNewAllowAllForTest(t *testing.T) {
	f := NewAllowAllForTest(logger.Discard)
	src := netip.MustParseAddr("100.100.2.3")
	dst := netip.MustParseAddr("100.100.1.2")
	res := f.CheckTCP(src, dst, 80)
	if res.IsDrop() {
		t.Fatalf("unexpected drop verdict: %v", res)
	}
}

func TestMatchesMatchProtoAndIPsOnlyIfAllPorts(t *testing.T) {
	tests := []struct {
		name string
		m    Match
		p    packet.Parsed
		want bool
	}{
		{
			name: "all_ports_okay",
			m:    m(nets("0.0.0.0/0"), netports("0.0.0.0/0:*"), testAllowedProto),
			p:    parsed(testAllowedProto, "1.2.3.4", "5.6.7.8", 0, 0),
			want: true,
		},
		{
			name: "all_ports_match_but_packet_wrong_proto",
			m:    m(nets("0.0.0.0/0"), netports("0.0.0.0/0:*"), testAllowedProto),
			p:    parsed(testDeniedProto, "1.2.3.4", "5.6.7.8", 0, 0),
			want: false,
		},
		{
			name: "ports_requirements_dont_match_unknown_proto",
			m:    m(nets("0.0.0.0/0"), netports("0.0.0.0/0:12345"), testAllowedProto),
			p:    parsed(testAllowedProto, "1.2.3.4", "5.6.7.8", 0, 0),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := matches{tt.m}
			got := matches.matchProtoAndIPsOnlyIfAllPorts(&tt.p)
			if got != tt.want {
				t.Errorf("got = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestCaps(t *testing.T) {
	mm, err := MatchesFromFilterRules([]tailcfg.FilterRule{
		{
			SrcIPs: []string{"*"},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
				Caps: []string{"is_ipv4"},
			}},
		},
		{
			SrcIPs: []string{"*"},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{
					netip.MustParsePrefix("::/0"),
				},
				Caps: []string{"is_ipv6"},
			}},
		},
		{
			SrcIPs: []string{"100.199.0.0/16"},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{
					netip.MustParsePrefix("100.200.0.0/16"),
				},
				Caps: []string{"some_super_admin"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	filt := New(mm, nil, nil, nil, t.Logf)
	tests := []struct {
		name     string
		src, dst string // IP
		want     []string
	}{
		{
			name: "v4",
			src:  "1.2.3.4",
			dst:  "2.4.5.5",
			want: []string{"is_ipv4"},
		},
		{
			name: "v6",
			src:  "1::1",
			dst:  "2::2",
			want: []string{"is_ipv6"},
		},
		{
			name: "admin",
			src:  "100.199.1.2",
			dst:  "100.200.3.4",
			want: []string{"is_ipv4", "some_super_admin"},
		},
		{
			name: "not_admin_bad_src",
			src:  "100.198.1.2", // 198, not 199
			dst:  "100.200.3.4",
			want: []string{"is_ipv4"},
		},
		{
			name: "not_admin_bad_dst",
			src:  "100.199.1.2",
			dst:  "100.201.3.4", // 201, not 200
			want: []string{"is_ipv4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filt.AppendCaps(nil, netip.MustParseAddr(tt.src), netip.MustParseAddr(tt.dst))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}
