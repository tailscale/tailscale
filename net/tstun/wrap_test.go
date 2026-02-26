// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"expvar"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"go4.org/mem"
	"go4.org/netipx"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/disco"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/tstest"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netlogtype"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/netstack/gro"
	"tailscale.com/wgengine/wgcfg"
)

func udp4(src, dst string, sport, dport uint16) []byte {
	sip, err := netip.ParseAddr(src)
	if err != nil {
		panic(err)
	}
	dip, err := netip.ParseAddr(dst)
	if err != nil {
		panic(err)
	}
	header := &packet.UDP4Header{
		IP4Header: packet.IP4Header{
			Src:  sip,
			Dst:  dip,
			IPID: 0,
		},
		SrcPort: sport,
		DstPort: dport,
	}
	return packet.Generate(header, []byte("udp_payload"))
}

func tcp4syn(src, dst string, sport, dport uint16) []byte {
	sip, err := netip.ParseAddr(src)
	if err != nil {
		panic(err)
	}
	dip, err := netip.ParseAddr(dst)
	if err != nil {
		panic(err)
	}
	ipHeader := packet.IP4Header{
		IPProto: ipproto.TCP,
		Src:     sip,
		Dst:     dip,
		IPID:    0,
	}
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:], sport)
	binary.BigEndian.PutUint16(tcpHeader[2:], dport)
	tcpHeader[13] |= 2 // SYN

	both := packet.Generate(ipHeader, tcpHeader)

	// 20 byte IP4 + 20 byte TCP
	binary.BigEndian.PutUint16(both[2:4], 40)

	return both
}

func nets(nets ...string) (ret []netip.Prefix) {
	for _, s := range nets {
		if i := strings.IndexByte(s, '/'); i == -1 {
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

func ports(s string) filter.PortRange {
	if s == "*" {
		return filter.PortRange{First: 0, Last: 65535}
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
	return filter.PortRange{First: uint16(first), Last: uint16(last)}
}

func netports(netPorts ...string) (ret []filter.NetPortRange) {
	for _, s := range netPorts {
		i := strings.LastIndexByte(s, ':')
		if i == -1 {
			panic(fmt.Sprintf("invalid NetPortRange %q", s))
		}

		npr := filter.NetPortRange{
			Net:   nets(s[:i])[0],
			Ports: ports(s[i+1:]),
		}
		ret = append(ret, npr)
	}
	return ret
}

func setfilter(logf logger.Logf, tun *Wrapper) {
	protos := views.SliceOf([]ipproto.Proto{
		ipproto.TCP,
		ipproto.UDP,
	})
	matches := []filter.Match{
		{IPProto: protos, Srcs: nets("5.6.7.8"), Dsts: netports("1.2.3.4:89-90")},
		{IPProto: protos, Srcs: nets("1.2.3.4"), Dsts: netports("5.6.7.8:98")},
	}
	var sb netipx.IPSetBuilder
	sb.AddPrefix(netip.MustParsePrefix("1.2.0.0/16"))
	ipSet, _ := sb.IPSet()
	tun.SetFilter(filter.New(matches, nil, ipSet, ipSet, nil, logf))
}

func newChannelTUN(logf logger.Logf, bus *eventbus.Bus, secure bool) (*tuntest.ChannelTUN, *Wrapper) {
	chtun := tuntest.NewChannelTUN()
	reg := new(usermetric.Registry)
	tun := Wrap(logf, chtun.TUN(), reg, bus)
	if secure {
		setfilter(logf, tun)
	} else {
		tun.disableFilter = true
	}
	tun.Start()
	return chtun, tun
}

func newFakeTUN(logf logger.Logf, bus *eventbus.Bus, secure bool) (*fakeTUN, *Wrapper) {
	ftun := NewFake()
	reg := new(usermetric.Registry)
	tun := Wrap(logf, ftun, reg, bus)
	if secure {
		setfilter(logf, tun)
	} else {
		tun.disableFilter = true
	}
	return ftun.(*fakeTUN), tun
}

func TestReadAndInject(t *testing.T) {
	bus := eventbustest.NewBus(t)
	chtun, tun := newChannelTUN(t.Logf, bus, false)
	defer tun.Close()

	const size = 2 // all payloads have this size
	written := []string{"w0", "w1"}
	injected := []string{"i0", "i1"}

	go func() {
		for _, packet := range written {
			payload := []byte(packet)
			chtun.Outbound <- payload
		}
	}()

	for _, packet := range injected {
		go func(packet string) {
			payload := []byte(packet)
			err := tun.InjectOutbound(payload)
			if err != nil {
				t.Errorf("%s: error: %v", packet, err)
			}
		}(packet)
	}

	var buf [MaxPacketSize]byte
	seen := make(map[string]bool)
	sizes := make([]int, 1)
	// We expect the same packets back, in no particular order.
	for i := range len(written) + len(injected) {
		packet := buf[:]
		buffs := [][]byte{packet}
		numPackets, err := tun.Read(buffs, sizes, 0)
		if err != nil {
			t.Errorf("read %d: error: %v", i, err)
		}
		if numPackets != 1 {
			t.Fatalf("read %d packets, expected %d", numPackets, 1)
		}
		packet = packet[:sizes[0]]
		packetLen := len(packet)
		if packetLen != size {
			t.Errorf("read %d: got size %d; want %d", i, packetLen, size)
		}
		got := string(packet)
		t.Logf("read %d: got %s", i, got)
		seen[got] = true
	}

	for _, packet := range written {
		if !seen[packet] {
			t.Errorf("%s not received", packet)
		}
	}
	for _, packet := range injected {
		if !seen[packet] {
			t.Errorf("%s not received", packet)
		}
	}
}

func TestWriteAndInject(t *testing.T) {
	bus := eventbustest.NewBus(t)
	chtun, tun := newChannelTUN(t.Logf, bus, false)
	defer tun.Close()

	written := []string{"w0", "w1"}
	injected := []string{"i0", "i1"}

	go func() {
		for _, packet := range written {
			payload := []byte(packet)
			_, err := tun.Write([][]byte{payload}, 0)
			if err != nil {
				t.Errorf("%s: error: %v", packet, err)
			}
		}
	}()

	for _, packet := range injected {
		go func(packet string) {
			payload := []byte(packet)
			err := tun.InjectInboundCopy(payload)
			if err != nil {
				t.Errorf("%s: error: %v", packet, err)
			}
		}(packet)
	}

	seen := make(map[string]bool)
	// We expect the same packets back, in no particular order.
	for i := range len(written) + len(injected) {
		packet := <-chtun.Inbound
		got := string(packet)
		t.Logf("read %d: got %s", i, got)
		seen[got] = true
	}

	for _, packet := range written {
		if !seen[packet] {
			t.Errorf("%s not received", packet)
		}
	}
	for _, packet := range injected {
		if !seen[packet] {
			t.Errorf("%s not received", packet)
		}
	}
}

// mustHexDecode is like hex.DecodeString, but panics on error
// and ignores whitespace in s.
func mustHexDecode(s string) []byte {
	return must.Get(hex.DecodeString(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)))
}

func TestFilter(t *testing.T) {
	bus := eventbustest.NewBus(t)
	chtun, tun := newChannelTUN(t.Logf, bus, true)
	defer tun.Close()

	// Reset the metrics before test. These are global
	// so the different tests might have affected them.
	tun.metrics.inboundDroppedPacketsTotal.ResetAllForTest()
	tun.metrics.outboundDroppedPacketsTotal.ResetAllForTest()

	type direction int

	const (
		in direction = iota
		out
	)

	tests := []struct {
		name string
		dir  direction
		drop bool
		data []byte
	}{
		{"short_in", in, true, []byte("\x45xxx")},
		{"short_out", out, true, []byte("\x45xxx")},
		{"ip97_out", out, false, mustHexDecode("4500 0019 d186 4000 4061 751d 644a 4603 6449 e549 6865 6c6c 6f")},
		{"bad_port_in", in, true, udp4("5.6.7.8", "1.2.3.4", 22, 22)},
		{"bad_port_out", out, false, udp4("1.2.3.4", "5.6.7.8", 22, 22)},
		{"bad_ip_in", in, true, udp4("8.1.1.1", "1.2.3.4", 89, 89)},
		{"bad_ip_out", out, false, udp4("1.2.3.4", "8.1.1.1", 98, 98)},
		{"good_packet_in", in, false, udp4("5.6.7.8", "1.2.3.4", 89, 89)},
		{"good_packet_out", out, false, udp4("1.2.3.4", "5.6.7.8", 98, 98)},
	}

	// A reader on the other end of the tun.
	go func() {
		var recvbuf []byte
		for {
			select {
			case <-tun.closed:
				return
			case recvbuf = <-chtun.Inbound:
				// continue
			}
			for _, tt := range tests {
				if tt.drop && bytes.Equal(recvbuf, tt.data) {
					t.Errorf("did not drop %s", tt.name)
				}
			}
		}
	}()

	var buf [MaxPacketSize]byte
	var stats netlogtype.CountsByConnection
	tun.SetConnectionCounter(stats.Add)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var n int
			var err error
			var filtered bool
			sizes := make([]int, 1)

			tunStats := stats.Clone()
			stats.Reset()
			if len(tunStats) > 0 {
				t.Errorf("netlogtype.CountsByConnection = %v, want {}", tunStats)
			}

			if tt.dir == in {
				// Use the side effect of updating the last
				// activity atomic to determine whether the
				// data was actually filtered.
				// If it stays zero, nothing made it through
				// to the wrapped TUN.
				tun.lastActivityAtomic.StoreAtomic(0)
				_, err = tun.Write([][]byte{tt.data}, 0)
				filtered = tun.lastActivityAtomic.LoadAtomic() == 0
			} else {
				chtun.Outbound <- tt.data
				n, err = tun.Read([][]byte{buf[:]}, sizes, 0)
				// In the read direction, errors are fatal, so we return n = 0 instead.
				filtered = (n == 0)
			}

			if err != nil {
				t.Errorf("got err %v; want nil", err)
			}

			if filtered {
				if !tt.drop {
					t.Errorf("got drop; want accept")
				}
			} else {
				if tt.drop {
					t.Errorf("got accept; want drop")
				}
			}

			got := stats.Clone()
			stats.Reset()
			want := map[netlogtype.Connection]netlogtype.Counts{}
			var wasUDP bool
			if !tt.drop {
				var p packet.Parsed
				p.Decode(tt.data)
				wasUDP = p.IPProto == ipproto.UDP
				switch tt.dir {
				case in:
					conn := netlogtype.Connection{Proto: ipproto.UDP, Src: p.Dst, Dst: p.Src}
					want[conn] = netlogtype.Counts{RxPackets: 1, RxBytes: uint64(len(tt.data))}
				case out:
					conn := netlogtype.Connection{Proto: ipproto.UDP, Src: p.Src, Dst: p.Dst}
					want[conn] = netlogtype.Counts{TxPackets: 1, TxBytes: uint64(len(tt.data))}
				}
			}
			if wasUDP {
				if diff := cmp.Diff(got, want, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("stats.TestExtract (-got +want):\n%s", diff)
				}
			}
		})
	}

	var metricInboundDroppedPacketsACL, metricInboundDroppedPacketsErr, metricOutboundDroppedPacketsACL int64
	if m, ok := tun.metrics.inboundDroppedPacketsTotal.Get(usermetric.DropLabels{Reason: usermetric.ReasonACL}).(*expvar.Int); ok {
		metricInboundDroppedPacketsACL = m.Value()
	}
	if m, ok := tun.metrics.inboundDroppedPacketsTotal.Get(usermetric.DropLabels{Reason: usermetric.ReasonError}).(*expvar.Int); ok {
		metricInboundDroppedPacketsErr = m.Value()
	}
	if m, ok := tun.metrics.outboundDroppedPacketsTotal.Get(usermetric.DropLabels{Reason: usermetric.ReasonACL}).(*expvar.Int); ok {
		metricOutboundDroppedPacketsACL = m.Value()
	}

	assertMetricPackets(t, "inACL", 3, metricInboundDroppedPacketsACL)
	assertMetricPackets(t, "inError", 0, metricInboundDroppedPacketsErr)
	assertMetricPackets(t, "outACL", 0, metricOutboundDroppedPacketsACL)
}

func assertMetricPackets(t *testing.T, metricName string, want, got int64) {
	t.Helper()
	if want != got {
		t.Errorf("%s got unexpected value, got %d, want %d", metricName, got, want)
	}
}

func TestAllocs(t *testing.T) {
	bus := eventbustest.NewBus(t)
	ftun, tun := newFakeTUN(t.Logf, bus, false)
	defer tun.Close()

	buf := [][]byte{{0x00}}
	err := tstest.MinAllocsPerRun(t, 0, func() {
		_, err := ftun.Write(buf, 0)
		if err != nil {
			t.Errorf("write: error: %v", err)
			return
		}
	})
	if err != nil {
		t.Error(err)
	}
}

func TestClose(t *testing.T) {
	bus := eventbustest.NewBus(t)
	ftun, tun := newFakeTUN(t.Logf, bus, false)

	data := [][]byte{udp4("1.2.3.4", "5.6.7.8", 98, 98)}
	_, err := ftun.Write(data, 0)
	if err != nil {
		t.Error(err)
	}

	tun.Close()
	_, err = ftun.Write(data, 0)
	if err == nil {
		t.Error("Expected error from ftun.Write() after Close()")
	}
}

func BenchmarkWrite(b *testing.B) {
	b.ReportAllocs()
	bus := eventbustest.NewBus(b)
	ftun, tun := newFakeTUN(b.Logf, bus, true)
	defer tun.Close()

	packet := [][]byte{udp4("5.6.7.8", "1.2.3.4", 89, 89)}
	for range b.N {
		_, err := ftun.Write(packet, 0)
		if err != nil {
			b.Errorf("err = %v; want nil", err)
		}
	}
}

func TestAtomic64Alignment(t *testing.T) {
	off := unsafe.Offsetof(Wrapper{}.lastActivityAtomic)
	if off%8 != 0 {
		t.Errorf("offset %v not 8-byte aligned", off)
	}

	c := new(Wrapper)
	c.lastActivityAtomic.StoreAtomic(mono.Now())
}

func TestPeerAPIBypass(t *testing.T) {
	reg := new(usermetric.Registry)
	wrapperWithPeerAPI := &Wrapper{
		PeerAPIPort: func(ip netip.Addr) (port uint16, ok bool) {
			if ip == netip.MustParseAddr("100.64.1.2") {
				return 60000, true
			}
			return
		},
		metrics: registerMetrics(reg),
	}

	tests := []struct {
		name   string
		w      *Wrapper
		filter *filter.Filter
		pkt    []byte
		want   filter.Response
	}{
		{
			name: "reject_nil_filter",
			w: &Wrapper{
				PeerAPIPort: func(netip.Addr) (port uint16, ok bool) {
					return 60000, true
				},
				metrics: registerMetrics(reg),
			},
			pkt:  tcp4syn("1.2.3.4", "100.64.1.2", 1234, 60000),
			want: filter.Drop,
		},
		{
			name: "reject_with_filter",
			w: &Wrapper{
				metrics: registerMetrics(reg),
			},
			filter: filter.NewAllowNone(logger.Discard, new(netipx.IPSet)),
			pkt:    tcp4syn("1.2.3.4", "100.64.1.2", 1234, 60000),
			want:   filter.Drop,
		},
		{
			name:   "peerapi_bypass_filter",
			w:      wrapperWithPeerAPI,
			filter: filter.NewAllowNone(logger.Discard, new(netipx.IPSet)),
			pkt:    tcp4syn("1.2.3.4", "100.64.1.2", 1234, 60000),
			want:   filter.Accept,
		},
		{
			name:   "peerapi_dont_bypass_filter_wrong_port",
			w:      wrapperWithPeerAPI,
			filter: filter.NewAllowNone(logger.Discard, new(netipx.IPSet)),
			pkt:    tcp4syn("1.2.3.4", "100.64.1.2", 1234, 60001),
			want:   filter.Drop,
		},
		{
			name:   "peerapi_dont_bypass_filter_wrong_dst_ip",
			w:      wrapperWithPeerAPI,
			filter: filter.NewAllowNone(logger.Discard, new(netipx.IPSet)),
			pkt:    tcp4syn("1.2.3.4", "100.64.1.3", 1234, 60000),
			want:   filter.Drop,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := new(packet.Parsed)
			p.Decode(tt.pkt)
			tt.w.SetFilter(tt.filter)
			tt.w.disableTSMPRejected = true
			tt.w.logf = t.Logf
			if got, _ := tt.w.filterPacketInboundFromWireGuard(p, nil, nil, nil); got != tt.want {
				t.Errorf("got = %v; want %v", got, tt.want)
			}
		})
	}
}

// Issue 1526: drop disco frames from ourselves.
func TestFilterDiscoLoop(t *testing.T) {
	var memLog tstest.MemLogger
	discoPub := key.DiscoPublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 31: 0}))
	tw := &Wrapper{logf: memLog.Logf, limitedLogf: memLog.Logf}
	tw.SetDiscoKey(discoPub)
	uh := packet.UDP4Header{
		IP4Header: packet.IP4Header{
			IPProto: ipproto.UDP,
			Src:     netaddr.IPv4(1, 2, 3, 4),
			Dst:     netaddr.IPv4(5, 6, 7, 8),
		},
		SrcPort: 9,
		DstPort: 10,
	}
	discobs := discoPub.Raw32()
	discoPayload := fmt.Sprintf("%s%s%s", disco.Magic, discobs[:], [disco.NonceLen]byte{})
	pkt := make([]byte, uh.Len()+len(discoPayload))
	uh.Marshal(pkt)
	copy(pkt[uh.Len():], discoPayload)

	p := new(packet.Parsed)
	p.Decode(pkt)
	got, _ := tw.filterPacketInboundFromWireGuard(p, nil, nil, nil)
	if got != filter.DropSilently {
		t.Errorf("got %v; want DropSilently", got)
	}
	if got, want := memLog.String(), "[unexpected] received self disco in packet over tstun; dropping\n"; got != want {
		t.Errorf("log output mismatch\n got: %q\nwant: %q\n", got, want)
	}

	memLog.Reset()
	pp := new(packet.Parsed)
	pp.Decode(pkt)
	got, _ = tw.filterPacketOutboundToWireGuard(pp, nil, nil)
	if got != filter.DropSilently {
		t.Errorf("got %v; want DropSilently", got)
	}
	if got, want := memLog.String(), "[unexpected] received self disco out packet over tstun; dropping\n"; got != want {
		t.Errorf("log output mismatch\n got: %q\nwant: %q\n", got, want)
	}
}

// TODO(andrew-d): refactor this test to no longer use addrFam, after #11945
// removed it in peerConfigFromWGConfig
func TestPeerCfg_NAT(t *testing.T) {
	node := func(ip, masqIP netip.Addr, otherAllowedIPs ...netip.Prefix) wgcfg.Peer {
		p := wgcfg.Peer{
			PublicKey: key.NewNode().Public(),
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(ip, ip.BitLen()),
			},
		}
		if masqIP.Is4() {
			p.V4MasqAddr = ptr.To(masqIP)
		} else {
			p.V6MasqAddr = ptr.To(masqIP)
		}
		p.AllowedIPs = append(p.AllowedIPs, otherAllowedIPs...)
		return p
	}
	test := func(addrFam ipproto.Version) {
		var (
			noIP netip.Addr

			selfNativeIP = netip.MustParseAddr("100.64.0.1")
			selfEIP1     = netip.MustParseAddr("100.64.1.1")
			selfEIP2     = netip.MustParseAddr("100.64.1.2")
			selfAddrs    = []netip.Prefix{netip.PrefixFrom(selfNativeIP, selfNativeIP.BitLen())}

			peer1IP = netip.MustParseAddr("100.64.0.2")
			peer2IP = netip.MustParseAddr("100.64.0.3")

			subnet   = netip.MustParsePrefix("192.168.0.0/24")
			subnetIP = netip.MustParseAddr("192.168.0.1")

			exitRoute = netip.MustParsePrefix("0.0.0.0/0")
			publicIP  = netip.MustParseAddr("8.8.8.8")
		)
		if addrFam == ipproto.Version6 {
			selfNativeIP = netip.MustParseAddr("fd7a:115c:a1e0::a")
			selfEIP1 = netip.MustParseAddr("fd7a:115c:a1e0::1a")
			selfEIP2 = netip.MustParseAddr("fd7a:115c:a1e0::1b")
			selfAddrs = []netip.Prefix{netip.PrefixFrom(selfNativeIP, selfNativeIP.BitLen())}

			peer1IP = netip.MustParseAddr("fd7a:115c:a1e0::b")
			peer2IP = netip.MustParseAddr("fd7a:115c:a1e0::c")

			subnet = netip.MustParsePrefix("2001:db8::/32")
			subnetIP = netip.MustParseAddr("2001:db8::FFFF")

			exitRoute = netip.MustParsePrefix("::/0")
			publicIP = netip.MustParseAddr("2001:4860:4860::8888")
		}

		type dnatTest struct {
			src  netip.Addr
			dst  netip.Addr
			want netip.Addr // new destination after DNAT
		}

		tests := []struct {
			name    string
			wcfg    *wgcfg.Config
			snatMap map[netip.Addr]netip.Addr // dst -> src
			dnat    []dnatTest
		}{
			{
				name: "no-cfg",
				wcfg: nil,
				snatMap: map[netip.Addr]netip.Addr{
					peer1IP:  selfNativeIP,
					peer2IP:  selfNativeIP,
					subnetIP: selfNativeIP,
				},
				dnat: []dnatTest{
					{selfNativeIP, selfNativeIP, selfNativeIP},
					{peer1IP, selfEIP1, selfEIP1},
					{peer2IP, selfEIP2, selfEIP2},
				},
			},
			{
				name: "single-peer-requires-nat",
				wcfg: &wgcfg.Config{
					Addresses: selfAddrs,
					Peers: []wgcfg.Peer{
						node(peer1IP, noIP),
						node(peer2IP, selfEIP2),
					},
				},
				snatMap: map[netip.Addr]netip.Addr{
					peer1IP:  selfNativeIP,
					peer2IP:  selfEIP2,
					subnetIP: selfNativeIP,
				},
				dnat: []dnatTest{
					{selfNativeIP, selfNativeIP, selfNativeIP},
					{peer1IP, selfEIP1, selfEIP1},
					{peer2IP, selfEIP2, selfNativeIP}, // NATed
					{peer2IP, subnetIP, subnetIP},
				},
			},
			{
				name: "multiple-peers-require-nat",
				wcfg: &wgcfg.Config{
					Addresses: selfAddrs,
					Peers: []wgcfg.Peer{
						node(peer1IP, selfEIP1),
						node(peer2IP, selfEIP2),
					},
				},
				snatMap: map[netip.Addr]netip.Addr{
					peer1IP:  selfEIP1,
					peer2IP:  selfEIP2,
					subnetIP: selfNativeIP,
				},
				dnat: []dnatTest{
					{selfNativeIP, selfNativeIP, selfNativeIP},
					{peer1IP, selfEIP1, selfNativeIP},
					{peer2IP, selfEIP2, selfNativeIP},
					{peer2IP, subnetIP, subnetIP},
				},
			},
			{
				name: "multiple-peers-require-nat-with-subnet",
				wcfg: &wgcfg.Config{
					Addresses: selfAddrs,
					Peers: []wgcfg.Peer{
						node(peer1IP, selfEIP1),
						node(peer2IP, selfEIP2, subnet),
					},
				},
				snatMap: map[netip.Addr]netip.Addr{
					peer1IP:  selfEIP1,
					peer2IP:  selfEIP2,
					subnetIP: selfEIP2,
				},
				dnat: []dnatTest{
					{selfNativeIP, selfNativeIP, selfNativeIP},
					{peer1IP, selfEIP1, selfNativeIP},
					{peer2IP, selfEIP2, selfNativeIP},
					{peer2IP, subnetIP, subnetIP},
				},
			},
			{
				name: "multiple-peers-require-nat-with-default-route",
				wcfg: &wgcfg.Config{
					Addresses: selfAddrs,
					Peers: []wgcfg.Peer{
						node(peer1IP, selfEIP1),
						node(peer2IP, selfEIP2, exitRoute),
					},
				},
				snatMap: map[netip.Addr]netip.Addr{
					peer1IP:  selfEIP1,
					peer2IP:  selfEIP2,
					publicIP: selfEIP2,
				},
				dnat: []dnatTest{
					{selfNativeIP, selfNativeIP, selfNativeIP},
					{peer1IP, selfEIP1, selfNativeIP},
					{peer2IP, selfEIP2, selfNativeIP},
					{peer2IP, subnetIP, subnetIP},
				},
			},
			{
				name: "no-nat",
				wcfg: &wgcfg.Config{
					Addresses: selfAddrs,
					Peers: []wgcfg.Peer{
						node(peer1IP, noIP),
						node(peer2IP, noIP),
					},
				},
				snatMap: map[netip.Addr]netip.Addr{
					peer1IP:  selfNativeIP,
					peer2IP:  selfNativeIP,
					subnetIP: selfNativeIP,
				},
				dnat: []dnatTest{
					{selfNativeIP, selfNativeIP, selfNativeIP},
					{peer1IP, selfEIP1, selfEIP1},
					{peer2IP, selfEIP2, selfEIP2},
					{peer2IP, subnetIP, subnetIP},
				},
			},
			{
				name: "exit-node-require-nat-peer-doesnt",
				wcfg: &wgcfg.Config{
					Addresses: selfAddrs,
					Peers: []wgcfg.Peer{
						node(peer1IP, noIP),
						node(peer2IP, selfEIP2, exitRoute),
					},
				},
				snatMap: map[netip.Addr]netip.Addr{
					peer1IP:  selfNativeIP,
					peer2IP:  selfEIP2,
					publicIP: selfEIP2,
				},
				dnat: []dnatTest{
					{selfNativeIP, selfNativeIP, selfNativeIP},
					{peer2IP, selfEIP2, selfNativeIP},
					{peer2IP, subnetIP, subnetIP},
				},
			},
		}

		for _, tc := range tests {
			t.Run(fmt.Sprintf("%v/%v", addrFam, tc.name), func(t *testing.T) {
				pcfg := peerConfigTableFromWGConfig(tc.wcfg)
				for peer, want := range tc.snatMap {
					if got := pcfg.selectSrcIP(selfNativeIP, peer); got != want {
						t.Errorf("selectSrcIP[%v]: got %v; want %v", peer, got, want)
					}
				}
				for i, dt := range tc.dnat {
					if got := pcfg.mapDstIP(dt.src, dt.dst); got != dt.want {
						t.Errorf("dnat[%d]: mapDstIP[%v, %v]: got %v; want %v", i, dt.src, dt.dst, got, dt.want)
					}
				}
				if t.Failed() {
					t.Logf("%v", pcfg)
				}
			})
		}
	}
	test(ipproto.Version4)
	test(ipproto.Version6)
}

// TestCaptureHook verifies that the Wrapper.captureHook callback is called
// with the correct parameters when various packet operations are performed.
func TestCaptureHook(t *testing.T) {
	type captureRecord struct {
		path packet.CapturePath
		now  time.Time
		pkt  []byte
		meta packet.CaptureMeta
	}

	var captured []captureRecord
	hook := func(path packet.CapturePath, now time.Time, pkt []byte, meta packet.CaptureMeta) {
		captured = append(captured, captureRecord{
			path: path,
			now:  now,
			pkt:  pkt,
			meta: meta,
		})
	}

	now := time.Unix(1682085856, 0)

	bus := eventbustest.NewBus(t)
	_, w := newFakeTUN(t.Logf, bus, true)
	w.timeNow = func() time.Time {
		return now
	}
	w.InstallCaptureHook(hook)
	defer w.Close()

	// Loop reading and discarding packets; this ensures that we don't have
	// packets stuck in vectorOutbound
	go func() {
		var (
			buf   [MaxPacketSize]byte
			sizes = make([]int, 1)
		)
		for {
			_, err := w.Read([][]byte{buf[:]}, sizes, 0)
			if err != nil {
				return
			}
		}
	}()

	// Do operations that should result in a packet being captured.
	w.Write([][]byte{
		[]byte("Write1"),
		[]byte("Write2"),
	}, 0)
	packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte("InjectInboundPacketBuffer")),
	})
	buffs := make([][]byte, 1)
	buffs[0] = make([]byte, PacketStartOffset+packetBuf.Size())
	sizes := make([]int, 1)
	w.InjectInboundPacketBuffer(packetBuf, buffs, sizes)

	packetBuf = stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte("InjectOutboundPacketBuffer")),
	})
	w.InjectOutboundPacketBuffer(packetBuf)

	// TODO: test Read
	// TODO: determine if we want InjectOutbound to log

	// Assert that the right packets are captured.
	want := []captureRecord{
		{
			path: packet.FromPeer,
			pkt:  []byte("Write1"),
		},
		{
			path: packet.FromPeer,
			pkt:  []byte("Write2"),
		},
		{
			path: packet.SynthesizedToLocal,
			pkt:  []byte("InjectInboundPacketBuffer"),
		},
		{
			path: packet.SynthesizedToPeer,
			pkt:  []byte("InjectOutboundPacketBuffer"),
		},
	}
	for i := range len(want) {
		want[i].now = now
	}
	if !reflect.DeepEqual(captured, want) {
		t.Errorf("mismatch between captured and expected packets\ngot: %+v\nwant: %+v",
			captured, want)
	}
}

func TestTSMPDisco(t *testing.T) {
	t.Run("IPv6DiscoAdvert", func(t *testing.T) {
		src := netip.MustParseAddr("2001:db8::1")
		dst := netip.MustParseAddr("2001:db8::2")
		discoKey := key.NewDisco()
		buf, _ := (&packet.TSMPDiscoKeyAdvertisement{
			Src: src,
			Dst: dst,
			Key: discoKey.Public(),
		}).Marshal()

		var p packet.Parsed
		p.Decode(buf)

		tda, ok := p.AsTSMPDiscoAdvertisement()
		if !ok {
			t.Error("Unable to parse message as TSMPDiscoAdversitement")
		}
		if tda.Src != src {
			t.Errorf("Src address did not match, expected %v, got %v", src, tda.Src)
		}
		if tda.Key.Compare(discoKey.Public()) != 0 {
			t.Errorf("Key did not match, expected %q, got %q", discoKey.Public(), tda.Key)
		}
	})
}

func TestInterceptOrdering(t *testing.T) {
	bus := eventbustest.NewBus(t)
	chtun, tun := newChannelTUN(t.Logf, bus, true)
	defer tun.Close()

	var seq uint8
	orderedFilterFn := func(expected uint8) FilterFunc {
		return func(_ *packet.Parsed, _ *Wrapper) filter.Response {
			seq++
			if expected != seq {
				t.Errorf("got sequence %d; want %d", seq, expected)
			}
			return filter.Accept
		}
	}

	ordereredGROFilterFn := func(expected uint8) GROFilterFunc {
		return func(_ *packet.Parsed, _ *Wrapper, _ *gro.GRO) (filter.Response, *gro.GRO) {
			seq++
			if expected != seq {
				t.Errorf("got sequence %d; want %d", seq, expected)
			}
			return filter.Accept, nil
		}
	}

	// As the number of inbound intercepts change,
	// this value should change.
	numInboundIntercepts := uint8(3)

	tun.PreFilterPacketInboundFromWireGuard = orderedFilterFn(1)
	tun.PostFilterPacketInboundFromWireGuardAppConnector = orderedFilterFn(2)
	tun.PostFilterPacketInboundFromWireGuard = ordereredGROFilterFn(3)

	// Write the packet.
	go func() { <-chtun.Inbound }() // Simulate tun device receiving.
	packet := [][]byte{udp4("5.6.7.8", "1.2.3.4", 89, 89)}
	tun.Write(packet, 0)

	if seq != numInboundIntercepts {
		t.Errorf("got number of intercepts run in Write(): %d; want: %d", seq, numInboundIntercepts)
	}

	// As the number of inbound intercepts change,
	// this value should change.
	numOutboundIntercepts := uint8(4)

	seq = 0
	tun.PreFilterPacketOutboundToWireGuardNetstackIntercept = ordereredGROFilterFn(1)
	tun.PreFilterPacketOutboundToWireGuardEngineIntercept = orderedFilterFn(2)
	tun.PreFilterPacketOutboundToWireGuardAppConnectorIntercept = orderedFilterFn(3)
	tun.PostFilterPacketOutboundToWireGuard = orderedFilterFn(4)

	// Read the packet.
	var buf [MaxPacketSize]byte
	sizes := make([]int, 1)
	chtun.Outbound <- udp4("1.2.3.4", "5.6.7.8", 98, 98) // Simulate tun device sending.
	tun.Read([][]byte{buf[:]}, sizes, 0)

	if seq != numOutboundIntercepts {
		t.Errorf("got number of intercepts run in Read(): %d; want: %d", seq, numOutboundIntercepts)
	}
}
