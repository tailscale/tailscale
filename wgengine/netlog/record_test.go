// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netlog && !ts_omit_logtail

package netlog

import (
	"net/netip"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/netlogtype"
	"tailscale.com/util/must"
)

func addr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	return must.Get(netip.ParseAddr(s))
}
func addrPort(s string) netip.AddrPort {
	if s == "" {
		return netip.AddrPort{}
	}
	return must.Get(netip.ParseAddrPort(s))
}
func prefix(s string) netip.Prefix {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p
	}
	a := addr(s)
	return netip.PrefixFrom(a, a.BitLen())
}

func conn(proto ipproto.Proto, src, dst string) netlogtype.Connection {
	return netlogtype.Connection{Proto: proto, Src: addrPort(src), Dst: addrPort(dst)}
}

func counts(txP, txB, rxP, rxB uint64) netlogtype.Counts {
	return netlogtype.Counts{TxPackets: txP, TxBytes: txB, RxPackets: rxP, RxBytes: rxB}
}

func TestToMessage(t *testing.T) {
	rec := record{
		selfNode: nodeUser{NodeView: (&tailcfg.Node{
			ID:        123456,
			StableID:  "n123456CNTL",
			Name:      "src.tail123456.ts.net.",
			Addresses: []netip.Prefix{prefix("100.1.2.3")},
			Tags:      []string{"tag:src"},
		}).View()},
		start: time.Now(),
		end:   time.Now().Add(5 * time.Second),

		seenNodes: map[netip.Addr]nodeUser{
			addr("100.1.2.4"): {NodeView: (&tailcfg.Node{
				ID:        123457,
				StableID:  "n123457CNTL",
				Name:      "dst1.tail123456.ts.net.",
				Addresses: []netip.Prefix{prefix("100.1.2.4")},
				Tags:      []string{"tag:dst1"},
			}).View()},
			addr("100.1.2.5"): {NodeView: (&tailcfg.Node{
				ID:        123458,
				StableID:  "n123458CNTL",
				Name:      "dst2.tail123456.ts.net.",
				Addresses: []netip.Prefix{prefix("100.1.2.5")},
				Tags:      []string{"tag:dst2"},
			}).View()},
		},

		virtConns: map[netlogtype.Connection]countsType{
			conn(0x1, "100.1.2.3:1234", "100.1.2.4:80"):    {Counts: counts(12, 34, 56, 78), connType: virtualTraffic},
			conn(0x1, "100.1.2.3:1234", "100.1.2.5:80"):    {Counts: counts(23, 45, 78, 790), connType: virtualTraffic},
			conn(0x6, "172.16.1.1:80", "100.1.2.4:1234"):   {Counts: counts(91, 54, 723, 621), connType: subnetTraffic},
			conn(0x6, "172.16.1.2:443", "100.1.2.5:1234"):  {Counts: counts(42, 813, 3, 1823), connType: subnetTraffic},
			conn(0x6, "172.16.1.3:80", "100.1.2.6:1234"):   {Counts: counts(34, 52, 78, 790), connType: subnetTraffic},
			conn(0x6, "100.1.2.3:1234", "12.34.56.78:80"):  {Counts: counts(11, 110, 10, 100), connType: exitTraffic},
			conn(0x6, "100.1.2.4:1234", "23.34.56.78:80"):  {Counts: counts(423, 1, 6, 123), connType: exitTraffic},
			conn(0x6, "100.1.2.4:1234", "23.34.56.78:443"): {Counts: counts(22, 220, 20, 200), connType: exitTraffic},
			conn(0x6, "100.1.2.5:1234", "45.34.56.78:80"):  {Counts: counts(33, 330, 30, 300), connType: exitTraffic},
			conn(0x6, "100.1.2.6:1234", "67.34.56.78:80"):  {Counts: counts(44, 440, 40, 400), connType: exitTraffic},
			conn(0x6, "42.54.72.42:555", "18.42.7.1:777"):  {Counts: counts(44, 440, 40, 400)},
		},

		physConns: map[netlogtype.Connection]netlogtype.Counts{
			conn(0, "100.1.2.4:0", "4.3.2.1:1234"):  counts(12, 34, 56, 78),
			conn(0, "100.1.2.5:0", "4.3.2.10:1234"): counts(78, 56, 34, 12),
		},
	}
	rec.seenNodes[rec.selfNode.toNode().Addresses[0]] = rec.selfNode

	got := rec.toMessage(false, false)
	want := netlogtype.Message{
		NodeID:  rec.selfNode.StableID(),
		Start:   rec.start,
		End:     rec.end,
		SrcNode: rec.selfNode.toNode(),
		DstNodes: []netlogtype.Node{
			rec.seenNodes[addr("100.1.2.4")].toNode(),
			rec.seenNodes[addr("100.1.2.5")].toNode(),
		},
		VirtualTraffic: []netlogtype.ConnectionCounts{
			{Connection: conn(0x1, "100.1.2.3:1234", "100.1.2.4:80"), Counts: counts(12, 34, 56, 78)},
			{Connection: conn(0x1, "100.1.2.3:1234", "100.1.2.5:80"), Counts: counts(23, 45, 78, 790)},
		},
		SubnetTraffic: []netlogtype.ConnectionCounts{
			{Connection: conn(0x6, "172.16.1.1:80", "100.1.2.4:1234"), Counts: counts(91, 54, 723, 621)},
			{Connection: conn(0x6, "172.16.1.2:443", "100.1.2.5:1234"), Counts: counts(42, 813, 3, 1823)},
			{Connection: conn(0x6, "172.16.1.3:80", "100.1.2.6:1234"), Counts: counts(34, 52, 78, 790)},
		},
		ExitTraffic: []netlogtype.ConnectionCounts{
			{Connection: conn(0x6, "42.54.72.42:555", "18.42.7.1:777"), Counts: counts(44, 440, 40, 400)},
			{Connection: conn(0x6, "100.1.2.3:1234", "12.34.56.78:80"), Counts: counts(11, 110, 10, 100)},
			{Connection: conn(0x6, "100.1.2.4:1234", "23.34.56.78:80"), Counts: counts(423, 1, 6, 123)},
			{Connection: conn(0x6, "100.1.2.4:1234", "23.34.56.78:443"), Counts: counts(22, 220, 20, 200)},
			{Connection: conn(0x6, "100.1.2.5:1234", "45.34.56.78:80"), Counts: counts(33, 330, 30, 300)},
			{Connection: conn(0x6, "100.1.2.6:1234", "67.34.56.78:80"), Counts: counts(44, 440, 40, 400)},
		},
		PhysicalTraffic: []netlogtype.ConnectionCounts{
			{Connection: conn(0, "100.1.2.4:0", "4.3.2.1:1234"), Counts: counts(12, 34, 56, 78)},
			{Connection: conn(0, "100.1.2.5:0", "4.3.2.10:1234"), Counts: counts(78, 56, 34, 12)},
		},
	}
	if d := cmp.Diff(got, want, cmpopts.EquateComparable(netip.Addr{}, netip.AddrPort{})); d != "" {
		t.Errorf("toMessage(false, false) mismatch (-got +want):\n%s", d)
	}

	got = rec.toMessage(true, false)
	want.SrcNode = netlogtype.Node{}
	want.DstNodes = nil
	if d := cmp.Diff(got, want, cmpopts.EquateComparable(netip.Addr{}, netip.AddrPort{})); d != "" {
		t.Errorf("toMessage(true, false) mismatch (-got +want):\n%s", d)
	}

	got = rec.toMessage(true, true)
	want.ExitTraffic = []netlogtype.ConnectionCounts{
		{Connection: conn(0, "", ""), Counts: counts(44+44, 440+440, 40+40, 400+400)},
		{Connection: conn(0, "100.1.2.3:0", ""), Counts: counts(11, 110, 10, 100)},
		{Connection: conn(0, "100.1.2.4:0", ""), Counts: counts(423+22, 1+220, 6+20, 123+200)},
		{Connection: conn(0, "100.1.2.5:0", ""), Counts: counts(33, 330, 30, 300)},
	}
	if d := cmp.Diff(got, want, cmpopts.EquateComparable(netip.Addr{}, netip.AddrPort{})); d != "" {
		t.Errorf("toMessage(true, true) mismatch (-got +want):\n%s", d)
	}
}

func TestToNode(t *testing.T) {
	tests := []struct {
		node *tailcfg.Node
		user *tailcfg.UserProfile
		want netlogtype.Node
	}{
		{},
		{
			node: &tailcfg.Node{
				StableID:  "n123456CNTL",
				Name:      "test.tail123456.ts.net.",
				Addresses: []netip.Prefix{prefix("100.1.2.3")},
				Tags:      []string{"tag:dupe", "tag:test", "tag:dupe"},
				User:      12345, // should be ignored
			},
			want: netlogtype.Node{
				NodeID:    "n123456CNTL",
				Name:      "test.tail123456.ts.net",
				Addresses: []netip.Addr{addr("100.1.2.3")},
				Tags:      []string{"tag:dupe", "tag:test"},
			},
		},
		{
			node: &tailcfg.Node{
				StableID:  "n123456CNTL",
				Addresses: []netip.Prefix{prefix("100.1.2.3")},
				User:      12345,
			},
			want: netlogtype.Node{
				NodeID:    "n123456CNTL",
				Addresses: []netip.Addr{addr("100.1.2.3")},
			},
		},
		{
			node: &tailcfg.Node{
				StableID:  "n123456CNTL",
				Addresses: []netip.Prefix{prefix("100.1.2.3")},
				Hostinfo:  (&tailcfg.Hostinfo{OS: "linux"}).View(),
				User:      12345,
			},
			user: &tailcfg.UserProfile{
				ID:        12345,
				LoginName: "user@domain",
			},
			want: netlogtype.Node{
				NodeID:    "n123456CNTL",
				Addresses: []netip.Addr{addr("100.1.2.3")},
				OS:        "linux",
				User:      "user@domain",
			},
		},
	}
	for _, tt := range tests {
		nu := nodeUser{tt.node.View(), tt.user.View()}
		got := nu.toNode()
		b := must.Get(jsonv2.Marshal(got))
		if len(b) > nu.jsonLen() {
			t.Errorf("jsonLen = %v, want >= %d", nu.jsonLen(), len(b))
		}
		if d := cmp.Diff(got, tt.want, cmpopts.EquateComparable(netip.Addr{})); d != "" {
			t.Errorf("toNode mismatch (-got +want):\n%s", d)
		}
	}
}

func FuzzQuotedLen(f *testing.F) {
	for _, s := range quotedLenTestdata {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		testQuotedLen(t, s)
	})
}

func TestQuotedLen(t *testing.T) {
	for _, s := range quotedLenTestdata {
		testQuotedLen(t, s)
	}
}

var quotedLenTestdata = []string{
	"", // empty string
	func() string {
		b := make([]byte, 128)
		for i := range b {
			b[i] = byte(i)
		}
		return string(b)
	}(), // all ASCII
	"�",     // replacement rune
	"\xff",  // invalid UTF-8
	"ʕ◔ϖ◔ʔ", // Unicode gopher
}

func testQuotedLen(t *testing.T, in string) {
	got := jsonQuotedLen(in)
	b, _ := jsontext.AppendQuote(nil, in)
	want := len(b)
	if got != want {
		t.Errorf("jsonQuotedLen(%q) = %v, want %v", in, got, want)
	}
}
