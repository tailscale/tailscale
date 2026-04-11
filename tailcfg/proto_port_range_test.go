// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

import (
	"encoding"
	"testing"

	"tailscale.com/types/ipproto"
	"tailscale.com/util/vizerror"
)

var _ encoding.TextUnmarshaler = (*ProtoPortRange)(nil)

func TestProtoPortRangeParsing(t *testing.T) {
	pr := func(s, e uint16) PortRange {
		return PortRange{First: s, Last: e}
	}
	tests := []struct {
		name string
		in   string
		out  ProtoPortRange
		err  error
	}{
		{name: "tcp-80", in: "tcp:80", out: ProtoPortRange{Proto: int(ipproto.TCP), Ports: pr(80, 80)}},
		{name: "80", in: "80", out: ProtoPortRange{Ports: pr(80, 80)}},
		{name: "star", in: "*", out: ProtoPortRange{Ports: PortRangeAny}},
		{name: "star-star", in: "*:*", out: ProtoPortRange{Ports: PortRangeAny}},
		{name: "tcp-star", in: "tcp:*", out: ProtoPortRange{Proto: int(ipproto.TCP), Ports: PortRangeAny}},
		{
			name: "tcp-empty-port",
			in:   "tcp:",
			err:  vizerror.Errorf("invalid port list: %#v", ""),
		},
		{
			name: "empty-proto-80",
			in:   ":80",
			err:  errEmptyProtocol,
		},
		{
			name: "empty-string",
			in:   "",
			err:  errEmptyString,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ppr ProtoPortRange
			err := ppr.UnmarshalText([]byte(tc.in))
			if tc.err != err {
				if err == nil || tc.err.Error() != err.Error() {
					t.Fatalf("want err=%v, got %v", tc.err, err)
				}
			}
			if ppr != tc.out {
				t.Fatalf("got %v; want %v", ppr, tc.out)
			}
		})
	}
}

func TestProtoPortRangeString(t *testing.T) {
	tests := []struct {
		input ProtoPortRange
		want  string
	}{
		{ProtoPortRange{}, "0"},

		// Zero protocol.
		{ProtoPortRange{Ports: PortRangeAny}, "*"},
		{ProtoPortRange{Ports: PortRange{23, 23}}, "23"},
		{ProtoPortRange{Ports: PortRange{80, 120}}, "80-120"},

		// Non-zero unnamed protocol.
		{ProtoPortRange{Proto: 100, Ports: PortRange{80, 80}}, "100:80"},
		{ProtoPortRange{Proto: 200, Ports: PortRange{101, 105}}, "200:101-105"},

		// Non-zero named protocol.
		{ProtoPortRange{Proto: 1, Ports: PortRangeAny}, "icmp:*"},
		{ProtoPortRange{Proto: 2, Ports: PortRangeAny}, "igmp:*"},
		{ProtoPortRange{Proto: 6, Ports: PortRange{10, 13}}, "tcp:10-13"},
		{ProtoPortRange{Proto: 17, Ports: PortRangeAny}, "udp:*"},
		{ProtoPortRange{Proto: 0x84, Ports: PortRange{999, 999}}, "sctp:999"},
		{ProtoPortRange{Proto: 0x3a, Ports: PortRangeAny}, "ipv6-icmp:*"},
		{ProtoPortRange{Proto: 0x21, Ports: PortRangeAny}, "dccp:*"},
		{ProtoPortRange{Proto: 0x2f, Ports: PortRangeAny}, "gre:*"},
	}
	for _, tc := range tests {
		if got := tc.input.String(); got != tc.want {
			t.Errorf("String for %v: got %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestProtoPortRangeRoundTrip(t *testing.T) {
	tests := []struct {
		input ProtoPortRange
		text  string
	}{
		{ProtoPortRange{Ports: PortRangeAny}, "*"},
		{ProtoPortRange{Ports: PortRange{23, 23}}, "23"},
		{ProtoPortRange{Ports: PortRange{80, 120}}, "80-120"},
		{ProtoPortRange{Proto: 100, Ports: PortRange{80, 80}}, "100:80"},
		{ProtoPortRange{Proto: 200, Ports: PortRange{101, 105}}, "200:101-105"},
		{ProtoPortRange{Proto: 1, Ports: PortRangeAny}, "icmp:*"},
		{ProtoPortRange{Proto: 2, Ports: PortRangeAny}, "igmp:*"},
		{ProtoPortRange{Proto: 6, Ports: PortRange{10, 13}}, "tcp:10-13"},
		{ProtoPortRange{Proto: 17, Ports: PortRangeAny}, "udp:*"},
		{ProtoPortRange{Proto: 0x84, Ports: PortRange{999, 999}}, "sctp:999"},
		{ProtoPortRange{Proto: 0x3a, Ports: PortRangeAny}, "ipv6-icmp:*"},
		{ProtoPortRange{Proto: 0x21, Ports: PortRangeAny}, "dccp:*"},
		{ProtoPortRange{Proto: 0x2f, Ports: PortRangeAny}, "gre:*"},
	}

	for _, tc := range tests {
		out, err := tc.input.MarshalText()
		if err != nil {
			t.Errorf("MarshalText for %v: %v", tc.input, err)
			continue
		}
		if got := string(out); got != tc.text {
			t.Errorf("MarshalText for %#v: got %q, want %q", tc.input, got, tc.text)
		}
		var ppr ProtoPortRange
		if err := ppr.UnmarshalText(out); err != nil {
			t.Errorf("UnmarshalText for %q: err=%v", tc.text, err)
			continue
		}
		if ppr != tc.input {
			t.Errorf("round trip error for %q: got %v, want %#v", tc.text, ppr, tc.input)
		}
	}
}
