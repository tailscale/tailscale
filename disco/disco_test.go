// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package disco

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/types/key"
)

func TestMarshalAndParse(t *testing.T) {
	relayHandshakeCommon := BindUDPRelayEndpointCommon{
		VNI:        1,
		Generation: 2,
		RemoteKey:  key.DiscoPublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 30: 30, 31: 31})),
		Challenge: [BindUDPRelayChallengeLen]byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
	}

	tests := []struct {
		name string
		want string
		m    Message
	}{
		{
			name: "ping",
			m: &Ping{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			},
			want: "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c",
		},
		{
			name: "ping_with_nodekey_src",
			m: &Ping{
				TxID:    [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				NodeKey: key.NodePublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 30: 30, 31: 31})),
			},
			want: "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f",
		},
		{
			name: "ping_with_padding",
			m: &Ping{
				TxID:    [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Padding: 3,
			},
			want: "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00",
		},
		{
			name: "ping_with_padding_and_nodekey_src",
			m: &Ping{
				TxID:    [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				NodeKey: key.NodePublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 30: 30, 31: 31})),
				Padding: 3,
			},
			want: "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00",
		},
		{
			name: "pong",
			m: &Pong{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Src:  mustIPPort("2.3.4.5:1234"),
			},
			want: "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 04 d2",
		},
		{
			name: "pongv6",
			m: &Pong{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Src:  mustIPPort("[fed0::12]:6666"),
			},
			want: "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c fe d0 00 00 00 00 00 00 00 00 00 00 00 00 00 12 1a 0a",
		},
		{
			name: "call_me_maybe",
			m:    &CallMeMaybe{},
			want: "03 00",
		},
		{
			name: "call_me_maybe_endpoints",
			m: &CallMeMaybe{
				MyNumber: []netip.AddrPort{
					netip.MustParseAddrPort("1.2.3.4:567"),
					netip.MustParseAddrPort("[2001::3456]:789"),
				},
			},
			want: "03 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 03 15",
		},
		{
			name: "bind_udp_relay_endpoint",
			m: &BindUDPRelayEndpoint{
				relayHandshakeCommon,
			},
			want: "04 00 00 00 00 01 00 00 00 02 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
		},
		{
			name: "bind_udp_relay_endpoint_challenge",
			m: &BindUDPRelayEndpointChallenge{
				relayHandshakeCommon,
			},
			want: "05 00 00 00 00 01 00 00 00 02 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
		},
		{
			name: "bind_udp_relay_endpoint_answer",
			m: &BindUDPRelayEndpointAnswer{
				relayHandshakeCommon,
			},
			want: "06 00 00 00 00 01 00 00 00 02 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f",
		},
		{
			name: "call_me_maybe_via",
			m: &CallMeMaybeVia{
				ServerDisco:         key.DiscoPublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 30: 30, 31: 31})),
				LamportID:           123,
				VNI:                 456,
				BindLifetime:        time.Second,
				SteadyStateLifetime: time.Minute,
				AddrPorts: []netip.AddrPort{
					netip.MustParseAddrPort("1.2.3.4:567"),
					netip.MustParseAddrPort("[2001::3456]:789"),
				},
			},
			want: "07 00 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00 00 00 00 00 7b 00 00 01 c8 00 00 00 00 3b 9a ca 00 00 00 00 0d f8 47 58 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 03 15",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			foo := []byte("foo")
			got := string(tt.m.AppendMarshal(foo))
			got, ok := strings.CutPrefix(got, "foo")
			if !ok {
				t.Fatalf("didn't start with foo: got %q", got)
			}

			gotHex := fmt.Sprintf("% x", got)
			if gotHex != tt.want {
				t.Fatalf("wrong marshal\n got: %s\nwant: %s\n", gotHex, tt.want)
			}

			back, err := Parse([]byte(got))
			if err != nil {
				t.Fatalf("parse back: %v", err)
			}
			if !reflect.DeepEqual(back, tt.m) {
				t.Errorf("message in %+v doesn't match Parse back result %+v", tt.m, back)
			}
		})
	}
}

func mustIPPort(s string) netip.AddrPort {
	ipp, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ipp
}
