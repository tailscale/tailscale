// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package disco

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"go4.org/mem"
	"tailscale.com/types/key"
	"tailscale.com/util/strs"
)

func TestMarshalAndParse(t *testing.T) {
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			foo := []byte("foo")
			got := string(tt.m.AppendMarshal(foo))
			got, ok := strs.CutPrefix(got, "foo")
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
