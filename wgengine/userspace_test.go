// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"

	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/net/dns"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestNoteReceiveActivity(t *testing.T) {
	now := time.Unix(1, 0)
	var logBuf bytes.Buffer

	confc := make(chan bool, 1)
	gotConf := func() bool {
		select {
		case <-confc:
			return true
		default:
			return false
		}
	}
	e := &userspaceEngine{
		timeNow:        func() time.Time { return now },
		recvActivityAt: map[tailcfg.DiscoKey]time.Time{},
		logf: func(format string, a ...interface{}) {
			fmt.Fprintf(&logBuf, format, a...)
		},
		tundev:                new(tstun.Wrapper),
		testMaybeReconfigHook: func() { confc <- true },
		trimmedDisco:          map[tailcfg.DiscoKey]bool{},
	}
	ra := e.recvActivityAt

	dk := tailcfg.DiscoKey(key.NewPrivate().Public())

	// Activity on an untracked key should do nothing.
	e.noteReceiveActivity(dk)
	if len(ra) != 0 {
		t.Fatalf("unexpected growth in map: now has %d keys; want 0", len(ra))
	}
	if logBuf.Len() != 0 {
		t.Fatalf("unexpected log write (and thus activity): %s", logBuf.Bytes())
	}

	// Now track it, but don't mark it trimmed, so shouldn't update.
	ra[dk] = time.Time{}
	e.noteReceiveActivity(dk)
	if len(ra) != 1 {
		t.Fatalf("unexpected growth in map: now has %d keys; want 1", len(ra))
	}
	if got := ra[dk]; got != now {
		t.Fatalf("time in map = %v; want %v", got, now)
	}
	if gotConf() {
		t.Fatalf("unexpected reconfig")
	}

	// Now mark it trimmed and expect an update.
	e.trimmedDisco[dk] = true
	e.noteReceiveActivity(dk)
	if len(ra) != 1 {
		t.Fatalf("unexpected growth in map: now has %d keys; want 1", len(ra))
	}
	if got := ra[dk]; got != now {
		t.Fatalf("time in map = %v; want %v", got, now)
	}
	if !gotConf() {
		t.Fatalf("didn't get expected reconfig")
	}
}

func TestUserspaceEngineReconfig(t *testing.T) {
	e, err := NewFakeUserspaceEngine(t.Logf, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ue := e.(*userspaceEngine)

	routerCfg := &router.Config{}

	for _, discoHex := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	} {
		cfg := &wgcfg.Config{
			Peers: []wgcfg.Peer{
				{
					AllowedIPs: []netaddr.IPPrefix{
						{IP: netaddr.IPv4(100, 100, 99, 1), Bits: 32},
					},
					Endpoints: wgcfg.Endpoints{DiscoKey: dkFromHex(discoHex)},
				},
			},
		}

		err = e.Reconfig(cfg, routerCfg, &dns.Config{})
		if err != nil {
			t.Fatal(err)
		}

		wantRecvAt := map[tailcfg.DiscoKey]time.Time{
			dkFromHex(discoHex): time.Time{},
		}
		if got := ue.recvActivityAt; !reflect.DeepEqual(got, wantRecvAt) {
			t.Errorf("wrong recvActivityAt\n got: %v\nwant: %v\n", got, wantRecvAt)
		}

		wantTrimmedDisco := map[tailcfg.DiscoKey]bool{
			dkFromHex(discoHex): true,
		}
		if got := ue.trimmedDisco; !reflect.DeepEqual(got, wantTrimmedDisco) {
			t.Errorf("wrong wantTrimmedDisco\n got: %v\nwant: %v\n", got, wantTrimmedDisco)
		}
	}
}

func dkFromHex(hex string) tailcfg.DiscoKey {
	if len(hex) != 64 {
		panic(fmt.Sprintf("%q is len %d; want 64", hex, len(hex)))
	}
	k, err := key.NewPublicFromHexMem(mem.S(hex[:64]))
	if err != nil {
		panic(fmt.Sprintf("%q is not hex: %v", hex, err))
	}
	return tailcfg.DiscoKey(k)
}

// an experiment to see if genLocalAddrFunc was worth it. As of Go
// 1.16, it still very much is. (30-40x faster)
func BenchmarkGenLocalAddrFunc(b *testing.B) {
	la1 := netaddr.MustParseIP("1.2.3.4")
	la2 := netaddr.MustParseIP("::4")
	lanot := netaddr.MustParseIP("5.5.5.5")
	var x bool
	b.Run("map1", func(b *testing.B) {
		m := map[netaddr.IP]bool{
			la1: true,
		}
		for i := 0; i < b.N; i++ {
			x = m[la1]
			x = m[lanot]
		}
	})
	b.Run("map2", func(b *testing.B) {
		m := map[netaddr.IP]bool{
			la1: true,
			la2: true,
		}
		for i := 0; i < b.N; i++ {
			x = m[la1]
			x = m[lanot]
		}
	})
	b.Run("or1", func(b *testing.B) {
		f := func(t netaddr.IP) bool {
			return t == la1
		}
		for i := 0; i < b.N; i++ {
			x = f(la1)
			x = f(lanot)
		}
	})
	b.Run("or2", func(b *testing.B) {
		f := func(t netaddr.IP) bool {
			return t == la1 || t == la2
		}
		for i := 0; i < b.N; i++ {
			x = f(la1)
			x = f(lanot)
		}
	})
	b.Logf("x = %v", x)
}
