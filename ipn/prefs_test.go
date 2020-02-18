// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"reflect"
	"testing"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/control/controlclient"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := 0; i < t.NumField(); i++ {
		fields = append(fields, t.Field(i).Name)
	}
	return
}

func TestPrefsEqual(t *testing.T) {
	prefsHandles := []string{"RouteAll", "AllowSingleHosts", "CorpDNS", "WantRunning", "UsePacketFilter", "AdvertiseRoutes", "NotepadURLs", "Persist"}
	if have := fieldsOf(reflect.TypeOf(Prefs{})); !reflect.DeepEqual(have, prefsHandles) {
		t.Errorf("Prefs.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, prefsHandles)
	}

	nets := func(strs ...string) (ns []wgcfg.CIDR) {
		for _, s := range strs {
			n, err := wgcfg.ParseCIDR(s)
			if err != nil {
				panic(err)
			}
			ns = append(ns, *n)
		}
		return ns
	}
	tests := []struct {
		a, b *Prefs
		want bool
	}{
		{
			&Prefs{},
			nil,
			false,
		},
		{
			nil,
			&Prefs{},
			false,
		},
		{
			&Prefs{},
			&Prefs{},
			true,
		},

		{
			&Prefs{RouteAll: true},
			&Prefs{RouteAll: false},
			false,
		},
		{
			&Prefs{RouteAll: true},
			&Prefs{RouteAll: true},
			true,
		},

		{
			&Prefs{AllowSingleHosts: true},
			&Prefs{AllowSingleHosts: false},
			false,
		},
		{
			&Prefs{AllowSingleHosts: true},
			&Prefs{AllowSingleHosts: true},
			true,
		},

		{
			&Prefs{CorpDNS: true},
			&Prefs{CorpDNS: false},
			false,
		},
		{
			&Prefs{CorpDNS: true},
			&Prefs{CorpDNS: true},
			true,
		},

		{
			&Prefs{WantRunning: true},
			&Prefs{WantRunning: false},
			false,
		},
		{
			&Prefs{WantRunning: true},
			&Prefs{WantRunning: true},
			true,
		},

		{
			&Prefs{NotepadURLs: true},
			&Prefs{NotepadURLs: false},
			false,
		},
		{
			&Prefs{NotepadURLs: true},
			&Prefs{NotepadURLs: true},
			true,
		},

		{
			&Prefs{UsePacketFilter: true},
			&Prefs{UsePacketFilter: false},
			false,
		},
		{
			&Prefs{UsePacketFilter: true},
			&Prefs{UsePacketFilter: true},
			true,
		},

		{
			&Prefs{AdvertiseRoutes: nil},
			&Prefs{AdvertiseRoutes: []wgcfg.CIDR{}},
			true,
		},
		{
			&Prefs{AdvertiseRoutes: []wgcfg.CIDR{}},
			&Prefs{AdvertiseRoutes: []wgcfg.CIDR{}},
			true,
		},
		{
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.1.0.0/16")},
			&Prefs{AdvertiseRoutes: nets("192.168.1.0/24", "10.2.0.0/16")},
			false,
		},
		{
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.1.0.0/16")},
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.2.0.0/16")},
			false,
		},
		{
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.1.0.0/16")},
			&Prefs{AdvertiseRoutes: nets("192.168.0.0/24", "10.1.0.0/16")},
			true,
		},

		{
			&Prefs{Persist: &controlclient.Persist{}},
			&Prefs{Persist: &controlclient.Persist{LoginName: "dave"}},
			false,
		},
		{
			&Prefs{Persist: &controlclient.Persist{LoginName: "dave"}},
			&Prefs{Persist: &controlclient.Persist{LoginName: "dave"}},
			true,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equals(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}

func checkPrefs(t *testing.T, p Prefs) {
	var err error
	var p2, p2c Prefs
	var p2b Prefs

	pp := p.Pretty()
	if pp == "" {
		t.Fatalf("default p.Pretty() failed\n")
	}
	t.Logf("\npp:   %#v\n", pp)
	b := p.ToBytes()
	if len(b) == 0 {
		t.Fatalf("default p.ToBytes() failed\n")
	}
	if !p.Equals(&p) {
		t.Fatalf("p != p\n")
	}
	p2 = p
	p2.RouteAll = true
	if p.Equals(&p2) {
		t.Fatalf("p == p2\n")
	}
	p2b, err = PrefsFromBytes(p2.ToBytes(), false)
	if err != nil {
		t.Fatalf("PrefsFromBytes(p2) failed\n")
	}
	p2p := p2.Pretty()
	p2bp := p2b.Pretty()
	t.Logf("\np2p:  %#v\np2bp: %#v\n", p2p, p2bp)
	if p2p != p2bp {
		t.Fatalf("p2p != p2bp\n%#v\n%#v\n", p2p, p2bp)
	}
	if !p2.Equals(&p2b) {
		t.Fatalf("p2 != p2b\n%#v\n%#v\n", p2, p2b)
	}
	p2c = *p2.Copy()
	if !p2b.Equals(&p2c) {
		t.Fatalf("p2b != p2c\n")
	}
}

func TestBasicPrefs(t *testing.T) {
	p := Prefs{}
	checkPrefs(t, p)
}

func TestPrefsPersist(t *testing.T) {
	c := controlclient.Persist{
		LoginName: "test@example.com",
	}
	p := Prefs{
		CorpDNS: true,
		Persist: &c,
	}
	checkPrefs(t, p)
}
