// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/types/wgkey"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := 0; i < t.NumField(); i++ {
		fields = append(fields, t.Field(i).Name)
	}
	return
}

func TestPrefsEqual(t *testing.T) {
	tstest.PanicOnLog()

	prefsHandles := []string{"ControlURL", "RouteAll", "AllowSingleHosts", "ExitNodeID", "ExitNodeIP", "ExitNodeAllowLANAccess", "CorpDNS", "WantRunning", "ShieldsUp", "AdvertiseTags", "Hostname", "OSVersion", "DeviceModel", "NotepadURLs", "ForceDaemon", "AdvertiseRoutes", "NoSNAT", "NetfilterMode", "Persist"}
	if have := fieldsOf(reflect.TypeOf(Prefs{})); !reflect.DeepEqual(have, prefsHandles) {
		t.Errorf("Prefs.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, prefsHandles)
	}

	nets := func(strs ...string) (ns []netaddr.IPPrefix) {
		for _, s := range strs {
			n, err := netaddr.ParseIPPrefix(s)
			if err != nil {
				panic(err)
			}
			ns = append(ns, n)
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
			&Prefs{ControlURL: "https://login.tailscale.com"},
			&Prefs{ControlURL: "https://login.private.co"},
			false,
		},
		{
			&Prefs{ControlURL: "https://login.tailscale.com"},
			&Prefs{ControlURL: "https://login.tailscale.com"},
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
			&Prefs{ExitNodeID: "n1234"},
			&Prefs{},
			false,
		},
		{
			&Prefs{ExitNodeID: "n1234"},
			&Prefs{ExitNodeID: "n1234"},
			true,
		},

		{
			&Prefs{ExitNodeIP: netaddr.MustParseIP("1.2.3.4")},
			&Prefs{},
			false,
		},
		{
			&Prefs{ExitNodeIP: netaddr.MustParseIP("1.2.3.4")},
			&Prefs{ExitNodeIP: netaddr.MustParseIP("1.2.3.4")},
			true,
		},

		{
			&Prefs{},
			&Prefs{ExitNodeAllowLANAccess: true},
			false,
		},
		{
			&Prefs{ExitNodeAllowLANAccess: true},
			&Prefs{ExitNodeAllowLANAccess: true},
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
			&Prefs{NoSNAT: true},
			&Prefs{NoSNAT: false},
			false,
		},
		{
			&Prefs{NoSNAT: true},
			&Prefs{NoSNAT: true},
			true,
		},

		{
			&Prefs{Hostname: "android-host01"},
			&Prefs{Hostname: "android-host02"},
			false,
		},
		{
			&Prefs{Hostname: ""},
			&Prefs{Hostname: ""},
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
			&Prefs{ShieldsUp: true},
			&Prefs{ShieldsUp: false},
			false,
		},
		{
			&Prefs{ShieldsUp: true},
			&Prefs{ShieldsUp: true},
			true,
		},

		{
			&Prefs{AdvertiseRoutes: nil},
			&Prefs{AdvertiseRoutes: []netaddr.IPPrefix{}},
			true,
		},
		{
			&Prefs{AdvertiseRoutes: []netaddr.IPPrefix{}},
			&Prefs{AdvertiseRoutes: []netaddr.IPPrefix{}},
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
			&Prefs{NetfilterMode: preftype.NetfilterOff},
			&Prefs{NetfilterMode: preftype.NetfilterOn},
			false,
		},
		{
			&Prefs{NetfilterMode: preftype.NetfilterOn},
			&Prefs{NetfilterMode: preftype.NetfilterOn},
			true,
		},

		{
			&Prefs{Persist: &persist.Persist{}},
			&Prefs{Persist: &persist.Persist{LoginName: "dave"}},
			false,
		},
		{
			&Prefs{Persist: &persist.Persist{LoginName: "dave"}},
			&Prefs{Persist: &persist.Persist{LoginName: "dave"}},
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
	var p2, p2c *Prefs
	var p2b *Prefs

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
	p2 = p.Clone()
	p2.RouteAll = true
	if p.Equals(p2) {
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
	if !p2.Equals(p2b) {
		t.Fatalf("p2 != p2b\n%#v\n%#v\n", p2, p2b)
	}
	p2c = p2.Clone()
	if !p2b.Equals(p2c) {
		t.Fatalf("p2b != p2c\n")
	}
}

func TestBasicPrefs(t *testing.T) {
	tstest.PanicOnLog()

	p := Prefs{
		ControlURL: "https://login.tailscale.com",
	}
	checkPrefs(t, p)
}

func TestPrefsPersist(t *testing.T) {
	tstest.PanicOnLog()

	c := persist.Persist{
		LoginName: "test@example.com",
	}
	p := Prefs{
		ControlURL: "https://login.tailscale.com",
		CorpDNS:    true,
		Persist:    &c,
	}
	checkPrefs(t, p)
}

func TestPrefsPretty(t *testing.T) {
	tests := []struct {
		p    Prefs
		os   string
		want string
	}{
		{
			Prefs{},
			"linux",
			"Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off Persist=nil}",
		},
		{
			Prefs{},
			"windows",
			"Prefs{ra=false mesh=false dns=false want=false Persist=nil}",
		},
		{
			Prefs{ShieldsUp: true},
			"windows",
			"Prefs{ra=false mesh=false dns=false want=false shields=true Persist=nil}",
		},
		{
			Prefs{AllowSingleHosts: true},
			"windows",
			"Prefs{ra=false dns=false want=false Persist=nil}",
		},
		{
			Prefs{
				NotepadURLs:      true,
				AllowSingleHosts: true,
			},
			"windows",
			"Prefs{ra=false dns=false want=false notepad=true Persist=nil}",
		},
		{
			Prefs{
				AllowSingleHosts: true,
				WantRunning:      true,
				ForceDaemon:      true, // server mode
			},
			"windows",
			"Prefs{ra=false dns=false want=true server=true Persist=nil}",
		},
		{
			Prefs{
				AllowSingleHosts: true,
				WantRunning:      true,
				ControlURL:       "http://localhost:1234",
				AdvertiseTags:    []string{"tag:foo", "tag:bar"},
			},
			"darwin",
			`Prefs{ra=false dns=false want=true tags=tag:foo,tag:bar url="http://localhost:1234" Persist=nil}`,
		},
		{
			Prefs{
				Persist: &persist.Persist{},
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off Persist{lm=, o=, n= u=""}}`,
		},
		{
			Prefs{
				Persist: &persist.Persist{
					PrivateNodeKey: wgkey.Private{1: 1},
				},
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off Persist{lm=, o=, n=[B1VKl] u=""}}`,
		},
		{
			Prefs{
				ExitNodeIP: netaddr.MustParseIP("1.2.3.4"),
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false exit=1.2.3.4 lan=false routes=[] nf=off Persist=nil}`,
		},
		{
			Prefs{
				ExitNodeID: tailcfg.StableNodeID("myNodeABC"),
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false exit=myNodeABC lan=false routes=[] nf=off Persist=nil}`,
		},
		{
			Prefs{
				ExitNodeID:             tailcfg.StableNodeID("myNodeABC"),
				ExitNodeAllowLANAccess: true,
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false exit=myNodeABC lan=true routes=[] nf=off Persist=nil}`,
		},
		{
			Prefs{
				ExitNodeAllowLANAccess: true,
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off Persist=nil}`,
		},
		{
			Prefs{
				Hostname: "foo",
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off host="foo" Persist=nil}`,
		},
	}
	for i, tt := range tests {
		got := tt.p.pretty(tt.os)
		if got != tt.want {
			t.Errorf("%d. wrong String:\n got: %s\nwant: %s\n", i, got, tt.want)
		}
	}
}

func TestLoadPrefsNotExist(t *testing.T) {
	bogusFile := fmt.Sprintf("/tmp/not-exist-%d", time.Now().UnixNano())

	p, err := LoadPrefs(bogusFile)
	if errors.Is(err, os.ErrNotExist) {
		// expected.
		return
	}
	t.Fatalf("unexpected prefs=%#v, err=%v", p, err)
}

// TestLoadPrefsFileWithZeroInIt verifies that LoadPrefs hanldes corrupted input files.
// See issue #954 for details.
func TestLoadPrefsFileWithZeroInIt(t *testing.T) {
	f, err := ioutil.TempFile("", "TestLoadPrefsFileWithZeroInIt")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	if _, err := f.Write(jsonEscapedZero); err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(path)

	p, err := LoadPrefs(path)
	if errors.Is(err, os.ErrNotExist) {
		// expected.
		return
	}
	t.Fatalf("unexpected prefs=%#v, err=%v", p, err)
}

func TestMaskedPrefsFields(t *testing.T) {
	have := map[string]bool{}
	for _, f := range fieldsOf(reflect.TypeOf(Prefs{})) {
		if f == "Persist" {
			// This one can't be edited.
			continue
		}
		have[f] = true
	}
	for _, f := range fieldsOf(reflect.TypeOf(MaskedPrefs{})) {
		if f == "Prefs" {
			continue
		}
		if !strings.HasSuffix(f, "Set") {
			t.Errorf("unexpected non-/Set$/ field %q", f)
			continue
		}
		bare := strings.TrimSuffix(f, "Set")
		_, ok := have[bare]
		if !ok {
			t.Errorf("no corresponding Prefs.%s field for MaskedPrefs.%s", bare, f)
			continue
		}
		delete(have, bare)
	}
	for f := range have {
		t.Errorf("missing MaskedPrefs.%sSet for Prefs.%s", f, f)
	}

	// And also make sure they line up in the right order, which
	// ApplyEdits assumes.
	pt := reflect.TypeOf(Prefs{})
	mt := reflect.TypeOf(MaskedPrefs{})
	for i := 0; i < mt.NumField(); i++ {
		name := mt.Field(i).Name
		if i == 0 {
			if name != "Prefs" {
				t.Errorf("first field of MaskedPrefs should be Prefs")
			}
			continue
		}
		prefName := pt.Field(i - 1).Name
		if prefName+"Set" != name {
			t.Errorf("MaskedField[%d] = %s; want %sSet", i-1, name, prefName)
		}
	}
}

func TestPrefsApplyEdits(t *testing.T) {
	tests := []struct {
		name  string
		prefs *Prefs
		edit  *MaskedPrefs
		want  *Prefs
	}{
		{
			name: "no_change",
			prefs: &Prefs{
				Hostname: "foo",
			},
			edit: &MaskedPrefs{},
			want: &Prefs{
				Hostname: "foo",
			},
		},
		{
			name: "set1_decoy1",
			prefs: &Prefs{
				Hostname: "foo",
			},
			edit: &MaskedPrefs{
				Prefs: Prefs{
					Hostname:    "bar",
					DeviceModel: "ignore-this", // not set
				},
				HostnameSet: true,
			},
			want: &Prefs{
				Hostname: "bar",
			},
		},
		{
			name:  "set_several",
			prefs: &Prefs{},
			edit: &MaskedPrefs{
				Prefs: Prefs{
					Hostname:    "bar",
					DeviceModel: "galaxybrain",
				},
				HostnameSet:    true,
				DeviceModelSet: true,
			},
			want: &Prefs{
				Hostname:    "bar",
				DeviceModel: "galaxybrain",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.prefs.Clone()
			got.ApplyEdits(tt.edit)
			if !got.Equals(tt.want) {
				gotj, _ := json.Marshal(got)
				wantj, _ := json.Marshal(tt.want)
				t.Errorf("fail.\n got: %s\nwant: %s\n", gotj, wantj)
			}
		})
	}
}

func TestMaskedPrefsPretty(t *testing.T) {
	tests := []struct {
		m    *MaskedPrefs
		want string
	}{
		{
			m:    &MaskedPrefs{},
			want: "MaskedPrefs{}",
		},
		{
			m: &MaskedPrefs{
				Prefs: Prefs{
					Hostname:         "bar",
					DeviceModel:      "galaxybrain",
					AllowSingleHosts: true,
					RouteAll:         false,
				},
				RouteAllSet:    true,
				HostnameSet:    true,
				DeviceModelSet: true,
			},
			want: `MaskedPrefs{RouteAll=false Hostname="bar" DeviceModel="galaxybrain"}`,
		},
	}
	for i, tt := range tests {
		got := tt.m.Pretty()
		if got != tt.want {
			t.Errorf("%d.\n got: %#q\nwant: %#q\n", i, got, tt.want)
		}
	}
}
