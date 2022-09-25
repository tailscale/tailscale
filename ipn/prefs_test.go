// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := 0; i < t.NumField(); i++ {
		fields = append(fields, t.Field(i).Name)
	}
	return
}

func TestPrefsEqual(t *testing.T) {
	tstest.PanicOnLog()

	prefsHandles := []string{
		"ControlURL",
		"RouteAll",
		"AllowSingleHosts",
		"ExitNodeID",
		"ExitNodeIP",
		"ExitNodeAllowLANAccess",
		"CorpDNS",
		"RunSSH",
		"WantRunning",
		"LoggedOut",
		"ShieldsUp",
		"AdvertiseTags",
		"Hostname",
		"NotepadURLs",
		"ForceDaemon",
		"Egg",
		"AdvertiseRoutes",
		"NoSNAT",
		"NetfilterMode",
		"OperatorUser",
		"Persist",
	}
	if have := fieldsOf(reflect.TypeOf(Prefs{})); !reflect.DeepEqual(have, prefsHandles) {
		t.Errorf("Prefs.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, prefsHandles)
	}

	nets := func(strs ...string) (ns []netip.Prefix) {
		for _, s := range strs {
			n, err := netip.ParsePrefix(s)
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
			&Prefs{ControlURL: "https://controlplane.tailscale.com"},
			&Prefs{ControlURL: "https://login.private.co"},
			false,
		},
		{
			&Prefs{ControlURL: "https://controlplane.tailscale.com"},
			&Prefs{ControlURL: "https://controlplane.tailscale.com"},
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
			&Prefs{ExitNodeIP: netip.MustParseAddr("1.2.3.4")},
			&Prefs{},
			false,
		},
		{
			&Prefs{ExitNodeIP: netip.MustParseAddr("1.2.3.4")},
			&Prefs{ExitNodeIP: netip.MustParseAddr("1.2.3.4")},
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
			&Prefs{AdvertiseRoutes: []netip.Prefix{}},
			true,
		},
		{
			&Prefs{AdvertiseRoutes: []netip.Prefix{}},
			&Prefs{AdvertiseRoutes: []netip.Prefix{}},
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
	p2b, err = PrefsFromBytes(p2.ToBytes())
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
		ControlURL: "https://controlplane.tailscale.com",
	}
	checkPrefs(t, p)
}

func TestPrefsPersist(t *testing.T) {
	tstest.PanicOnLog()

	c := persist.Persist{
		LoginName: "test@example.com",
	}
	p := Prefs{
		ControlURL: "https://controlplane.tailscale.com",
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
					PrivateNodeKey: key.NodePrivateFromRaw32(mem.B([]byte{1: 1, 31: 0})),
				},
			},
			"linux",
			`Prefs{ra=false mesh=false dns=false want=false routes=[] nf=off Persist{lm=, o=, n=[B1VKl] u=""}}`,
		},
		{
			Prefs{
				ExitNodeIP: netip.MustParseAddr("1.2.3.4"),
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

// TestLoadPrefsFileWithZeroInIt verifies that LoadPrefs handles corrupted input files.
// See issue #954 for details.
func TestLoadPrefsFileWithZeroInIt(t *testing.T) {
	f, err := os.CreateTemp("", "TestLoadPrefsFileWithZeroInIt")
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
					Hostname:     "bar",
					OperatorUser: "ignore-this", // not set
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
					Hostname:     "bar",
					OperatorUser: "galaxybrain",
				},
				HostnameSet:     true,
				OperatorUserSet: true,
			},
			want: &Prefs{
				Hostname:     "bar",
				OperatorUser: "galaxybrain",
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
					OperatorUser:     "galaxybrain",
					AllowSingleHosts: true,
					RouteAll:         false,
					ExitNodeID:       "foo",
					AdvertiseTags:    []string{"tag:foo", "tag:bar"},
					NetfilterMode:    preftype.NetfilterNoDivert,
				},
				RouteAllSet:      true,
				HostnameSet:      true,
				OperatorUserSet:  true,
				ExitNodeIDSet:    true,
				AdvertiseTagsSet: true,
				NetfilterModeSet: true,
			},
			want: `MaskedPrefs{RouteAll=false ExitNodeID="foo" AdvertiseTags=["tag:foo" "tag:bar"] Hostname="bar" NetfilterMode=nodivert OperatorUser="galaxybrain"}`,
		},
		{
			m: &MaskedPrefs{
				Prefs: Prefs{
					ExitNodeIP: netaddr.IPv4(100, 102, 104, 105),
				},
				ExitNodeIPSet: true,
			},
			want: `MaskedPrefs{ExitNodeIP=100.102.104.105}`,
		},
	}
	for i, tt := range tests {
		got := tt.m.Pretty()
		if got != tt.want {
			t.Errorf("%d.\n got: %#q\nwant: %#q\n", i, got, tt.want)
		}
	}
}

func TestPrefsExitNode(t *testing.T) {
	var p *Prefs
	if p.AdvertisesExitNode() {
		t.Errorf("nil shouldn't advertise exit node")
	}
	p = NewPrefs()
	if p.AdvertisesExitNode() {
		t.Errorf("default shouldn't advertise exit node")
	}
	p.AdvertiseRoutes = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
	}
	p.SetAdvertiseExitNode(true)
	if got, want := len(p.AdvertiseRoutes), 3; got != want {
		t.Errorf("routes = %d; want %d", got, want)
	}
	p.SetAdvertiseExitNode(true)
	if got, want := len(p.AdvertiseRoutes), 3; got != want {
		t.Errorf("routes = %d; want %d", got, want)
	}
	if !p.AdvertisesExitNode() {
		t.Errorf("not advertising after enable")
	}
	p.SetAdvertiseExitNode(false)
	if p.AdvertisesExitNode() {
		t.Errorf("advertising after disable")
	}
	if got, want := len(p.AdvertiseRoutes), 1; got != want {
		t.Errorf("routes = %d; want %d", got, want)
	}
}

func TestExitNodeIPOfArg(t *testing.T) {
	mustIP := netip.MustParseAddr
	tests := []struct {
		name    string
		arg     string
		st      *ipnstate.Status
		want    netip.Addr
		wantErr string
	}{
		{
			name: "ip_while_stopped_okay",
			arg:  "1.2.3.4",
			st: &ipnstate.Status{
				BackendState: "Stopped",
			},
			want: mustIP("1.2.3.4"),
		},
		{
			name: "ip_not_found",
			arg:  "1.2.3.4",
			st: &ipnstate.Status{
				BackendState: "Running",
			},
			wantErr: `no node found in netmap with IP 1.2.3.4`,
		},
		{
			name: "ip_not_exit",
			arg:  "1.2.3.4",
			st: &ipnstate.Status{
				BackendState: "Running",
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					key.NewNode().Public(): {
						TailscaleIPs: []netip.Addr{mustIP("1.2.3.4")},
					},
				},
			},
			wantErr: `node 1.2.3.4 is not advertising an exit node`,
		},
		{
			name: "ip",
			arg:  "1.2.3.4",
			st: &ipnstate.Status{
				BackendState: "Running",
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					key.NewNode().Public(): {
						TailscaleIPs:   []netip.Addr{mustIP("1.2.3.4")},
						ExitNodeOption: true,
					},
				},
			},
			want: mustIP("1.2.3.4"),
		},
		{
			name:    "no_match",
			arg:     "unknown",
			st:      &ipnstate.Status{MagicDNSSuffix: ".foo"},
			wantErr: `invalid value "unknown" for --exit-node; must be IP or unique node name`,
		},
		{
			name: "name",
			arg:  "skippy",
			st: &ipnstate.Status{
				MagicDNSSuffix: ".foo",
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					key.NewNode().Public(): {
						DNSName:        "skippy.foo.",
						TailscaleIPs:   []netip.Addr{mustIP("1.0.0.2")},
						ExitNodeOption: true,
					},
				},
			},
			want: mustIP("1.0.0.2"),
		},
		{
			name: "name_not_exit",
			arg:  "skippy",
			st: &ipnstate.Status{
				MagicDNSSuffix: ".foo",
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					key.NewNode().Public(): {
						DNSName:      "skippy.foo.",
						TailscaleIPs: []netip.Addr{mustIP("1.0.0.2")},
					},
				},
			},
			wantErr: `node "skippy" is not advertising an exit node`,
		},
		{
			name: "ambiguous",
			arg:  "skippy",
			st: &ipnstate.Status{
				MagicDNSSuffix: ".foo",
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{
					key.NewNode().Public(): {
						DNSName:        "skippy.foo.",
						TailscaleIPs:   []netip.Addr{mustIP("1.0.0.2")},
						ExitNodeOption: true,
					},
					key.NewNode().Public(): {
						DNSName:        "SKIPPY.foo.",
						TailscaleIPs:   []netip.Addr{mustIP("1.0.0.2")},
						ExitNodeOption: true,
					},
				},
			},
			wantErr: `ambiguous exit node name "skippy"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := exitNodeIPOfArg(tt.arg, tt.st)
			if err != nil {
				if err.Error() == tt.wantErr {
					return
				}
				if tt.wantErr == "" {
					t.Fatal(err)
				}
				t.Fatalf("error = %#q; want %#q", err, tt.wantErr)
			}
			if tt.wantErr != "" {
				t.Fatalf("got %v; want error %#q", got, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestControlURLOrDefault(t *testing.T) {
	var p Prefs
	if got, want := p.ControlURLOrDefault(), DefaultControlURL; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	p.ControlURL = "http://foo.bar"
	if got, want := p.ControlURLOrDefault(), "http://foo.bar"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	p.ControlURL = "https://login.tailscale.com"
	if got, want := p.ControlURLOrDefault(), DefaultControlURL; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}
