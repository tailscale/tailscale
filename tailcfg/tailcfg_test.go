// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

import (
	"bytes"
	"encoding"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"inet.af/netaddr"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/version"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := 0; i < t.NumField(); i++ {
		fields = append(fields, t.Field(i).Name)
	}
	return
}

func TestHostinfoEqual(t *testing.T) {
	hiHandles := []string{
		"IPNVersion", "FrontendLogID", "BackendLogID",
		"OS", "OSVersion", "Package", "DeviceModel", "Hostname",
		"ShieldsUp", "ShareeNode",
		"GoArch",
		"RoutableIPs", "RequestTags",
		"Services", "NetInfo",
	}
	if have := fieldsOf(reflect.TypeOf(Hostinfo{})); !reflect.DeepEqual(have, hiHandles) {
		t.Errorf("Hostinfo.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, hiHandles)
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
		a, b *Hostinfo
		want bool
	}{
		{
			nil,
			nil,
			true,
		},
		{
			&Hostinfo{},
			nil,
			false,
		},
		{
			nil,
			&Hostinfo{},
			false,
		},
		{
			&Hostinfo{},
			&Hostinfo{},
			true,
		},

		{
			&Hostinfo{IPNVersion: "1"},
			&Hostinfo{IPNVersion: "2"},
			false,
		},
		{
			&Hostinfo{IPNVersion: "2"},
			&Hostinfo{IPNVersion: "2"},
			true,
		},

		{
			&Hostinfo{FrontendLogID: "1"},
			&Hostinfo{FrontendLogID: "2"},
			false,
		},
		{
			&Hostinfo{FrontendLogID: "2"},
			&Hostinfo{FrontendLogID: "2"},
			true,
		},

		{
			&Hostinfo{BackendLogID: "1"},
			&Hostinfo{BackendLogID: "2"},
			false,
		},
		{
			&Hostinfo{BackendLogID: "2"},
			&Hostinfo{BackendLogID: "2"},
			true,
		},

		{
			&Hostinfo{OS: "windows"},
			&Hostinfo{OS: "linux"},
			false,
		},
		{
			&Hostinfo{OS: "windows"},
			&Hostinfo{OS: "windows"},
			true,
		},

		{
			&Hostinfo{Hostname: "vega"},
			&Hostinfo{Hostname: "iris"},
			false,
		},
		{
			&Hostinfo{Hostname: "vega"},
			&Hostinfo{Hostname: "vega"},
			true,
		},

		{
			&Hostinfo{RoutableIPs: nil},
			&Hostinfo{RoutableIPs: nets("10.0.0.0/16")},
			false,
		},
		{
			&Hostinfo{RoutableIPs: nets("10.1.0.0/16", "192.168.1.0/24")},
			&Hostinfo{RoutableIPs: nets("10.2.0.0/16", "192.168.2.0/24")},
			false,
		},
		{
			&Hostinfo{RoutableIPs: nets("10.1.0.0/16", "192.168.1.0/24")},
			&Hostinfo{RoutableIPs: nets("10.1.0.0/16", "192.168.2.0/24")},
			false,
		},
		{
			&Hostinfo{RoutableIPs: nets("10.1.0.0/16", "192.168.1.0/24")},
			&Hostinfo{RoutableIPs: nets("10.1.0.0/16", "192.168.1.0/24")},
			true,
		},

		{
			&Hostinfo{RequestTags: []string{"abc", "def"}},
			&Hostinfo{RequestTags: []string{"abc", "def"}},
			true,
		},
		{
			&Hostinfo{RequestTags: []string{"abc", "def"}},
			&Hostinfo{RequestTags: []string{"abc", "123"}},
			false,
		},
		{
			&Hostinfo{RequestTags: []string{}},
			&Hostinfo{RequestTags: []string{"abc"}},
			false,
		},

		{
			&Hostinfo{Services: []Service{{Proto: TCP, Port: 1234, Description: "foo"}}},
			&Hostinfo{Services: []Service{{Proto: UDP, Port: 2345, Description: "bar"}}},
			false,
		},
		{
			&Hostinfo{Services: []Service{{Proto: TCP, Port: 1234, Description: "foo"}}},
			&Hostinfo{Services: []Service{{Proto: TCP, Port: 1234, Description: "foo"}}},
			true,
		},
		{
			&Hostinfo{ShareeNode: true},
			&Hostinfo{},
			false,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equal(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}

func TestNodeEqual(t *testing.T) {
	nodeHandles := []string{
		"ID", "StableID", "Name", "User", "Sharer",
		"Key", "KeyExpiry", "Machine", "DiscoKey",
		"Addresses", "AllowedIPs", "Endpoints", "DERP", "Hostinfo",
		"Created", "Tags", "PrimaryRoutes",
		"LastSeen", "Online", "KeepAlive", "MachineAuthorized",
		"Capabilities",
		"ComputedName", "computedHostIfDifferent", "ComputedNameWithHost",
	}
	if have := fieldsOf(reflect.TypeOf(Node{})); !reflect.DeepEqual(have, nodeHandles) {
		t.Errorf("Node.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, nodeHandles)
	}

	n1 := key.NewNode().Public()
	m1 := key.NewMachine().Public()
	now := time.Now()

	tests := []struct {
		a, b *Node
		want bool
	}{
		{
			&Node{},
			nil,
			false,
		},
		{
			nil,
			&Node{},
			false,
		},
		{
			&Node{},
			&Node{},
			true,
		},
		{
			&Node{},
			&Node{},
			true,
		},
		{
			&Node{ID: 1},
			&Node{},
			false,
		},
		{
			&Node{ID: 1},
			&Node{ID: 1},
			true,
		},
		{
			&Node{StableID: "node-abcd"},
			&Node{},
			false,
		},
		{
			&Node{StableID: "node-abcd"},
			&Node{StableID: "node-abcd"},
			true,
		},
		{
			&Node{User: 0},
			&Node{User: 1},
			false,
		},
		{
			&Node{User: 1},
			&Node{User: 1},
			true,
		},
		{
			&Node{Key: NodeKeyFromNodePublic(n1)},
			&Node{Key: NodeKeyFromNodePublic(key.NewNode().Public())},
			false,
		},
		{
			&Node{Key: NodeKeyFromNodePublic(n1)},
			&Node{Key: NodeKeyFromNodePublic(n1)},
			true,
		},
		{
			&Node{KeyExpiry: now},
			&Node{KeyExpiry: now.Add(60 * time.Second)},
			false,
		},
		{
			&Node{KeyExpiry: now},
			&Node{KeyExpiry: now},
			true,
		},
		{
			&Node{Machine: m1},
			&Node{Machine: key.NewMachine().Public()},
			false,
		},
		{
			&Node{Machine: m1},
			&Node{Machine: m1},
			true,
		},
		{
			&Node{Addresses: []netaddr.IPPrefix{}},
			&Node{Addresses: nil},
			false,
		},
		{
			&Node{Addresses: []netaddr.IPPrefix{}},
			&Node{Addresses: []netaddr.IPPrefix{}},
			true,
		},
		{
			&Node{AllowedIPs: []netaddr.IPPrefix{}},
			&Node{AllowedIPs: nil},
			false,
		},
		{
			&Node{Addresses: []netaddr.IPPrefix{}},
			&Node{Addresses: []netaddr.IPPrefix{}},
			true,
		},
		{
			&Node{Endpoints: []string{}},
			&Node{Endpoints: nil},
			false,
		},
		{
			&Node{Endpoints: []string{}},
			&Node{Endpoints: []string{}},
			true,
		},
		{
			&Node{Hostinfo: Hostinfo{Hostname: "alice"}},
			&Node{Hostinfo: Hostinfo{Hostname: "bob"}},
			false,
		},
		{
			&Node{Hostinfo: Hostinfo{}},
			&Node{Hostinfo: Hostinfo{}},
			true,
		},
		{
			&Node{Created: now},
			&Node{Created: now.Add(60 * time.Second)},
			false,
		},
		{
			&Node{Created: now},
			&Node{Created: now},
			true,
		},
		{
			&Node{LastSeen: &now},
			&Node{LastSeen: nil},
			false,
		},
		{
			&Node{LastSeen: &now},
			&Node{LastSeen: &now},
			true,
		},
		{
			&Node{DERP: "foo"},
			&Node{DERP: "bar"},
			false,
		},
		{
			&Node{Tags: []string{"tag:foo"}},
			&Node{Tags: []string{"tag:foo"}},
			true,
		},
		{
			&Node{Tags: []string{"tag:foo", "tag:bar"}},
			&Node{Tags: []string{"tag:bar"}},
			false,
		},
		{
			&Node{Tags: []string{"tag:foo"}},
			&Node{Tags: []string{"tag:bar"}},
			false,
		},
		{
			&Node{Tags: []string{"tag:foo"}},
			&Node{},
			false,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equal(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}

func TestNetInfoFields(t *testing.T) {
	handled := []string{
		"MappingVariesByDestIP",
		"HairPinning",
		"WorkingIPv6",
		"WorkingUDP",
		"HavePortMap",
		"UPnP",
		"PMP",
		"PCP",
		"PreferredDERP",
		"LinkType",
		"DERPLatency",
	}
	if have := fieldsOf(reflect.TypeOf(NetInfo{})); !reflect.DeepEqual(have, handled) {
		t.Errorf("NetInfo.Clone/BasicallyEqually check might be out of sync\nfields: %q\nhandled: %q\n",
			have, handled)
	}
}

func TestNodeKeyMarshal(t *testing.T) {
	var k1, k2 NodeKey
	for i := range k1 {
		k1[i] = byte(i)
	}
	testKey(t, "nodekey:", k1, &k2)
}

func TestNodeKeyRoundTrip(t *testing.T) {
	serialized := `{
      "Pub":"nodekey:50d20b455ecf12bc453f83c2cfdb2a24925d06cf2598dcaa54e91af82ce9f765"
    }`

	// Carefully check that the expected serialized data decodes and
	// re-encodes to the expected keys. These types are serialized to
	// disk all over the place and need to be stable.
	pub := NodeKey{
		0x50, 0xd2, 0xb, 0x45, 0x5e, 0xcf, 0x12, 0xbc, 0x45, 0x3f, 0x83,
		0xc2, 0xcf, 0xdb, 0x2a, 0x24, 0x92, 0x5d, 0x6, 0xcf, 0x25, 0x98,
		0xdc, 0xaa, 0x54, 0xe9, 0x1a, 0xf8, 0x2c, 0xe9, 0xf7, 0x65,
	}

	type key struct {
		Pub NodeKey
	}

	var a key
	if err := json.Unmarshal([]byte(serialized), &a); err != nil {
		t.Fatal(err)
	}
	if a.Pub != pub {
		t.Errorf("wrong deserialization of public key, got %#v want %#v", a.Pub, pub)
	}

	bs, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	json.Indent(&b, []byte(serialized), "", "  ")
	if got, want := string(bs), b.String(); got != want {
		t.Error("json serialization doesn't roundtrip")
	}
}

func TestDiscoKeyMarshal(t *testing.T) {
	var k1, k2 DiscoKey
	for i := range k1 {
		k1[i] = byte(i)
	}
	testKey(t, "discokey:", k1, &k2)
}

type keyIn interface {
	String() string
	MarshalText() ([]byte, error)
}

func testKey(t *testing.T, prefix string, in keyIn, out encoding.TextUnmarshaler) {
	got, err := in.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := out.UnmarshalText(got); err != nil {
		t.Fatal(err)
	}
	if s := in.String(); string(got) != s {
		t.Errorf("MarshalText = %q != String %q", got, s)
	}
	if !strings.HasPrefix(string(got), prefix) {
		t.Errorf("%q didn't start with prefix %q", got, prefix)
	}
	if reflect.ValueOf(out).Elem().Interface() != in {
		t.Errorf("mismatch after unmarshal")
	}
}

func TestCloneUser(t *testing.T) {
	tests := []struct {
		name string
		u    *User
	}{
		{"nil_logins", &User{}},
		{"zero_logins", &User{Logins: make([]LoginID, 0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u2 := tt.u.Clone()
			if !reflect.DeepEqual(tt.u, u2) {
				t.Errorf("not equal")
			}
		})
	}
}

func TestCloneNode(t *testing.T) {
	tests := []struct {
		name string
		v    *Node
	}{
		{"nil_fields", &Node{}},
		{"zero_fields", &Node{
			Addresses:  make([]netaddr.IPPrefix, 0),
			AllowedIPs: make([]netaddr.IPPrefix, 0),
			Endpoints:  make([]string, 0),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v2 := tt.v.Clone()
			if !reflect.DeepEqual(tt.v, v2) {
				t.Errorf("not equal")
			}
		})
	}
}

func TestUserProfileJSONMarshalForMac(t *testing.T) {
	// Old macOS clients had a bug where they required
	// UserProfile.Roles to be non-null. Lock that in
	// 1.0.x/1.2.x clients are gone in the wild.
	// See mac commit 0242c08a2ca496958027db1208f44251bff8488b (Sep 30).
	// It was fixed in at least 1.4.x, and perhaps 1.2.x.
	j, err := json.Marshal(UserProfile{})
	if err != nil {
		t.Fatal(err)
	}
	const wantSub = `"Roles":[]`
	if !strings.Contains(string(j), wantSub) {
		t.Fatalf("didn't contain %#q; got: %s", wantSub, j)
	}

	// And back:
	var up UserProfile
	if err := json.Unmarshal(j, &up); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
}

func TestEndpointTypeMarshal(t *testing.T) {
	eps := []EndpointType{
		EndpointUnknownType,
		EndpointLocal,
		EndpointSTUN,
		EndpointPortmapped,
		EndpointSTUN4LocalPort,
	}
	got, err := json.Marshal(eps)
	if err != nil {
		t.Fatal(err)
	}
	const want = `[0,1,2,3,4]`
	if string(got) != want {
		t.Errorf("got %s; want %s", got, want)
	}
}

var sinkBytes []byte

func BenchmarkKeyMarshalText(b *testing.B) {
	b.ReportAllocs()
	var k [32]byte
	for i := 0; i < b.N; i++ {
		sinkBytes = keyMarshalText("prefix", k)
	}
}

func TestAppendKeyAllocs(t *testing.T) {
	if version.IsRace() {
		t.Skip("skipping in race detector") // append(b, make([]byte, N)...) not optimized in compiler with race
	}
	var k [32]byte
	err := tstest.MinAllocsPerRun(t, 1, func() {
		sinkBytes = keyMarshalText("prefix", k)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDiscoKeyAppend(t *testing.T) {
	d := DiscoKey{1: 1, 2: 2}
	got := string(d.AppendTo([]byte("foo")))
	want := "foodiscokey:0001020000000000000000000000000000000000000000000000000000000000"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestRegisterRequestNilClone(t *testing.T) {
	var nilReq *RegisterRequest
	got := nilReq.Clone()
	if got != nil {
		t.Errorf("got = %v; want nil", got)
	}
}
