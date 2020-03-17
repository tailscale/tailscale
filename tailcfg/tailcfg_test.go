// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

import (
	"reflect"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := 0; i < t.NumField(); i++ {
		fields = append(fields, t.Field(i).Name)
	}
	return
}

func TestHostinfoEqual(t *testing.T) {
	hiHandles := []string{
		"IPNVersion", "FrontendLogID", "BackendLogID", "OS", "Hostname", "RoutableIPs", "Services",
		"NetInfo",
	}
	if have := fieldsOf(reflect.TypeOf(Hostinfo{})); !reflect.DeepEqual(have, hiHandles) {
		t.Errorf("Hostinfo.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, hiHandles)
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
			&Hostinfo{Services: []Service{Service{TCP, 1234, "foo"}}},
			&Hostinfo{Services: []Service{Service{UDP, 2345, "bar"}}},
			false,
		},
		{
			&Hostinfo{Services: []Service{Service{TCP, 1234, "foo"}}},
			&Hostinfo{Services: []Service{Service{TCP, 1234, "foo"}}},
			true,
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
	nodeHandles := []string{"ID", "Name", "User", "Key", "KeyExpiry", "Machine", "Addresses", "AllowedIPs", "Endpoints", "DERP", "Hostinfo", "Created", "LastSeen", "KeepAlive", "MachineAuthorized"}
	if have := fieldsOf(reflect.TypeOf(Node{})); !reflect.DeepEqual(have, nodeHandles) {
		t.Errorf("Node.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, nodeHandles)
	}

	newPublicKey := func(t *testing.T) wgcfg.Key {
		t.Helper()
		k, err := wgcfg.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k.Public()
	}
	n1 := newPublicKey(t)
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
			&Node{Key: NodeKey(n1)},
			&Node{Key: NodeKey(newPublicKey(t))},
			false,
		},
		{
			&Node{Key: NodeKey(n1)},
			&Node{Key: NodeKey(n1)},
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
			&Node{Machine: MachineKey(n1)},
			&Node{Machine: MachineKey(newPublicKey(t))},
			false,
		},
		{
			&Node{Machine: MachineKey(n1)},
			&Node{Machine: MachineKey(n1)},
			true,
		},
		{
			&Node{Addresses: []wgcfg.CIDR{}},
			&Node{Addresses: nil},
			false,
		},
		{
			&Node{Addresses: []wgcfg.CIDR{}},
			&Node{Addresses: []wgcfg.CIDR{}},
			true,
		},
		{
			&Node{AllowedIPs: []wgcfg.CIDR{}},
			&Node{AllowedIPs: nil},
			false,
		},
		{
			&Node{Addresses: []wgcfg.CIDR{}},
			&Node{Addresses: []wgcfg.CIDR{}},
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
		"PreferredDERP",
		"LinkType",
		"DERPLatency",
	}
	if have := fieldsOf(reflect.TypeOf(NetInfo{})); !reflect.DeepEqual(have, handled) {
		t.Errorf("NetInfo.Clone/BasicallyEqually check might be out of sync\nfields: %q\nhandled: %q\n",
			have, handled)
	}
}
