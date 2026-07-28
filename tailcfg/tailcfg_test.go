// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg_test

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	. "tailscale.com/tailcfg"
	"tailscale.com/tstest/deptest"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/util/must"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for field := range t.Fields() {
		fields = append(fields, field.Name)
	}
	return
}

func TestHostinfoEqual(t *testing.T) {
	hiHandles := []string{
		"IPNVersion",
		"FrontendLogID",
		"BackendLogID",
		"OS",
		"OSVersion",
		"Container",
		"Env",
		"Distro",
		"DistroVersion",
		"DistroCodeName",
		"App",
		"Desktop",
		"Package",
		"DeviceModel",
		"PushDeviceToken",
		"Hostname",
		"ShieldsUp",
		"ShareeNode",
		"NoLogsNoSupport",
		"RemoteConfig",
		"WireIngress",
		"IngressEnabled",
		"AllowsUpdate",
		"Machine",
		"GoArch",
		"GoArchVar",
		"GoVersion",
		"RoutableIPs",
		"RequestTags",
		"WoLMACs",
		"Services",
		"NetInfo",
		"SSH_HostKeys",
		"Cloud",
		"Userspace",
		"UserspaceRouter",
		"AppConnector",
		"ServicesHash",
		"PeerRelay",
		"ExitNodeID",
		"Location",
		"TPM",
		"StateEncrypted",
	}
	if have := fieldsOf(reflect.TypeFor[Hostinfo]()); !reflect.DeepEqual(have, hiHandles) {
		t.Errorf("Hostinfo.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, hiHandles)
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
		{
			&Hostinfo{SSH_HostKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO.... root@bar"}},
			&Hostinfo{},
			false,
		},
		{
			&Hostinfo{App: "golink"},
			&Hostinfo{App: "abc"},
			false,
		},
		{
			&Hostinfo{App: "golink"},
			&Hostinfo{App: "golink"},
			true,
		},
		{
			&Hostinfo{AppConnector: opt.Bool("true")},
			&Hostinfo{AppConnector: opt.Bool("true")},
			true,
		},
		{
			&Hostinfo{AppConnector: opt.Bool("true")},
			&Hostinfo{AppConnector: opt.Bool("false")},
			false,
		},
		{
			&Hostinfo{PeerRelay: true},
			&Hostinfo{PeerRelay: true},
			true,
		},
		{
			&Hostinfo{PeerRelay: true},
			&Hostinfo{PeerRelay: false},
			false,
		},
		{
			&Hostinfo{ServicesHash: "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049"},
			&Hostinfo{ServicesHash: "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049"},
			true,
		},
		{
			&Hostinfo{ServicesHash: "084c799cd551dd1d8d5c5f9a5d593b2e931f5e36122ee5c793c1d08a19839cc0"},
			&Hostinfo{},
			false,
		},
		{
			&Hostinfo{IngressEnabled: true},
			&Hostinfo{},
			false,
		},
		{
			&Hostinfo{IngressEnabled: true},
			&Hostinfo{IngressEnabled: true},
			true,
		},
		{
			&Hostinfo{IngressEnabled: false},
			&Hostinfo{},
			true,
		},
		{
			&Hostinfo{IngressEnabled: false},
			&Hostinfo{IngressEnabled: true},
			false,
		},
		{
			&Hostinfo{ExitNodeID: "stable-exit"},
			&Hostinfo{ExitNodeID: "stable-exit"},
			true,
		},
		{
			&Hostinfo{ExitNodeID: ""},
			&Hostinfo{},
			true,
		},
		{
			&Hostinfo{ExitNodeID: ""},
			&Hostinfo{ExitNodeID: "stable-exit"},
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

func TestHostinfoTailscaleSSHEnabled(t *testing.T) {
	tests := []struct {
		hi   *Hostinfo
		want bool
	}{
		{
			nil,
			false,
		},
		{
			&Hostinfo{},
			false,
		},
		{
			&Hostinfo{SSH_HostKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO.... root@bar"}},
			true,
		},
	}

	for i, tt := range tests {
		got := tt.hi.TailscaleSSHEnabled()
		if got != tt.want {
			t.Errorf("%d. got %v; want %v", i, got, tt.want)
		}
	}
}

func TestNodeEqual(t *testing.T) {
	nodeHandles := []string{
		"ID", "StableID", "Name", "User", "Sharer",
		"Key", "KeyExpiry", "KeySignature", "Machine", "DiscoKey",
		"Addresses", "AllowedIPs", "Endpoints", "LegacyDERPString", "HomeDERP", "Hostinfo",
		"Created", "Cap", "Tags", "PrimaryRoutes",
		"LastSeen", "Online", "MachineAuthorized",
		"Capabilities", "CapMap",
		"UnsignedPeerAPIOnly",
		"ComputedName", "computedHostIfDifferent", "ComputedNameWithHost",
		"DataPlaneAuditLogID", "Expired", "SelfNodeV4MasqAddrForThisPeer",
		"SelfNodeV6MasqAddrForThisPeer", "IsWireGuardOnly", "IsJailed", "ExitNodeDNSResolvers",
	}
	if have := fieldsOf(reflect.TypeFor[Node]()); !reflect.DeepEqual(have, nodeHandles) {
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
			&Node{Key: n1},
			&Node{Key: key.NewNode().Public()},
			false,
		},
		{
			&Node{Key: n1},
			&Node{Key: n1},
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
			&Node{Addresses: []netip.Prefix{}},
			&Node{Addresses: nil},
			false,
		},
		{
			&Node{Addresses: []netip.Prefix{}},
			&Node{Addresses: []netip.Prefix{}},
			true,
		},
		{
			&Node{AllowedIPs: []netip.Prefix{}},
			&Node{AllowedIPs: nil},
			false,
		},
		{
			&Node{Addresses: []netip.Prefix{}},
			&Node{Addresses: []netip.Prefix{}},
			true,
		},
		{
			&Node{Endpoints: []netip.AddrPort{}},
			&Node{Endpoints: nil},
			false,
		},
		{
			&Node{Endpoints: []netip.AddrPort{}},
			&Node{Endpoints: []netip.AddrPort{}},
			true,
		},
		{
			&Node{Hostinfo: (&Hostinfo{Hostname: "alice"}).View()},
			&Node{Hostinfo: (&Hostinfo{Hostname: "bob"}).View()},
			false,
		},
		{
			&Node{Hostinfo: (&Hostinfo{}).View()},
			&Node{Hostinfo: (&Hostinfo{}).View()},
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
			&Node{LegacyDERPString: "foo"},
			&Node{LegacyDERPString: "bar"},
			false,
		},
		{
			&Node{HomeDERP: 1},
			&Node{HomeDERP: 2},
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
		{
			&Node{Expired: true},
			&Node{},
			false,
		},
		{
			&Node{},
			&Node{SelfNodeV4MasqAddrForThisPeer: new(netip.MustParseAddr("100.64.0.1"))},
			false,
		},
		{
			&Node{SelfNodeV4MasqAddrForThisPeer: new(netip.MustParseAddr("100.64.0.1"))},
			&Node{SelfNodeV4MasqAddrForThisPeer: new(netip.MustParseAddr("100.64.0.1"))},
			true,
		},
		{
			&Node{},
			&Node{SelfNodeV6MasqAddrForThisPeer: new(netip.MustParseAddr("2001::3456"))},
			false,
		},
		{
			&Node{SelfNodeV6MasqAddrForThisPeer: new(netip.MustParseAddr("2001::3456"))},
			&Node{SelfNodeV6MasqAddrForThisPeer: new(netip.MustParseAddr("2001::3456"))},
			true,
		},
		{
			&Node{
				CapMap: NodeCapMap{
					"foo": []RawMessage{`"foo"`},
				},
			},
			&Node{
				CapMap: NodeCapMap{
					"foo": []RawMessage{`"foo"`},
				},
			},
			true,
		},
		{
			&Node{
				CapMap: NodeCapMap{
					"bar": []RawMessage{`"foo"`},
				},
			},
			&Node{
				CapMap: NodeCapMap{
					"foo": []RawMessage{`"bar"`},
				},
			},
			false,
		},
		{
			&Node{
				CapMap: NodeCapMap{
					"foo": nil,
				},
			},
			&Node{
				CapMap: NodeCapMap{
					"foo": []RawMessage{`"bar"`},
				},
			},
			false,
		},
		{
			&Node{IsJailed: true},
			&Node{IsJailed: true},
			true,
		},
		{
			&Node{IsJailed: false},
			&Node{IsJailed: true},
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

var nodeIsRouterCases = []struct {
	name string
	node Node
	want bool
}{
	{
		name: "empty",
		node: Node{},
		want: false,
	},
	{
		name: "too-few-allowedips",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
			AllowedIPs: []netip.Prefix{},
		},
		want: false,
	},
	{
		name: "duplicates",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.1/32"),
			},
		},
		want: false,
	},
	{
		name: "plain-ipv4",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
		},
		want: false,
	},
	{
		name: "plain-ipv6",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
		},
		want: false,
	},
	{
		name: "plain-ipv4-ipv6",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
		},
		want: false,
	},
	{
		name: "exit-node-ipv4",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("0.0.0.0/0"),
			},
		},
		want: true,
	},
	{
		name: "exit-node-ipv6",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("::/0"),
			},
		},
		want: true,
	},
	{
		name: "exit-node-ipv4-ipv6",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		},
		want: true,
	},
	{
		name: "subnet-router-ipv4",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("192.0.2.0/24"),
			},
		},
		want: true,
	},
	{
		name: "subnet-router-ipv6",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("2001:db8::/32"),
			},
		},
		want: true,
	},
	{
		name: "subnet-router-ipv4-ipv6",
		node: Node{
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
				netip.MustParsePrefix("192.0.2.0/24"),
				netip.MustParsePrefix("2001:db8::/32"),
			},
		},
		want: true,
	},
}

func TestNodeIsRouter(t *testing.T) {
	for _, tc := range nodeIsRouterCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.node.IsRouter(); got != tc.want {
				t.Errorf("node: got %t, want %t", got, tc.want)
			}

			nv := tc.node.View()
			if got := nv.IsRouter(); got != tc.want {
				t.Errorf("view: got %t, want %t", got, tc.want)
			}

			// Check that [ipnstate.PeerStatus.IsRouter] matches.
			ps := peerStatusFromNode(nv)
			if got := ps.IsRouter(); got != tc.want {
				t.Errorf("peer status: got %t, want %t", got, tc.want)
			}
		})
	}
}

func FuzzNodeIsRouter(f *testing.F) {
	encodePrefixes := func(f *testing.F, prefixes ...netip.Prefix) string {
		f.Helper()
		out := make([]string, len(prefixes))
		for i, p := range prefixes {
			out[i] = p.String()
		}
		return strings.Join(out, " ")
	}
	decodePrefixes := func(t *testing.T, prefixes string) []netip.Prefix {
		t.Helper()
		var out []netip.Prefix
		for p := range strings.FieldsSeq(prefixes) {
			pfx, err := netip.ParsePrefix(p)
			if err != nil {
				log.Printf("skipping %q: %v", prefixes, err)
				t.Skipf("%q: %v", prefixes, err)
			}
			out = append(out, pfx)
		}
		return out
	}

	for _, tc := range nodeIsRouterCases {
		addresses := encodePrefixes(f, tc.node.Addresses...)
		allowedIPs := encodePrefixes(f, tc.node.AllowedIPs...)
		f.Logf("addresses=%q allowedIPs=%q", addresses, allowedIPs)
		f.Add(addresses, allowedIPs)
	}
	f.Fuzz(func(t *testing.T, addresses, allowedIPs string) {
		n := Node{
			Addresses:  decodePrefixes(t, addresses),
			AllowedIPs: decodePrefixes(t, allowedIPs),
		}
		ps := peerStatusFromNode(n.View())
		t.Logf("%v %v", n.Addresses, n.AllowedIPs)

		if len(n.Addresses) != len(ps.TailscaleIPs) ||
			len(n.AllowedIPs) != ps.AllowedIPs.Len() {
			t.Skip("n and ps are not equivalent")
		}

		gotN := n.IsRouter()
		gotPS := ps.IsRouter()
		if gotN != gotPS {
			t.Errorf("mismatched node %t, peer status %t; addresses=%q allowedIPs=%q",
				gotN, gotPS, addresses, allowedIPs)
		}
	})
}

func peerStatusFromNode(n NodeView) *ipnstate.PeerStatus {
	ps := &ipnstate.PeerStatus{
		ID:        n.StableID(),
		NodeID:    n.ID(),
		PublicKey: n.Key(),
		DNSName:   n.Name(),
	}
	for _, p := range n.Addresses().All() {
		if p.IsSingleIP() {
			ps.TailscaleIPs = append(ps.TailscaleIPs, p.Addr())
		}
	}
	ps.AllowedIPs = new(n.AllowedIPs())
	return ps
}

func TestNetInfoFields(t *testing.T) {
	handled := []string{
		"MappingVariesByDestIP",
		"WorkingIPv6",
		"OSHasIPv6",
		"WorkingUDP",
		"WorkingICMPv4",
		"HavePortMap",
		"UPnP",
		"PMP",
		"PCP",
		"PreferredDERP",
		"LinkType",
		"DERPLatency",
		"FirewallMode",
	}
	if have := fieldsOf(reflect.TypeFor[NetInfo]()); !reflect.DeepEqual(have, handled) {
		t.Errorf("NetInfo.Clone/BasicallyEqually check might be out of sync\nfields: %q\nhandled: %q\n",
			have, handled)
	}
}

func TestCloneUser(t *testing.T) {
	tests := []struct {
		name string
		u    *User
	}{
		{"nil_logins", &User{}},
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
			Addresses:  make([]netip.Prefix, 0),
			AllowedIPs: make([]netip.Prefix, 0),
			Endpoints:  make([]netip.AddrPort, 0),
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

func TestRegisterRequestNilClone(t *testing.T) {
	var nilReq *RegisterRequest
	got := nilReq.Clone()
	if got != nil {
		t.Errorf("got = %v; want nil", got)
	}
}

// Tests that CurrentCapabilityVersion is bumped when the comment block above it gets bumped.
// We've screwed this up several times.
func TestCurrentCapabilityVersion(t *testing.T) {
	f := must.Get(os.ReadFile("tailcfg.go"))
	matches := regexp.MustCompile(`(?m)^//[\s-]+(\d+): \d\d\d\d-\d\d-\d\d: `).FindAllStringSubmatch(string(f), -1)
	max := 0
	for _, m := range matches {
		n := must.Get(strconv.Atoi(m[1]))
		if n > max {
			max = n
		}
	}
	if CapabilityVersion(max) != CurrentCapabilityVersion {
		t.Errorf("CurrentCapabilityVersion = %d; want %d", CurrentCapabilityVersion, max)
	}
}

func TestUnmarshalHealth(t *testing.T) {
	tests := []struct {
		in   string   // MapResponse JSON
		want []string // MapResponse.Health wanted value post-unmarshal
	}{
		{in: `{}`},
		{in: `{"Health":null}`},
		{in: `{"Health":[]}`, want: []string{}},
		{in: `{"Health":["bad"]}`, want: []string{"bad"}},
	}
	for _, tt := range tests {
		var mr MapResponse
		if err := json.Unmarshal([]byte(tt.in), &mr); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(mr.Health, tt.want) {
			t.Errorf("for %#q: got %v; want %v", tt.in, mr.Health, tt.want)
		}
	}
}

func TestRawMessage(t *testing.T) {
	// Create a few types of json.RawMessages and then marshal them back and
	// forth to make sure they round-trip.

	type rule struct {
		Ports []int `json:",omitempty"`
	}
	tests := []struct {
		name string
		val  map[string][]rule
		wire map[string][]RawMessage
	}{
		{
			name: "nil",
			val:  nil,
			wire: nil,
		},
		{
			name: "empty",
			val:  map[string][]rule{},
			wire: map[string][]RawMessage{},
		},
		{
			name: "one",
			val: map[string][]rule{
				"foo": {{Ports: []int{1, 2, 3}}},
			},
			wire: map[string][]RawMessage{
				"foo": {
					`{"Ports":[1,2,3]}`,
				},
			},
		},
		{
			name: "many",
			val: map[string][]rule{
				"foo": {{Ports: []int{1, 2, 3}}},
				"bar": {{Ports: []int{4, 5, 6}}, {Ports: []int{7, 8, 9}}},
				"baz": nil,
				"abc": {},
				"def": {{}},
			},
			wire: map[string][]RawMessage{
				"foo": {
					`{"Ports":[1,2,3]}`,
				},
				"bar": {
					`{"Ports":[4,5,6]}`,
					`{"Ports":[7,8,9]}`,
				},
				"baz": nil,
				"abc": {},
				"def": {"{}"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j := must.Get(json.Marshal(tc.val))
			var gotWire map[string][]RawMessage
			if err := json.Unmarshal(j, &gotWire); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !reflect.DeepEqual(gotWire, tc.wire) {
				t.Errorf("got %#v; want %#v", gotWire, tc.wire)
			}

			j = must.Get(json.Marshal(tc.wire))
			var gotVal map[string][]rule
			if err := json.Unmarshal(j, &gotVal); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !reflect.DeepEqual(gotVal, tc.val) {
				t.Errorf("got %#v; want %#v", gotVal, tc.val)
			}
		})
	}
}

func TestMarshalToRawMessageAndBack(t *testing.T) {
	type inner struct {
		Groups []string `json:"groups,omitempty"`
	}
	testip := netip.MustParseAddrPort("1.2.3.4:80")
	type testRule struct {
		Ports    []int            `json:"ports,omitempty"`
		ToggleOn bool             `json:"toggleOn,omitempty"`
		Name     string           `json:"name,omitempty"`
		Groups   inner            `json:"groups"`
		Addrs    []netip.AddrPort `json:"addrs"`
	}
	tests := []struct {
		name    string
		capType PeerCapability
		val     testRule
	}{
		{
			name:    "empty",
			val:     testRule{},
			capType: PeerCapability("foo"),
		},
		{
			name:    "some-values",
			val:     testRule{Ports: []int{80, 443}, Name: "foo"},
			capType: PeerCapability("foo"),
		},
		{
			name:    "all-values",
			val:     testRule{Ports: []int{80, 443}, Name: "foo", ToggleOn: true, Groups: inner{Groups: []string{"foo", "bar"}}, Addrs: []netip.AddrPort{testip}},
			capType: PeerCapability("foo"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := MarshalCapJSON(tc.val)
			if err != nil {
				t.Fatalf("unexpected error marshalling raw message: %v", err)
			}
			cap := PeerCapMap{tc.capType: []RawMessage{raw}}
			after, err := UnmarshalCapJSON[testRule](cap, tc.capType)
			if err != nil {
				t.Fatalf("unexpected error unmarshaling raw message: %v", err)
			}
			if !reflect.DeepEqual([]testRule{tc.val}, after) {
				t.Errorf("got %#v; want %#v", after, []testRule{tc.val})
			}
		})
	}
}

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			// Make sure we don't again accidentally bring in a dependency on
			// drive or its transitive dependencies
			"testing":                        "do not use testing package in production code",
			"tailscale.com/drive/driveimpl":  "https://github.com/tailscale/tailscale/pull/10631",
			"github.com/studio-b12/gowebdav": "https://github.com/tailscale/tailscale/pull/10631",
		},
	}.Check(t)
}

func TestCheckTag(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		want bool
	}{
		{"empty", "", false},
		{"good", "tag:foo", true},
		{"bad", "tag:", false},
		{"no_leading_num", "tag:1foo", false},
		{"no_punctuation", "tag:foa@bar", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckTag(tt.tag)
			if err == nil && !tt.want {
				t.Errorf("got nil; want error")
			} else if err != nil && tt.want {
				t.Errorf("got %v; want nil", err)
			}
		})
	}
}

func TestDisplayMessageEqual(t *testing.T) {
	type test struct {
		name      string
		value1    DisplayMessage
		value2    DisplayMessage
		wantEqual bool
	}

	for _, test := range []test{
		{
			name: "same",
			value1: DisplayMessage{
				Title:               "title",
				Text:                "text",
				Severity:            SeverityHigh,
				ImpactsConnectivity: false,
				PrimaryAction: &DisplayMessageAction{
					URL:   "https://example.com",
					Label: "Open",
				},
			},
			value2: DisplayMessage{
				Title:               "title",
				Text:                "text",
				Severity:            SeverityHigh,
				ImpactsConnectivity: false,
				PrimaryAction: &DisplayMessageAction{
					URL:   "https://example.com",
					Label: "Open",
				},
			},
			wantEqual: true,
		},
		{
			name: "different-title",
			value1: DisplayMessage{
				Title: "title",
			},
			value2: DisplayMessage{
				Title: "different title",
			},
			wantEqual: false,
		},
		{
			name: "different-text",
			value1: DisplayMessage{
				Text: "some text",
			},
			value2: DisplayMessage{
				Text: "different text",
			},
			wantEqual: false,
		},
		{
			name: "different-severity",
			value1: DisplayMessage{
				Severity: SeverityHigh,
			},
			value2: DisplayMessage{
				Severity: SeverityMedium,
			},
			wantEqual: false,
		},
		{
			name: "different-impactsConnectivity",
			value1: DisplayMessage{
				ImpactsConnectivity: true,
			},
			value2: DisplayMessage{
				ImpactsConnectivity: false,
			},
			wantEqual: false,
		},
		{
			name:   "different-primaryAction-nil-non-nil",
			value1: DisplayMessage{},
			value2: DisplayMessage{
				PrimaryAction: &DisplayMessageAction{
					URL:   "https://example.com",
					Label: "Open",
				},
			},
			wantEqual: false,
		},
		{
			name: "different-primaryAction-url",
			value1: DisplayMessage{
				PrimaryAction: &DisplayMessageAction{
					URL:   "https://example.com",
					Label: "Open",
				},
			},
			value2: DisplayMessage{
				PrimaryAction: &DisplayMessageAction{
					URL:   "https://zombo.com",
					Label: "Open",
				},
			},
			wantEqual: false,
		},
		{
			name: "different-primaryAction-label",
			value1: DisplayMessage{
				PrimaryAction: &DisplayMessageAction{
					URL:   "https://example.com",
					Label: "Open",
				},
			},
			value2: DisplayMessage{
				PrimaryAction: &DisplayMessageAction{
					URL:   "https://example.com",
					Label: "Learn more",
				},
			},
			wantEqual: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := test.value1.Equal(test.value2)

			if got != test.wantEqual {
				value1 := must.Get(json.MarshalIndent(test.value1, "", "  "))
				value2 := must.Get(json.MarshalIndent(test.value2, "", "  "))
				t.Errorf("value1.Equal(value2): got %t, want %t\nvalue1:\n%s\nvalue2:\n%s", got, test.wantEqual, value1, value2)
			}
		})
	}
}

func TestServiceActionTypeValid(t *testing.T) {
	tests := []struct {
		typ  ServiceActionType
		want bool
	}{
		{ServiceActionTypeAWSS3, true},
		{ServiceActionTypeCockroachDB, true},
		{ServiceActionTypeElasticSearch, true},
		{ServiceActionTypeHTTP, true},
		{ServiceActionTypeKubernetes, true},
		{ServiceActionTypeMongoDB, true},
		{ServiceActionTypeMSSQL, true},
		{ServiceActionTypeMySQL, true},
		{ServiceActionTypePostgreSQL, true},
		{ServiceActionTypeRDP, true},
		{ServiceActionTypeVNC, true},
		{ServiceActionTypeSSH, true},
		{ServiceActionTypeTCP, true},
		{"ftp", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := tt.typ.Valid(); got != tt.want {
			t.Errorf("ServiceActionType(%q).Valid() = %v, want %v", tt.typ, got, tt.want)
		}
	}
}

// TestSSHActionJSON verifies that SSHAction round-trips through
// encoding/json with SessionDuration encoded as int64 nanoseconds.
// It notably guards against jsonv2 `format` tag options in struct
// tags, which Go 1.27's encoding/json rejects at runtime.
// See https://github.com/tailscale/tailscale/issues/20528.
func TestSSHActionJSON(t *testing.T) {
	a := SSHAction{
		Accept:          true,
		SessionDuration: 5 * time.Second,
	}
	got, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"accept":true,"sessionDuration":5000000000}`
	if string(got) != want {
		t.Errorf("Marshal = %s; want %s", got, want)
	}
	var back SSHAction
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back, a) {
		t.Errorf("round trip = %+v; want %+v", back, a)
	}
}
