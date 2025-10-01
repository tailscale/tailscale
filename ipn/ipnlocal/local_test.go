// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	memro "go4.org/mem"
	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/appc/appctest"
	"tailscale.com/control/controlclient"
	"tailscale.com/drive"
	"tailscale.com/drive/driveimpl"
	"tailscale.com/feature"
	_ "tailscale.com/feature/condregister/portmapper"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/tstest/deptest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
	"tailscale.com/util/syspolicy"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
	"tailscale.com/util/syspolicy/source"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/filter/filtertype"
	"tailscale.com/wgengine/wgcfg"
)

func fakeStoreRoutes(*appc.RouteInfo) error { return nil }

func inRemove(ip netip.Addr) bool {
	for _, pfx := range removeFromDefaultRoute {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

func makeNodeKeyFromID(nodeID tailcfg.NodeID) key.NodePublic {
	raw := make([]byte, 32)
	binary.BigEndian.PutUint64(raw[24:], uint64(nodeID))
	return key.NodePublicFromRaw32(memro.B(raw))
}

func makeDiscoKeyFromID(nodeID tailcfg.NodeID) (ret key.DiscoPublic) {
	raw := make([]byte, 32)
	binary.BigEndian.PutUint64(raw[24:], uint64(nodeID))
	return key.DiscoPublicFromRaw32(memro.B(raw))
}

func TestShrinkDefaultRoute(t *testing.T) {
	tests := []struct {
		route     string
		in        []string
		out       []string
		localIPFn func(netip.Addr) bool // true if this machine's local IP address should be "in" after shrinking.
	}{
		{
			route: "0.0.0.0/0",
			in:    []string{"1.2.3.4", "25.0.0.1"},
			out: []string{
				"10.0.0.1",
				"10.255.255.255",
				"192.168.0.1",
				"192.168.255.255",
				"172.16.0.1",
				"172.31.255.255",
				"100.101.102.103",
				"224.0.0.1",
				"169.254.169.254",
				// Some random IPv6 stuff that shouldn't be in a v4
				// default route.
				"fe80::",
				"2601::1",
			},
			localIPFn: func(ip netip.Addr) bool { return !inRemove(ip) && ip.Is4() },
		},
		{
			route: "::/0",
			in:    []string{"::1", "2601::1"},
			out: []string{
				"fe80::1",
				"ff00::1",
				tsaddr.TailscaleULARange().Addr().String(),
			},
			localIPFn: func(ip netip.Addr) bool { return !inRemove(ip) && ip.Is6() },
		},
	}

	// Construct a fake local network environment to make this test hermetic.
	// localInterfaceRoutes and hostIPs would normally come from calling interfaceRoutes,
	// and localAddresses would normally come from calling interfaces.LocalAddresses.
	var b netipx.IPSetBuilder
	for _, c := range []string{"127.0.0.0/8", "192.168.9.0/24", "fe80::/32"} {
		p := netip.MustParsePrefix(c)
		b.AddPrefix(p)
	}
	localInterfaceRoutes, err := b.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	hostIPs := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("192.168.9.39"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("fe80::437d:feff:feca:49a7"),
	}
	localAddresses := []netip.Addr{
		netip.MustParseAddr("192.168.9.39"),
	}

	for _, test := range tests {
		def := netip.MustParsePrefix(test.route)
		got, err := shrinkDefaultRoute(def, localInterfaceRoutes, hostIPs)
		if err != nil {
			t.Fatalf("shrinkDefaultRoute(%q): %v", test.route, err)
		}
		for _, ip := range test.in {
			if !got.Contains(netip.MustParseAddr(ip)) {
				t.Errorf("shrink(%q).Contains(%v) = false, want true", test.route, ip)
			}
		}
		for _, ip := range test.out {
			if got.Contains(netip.MustParseAddr(ip)) {
				t.Errorf("shrink(%q).Contains(%v) = true, want false", test.route, ip)
			}
		}
		for _, ip := range localAddresses {
			want := test.localIPFn(ip)
			if gotContains := got.Contains(ip); gotContains != want {
				t.Errorf("shrink(%q).Contains(%v) = %v, want %v", test.route, ip, gotContains, want)
			}
		}
	}
}

func TestPeerRoutes(t *testing.T) {
	pp := netip.MustParsePrefix
	tests := []struct {
		name  string
		peers []wgcfg.Peer
		want  []netip.Prefix
	}{
		{
			name: "small_v4",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netip.Prefix{
						pp("100.101.102.103/32"),
					},
				},
			},
			want: []netip.Prefix{
				pp("100.101.102.103/32"),
			},
		},
		{
			name: "big_v4",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netip.Prefix{
						pp("100.101.102.103/32"),
						pp("100.101.102.104/32"),
						pp("100.101.102.105/32"),
					},
				},
			},
			want: []netip.Prefix{
				pp("100.64.0.0/10"),
			},
		},
		{
			name: "has_1_v6",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netip.Prefix{
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/128"),
					},
				},
			},
			want: []netip.Prefix{
				pp("fd7a:115c:a1e0::/48"),
			},
		},
		{
			name: "has_2_v6",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netip.Prefix{
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/128"),
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b241/128"),
					},
				},
			},
			want: []netip.Prefix{
				pp("fd7a:115c:a1e0::/48"),
			},
		},
		{
			name: "big_v4_big_v6",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netip.Prefix{
						pp("100.101.102.103/32"),
						pp("100.101.102.104/32"),
						pp("100.101.102.105/32"),
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/128"),
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b241/128"),
					},
				},
			},
			want: []netip.Prefix{
				pp("100.64.0.0/10"),
				pp("fd7a:115c:a1e0::/48"),
			},
		},
		{
			name: "output-should-be-sorted",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netip.Prefix{
						pp("100.64.0.2/32"),
						pp("10.0.0.0/16"),
					},
				},
				{
					AllowedIPs: []netip.Prefix{
						pp("100.64.0.1/32"),
						pp("10.0.0.0/8"),
					},
				},
			},
			want: []netip.Prefix{
				pp("10.0.0.0/8"),
				pp("10.0.0.0/16"),
				pp("100.64.0.1/32"),
				pp("100.64.0.2/32"),
			},
		},
		{
			name: "skip-unmasked-prefixes",
			peers: []wgcfg.Peer{
				{
					PublicKey: key.NewNode().Public(),
					AllowedIPs: []netip.Prefix{
						pp("100.64.0.2/32"),
						pp("10.0.0.100/16"),
					},
				},
			},
			want: []netip.Prefix{
				pp("100.64.0.2/32"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerRoutes(t.Logf, tt.peers, 2)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestPeerAPIBase(t *testing.T) {
	tests := []struct {
		name string
		nm   *netmap.NetworkMap
		peer *tailcfg.Node
		want string
	}{
		{
			name: "nil_netmap",
			peer: new(tailcfg.Node),
			want: "",
		},
		{
			name: "nil_peer",
			nm:   new(netmap.NetworkMap),
			want: "",
		},
		{
			name: "self_only_4_them_both",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("100.64.1.1/32"),
					},
				}).View(),
			},
			peer: &tailcfg.Node{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.1.2/32"),
					netip.MustParsePrefix("fe70::2/128"),
				},
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: "peerapi4", Port: 444},
						{Proto: "peerapi6", Port: 666},
					},
				}).View(),
			},
			want: "http://100.64.1.2:444",
		},
		{
			name: "self_only_6_them_both",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("fe70::1/128"),
					},
				}).View(),
			},
			peer: &tailcfg.Node{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.1.2/32"),
					netip.MustParsePrefix("fe70::2/128"),
				},
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: "peerapi4", Port: 444},
						{Proto: "peerapi6", Port: 666},
					},
				}).View(),
			},
			want: "http://[fe70::2]:666",
		},
		{
			name: "self_both_them_only_4",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("100.64.1.1/32"),
						netip.MustParsePrefix("fe70::1/128"),
					},
				}).View(),
			},
			peer: &tailcfg.Node{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.1.2/32"),
					netip.MustParsePrefix("fe70::2/128"),
				},
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: "peerapi4", Port: 444},
					},
				}).View(),
			},
			want: "http://100.64.1.2:444",
		},
		{
			name: "self_both_them_only_6",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("100.64.1.1/32"),
						netip.MustParsePrefix("fe70::1/128"),
					},
				}).View(),
			},
			peer: &tailcfg.Node{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.1.2/32"),
					netip.MustParsePrefix("fe70::2/128"),
				},
				Hostinfo: (&tailcfg.Hostinfo{
					Services: []tailcfg.Service{
						{Proto: "peerapi6", Port: 666},
					},
				}).View(),
			},
			want: "http://[fe70::2]:666",
		},
		{
			name: "self_both_them_no_peerapi_service",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						netip.MustParsePrefix("100.64.1.1/32"),
						netip.MustParsePrefix("fe70::1/128"),
					},
				}).View(),
			},
			peer: &tailcfg.Node{
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.1.2/32"),
					netip.MustParsePrefix("fe70::2/128"),
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerAPIBase(tt.nm, tt.peer.View())
			if got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

type panicOnUseTransport struct{}

func (panicOnUseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("unexpected HTTP request")
}

func newTestLocalBackend(t testing.TB) *LocalBackend {
	bus := eventbustest.NewBus(t)
	return newTestLocalBackendWithSys(t, tsd.NewSystemWithBus(bus))
}

// newTestLocalBackendWithSys creates a new LocalBackend with the given tsd.System.
// If the state store or engine are not set in sys, they will be set to a new
// in-memory store and fake userspace engine, respectively.
func newTestLocalBackendWithSys(t testing.TB, sys *tsd.System) *LocalBackend {
	var logf logger.Logf = logger.Discard
	if _, ok := sys.StateStore.GetOK(); !ok {
		sys.Set(new(mem.Store))
		t.Log("Added memory store for testing")
	}
	if _, ok := sys.Engine.GetOK(); !ok {
		eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
		if err != nil {
			t.Fatalf("NewFakeUserspaceEngine: %v", err)
		}
		t.Cleanup(eng.Close)
		sys.Set(eng)
		t.Log("Added fake userspace engine for testing")
	}
	if _, ok := sys.Dialer.GetOK(); !ok {
		sys.Set(tsdial.NewDialer(netmon.NewStatic()))
		t.Log("Added static dialer for testing")
	}
	lb, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(lb.Shutdown)
	return lb
}

// Issue 1573: don't generate a machine key if we don't want to be running.
func TestLazyMachineKeyGeneration(t *testing.T) {
	tstest.Replace(t, &panicOnMachineKeyGeneration, func() bool { return true })

	lb := newTestLocalBackend(t)
	lb.SetHTTPTestClient(&http.Client{
		Transport: panicOnUseTransport{}, // validate we don't send HTTP requests
	})

	if err := lb.Start(ipn.Options{}); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give the controlclient package goroutines (if they're
	// accidentally started) extra time to schedule and run (and thus
	// hit panicOnUseTransport).
	time.Sleep(500 * time.Millisecond)
}

func TestZeroExitNodeViaLocalAPI(t *testing.T) {
	lb := newTestLocalBackend(t)
	user := &ipnauth.TestActor{}

	// Give it an initial exit node in use.
	if _, err := lb.EditPrefsAs(&ipn.MaskedPrefs{
		ExitNodeIDSet: true,
		Prefs: ipn.Prefs{
			ExitNodeID: "foo",
		},
	}, user); err != nil {
		t.Fatalf("enabling first exit node: %v", err)
	}

	// SetUseExitNodeEnabled(false) "remembers" the prior exit node.
	if _, err := lb.SetUseExitNodeEnabled(user, false); err != nil {
		t.Fatal("expected failure")
	}

	// Zero the exit node
	pv, err := lb.EditPrefsAs(&ipn.MaskedPrefs{
		ExitNodeIDSet: true,
		Prefs: ipn.Prefs{
			ExitNodeID: "",
		},
	}, user)
	if err != nil {
		t.Fatalf("enabling first exit node: %v", err)
	}

	// We just set the internal exit node to the empty string, so InternalExitNodePrior should
	// also be zero'd
	if got, want := pv.InternalExitNodePrior(), tailcfg.StableNodeID(""); got != want {
		t.Fatalf("unexpected InternalExitNodePrior %q, want: %q", got, want)
	}
}

func TestSetUseExitNodeEnabled(t *testing.T) {
	lb := newTestLocalBackend(t)
	user := &ipnauth.TestActor{}

	// Can't turn it on if it never had an old value.
	if _, err := lb.SetUseExitNodeEnabled(user, true); err == nil {
		t.Fatal("expected success")
	}

	// But we can turn it off when it's already off.
	if _, err := lb.SetUseExitNodeEnabled(user, false); err != nil {
		t.Fatal("expected failure")
	}

	// Give it an initial exit node in use.
	if _, err := lb.EditPrefsAs(&ipn.MaskedPrefs{
		ExitNodeIDSet: true,
		Prefs: ipn.Prefs{
			ExitNodeID: "foo",
		},
	}, user); err != nil {
		t.Fatalf("enabling first exit node: %v", err)
	}

	// Now turn off that exit node.
	if prefs, err := lb.SetUseExitNodeEnabled(user, false); err != nil {
		t.Fatal("expected failure")
	} else {
		if g, w := prefs.ExitNodeID(), tailcfg.StableNodeID(""); g != w {
			t.Fatalf("unexpected exit node ID %q; want %q", g, w)
		}
		if g, w := prefs.InternalExitNodePrior(), tailcfg.StableNodeID("foo"); g != w {
			t.Fatalf("unexpected exit node prior %q; want %q", g, w)
		}
	}

	// And turn it back on.
	if prefs, err := lb.SetUseExitNodeEnabled(user, true); err != nil {
		t.Fatal("expected failure")
	} else {
		if g, w := prefs.ExitNodeID(), tailcfg.StableNodeID("foo"); g != w {
			t.Fatalf("unexpected exit node ID %q; want %q", g, w)
		}
		if g, w := prefs.InternalExitNodePrior(), tailcfg.StableNodeID("foo"); g != w {
			t.Fatalf("unexpected exit node prior %q; want %q", g, w)
		}
	}

	// Verify we block setting an Internal field.
	if _, err := lb.EditPrefsAs(&ipn.MaskedPrefs{
		InternalExitNodePriorSet: true,
	}, user); err == nil {
		t.Fatalf("unexpected success; want an error trying to set an internal field")
	}
}

func makeExitNode(id tailcfg.NodeID, opts ...peerOptFunc) tailcfg.NodeView {
	return makePeer(id, append([]peerOptFunc{withCap(26), withSuggest(), withExitRoutes()}, opts...)...)
}

func TestConfigureExitNode(t *testing.T) {
	controlURL := "https://localhost:1/"
	exitNode1 := makeExitNode(1, withName("node-1"), withDERP(1), withAddresses(netip.MustParsePrefix("100.64.1.1/32")))
	exitNode2 := makeExitNode(2, withName("node-2"), withDERP(2), withAddresses(netip.MustParsePrefix("100.64.1.2/32")))
	selfNode := makeExitNode(3, withName("node-3"), withDERP(1), withAddresses(netip.MustParsePrefix("100.64.1.3/32")))
	clientNetmap := buildNetmapWithPeers(selfNode, exitNode1, exitNode2)

	report := &netcheck.Report{
		RegionLatency: map[int]time.Duration{
			1: 5 * time.Millisecond,
			2: 10 * time.Millisecond,
		},
		PreferredDERP: 1,
	}

	tests := []struct {
		name                   string
		prefs                  ipn.Prefs
		netMap                 *netmap.NetworkMap
		report                 *netcheck.Report
		changePrefs            *ipn.MaskedPrefs
		useExitNodeEnabled     *bool
		exitNodeIDPolicy       *tailcfg.StableNodeID
		exitNodeIPPolicy       *netip.Addr
		exitNodeAllowedIDs     []tailcfg.StableNodeID // nil if all IDs are allowed for auto exit nodes
		exitNodeAllowOverride  bool                   // whether [pkey.AllowExitNodeOverride] should be set to true
		wantChangePrefsErr     error                  // if non-nil, the error we expect from [LocalBackend.EditPrefsAs]
		wantPrefs              ipn.Prefs
		wantExitNodeToggleErr  error // if non-nil, the error we expect from [LocalBackend.SetUseExitNodeEnabled]
		wantHostinfoExitNodeID tailcfg.StableNodeID
	}{
		{
			name: "exit-node-id-via-prefs", // set exit node ID via prefs
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap: clientNetmap,
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:         ipn.Prefs{ExitNodeID: exitNode1.StableID()},
				ExitNodeIDSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode1.StableID(),
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "exit-node-ip-via-prefs", // set exit node IP via prefs (should be resolved to an ID)
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap: clientNetmap,
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:         ipn.Prefs{ExitNodeIP: exitNode1.Addresses().At(0).Addr()},
				ExitNodeIPSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode1.StableID(),
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-exit-node-via-prefs/any", // set auto exit node via prefs
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap: clientNetmap,
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:           ipn.Prefs{AutoExitNode: "any"},
				AutoExitNodeSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode1.StableID(),
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-exit-node-via-prefs/set-exit-node-id-via-prefs", // setting exit node ID explicitly should disable auto exit node
			prefs: ipn.Prefs{
				ControlURL:   controlURL,
				AutoExitNode: "any",
				ExitNodeID:   exitNode1.StableID(),
			},
			netMap: clientNetmap,
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:         ipn.Prefs{ExitNodeID: exitNode2.StableID()},
				ExitNodeIDSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode2.StableID(),
				AutoExitNode: "", // should be unset
			},
			wantHostinfoExitNodeID: exitNode2.StableID(),
		},
		{
			name: "auto-exit-node-via-prefs/any/no-report", // set auto exit node via prefs, but no report means we can't resolve the exit node ID
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap: clientNetmap,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:           ipn.Prefs{AutoExitNode: "any"},
				AutoExitNodeSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   unresolvedExitNodeID, // cannot resolve; traffic will be dropped
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: "",
		},
		{
			name: "auto-exit-node-via-prefs/any/no-netmap", // similarly, but without a netmap (no exit node should be selected)
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:           ipn.Prefs{AutoExitNode: "any"},
				AutoExitNodeSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   unresolvedExitNodeID, // cannot resolve; traffic will be dropped
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: "",
		},
		{
			name: "auto-exit-node-via-prefs/foo", // set auto exit node via prefs with an unknown/unsupported expression
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap: clientNetmap,
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:           ipn.Prefs{AutoExitNode: "foo"},
				AutoExitNodeSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode1.StableID(), // unknown exit node expressions should work as "any"
				AutoExitNode: "foo",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-exit-node-via-prefs/off", // toggle the exit node off after it was set to "any"
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap: clientNetmap,
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:           ipn.Prefs{AutoExitNode: "any"},
				AutoExitNodeSet: true,
			},
			useExitNodeEnabled: ptr.To(false),
			wantPrefs: ipn.Prefs{
				ControlURL:            controlURL,
				ExitNodeID:            "",
				AutoExitNode:          "",
				InternalExitNodePrior: "auto:any",
			},
			wantHostinfoExitNodeID: "",
		},
		{
			name: "auto-exit-node-via-prefs/on", // toggle the exit node on
			prefs: ipn.Prefs{
				ControlURL:            controlURL,
				InternalExitNodePrior: "auto:any",
			},
			netMap:             clientNetmap,
			report:             report,
			useExitNodeEnabled: ptr.To(true),
			wantPrefs: ipn.Prefs{
				ControlURL:            controlURL,
				ExitNodeID:            exitNode1.StableID(),
				AutoExitNode:          "any",
				InternalExitNodePrior: "auto:any",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "id-via-policy", // set exit node ID via syspolicy
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           clientNetmap,
			exitNodeIDPolicy: ptr.To(exitNode1.StableID()),
			wantPrefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode1.StableID(),
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "id-via-policy/cannot-override-via-prefs/by-id", // syspolicy should take precedence over prefs
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           clientNetmap,
			exitNodeIDPolicy: ptr.To(exitNode1.StableID()),
			changePrefs: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ExitNodeID: exitNode2.StableID(), // this should be ignored
				},
				ExitNodeIDSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode1.StableID(),
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
			wantChangePrefsErr:     errManagedByPolicy,
		},
		{
			name: "id-via-policy/cannot-override-via-prefs/by-ip", // syspolicy should take precedence over prefs
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           clientNetmap,
			exitNodeIDPolicy: ptr.To(exitNode1.StableID()),
			changePrefs: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ExitNodeIP: exitNode2.Addresses().At(0).Addr(), // this should be ignored
				},
				ExitNodeIPSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode1.StableID(),
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
			wantChangePrefsErr:     errManagedByPolicy,
		},
		{
			name: "id-via-policy/cannot-override-via-prefs/by-auto-expr", // syspolicy should take precedence over prefs
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           clientNetmap,
			exitNodeIDPolicy: ptr.To(exitNode1.StableID()),
			changePrefs: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					AutoExitNode: "any", // this should be ignored
				},
				AutoExitNodeSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode1.StableID(),
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
			wantChangePrefsErr:     errManagedByPolicy,
		},
		{
			name: "ip-via-policy", // set exit node IP via syspolicy (should be resolved to an ID)
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           clientNetmap,
			exitNodeIPPolicy: ptr.To(exitNode2.Addresses().At(0).Addr()),
			wantPrefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode2.StableID(),
			},
			wantHostinfoExitNodeID: exitNode2.StableID(),
		},
		{
			name: "auto-any-via-policy", // set auto exit node via syspolicy (an exit node should be selected)
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           clientNetmap,
			report:           report,
			exitNodeIDPolicy: ptr.To(tailcfg.StableNodeID("auto:any")),
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode1.StableID(),
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-any-via-policy/no-report", // set auto exit node via syspolicy without a netcheck report (no exit node should be selected)
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           clientNetmap,
			report:           nil,
			exitNodeIDPolicy: ptr.To(tailcfg.StableNodeID("auto:any")),
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   unresolvedExitNodeID,
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: "",
		},
		{
			name: "auto-any-via-policy/no-netmap", // similarly, but without a netmap (no exit node should be selected)
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           nil,
			report:           report,
			exitNodeIDPolicy: ptr.To(tailcfg.StableNodeID("auto:any")),
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   unresolvedExitNodeID,
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: "",
		},
		{
			name: "auto-any-via-policy/no-netmap/with-existing", // set auto exit node via syspolicy without a netmap, but with a previously set exit node ID
			prefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode2.StableID(), // should be retained
			},
			netMap:             nil,
			report:             report,
			exitNodeIDPolicy:   ptr.To(tailcfg.StableNodeID("auto:any")),
			exitNodeAllowedIDs: nil, // not configured, so all exit node IDs are implicitly allowed
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode2.StableID(),
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: exitNode2.StableID(),
		},
		{
			name: "auto-any-via-policy/no-netmap/with-allowed-existing", // same, but now with a syspolicy setting that explicitly allows the existing exit node ID
			prefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode2.StableID(), // should be retained
			},
			netMap:           nil,
			report:           report,
			exitNodeIDPolicy: ptr.To(tailcfg.StableNodeID("auto:any")),
			exitNodeAllowedIDs: []tailcfg.StableNodeID{
				exitNode2.StableID(), // the current exit node ID is allowed
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode2.StableID(),
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: exitNode2.StableID(),
		},
		{
			name: "auto-any-via-policy/no-netmap/with-disallowed-existing", // same, but now with a syspolicy setting that does not allow the existing exit node ID
			prefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode2.StableID(), // not allowed by [pkey.AllowedSuggestedExitNodes]
			},
			netMap:           nil,
			report:           report,
			exitNodeIDPolicy: ptr.To(tailcfg.StableNodeID("auto:any")),
			exitNodeAllowedIDs: []tailcfg.StableNodeID{
				exitNode1.StableID(), // a different exit node ID; the current one is not allowed
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   unresolvedExitNodeID, // we don't have a netmap yet, and the current exit node ID is not allowed; block traffic
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: "",
		},
		{
			name: "auto-any-via-policy/with-netmap/with-allowed-existing", // same, but now with a syspolicy setting that does not allow the existing exit node ID
			prefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode1.StableID(), // not allowed by [pkey.AllowedSuggestedExitNodes]
			},
			netMap:           clientNetmap,
			report:           report,
			exitNodeIDPolicy: ptr.To(tailcfg.StableNodeID("auto:any")),
			exitNodeAllowedIDs: []tailcfg.StableNodeID{
				exitNode2.StableID(), // a different exit node ID; the current one is not allowed
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode2.StableID(), // we have a netmap; switch to the best allowed exit node
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: exitNode2.StableID(),
		},
		{
			name: "auto-any-via-policy/with-netmap/switch-to-better", // if all exit nodes are allowed, switch to the best one once we have a netmap
			prefs: ipn.Prefs{
				ControlURL: controlURL,
				ExitNodeID: exitNode2.StableID(),
			},
			netMap:           clientNetmap,
			report:           report,
			exitNodeIDPolicy: ptr.To(tailcfg.StableNodeID("auto:any")),
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode1.StableID(), // switch to the best exit node
				AutoExitNode: "any",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-foo-via-policy", // set auto exit node via syspolicy with an unknown/unsupported expression
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:           clientNetmap,
			report:           report,
			exitNodeIDPolicy: ptr.To(tailcfg.StableNodeID("auto:foo")),
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode1.StableID(), // unknown exit node expressions should work as "any"
				AutoExitNode: "foo",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-foo-via-edit-prefs", // set auto exit node via EditPrefs with an unknown/unsupported expression
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap: clientNetmap,
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs:           ipn.Prefs{AutoExitNode: "foo"},
				AutoExitNodeSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode1.StableID(), // unknown exit node expressions should work as "any"
				AutoExitNode: "foo",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-any-via-policy/toggle-off", // cannot toggle off the exit node if it was set via syspolicy
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:                clientNetmap,
			report:                report,
			exitNodeIDPolicy:      ptr.To(tailcfg.StableNodeID("auto:any")),
			useExitNodeEnabled:    ptr.To(false), // should fail with an error
			wantExitNodeToggleErr: errManagedByPolicy,
			wantPrefs: ipn.Prefs{
				ControlURL:            controlURL,
				ExitNodeID:            exitNode1.StableID(), // still enforced by the policy setting
				AutoExitNode:          "any",
				InternalExitNodePrior: "",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-any-via-policy/allow-override/change", // changing the exit node is allowed by [pkey.AllowExitNodeOverride]
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:                clientNetmap,
			report:                report,
			exitNodeIDPolicy:      ptr.To(tailcfg.StableNodeID("auto:any")),
			exitNodeAllowOverride: true, // allow changing the exit node
			changePrefs: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ExitNodeID: exitNode2.StableID(), // change the exit node ID
				},
				ExitNodeIDSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				ExitNodeID:   exitNode2.StableID(), // overridden by user
				AutoExitNode: "",                   // cleared, as we are setting the exit node ID explicitly
			},
			wantHostinfoExitNodeID: exitNode2.StableID(),
		},
		{
			name: "auto-any-via-policy/allow-override/clear", // clearing the exit node ID is not allowed by [pkey.AllowExitNodeOverride]
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:                clientNetmap,
			report:                report,
			exitNodeIDPolicy:      ptr.To(tailcfg.StableNodeID("auto:any")),
			exitNodeAllowOverride: true, // allow changing, but not disabling, the exit node
			changePrefs: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ExitNodeID: "", // clearing the exit node ID disables the exit node and should not be allowed
				},
				ExitNodeIDSet: true,
			},
			wantChangePrefsErr: errManagedByPolicy, // edit prefs should fail with an error
			wantPrefs: ipn.Prefs{
				ControlURL:            controlURL,
				ExitNodeID:            exitNode1.StableID(), // still enforced by the policy setting
				AutoExitNode:          "any",
				InternalExitNodePrior: "",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-any-via-policy/allow-override/toggle-off", // similarly, toggling off the exit node is not allowed even with [pkey.AllowExitNodeOverride]
			prefs: ipn.Prefs{
				ControlURL: controlURL,
			},
			netMap:                clientNetmap,
			report:                report,
			exitNodeIDPolicy:      ptr.To(tailcfg.StableNodeID("auto:any")),
			exitNodeAllowOverride: true,          // allow changing, but not disabling, the exit node
			useExitNodeEnabled:    ptr.To(false), // should fail with an error
			wantExitNodeToggleErr: errManagedByPolicy,
			wantPrefs: ipn.Prefs{
				ControlURL:            controlURL,
				ExitNodeID:            exitNode1.StableID(), // still enforced by the policy setting
				AutoExitNode:          "any",
				InternalExitNodePrior: "",
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
		{
			name: "auto-any-via-initial-prefs/no-netmap/clear-auto-exit-node",
			prefs: ipn.Prefs{
				ControlURL:   controlURL,
				AutoExitNode: ipn.AnyExitNode,
			},
			netMap: nil, // no netmap; exit node cannot be resolved
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					AutoExitNode: "", // clear the auto exit node
				},
				AutoExitNodeSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				AutoExitNode: "", // cleared
				ExitNodeID:   "", // has never been resolved, so it should be cleared as well
			},
			wantHostinfoExitNodeID: "",
		},
		{
			name: "auto-any-via-initial-prefs/with-netmap/clear-auto-exit-node",
			prefs: ipn.Prefs{
				ControlURL:   controlURL,
				AutoExitNode: ipn.AnyExitNode,
			},
			netMap: clientNetmap, // has a netmap; exit node will be resolved
			report: report,
			changePrefs: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					AutoExitNode: "", // clear the auto exit node
				},
				AutoExitNodeSet: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:   controlURL,
				AutoExitNode: "",                   // cleared
				ExitNodeID:   exitNode1.StableID(), // a resolved exit node ID should be retained
			},
			wantHostinfoExitNodeID: exitNode1.StableID(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var pol policytest.Config
			// Configure policy settings, if any.
			if tt.exitNodeIDPolicy != nil {
				pol.Set(pkey.ExitNodeID, string(*tt.exitNodeIDPolicy))
			}
			if tt.exitNodeIPPolicy != nil {
				pol.Set(pkey.ExitNodeIP, tt.exitNodeIPPolicy.String())
			}
			if tt.exitNodeAllowedIDs != nil {
				pol.Set(pkey.AllowedSuggestedExitNodes, toStrings(tt.exitNodeAllowedIDs))
			}
			if tt.exitNodeAllowOverride {
				pol.Set(pkey.AllowExitNodeOverride, true)
			}

			// Create a new LocalBackend with the given prefs.
			// Any syspolicy settings will be applied to the initial prefs.
			sys := tsd.NewSystem()
			sys.PolicyClient.Set(pol)
			lb := newTestLocalBackendWithSys(t, sys)
			lb.SetPrefsForTest(tt.prefs.Clone())

			// Then set the netcheck report and netmap, if any.
			if tt.report != nil {
				lb.MagicConn().SetLastNetcheckReportForTest(t.Context(), tt.report)
			}
			if tt.netMap != nil {
				lb.SetControlClientStatus(lb.cc, controlclient.Status{NetMap: tt.netMap})
			}

			user := &ipnauth.TestActor{}
			// If we have a changePrefs, apply it.
			if tt.changePrefs != nil {
				_, err := lb.EditPrefsAs(tt.changePrefs, user)
				checkError(t, err, tt.wantChangePrefsErr, true)
			}

			// If we need to flip exit node toggle on or off, do it.
			if tt.useExitNodeEnabled != nil {
				_, err := lb.SetUseExitNodeEnabled(user, *tt.useExitNodeEnabled)
				checkError(t, err, tt.wantExitNodeToggleErr, true)
			}

			// Now check the prefs.
			opts := []cmp.Option{
				cmpopts.EquateComparable(netip.Addr{}, netip.Prefix{}),
			}
			if diff := cmp.Diff(&tt.wantPrefs, lb.Prefs().AsStruct(), opts...); diff != "" {
				t.Errorf("Prefs(+got -want): %v", diff)
			}

			// And check Hostinfo.
			if got := lb.hostinfo.ExitNodeID; got != tt.wantHostinfoExitNodeID {
				t.Errorf("Hostinfo.ExitNodeID got %s, want %s", got, tt.wantHostinfoExitNodeID)
			}
		})
	}
}

func TestPrefsChangeDisablesExitNode(t *testing.T) {
	tests := []struct {
		name                 string
		netMap               *netmap.NetworkMap
		prefs                ipn.Prefs
		change               ipn.MaskedPrefs
		wantDisablesExitNode bool
	}{
		{
			name: "has-exit-node-id/no-change",
			prefs: ipn.Prefs{
				ExitNodeID: "test-exit-node",
			},
			change:               ipn.MaskedPrefs{},
			wantDisablesExitNode: false,
		},
		{
			name: "has-exit-node-ip/no-change",
			prefs: ipn.Prefs{
				ExitNodeIP: netip.MustParseAddr("100.100.1.1"),
			},
			change:               ipn.MaskedPrefs{},
			wantDisablesExitNode: false,
		},
		{
			name: "has-auto-exit-node/no-change",
			prefs: ipn.Prefs{
				AutoExitNode: ipn.AnyExitNode,
			},
			change:               ipn.MaskedPrefs{},
			wantDisablesExitNode: false,
		},
		{
			name: "has-exit-node-id/non-exit-node-change",
			prefs: ipn.Prefs{
				ExitNodeID: "test-exit-node",
			},
			change: ipn.MaskedPrefs{
				WantRunningSet:            true,
				HostnameSet:               true,
				ExitNodeAllowLANAccessSet: true,
				Prefs: ipn.Prefs{
					WantRunning:            true,
					Hostname:               "test-hostname",
					ExitNodeAllowLANAccess: true,
				},
			},
			wantDisablesExitNode: false,
		},
		{
			name: "has-exit-node-ip/non-exit-node-change",
			prefs: ipn.Prefs{
				ExitNodeIP: netip.MustParseAddr("100.100.1.1"),
			},
			change: ipn.MaskedPrefs{
				WantRunningSet: true,
				RouteAllSet:    true,
				ShieldsUpSet:   true,
				Prefs: ipn.Prefs{
					WantRunning: false,
					RouteAll:    false,
					ShieldsUp:   true,
				},
			},
			wantDisablesExitNode: false,
		},
		{
			name: "has-auto-exit-node/non-exit-node-change",
			prefs: ipn.Prefs{
				AutoExitNode: ipn.AnyExitNode,
			},
			change: ipn.MaskedPrefs{
				CorpDNSSet:                true,
				RouteAllSet:               true,
				ExitNodeAllowLANAccessSet: true,
				Prefs: ipn.Prefs{
					CorpDNS:                true,
					RouteAll:               false,
					ExitNodeAllowLANAccess: true,
				},
			},
			wantDisablesExitNode: false,
		},
		{
			name: "has-exit-node-id/change-exit-node-id",
			prefs: ipn.Prefs{
				ExitNodeID: "exit-node-1",
			},
			change: ipn.MaskedPrefs{
				ExitNodeIDSet: true,
				Prefs: ipn.Prefs{
					ExitNodeID: "exit-node-2",
				},
			},
			wantDisablesExitNode: false, // changing the exit node ID does not disable it
		},
		{
			name: "has-exit-node-id/enable-auto-exit-node",
			prefs: ipn.Prefs{
				ExitNodeID: "exit-node-1",
			},
			change: ipn.MaskedPrefs{
				AutoExitNodeSet: true,
				Prefs: ipn.Prefs{
					AutoExitNode: ipn.AnyExitNode,
				},
			},
			wantDisablesExitNode: false, // changing the exit node ID does not disable it
		},
		{
			name: "has-exit-node-id/clear-exit-node-id",
			prefs: ipn.Prefs{
				ExitNodeID: "exit-node-1",
			},
			change: ipn.MaskedPrefs{
				ExitNodeIDSet: true,
				Prefs: ipn.Prefs{
					ExitNodeID: "",
				},
			},
			wantDisablesExitNode: true, // clearing the exit node ID disables it
		},
		{
			name: "has-auto-exit-node/clear-exit-node-id",
			prefs: ipn.Prefs{
				AutoExitNode: ipn.AnyExitNode,
			},
			change: ipn.MaskedPrefs{
				ExitNodeIDSet: true,
				Prefs: ipn.Prefs{
					ExitNodeID: "",
				},
			},
			wantDisablesExitNode: true, // clearing the exit node ID disables auto exit node as well...
		},
		{
			name: "has-auto-exit-node/clear-exit-node-id/but-keep-auto-exit-node",
			prefs: ipn.Prefs{
				AutoExitNode: ipn.AnyExitNode,
			},
			change: ipn.MaskedPrefs{
				ExitNodeIDSet:   true,
				AutoExitNodeSet: true,
				Prefs: ipn.Prefs{
					ExitNodeID:   "",
					AutoExitNode: ipn.AnyExitNode,
				},
			},
			wantDisablesExitNode: false, // ... unless we explicitly keep the auto exit node enabled
		},
		{
			name: "has-auto-exit-node/clear-exit-node-ip",
			prefs: ipn.Prefs{
				AutoExitNode: ipn.AnyExitNode,
			},
			change: ipn.MaskedPrefs{
				ExitNodeIPSet: true,
				Prefs: ipn.Prefs{
					ExitNodeIP: netip.Addr{},
				},
			},
			wantDisablesExitNode: false, // auto exit node is still enabled
		},
		{
			name: "has-auto-exit-node/clear-auto-exit-node",
			prefs: ipn.Prefs{
				AutoExitNode: ipn.AnyExitNode,
			},
			change: ipn.MaskedPrefs{
				AutoExitNodeSet: true,
				Prefs: ipn.Prefs{
					AutoExitNode: "",
				},
			},
			wantDisablesExitNode: true, // clearing the auto exit while the exit node ID is unresolved disables exit node usage
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lb := newTestLocalBackend(t)
			if tt.netMap != nil {
				lb.SetControlClientStatus(lb.cc, controlclient.Status{NetMap: tt.netMap})
			}
			// Set the initial prefs via SetPrefsForTest
			// to apply necessary adjustments.
			lb.SetPrefsForTest(tt.prefs.Clone())
			initialPrefs := lb.Prefs()

			// Check whether changeDisablesExitNodeLocked correctly identifies the change.
			if got := lb.changeDisablesExitNodeLocked(initialPrefs, &tt.change); got != tt.wantDisablesExitNode {
				t.Errorf("disablesExitNode: got %v; want %v", got, tt.wantDisablesExitNode)
			}

			// Apply the change and check if it the actual behavior matches the expectation.
			gotPrefs, err := lb.EditPrefsAs(&tt.change, &ipnauth.TestActor{})
			if err != nil {
				t.Fatalf("EditPrefsAs failed: %v", err)
			}
			gotDisabledExitNode := initialPrefs.ExitNodeID() != "" && gotPrefs.ExitNodeID() == ""
			if gotDisabledExitNode != tt.wantDisablesExitNode {
				t.Errorf("disabledExitNode: got %v; want %v", gotDisabledExitNode, tt.wantDisablesExitNode)
			}
		})
	}
}

func TestExitNodeNotifyOrder(t *testing.T) {
	const controlURL = "https://localhost:1/"

	report := &netcheck.Report{
		RegionLatency: map[int]time.Duration{
			1: 5 * time.Millisecond,
			2: 10 * time.Millisecond,
		},
		PreferredDERP: 1,
	}

	exitNode1 := makeExitNode(1, withName("node-1"), withDERP(1), withAddresses(netip.MustParsePrefix("100.64.1.1/32")))
	exitNode2 := makeExitNode(2, withName("node-2"), withDERP(2), withAddresses(netip.MustParsePrefix("100.64.1.2/32")))
	selfNode := makeExitNode(3, withName("node-3"), withDERP(1), withAddresses(netip.MustParsePrefix("100.64.1.3/32")))
	clientNetmap := buildNetmapWithPeers(selfNode, exitNode1, exitNode2)

	lb := newTestLocalBackend(t)
	lb.sys.MagicSock.Get().SetLastNetcheckReportForTest(lb.ctx, report)
	lb.SetPrefsForTest(&ipn.Prefs{
		ControlURL:   controlURL,
		AutoExitNode: ipn.AnyExitNode,
	})

	nw := newNotificationWatcher(t, lb, ipnauth.Self)

	// Updating the netmap should trigger both a netmap notification
	// and an exit node ID notification (since an exit node is selected).
	// The netmap notification should be sent first.
	nw.watch(0, []wantedNotification{
		wantNetmapNotify(clientNetmap),
		wantExitNodeIDNotify(exitNode1.StableID()),
	})
	lb.SetControlClientStatus(lb.cc, controlclient.Status{NetMap: clientNetmap})
	nw.check()
}

func wantNetmapNotify(want *netmap.NetworkMap) wantedNotification {
	return wantedNotification{
		name: "Netmap",
		cond: func(t testing.TB, _ ipnauth.Actor, n *ipn.Notify) bool {
			return n.NetMap == want
		},
	}
}

func wantExitNodeIDNotify(want tailcfg.StableNodeID) wantedNotification {
	return wantedNotification{
		name: fmt.Sprintf("ExitNodeID-%s", want),
		cond: func(_ testing.TB, _ ipnauth.Actor, n *ipn.Notify) bool {
			return n.Prefs != nil && n.Prefs.Valid() && n.Prefs.ExitNodeID() == want
		},
	}
}

func TestInternalAndExternalInterfaces(t *testing.T) {
	type interfacePrefix struct {
		i   netmon.Interface
		pfx netip.Prefix
	}

	masked := func(ips ...interfacePrefix) (pfxs []netip.Prefix) {
		for _, ip := range ips {
			pfxs = append(pfxs, ip.pfx.Masked())
		}
		return pfxs
	}
	iList := func(ips ...interfacePrefix) (il netmon.InterfaceList) {
		for _, ip := range ips {
			il = append(il, ip.i)
		}
		return il
	}
	newInterface := func(name, pfx string, wsl2, loopback bool) interfacePrefix {
		ippfx := netip.MustParsePrefix(pfx)
		ip := netmon.Interface{
			Interface: &net.Interface{},
			AltAddrs: []net.Addr{
				netipx.PrefixIPNet(ippfx),
			},
		}
		if loopback {
			ip.Flags = net.FlagLoopback
		}
		if wsl2 {
			ip.HardwareAddr = []byte{0x00, 0x15, 0x5d, 0x00, 0x00, 0x00}
		}
		return interfacePrefix{i: ip, pfx: ippfx}
	}
	var (
		en0      = newInterface("en0", "10.20.2.5/16", false, false)
		en1      = newInterface("en1", "192.168.1.237/24", false, false)
		wsl      = newInterface("wsl", "192.168.5.34/24", true, false)
		loopback = newInterface("lo0", "127.0.0.1/8", false, true)
	)

	tests := []struct {
		name    string
		goos    string
		il      netmon.InterfaceList
		wantInt []netip.Prefix
		wantExt []netip.Prefix
	}{
		{
			name: "single-interface",
			goos: "linux",
			il: iList(
				en0,
				loopback,
			),
			wantInt: masked(loopback),
			wantExt: masked(en0),
		},
		{
			name: "multiple-interfaces",
			goos: "linux",
			il: iList(
				en0,
				en1,
				wsl,
				loopback,
			),
			wantInt: masked(loopback),
			wantExt: masked(en0, en1, wsl),
		},
		{
			name: "wsl2",
			goos: "windows",
			il: iList(
				en0,
				en1,
				wsl,
				loopback,
			),
			wantInt: masked(loopback, wsl),
			wantExt: masked(en0, en1),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotInt, gotExt, err := internalAndExternalInterfacesFrom(tc.il, tc.goos)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotInt, tc.wantInt) {
				t.Errorf("unexpected internal prefixes\ngot %v\nwant %v", gotInt, tc.wantInt)
			}
			if !reflect.DeepEqual(gotExt, tc.wantExt) {
				t.Errorf("unexpected external prefixes\ngot %v\nwant %v", gotExt, tc.wantExt)
			}
		})
	}
}

func TestPacketFilterPermitsUnlockedNodes(t *testing.T) {
	tests := []struct {
		name   string
		peers  []*tailcfg.Node
		filter []filter.Match
		want   bool
	}{
		{
			name: "empty",
			want: false,
		},
		{
			name: "no-unsigned",
			peers: []*tailcfg.Node{
				{ID: 1},
			},
			want: false,
		},
		{
			name: "unsigned-good",
			peers: []*tailcfg.Node{
				{ID: 1, UnsignedPeerAPIOnly: true},
			},
			want: false,
		},
		{
			name: "unsigned-bad",
			peers: []*tailcfg.Node{
				{
					ID:                  1,
					UnsignedPeerAPIOnly: true,
					AllowedIPs: []netip.Prefix{
						netip.MustParsePrefix("100.64.0.0/32"),
					},
				},
			},
			filter: []filter.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/32")},
					Dsts: []filter.NetPortRange{
						{
							Net: netip.MustParsePrefix("100.99.0.0/32"),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "unsigned-bad-src-is-superset",
			peers: []*tailcfg.Node{
				{
					ID:                  1,
					UnsignedPeerAPIOnly: true,
					AllowedIPs: []netip.Prefix{
						netip.MustParsePrefix("100.64.0.0/32"),
					},
				},
			},
			filter: []filter.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24")},
					Dsts: []filter.NetPortRange{
						{
							Net: netip.MustParsePrefix("100.99.0.0/32"),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "unsigned-okay-because-no-dsts",
			peers: []*tailcfg.Node{
				{
					ID:                  1,
					UnsignedPeerAPIOnly: true,
					AllowedIPs: []netip.Prefix{
						netip.MustParsePrefix("100.64.0.0/32"),
					},
				},
			},
			filter: []filter.Match{
				{
					Srcs: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/32")},
					Caps: []filter.CapMatch{
						{
							Dst: netip.MustParsePrefix("100.99.0.0/32"),
							Cap: "foo",
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := packetFilterPermitsUnlockedNodes(peersMap(nodeViews(tt.peers)), tt.filter); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusPeerCapabilities(t *testing.T) {
	tests := []struct {
		name                     string
		peers                    []tailcfg.NodeView
		expectedPeerCapabilities map[tailcfg.StableNodeID][]tailcfg.NodeCapability
		expectedPeerCapMap       map[tailcfg.StableNodeID]tailcfg.NodeCapMap
	}{
		{
			name: "peers-with-capabilities",
			peers: []tailcfg.NodeView{
				(&tailcfg.Node{
					ID:              1,
					StableID:        "foo",
					Key:             makeNodeKeyFromID(1),
					IsWireGuardOnly: true,
					Hostinfo:        (&tailcfg.Hostinfo{}).View(),
					Capabilities:    []tailcfg.NodeCapability{tailcfg.CapabilitySSH},
					CapMap: (tailcfg.NodeCapMap)(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
						tailcfg.CapabilitySSH: nil,
					}),
				}).View(),
				(&tailcfg.Node{
					ID:           2,
					StableID:     "bar",
					Key:          makeNodeKeyFromID(2),
					Hostinfo:     (&tailcfg.Hostinfo{}).View(),
					Capabilities: []tailcfg.NodeCapability{tailcfg.CapabilityAdmin},
					CapMap: (tailcfg.NodeCapMap)(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
						tailcfg.CapabilityAdmin: {`{"test": "true}`},
					}),
				}).View(),
				(&tailcfg.Node{
					ID:           3,
					StableID:     "baz",
					Key:          makeNodeKeyFromID(3),
					Hostinfo:     (&tailcfg.Hostinfo{}).View(),
					Capabilities: []tailcfg.NodeCapability{tailcfg.CapabilityOwner},
					CapMap: (tailcfg.NodeCapMap)(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
						tailcfg.CapabilityOwner: nil,
					}),
				}).View(),
			},
			expectedPeerCapabilities: map[tailcfg.StableNodeID][]tailcfg.NodeCapability{
				tailcfg.StableNodeID("foo"): {tailcfg.CapabilitySSH},
				tailcfg.StableNodeID("bar"): {tailcfg.CapabilityAdmin},
				tailcfg.StableNodeID("baz"): {tailcfg.CapabilityOwner},
			},
			expectedPeerCapMap: map[tailcfg.StableNodeID]tailcfg.NodeCapMap{
				tailcfg.StableNodeID("foo"): (tailcfg.NodeCapMap)(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
					tailcfg.CapabilitySSH: nil,
				}),
				tailcfg.StableNodeID("bar"): (tailcfg.NodeCapMap)(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
					tailcfg.CapabilityAdmin: {`{"test": "true}`},
				}),
				tailcfg.StableNodeID("baz"): (tailcfg.NodeCapMap)(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
					tailcfg.CapabilityOwner: nil,
				}),
			},
		},
		{
			name: "peers-without-capabilities",
			peers: []tailcfg.NodeView{
				(&tailcfg.Node{
					ID:              1,
					StableID:        "foo",
					Key:             makeNodeKeyFromID(1),
					IsWireGuardOnly: true,
					Hostinfo:        (&tailcfg.Hostinfo{}).View(),
				}).View(),
				(&tailcfg.Node{
					ID:       2,
					StableID: "bar",
					Key:      makeNodeKeyFromID(2),
					Hostinfo: (&tailcfg.Hostinfo{}).View(),
				}).View(),
			},
		},
	}
	b := newTestLocalBackend(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b.setNetMapLocked(&netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					MachineAuthorized: true,
					Addresses:         ipps("100.101.101.101"),
				}).View(),
				Peers: tt.peers,
			})
			got := b.Status()
			for _, peer := range got.Peer {
				if !reflect.DeepEqual(peer.Capabilities, tt.expectedPeerCapabilities[peer.ID]) {
					t.Errorf("peer capabilities: expected %v got %v", tt.expectedPeerCapabilities, peer.Capabilities)
				}
				if !reflect.DeepEqual(peer.CapMap, tt.expectedPeerCapMap[peer.ID]) {
					t.Errorf("peer capmap: expected %v got %v", tt.expectedPeerCapMap, peer.CapMap)
				}
			}
		})
	}
}

// legacyBackend was the interface between Tailscale frontends
// (e.g. cmd/tailscale, iOS/MacOS/Windows GUIs) and the tailscale
// backend (e.g. cmd/tailscaled) running on the same machine.
// (It has nothing to do with the interface between the backends
// and the cloud control plane.)
type legacyBackend interface {
	// SetNotifyCallback sets the callback to be called on updates
	// from the backend to the client.
	SetNotifyCallback(func(ipn.Notify))
	// Start starts or restarts the backend, typically when a
	// frontend client connects.
	Start(ipn.Options) error
}

// Verify that LocalBackend still implements the legacyBackend interface
// for now, at least until the macOS and iOS clients move off of it.
var _ legacyBackend = (*LocalBackend)(nil)

func TestWatchNotificationsCallbacks(t *testing.T) {
	b := new(LocalBackend)
	n := new(ipn.Notify)
	b.WatchNotifications(context.Background(), 0, func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		// Ensure a watcher has been installed.
		if len(b.notifyWatchers) != 1 {
			t.Fatalf("unexpected number of watchers in new LocalBackend, want: 1 got: %v", len(b.notifyWatchers))
		}
		// Send a notification. Range over notifyWatchers to get the channel
		// because WatchNotifications doesn't expose the handle for it.
		for _, sess := range b.notifyWatchers {
			select {
			case sess.ch <- n:
			default:
				t.Fatalf("could not send notification")
			}
		}
	}, func(roNotify *ipn.Notify) bool {
		if roNotify != n {
			t.Fatalf("unexpected notification received. want: %v got: %v", n, roNotify)
		}
		return false
	})

	// Ensure watchers have been cleaned up.
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.notifyWatchers) != 0 {
		t.Fatalf("unexpected number of watchers in new LocalBackend, want: 0 got: %v", len(b.notifyWatchers))
	}
}

// tests LocalBackend.updateNetmapDeltaLocked
func TestUpdateNetmapDelta(t *testing.T) {
	b := newTestLocalBackend(t)
	if b.currentNode().UpdateNetmapDelta(nil) {
		t.Errorf("updateNetmapDeltaLocked() = true, want false with nil netmap")
	}

	nm := &netmap.NetworkMap{}
	for i := range 5 {
		id := tailcfg.NodeID(i + 1)
		nm.Peers = append(nm.Peers, (&tailcfg.Node{
			ID:  id,
			Key: makeNodeKeyFromID(id),
		}).View())
	}
	b.currentNode().SetNetMap(nm)

	someTime := time.Unix(123, 0)
	muts, ok := netmap.MutationsFromMapResponse(&tailcfg.MapResponse{
		PeersChangedPatch: []*tailcfg.PeerChange{
			{
				NodeID:     1,
				DERPRegion: 1,
			},
			{
				NodeID: 2,
				Online: ptr.To(true),
			},
			{
				NodeID: 3,
				Online: ptr.To(false),
			},
			{
				NodeID:   4,
				LastSeen: ptr.To(someTime),
			},
		},
	}, someTime)
	if !ok {
		t.Fatal("netmap.MutationsFromMapResponse failed")
	}

	if !b.currentNode().UpdateNetmapDelta(muts) {
		t.Fatalf("updateNetmapDeltaLocked() = false, want true with new netmap")
	}

	wants := []*tailcfg.Node{
		{
			ID:       1,
			Key:      makeNodeKeyFromID(1),
			HomeDERP: 1,
		},
		{
			ID:     2,
			Key:    makeNodeKeyFromID(2),
			Online: ptr.To(true),
		},
		{
			ID:     3,
			Key:    makeNodeKeyFromID(3),
			Online: ptr.To(false),
		},
		{
			ID:       4,
			Key:      makeNodeKeyFromID(4),
			LastSeen: ptr.To(someTime),
		},
	}
	for _, want := range wants {
		gotv, ok := b.currentNode().NodeByID(want.ID)
		if !ok {
			t.Errorf("netmap.Peer %v missing from b.profile.Peers", want.ID)
			continue
		}
		got := gotv.AsStruct()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("netmap.Peer %v wrong.\n got: %v\nwant: %v", want.ID, logger.AsJSON(got), logger.AsJSON(want))
		}
	}
}

// tests WhoIs and indirectly that setNetMapLocked updates b.nodeByAddr correctly.
func TestWhoIs(t *testing.T) {
	b := newTestLocalBackend(t)
	b.setNetMapLocked(&netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:        1,
			User:      10,
			Key:       makeNodeKeyFromID(1),
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.101.102.103/32")},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:        2,
				User:      20,
				Key:       makeNodeKeyFromID(2),
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.200.200.200/32")},
			}).View(),
		},
		UserProfiles: map[tailcfg.UserID]tailcfg.UserProfileView{
			10: (&tailcfg.UserProfile{
				DisplayName: "Myself",
			}).View(),
			20: (&tailcfg.UserProfile{
				DisplayName: "Peer",
			}).View(),
		},
	})
	tests := []struct {
		q        string
		want     tailcfg.NodeID // 0 means want ok=false
		wantName string
	}{
		{"100.101.102.103:0", 1, "Myself"},
		{"100.101.102.103:123", 1, "Myself"},
		{"100.200.200.200:0", 2, "Peer"},
		{"100.200.200.200:123", 2, "Peer"},
		{"100.4.0.4:404", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.q, func(t *testing.T) {
			nv, up, ok := b.WhoIs("", netip.MustParseAddrPort(tt.q))
			var got tailcfg.NodeID
			if ok {
				got = nv.ID()
			}
			if got != tt.want {
				t.Errorf("got nodeID %v; want %v", got, tt.want)
			}
			if up.DisplayName != tt.wantName {
				t.Errorf("got name %q; want %q", up.DisplayName, tt.wantName)
			}
		})
	}
}

func TestWireguardExitNodeDNSResolvers(t *testing.T) {
	type tc struct {
		name          string
		id            tailcfg.StableNodeID
		peers         []*tailcfg.Node
		wantOK        bool
		wantResolvers []*dnstype.Resolver
	}

	tests := []tc{
		{
			name:          "no peers",
			id:            "1",
			wantOK:        false,
			wantResolvers: nil,
		},
		{
			name: "non wireguard peer",
			id:   "1",
			peers: []*tailcfg.Node{
				{
					ID:                   1,
					StableID:             "1",
					IsWireGuardOnly:      false,
					ExitNodeDNSResolvers: []*dnstype.Resolver{{Addr: "dns.example.com"}},
				},
			},
			wantOK:        false,
			wantResolvers: nil,
		},
		{
			name: "no matching IDs",
			id:   "2",
			peers: []*tailcfg.Node{
				{
					ID:                   1,
					StableID:             "1",
					IsWireGuardOnly:      true,
					ExitNodeDNSResolvers: []*dnstype.Resolver{{Addr: "dns.example.com"}},
				},
			},
			wantOK:        false,
			wantResolvers: nil,
		},
		{
			name: "wireguard peer",
			id:   "1",
			peers: []*tailcfg.Node{
				{
					ID:                   1,
					StableID:             "1",
					IsWireGuardOnly:      true,
					ExitNodeDNSResolvers: []*dnstype.Resolver{{Addr: "dns.example.com"}},
				},
			},
			wantOK:        true,
			wantResolvers: []*dnstype.Resolver{{Addr: "dns.example.com"}},
		},
	}

	for _, tc := range tests {
		peers := peersMap(nodeViews(tc.peers))
		nm := &netmap.NetworkMap{}
		gotResolvers, gotOK := wireguardExitNodeDNSResolvers(nm, peers, tc.id)

		if gotOK != tc.wantOK || !resolversEqual(t, gotResolvers, tc.wantResolvers) {
			t.Errorf("case: %s: got %v, %v, want %v, %v", tc.name, gotOK, gotResolvers, tc.wantOK, tc.wantResolvers)
		}
	}
}

func TestDNSConfigForNetmapForExitNodeConfigs(t *testing.T) {
	type tc struct {
		name                 string
		exitNode             tailcfg.StableNodeID
		peers                []tailcfg.NodeView
		dnsConfig            *tailcfg.DNSConfig
		wantDefaultResolvers []*dnstype.Resolver
		wantRoutes           map[dnsname.FQDN][]*dnstype.Resolver
	}

	const tsUseWithExitNodeResolverAddr = "usewithexitnode.example.com"
	defaultResolvers := []*dnstype.Resolver{
		{Addr: "default.example.com"},
	}
	containsFlaggedResolvers := append([]*dnstype.Resolver{
		{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true},
	}, defaultResolvers...)

	wgResolvers := []*dnstype.Resolver{{Addr: "wg.example.com"}}
	peers := []tailcfg.NodeView{
		(&tailcfg.Node{
			ID:                   1,
			StableID:             "wg",
			IsWireGuardOnly:      true,
			ExitNodeDNSResolvers: wgResolvers,
			Hostinfo:             (&tailcfg.Hostinfo{}).View(),
		}).View(),
		// regular tailscale exit node with DNS capabilities
		(&tailcfg.Node{
			Cap:      26,
			ID:       2,
			StableID: "ts",
			Hostinfo: (&tailcfg.Hostinfo{}).View(),
		}).View(),
	}
	exitDOH := peerAPIBase(&netmap.NetworkMap{Peers: peers}, peers[0]) + "/dns-query"
	baseRoutes := map[dnsname.FQDN][]*dnstype.Resolver{
		"route.example.com.": {{Addr: "route.example.com"}},
	}
	containsEmptyRoutes := map[dnsname.FQDN][]*dnstype.Resolver{
		"route.example.com.": {{Addr: "route.example.com"}},
		"empty.example.com.": {},
	}
	containsFlaggedRoutes := map[dnsname.FQDN][]*dnstype.Resolver{
		"route.example.com.":    {{Addr: "route.example.com"}},
		"withexit.example.com.": {{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true}},
	}
	containsFlaggedAndEmptyRoutes := map[dnsname.FQDN][]*dnstype.Resolver{
		"empty.example.com.":    {},
		"route.example.com.":    {{Addr: "route.example.com"}},
		"withexit.example.com.": {{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true}},
	}
	flaggedRoutes := map[dnsname.FQDN][]*dnstype.Resolver{
		"withexit.example.com.": {{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true}},
	}
	emptyRoutes := map[dnsname.FQDN][]*dnstype.Resolver{
		"empty.example.com.": {},
	}
	flaggedAndEmptyRoutes := map[dnsname.FQDN][]*dnstype.Resolver{
		"empty.example.com.":    {},
		"withexit.example.com.": {{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true}},
	}

	stringifyRoutes := func(routes map[dnsname.FQDN][]*dnstype.Resolver) map[string][]*dnstype.Resolver {
		if routes == nil {
			return nil
		}
		m := make(map[string][]*dnstype.Resolver)
		for k, v := range routes {
			m[string(k)] = v
		}
		return m
	}

	tests := []tc{
		{
			name:                 "noExit/noRoutes/noResolver",
			exitNode:             "",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{},
			wantDefaultResolvers: nil,
			wantRoutes:           nil,
		},
		{
			name:                 "tsExit/noRoutes/noResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           nil,
		},
		{
			name:                 "tsExit/noRoutes/defaultResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Resolvers: defaultResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           nil,
		},
		{
			name:                 "tsExit/noRoutes/flaggedResolverOnly",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Resolvers: containsFlaggedResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true}},
			wantRoutes:           nil,
		},

		// When at tailscale exit node is in use,
		// only routes that reference resolvers with the UseWithExitNode should be installed,
		// as well as routes with 0-length resolver lists, which should be installed in all cases.
		{
			name:                 "tsExit/routes/noResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(baseRoutes)},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           nil,
		},
		{
			name:                 "tsExit/routes/defaultResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(baseRoutes), Resolvers: defaultResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           nil,
		},
		{
			name:                 "tsExit/routes/flaggedResolverOnly",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(baseRoutes), Resolvers: containsFlaggedResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true}},
			wantRoutes:           nil,
		},
		{
			name:                 "tsExit/flaggedRoutesOnly/defaultResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(containsFlaggedRoutes), Resolvers: defaultResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           flaggedRoutes,
		},
		{
			name:                 "tsExit/flaggedRoutesOnly/flaggedResolverOnly",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(containsFlaggedRoutes), Resolvers: containsFlaggedResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true}},
			wantRoutes:           flaggedRoutes,
		},
		{
			name:                 "tsExit/emptyRoutesOnly/defaultResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(containsEmptyRoutes), Resolvers: defaultResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           emptyRoutes,
		},
		{
			name:                 "tsExit/flaggedAndEmptyRoutesOnly/defaultResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(containsFlaggedAndEmptyRoutes), Resolvers: defaultResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           flaggedAndEmptyRoutes,
		},
		{
			name:                 "tsExit/flaggedAndEmptyRoutesOnly/flaggedResolverOnly",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(containsFlaggedAndEmptyRoutes), Resolvers: containsFlaggedResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: tsUseWithExitNodeResolverAddr, UseWithExitNode: true}},
			wantRoutes:           flaggedAndEmptyRoutes,
		},

		// WireGuard exit nodes with DNS capabilities provide a "fallback" type
		// behavior, they have a lower precedence than a default resolver, but
		// otherwise allow split-DNS to operate as normal, and are used when
		// there is no default resolver.
		{
			name:                 "wgExit/noRoutes/noResolver",
			exitNode:             "wg",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{},
			wantDefaultResolvers: wgResolvers,
			wantRoutes:           nil,
		},
		{
			name:                 "wgExit/noRoutes/defaultResolver",
			exitNode:             "wg",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Resolvers: defaultResolvers},
			wantDefaultResolvers: defaultResolvers,
			wantRoutes:           nil,
		},
		{
			name:                 "wgExit/routes/defaultResolver",
			exitNode:             "wg",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(baseRoutes), Resolvers: defaultResolvers},
			wantDefaultResolvers: defaultResolvers,
			wantRoutes:           baseRoutes,
		},
		{
			name:                 "wgExit/routes/noResolver",
			exitNode:             "wg",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(baseRoutes)},
			wantDefaultResolvers: wgResolvers,
			wantRoutes:           baseRoutes,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nm := &netmap.NetworkMap{
				Peers: tc.peers,
				DNS:   *tc.dnsConfig,
			}

			prefs := &ipn.Prefs{ExitNodeID: tc.exitNode, CorpDNS: true}
			got := dnsConfigForNetmap(nm, peersMap(tc.peers), prefs.View(), false, t.Logf, "")
			if !resolversEqual(t, got.DefaultResolvers, tc.wantDefaultResolvers) {
				t.Errorf("DefaultResolvers: got %#v, want %#v", got.DefaultResolvers, tc.wantDefaultResolvers)
			}
			if !routesEqual(t, got.Routes, tc.wantRoutes) {
				t.Errorf("Routes: got %#v, want %#v", got.Routes, tc.wantRoutes)
			}
		})
	}
}

func TestOfferingAppConnector(t *testing.T) {
	for _, shouldStore := range []bool{false, true} {
		b := newTestBackend(t)
		if b.OfferingAppConnector() {
			t.Fatal("unexpected offering app connector")
		}
		if shouldStore {
			b.appConnector = appc.NewAppConnector(t.Logf, nil, &appc.RouteInfo{}, fakeStoreRoutes)
		} else {
			b.appConnector = appc.NewAppConnector(t.Logf, nil, nil, nil)
		}
		if !b.OfferingAppConnector() {
			t.Fatal("unexpected not offering app connector")
		}
	}
}

func TestRouteAdvertiser(t *testing.T) {
	b := newTestBackend(t)
	testPrefix := netip.MustParsePrefix("192.0.0.8/32")

	ra := appc.RouteAdvertiser(b)
	must.Do(ra.AdvertiseRoute(testPrefix))

	routes := b.Prefs().AdvertiseRoutes()
	if routes.Len() != 1 || routes.At(0) != testPrefix {
		t.Fatalf("got routes %v, want %v", routes, []netip.Prefix{testPrefix})
	}

	must.Do(ra.UnadvertiseRoute(testPrefix))

	routes = b.Prefs().AdvertiseRoutes()
	if routes.Len() != 0 {
		t.Fatalf("got routes %v, want none", routes)
	}
}

func TestRouterAdvertiserIgnoresContainedRoutes(t *testing.T) {
	b := newTestBackend(t)
	testPrefix := netip.MustParsePrefix("192.0.0.0/24")
	ra := appc.RouteAdvertiser(b)
	must.Do(ra.AdvertiseRoute(testPrefix))

	routes := b.Prefs().AdvertiseRoutes()
	if routes.Len() != 1 || routes.At(0) != testPrefix {
		t.Fatalf("got routes %v, want %v", routes, []netip.Prefix{testPrefix})
	}

	must.Do(ra.AdvertiseRoute(netip.MustParsePrefix("192.0.0.8/32")))

	// the above /32 is not added as it is contained within the /24
	routes = b.Prefs().AdvertiseRoutes()
	if routes.Len() != 1 || routes.At(0) != testPrefix {
		t.Fatalf("got routes %v, want %v", routes, []netip.Prefix{testPrefix})
	}
}

func TestObserveDNSResponse(t *testing.T) {
	for _, shouldStore := range []bool{false, true} {
		b := newTestBackend(t)

		// ensure no error when no app connector is configured
		if err := b.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}

		rc := &appctest.RouteCollector{}
		if shouldStore {
			b.appConnector = appc.NewAppConnector(t.Logf, rc, &appc.RouteInfo{}, fakeStoreRoutes)
		} else {
			b.appConnector = appc.NewAppConnector(t.Logf, rc, nil, nil)
		}
		b.appConnector.UpdateDomains([]string{"example.com"})
		b.appConnector.Wait(context.Background())

		if err := b.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8")); err != nil {
			t.Errorf("ObserveDNSResponse: %v", err)
		}
		b.appConnector.Wait(context.Background())
		wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}
		if !slices.Equal(rc.Routes(), wantRoutes) {
			t.Fatalf("got routes %v, want %v", rc.Routes(), wantRoutes)
		}
	}
}

func TestCoveredRouteRangeNoDefault(t *testing.T) {
	tests := []struct {
		existingRoute netip.Prefix
		newRoute      netip.Prefix
		want          bool
	}{
		{
			existingRoute: netip.MustParsePrefix("192.0.0.1/32"),
			newRoute:      netip.MustParsePrefix("192.0.0.1/32"),
			want:          true,
		},
		{
			existingRoute: netip.MustParsePrefix("192.0.0.1/32"),
			newRoute:      netip.MustParsePrefix("192.0.0.2/32"),
			want:          false,
		},
		{
			existingRoute: netip.MustParsePrefix("192.0.0.0/24"),
			newRoute:      netip.MustParsePrefix("192.0.0.1/32"),
			want:          true,
		},
		{
			existingRoute: netip.MustParsePrefix("192.0.0.0/16"),
			newRoute:      netip.MustParsePrefix("192.0.0.0/24"),
			want:          true,
		},
		{
			existingRoute: netip.MustParsePrefix("0.0.0.0/0"),
			newRoute:      netip.MustParsePrefix("192.0.0.0/24"),
			want:          false,
		},
		{
			existingRoute: netip.MustParsePrefix("::/0"),
			newRoute:      netip.MustParsePrefix("2001:db8::/32"),
			want:          false,
		},
	}

	for _, tt := range tests {
		got := coveredRouteRangeNoDefault([]netip.Prefix{tt.existingRoute}, tt.newRoute)
		if got != tt.want {
			t.Errorf("coveredRouteRange(%v, %v) = %v, want %v", tt.existingRoute, tt.newRoute, got, tt.want)
		}
	}
}

func TestReconfigureAppConnector(t *testing.T) {
	b := newTestBackend(t)
	b.reconfigAppConnectorLocked(b.NetMap(), b.pm.prefs)
	if b.appConnector != nil {
		t.Fatal("unexpected app connector")
	}

	b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AppConnector: ipn.AppConnectorPrefs{
				Advertise: true,
			},
		},
		AppConnectorSet: true,
	})
	b.reconfigAppConnectorLocked(b.NetMap(), b.pm.prefs)
	if b.appConnector == nil {
		t.Fatal("expected app connector")
	}

	appCfg := `{
		"name": "example",
		"domains": ["example.com"],
		"connectors": ["tag:example"]
	}`

	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Name: "example.ts.net",
			Tags: []string{"tag:example"},
			CapMap: (tailcfg.NodeCapMap)(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
				"tailscale.com/app-connectors": {tailcfg.RawMessage(appCfg)},
			}),
		}).View(),
	}

	b.currentNode().SetNetMap(nm)

	b.reconfigAppConnectorLocked(b.NetMap(), b.pm.prefs)
	b.appConnector.Wait(context.Background())

	want := []string{"example.com"}
	if !slices.Equal(b.appConnector.Domains().AsSlice(), want) {
		t.Fatalf("got domains %v, want %v", b.appConnector.Domains(), want)
	}
	if v, _ := b.hostinfo.AppConnector.Get(); !v {
		t.Fatalf("expected app connector service")
	}

	// disable the connector in order to assert that the service is removed
	b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AppConnector: ipn.AppConnectorPrefs{
				Advertise: false,
			},
		},
		AppConnectorSet: true,
	})
	b.reconfigAppConnectorLocked(b.NetMap(), b.pm.prefs)
	if b.appConnector != nil {
		t.Fatal("expected no app connector")
	}
	if v, _ := b.hostinfo.AppConnector.Get(); v {
		t.Fatalf("expected no app connector service")
	}
}

func TestBackfillAppConnectorRoutes(t *testing.T) {
	// Create backend with an empty app connector.
	b := newTestBackend(t)
	// newTestBackend creates a backend with a non-nil netmap,
	// but this test requires a nil netmap.
	// Otherwise, instead of backfilling, [LocalBackend.reconfigAppConnectorLocked]
	// uses the domains and routes from netmap's [appctype.AppConnectorAttr].
	// Additionally, a non-nil netmap makes reconfigAppConnectorLocked
	// asynchronous, resulting in a flaky test.
	// Therefore, we set the netmap to nil to simulate a fresh backend start
	// or a profile switch where the netmap is not yet available.
	b.setNetMapLocked(nil)
	if err := b.Start(ipn.Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AppConnector: ipn.AppConnectorPrefs{Advertise: true},
		},
		AppConnectorSet: true,
	}); err != nil {
		t.Fatal(err)
	}
	b.reconfigAppConnectorLocked(b.NetMap(), b.pm.prefs)

	// Smoke check that AdvertiseRoutes doesn't have the test IP.
	ip := netip.MustParseAddr("1.2.3.4")
	routes := b.Prefs().AdvertiseRoutes().AsSlice()
	if slices.Contains(routes, netip.PrefixFrom(ip, ip.BitLen())) {
		t.Fatalf("AdvertiseRoutes %v on a fresh backend already contains advertised route for %v", routes, ip)
	}

	// Store the test IP in profile data, but not in Prefs.AdvertiseRoutes.
	b.ControlKnobs().AppCStoreRoutes.Store(true)
	if err := b.storeRouteInfo(&appc.RouteInfo{
		Domains: map[string][]netip.Addr{
			"example.com": {ip},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Mimic b.authReconfigure for the app connector bits.
	b.mu.Lock()
	b.reconfigAppConnectorLocked(b.NetMap(), b.pm.prefs)
	b.mu.Unlock()
	b.readvertiseAppConnectorRoutes()

	// Check that Prefs.AdvertiseRoutes got backfilled with routes stored in
	// profile data.
	routes = b.Prefs().AdvertiseRoutes().AsSlice()
	if !slices.Contains(routes, netip.PrefixFrom(ip, ip.BitLen())) {
		t.Fatalf("AdvertiseRoutes %v was not backfilled from stored app connector routes with %v", routes, ip)
	}
}

func resolversEqual(t *testing.T, a, b []*dnstype.Resolver) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		t.Errorf("resolversEqual: a == nil || b == nil : %#v != %#v", a, b)
		return false
	}
	if len(a) != len(b) {
		t.Errorf("resolversEqual: len(a) != len(b) : %#v != %#v", a, b)
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			t.Errorf("resolversEqual: a != b [%d]: %v != %v", i, *a[i], *b[i])
			return false
		}
	}
	return true
}

func routesEqual(t *testing.T, a, b map[dnsname.FQDN][]*dnstype.Resolver) bool {
	if len(a) != len(b) {
		t.Logf("routes: len(a) != len(b): %d != %d", len(a), len(b))
		return false
	}
	for name := range a {
		if !resolversEqual(t, a[name], b[name]) {
			t.Logf("routes: a != b [%s]: %v != %v", name, a[name], b[name])
			return false
		}
	}
	return true
}

// dnsResponse is a test helper that creates a DNS response buffer for the given domain and address
func dnsResponse(domain, address string) []byte {
	addr := netip.MustParseAddr(address)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.EnableCompression()
	b.StartAnswers()
	switch addr.BitLen() {
	case 32:
		b.AResource(
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(domain),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   0,
			},
			dnsmessage.AResource{
				A: addr.As4(),
			},
		)
	case 128:
		b.AAAAResource(
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(domain),
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
				TTL:   0,
			},
			dnsmessage.AAAAResource{
				AAAA: addr.As16(),
			},
		)
	default:
		panic("invalid address length")
	}
	return must.Get(b.Finish())
}

func TestSetExitNodeIDPolicy(t *testing.T) {
	zeroValHostinfoView := new(tailcfg.Hostinfo).View()
	pfx := netip.MustParsePrefix
	tests := []struct {
		name                  string
		exitNodeIPKey         bool
		exitNodeIDKey         bool
		exitNodeID            string
		exitNodeIP            string
		prefs                 *ipn.Prefs
		exitNodeIPWant        string
		exitNodeIDWant        string
		autoExitNodeWant      ipn.ExitNodeExpression
		prefsChanged          bool
		nm                    *netmap.NetworkMap
		lastSuggestedExitNode tailcfg.StableNodeID
	}{
		{
			name:           "ExitNodeID key is set",
			exitNodeIDKey:  true,
			exitNodeID:     "123",
			exitNodeIDWant: "123",
			prefsChanged:   true,
		},
		{
			name:           "ExitNodeID key not set",
			exitNodeIDKey:  true,
			exitNodeIDWant: "",
			prefsChanged:   false,
		},
		{
			name:           "ExitNodeID key set, ExitNodeIP preference set",
			exitNodeIDKey:  true,
			exitNodeID:     "123",
			prefs:          &ipn.Prefs{ExitNodeIP: netip.MustParseAddr("127.0.0.1")},
			exitNodeIDWant: "123",
			prefsChanged:   true,
		},
		{
			name:           "ExitNodeID key not set, ExitNodeIP key set",
			exitNodeIPKey:  true,
			exitNodeIP:     "127.0.0.1",
			prefs:          &ipn.Prefs{ExitNodeIP: netip.MustParseAddr("127.0.0.1")},
			exitNodeIPWant: "127.0.0.1",
			prefsChanged:   false,
		},
		{
			name:           "ExitNodeIP key set, existing ExitNodeIP pref",
			exitNodeIPKey:  true,
			exitNodeIP:     "127.0.0.1",
			prefs:          &ipn.Prefs{ExitNodeIP: netip.MustParseAddr("127.0.0.1")},
			exitNodeIPWant: "127.0.0.1",
			prefsChanged:   false,
		},
		{
			name:           "existing preferences match policy",
			exitNodeIDKey:  true,
			exitNodeID:     "123",
			prefs:          &ipn.Prefs{ExitNodeID: tailcfg.StableNodeID("123")},
			exitNodeIDWant: "123",
			prefsChanged:   false,
		},
		{
			name:           "ExitNodeIP set if net map does not have corresponding node",
			exitNodeIPKey:  true,
			prefs:          &ipn.Prefs{ExitNodeIP: netip.MustParseAddr("127.0.0.1")},
			exitNodeIP:     "127.0.0.1",
			exitNodeIPWant: "127.0.0.1",
			prefsChanged:   false,
			nm: &netmap.NetworkMap{
				Name: "foo.tailnet",
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						pfx("100.102.103.104/32"),
						pfx("100::123/128"),
					},
				}).View(),
				Peers: []tailcfg.NodeView{
					(&tailcfg.Node{
						ID:   201,
						Name: "a.tailnet",
						Key:  makeNodeKeyFromID(201),
						Addresses: []netip.Prefix{
							pfx("100.0.0.201/32"),
							pfx("100::201/128"),
						},
					}).View(),
					(&tailcfg.Node{
						ID:   202,
						Name: "b.tailnet",
						Key:  makeNodeKeyFromID(202),
						Addresses: []netip.Prefix{
							pfx("100::202/128"),
						},
					}).View(),
				},
			},
		},
		{
			name:           "ExitNodeIP cleared if net map has corresponding node - policy matches prefs",
			prefs:          &ipn.Prefs{ExitNodeIP: netip.MustParseAddr("127.0.0.1")},
			exitNodeIPKey:  true,
			exitNodeIP:     "127.0.0.1",
			exitNodeIPWant: "",
			exitNodeIDWant: "123",
			prefsChanged:   true,
			nm: &netmap.NetworkMap{
				Name: "foo.tailnet",
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						pfx("100.102.103.104/32"),
						pfx("100::123/128"),
					},
				}).View(),
				Peers: []tailcfg.NodeView{
					(&tailcfg.Node{
						ID:       123,
						Name:     "a.tailnet",
						StableID: tailcfg.StableNodeID("123"),
						Key:      makeNodeKeyFromID(123),
						Addresses: []netip.Prefix{
							pfx("127.0.0.1/32"),
							pfx("100::201/128"),
						},
						Hostinfo: zeroValHostinfoView,
					}).View(),
					(&tailcfg.Node{
						ID:   202,
						Name: "b.tailnet",
						Key:  makeNodeKeyFromID(202),
						Addresses: []netip.Prefix{
							pfx("100::202/128"),
						},
						Hostinfo: zeroValHostinfoView,
					}).View(),
				},
			},
		},
		{
			name:           "ExitNodeIP cleared if net map has corresponding node - no policy set",
			prefs:          &ipn.Prefs{ExitNodeIP: netip.MustParseAddr("127.0.0.1")},
			exitNodeIPWant: "",
			exitNodeIDWant: "123",
			prefsChanged:   true,
			nm: &netmap.NetworkMap{
				Name: "foo.tailnet",
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						pfx("100.102.103.104/32"),
						pfx("100::123/128"),
					},
				}).View(),
				Peers: []tailcfg.NodeView{
					(&tailcfg.Node{
						ID:       123,
						Name:     "a.tailnet",
						StableID: tailcfg.StableNodeID("123"),
						Key:      makeNodeKeyFromID(123),
						Addresses: []netip.Prefix{
							pfx("127.0.0.1/32"),
							pfx("100::201/128"),
						},
						Hostinfo: zeroValHostinfoView,
					}).View(),
					(&tailcfg.Node{
						ID:   202,
						Name: "b.tailnet",
						Key:  makeNodeKeyFromID(202),
						Addresses: []netip.Prefix{
							pfx("100::202/128"),
						},
						Hostinfo: zeroValHostinfoView,
					}).View(),
				},
			},
		},
		{
			name:           "ExitNodeIP cleared if net map has corresponding node - different exit node IP in policy",
			exitNodeIPKey:  true,
			prefs:          &ipn.Prefs{ExitNodeIP: netip.MustParseAddr("127.0.0.1")},
			exitNodeIP:     "100.64.5.6",
			exitNodeIPWant: "",
			exitNodeIDWant: "123",
			prefsChanged:   true,
			nm: &netmap.NetworkMap{
				Name: "foo.tailnet",
				SelfNode: (&tailcfg.Node{
					Addresses: []netip.Prefix{
						pfx("100.102.103.104/32"),
						pfx("100::123/128"),
					},
				}).View(),
				Peers: []tailcfg.NodeView{
					(&tailcfg.Node{
						ID:       123,
						Name:     "a.tailnet",
						StableID: tailcfg.StableNodeID("123"),
						Key:      makeNodeKeyFromID(123),
						Addresses: []netip.Prefix{
							pfx("100.64.5.6/32"),
							pfx("100::201/128"),
						},
						Hostinfo: zeroValHostinfoView,
					}).View(),
					(&tailcfg.Node{
						ID:   202,
						Name: "b.tailnet",
						Key:  makeNodeKeyFromID(202),
						Addresses: []netip.Prefix{
							pfx("100::202/128"),
						},
						Hostinfo: zeroValHostinfoView,
					}).View(),
				},
			},
		},
		{
			name:                  "ExitNodeID key is set to auto:any and last suggested exit node is populated",
			exitNodeIDKey:         true,
			exitNodeID:            "auto:any",
			lastSuggestedExitNode: "123",
			exitNodeIDWant:        "123",
			autoExitNodeWant:      "any",
			prefsChanged:          true,
		},
		{
			name:             "ExitNodeID key is set to auto:any and last suggested exit node is not populated",
			exitNodeIDKey:    true,
			exitNodeID:       "auto:any",
			exitNodeIDWant:   "auto:any",
			autoExitNodeWant: "any",
			prefsChanged:     true,
		},
		{
			name:                  "ExitNodeID key is set to auto:foo and last suggested exit node is populated",
			exitNodeIDKey:         true,
			exitNodeID:            "auto:foo",
			lastSuggestedExitNode: "123",
			exitNodeIDWant:        "123",
			autoExitNodeWant:      "foo",
			prefsChanged:          true,
		},
		{
			name:             "ExitNodeID key is set to auto:foo and last suggested exit node is not populated",
			exitNodeIDKey:    true,
			exitNodeID:       "auto:foo",
			exitNodeIDWant:   "auto:any", // should be "auto:any" for compatibility with existing clients
			autoExitNodeWant: "foo",
			prefsChanged:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var polc policytest.Config
			if test.exitNodeIDKey {
				polc.Set(pkey.ExitNodeID, test.exitNodeID)
			}
			if test.exitNodeIPKey {
				polc.Set(pkey.ExitNodeIP, test.exitNodeIP)
			}
			b := newTestBackend(t, polc)

			if test.nm == nil {
				test.nm = new(netmap.NetworkMap)
			}
			if test.prefs == nil {
				test.prefs = ipn.NewPrefs()
			}
			pm := must.Get(newProfileManager(new(mem.Store), t.Logf, health.NewTracker(eventbustest.NewBus(t))))
			pm.prefs = test.prefs.View()
			b.currentNode().SetNetMap(test.nm)
			b.pm = pm
			b.lastSuggestedExitNode = test.lastSuggestedExitNode
			prefs := b.pm.prefs.AsStruct()
			if changed := b.reconcilePrefsLocked(prefs); changed != test.prefsChanged {
				t.Errorf("wanted prefs changed %v, got prefs changed %v", test.prefsChanged, changed)
			}

			// Both [LocalBackend.SetPrefsForTest] and [LocalBackend.EditPrefs]
			// apply syspolicy settings to the current profile's preferences. Therefore,
			// we pass the current, unmodified preferences and expect the effective
			// preferences to change.
			b.SetPrefsForTest(pm.CurrentPrefs().AsStruct())

			if got := b.Prefs().ExitNodeID(); got != tailcfg.StableNodeID(test.exitNodeIDWant) {
				t.Errorf("ExitNodeID: got %q; want %q", got, test.exitNodeIDWant)
			}
			if got := b.Prefs().ExitNodeIP(); test.exitNodeIPWant == "" {
				if got.String() != "invalid IP" {
					t.Errorf("ExitNodeIP: got %v want invalid IP", got)
				}
			} else if got.String() != test.exitNodeIPWant {
				t.Errorf("ExitNodeIP: got %q; want %q", got, test.exitNodeIPWant)
			}
			if got := b.Prefs().AutoExitNode(); got != test.autoExitNodeWant {
				t.Errorf("AutoExitNode: got %q; want %q", got, test.autoExitNodeWant)
			}
		})
	}
}

func TestUpdateNetmapDeltaAutoExitNode(t *testing.T) {
	peer1 := makePeer(1, withCap(26), withSuggest(), withOnline(true), withExitRoutes())
	peer2 := makePeer(2, withCap(26), withSuggest(), withOnline(true), withExitRoutes())
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "t1",
						RegionID: 1,
					},
				},
			},
			2: {
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "t2",
						RegionID: 2,
					},
				},
			},
		},
	}
	report := &netcheck.Report{
		RegionLatency: map[int]time.Duration{
			1: 10 * time.Millisecond,
			2: 5 * time.Millisecond,
			3: 30 * time.Millisecond,
		},
		PreferredDERP: 2,
	}
	tests := []struct {
		name                  string
		lastSuggestedExitNode tailcfg.StableNodeID
		netmap                *netmap.NetworkMap
		muts                  []*tailcfg.PeerChange
		exitNodeIDWant        tailcfg.StableNodeID
		report                *netcheck.Report
	}{
		{
			// selected auto exit node goes offline
			name: "exit-node-goes-offline",
			// PreferredDERP is 2, and it's also the region with the lowest latency.
			// So, peer2 should be selected as the exit node.
			lastSuggestedExitNode: peer2.StableID(),
			netmap: &netmap.NetworkMap{
				Peers: []tailcfg.NodeView{
					peer1,
					peer2,
				},
				DERPMap: derpMap,
			},
			muts: []*tailcfg.PeerChange{
				{
					NodeID: 1,
					Online: ptr.To(true),
				},
				{
					NodeID: 2,
					Online: ptr.To(false), // the selected exit node goes offline
				},
			},
			exitNodeIDWant: peer1.StableID(),
			report:         report,
		},
		{
			// other exit node goes offline doesn't change selected auto exit node that's still online
			name:                  "other-node-goes-offline",
			lastSuggestedExitNode: peer2.StableID(),
			netmap: &netmap.NetworkMap{
				Peers: []tailcfg.NodeView{
					peer1,
					peer2,
				},
				DERPMap: derpMap,
			},
			muts: []*tailcfg.PeerChange{
				{
					NodeID: 1,
					Online: ptr.To(false), // a different exit node goes offline
				},
				{
					NodeID: 2,
					Online: ptr.To(true),
				},
			},
			exitNodeIDWant: peer2.StableID(),
			report:         report,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := tsd.NewSystem()
			sys.PolicyClient.Set(policytest.Config{
				pkey.ExitNodeID: "auto:any",
			})
			b := newTestLocalBackendWithSys(t, sys)
			b.currentNode().SetNetMap(tt.netmap)
			b.lastSuggestedExitNode = tt.lastSuggestedExitNode
			b.sys.MagicSock.Get().SetLastNetcheckReportForTest(b.ctx, tt.report)
			b.SetPrefsForTest(b.pm.CurrentPrefs().AsStruct())

			allDone := make(chan bool, 1)
			defer b.goTracker.AddDoneCallback(func() {
				b.mu.Lock()
				defer b.mu.Unlock()
				if b.goTracker.RunningGoroutines() > 0 {
					return
				}
				select {
				case allDone <- true:
				default:
				}
			})()

			someTime := time.Unix(123, 0)
			muts, ok := netmap.MutationsFromMapResponse(&tailcfg.MapResponse{
				PeersChangedPatch: tt.muts,
			}, someTime)
			if !ok {
				t.Fatal("netmap.MutationsFromMapResponse failed")
			}

			if b.pm.prefs.ExitNodeID() != tt.lastSuggestedExitNode {
				t.Fatalf("did not set exit node ID to last suggested exit node despite auto policy")
			}

			was := b.goTracker.StartedGoroutines()
			got := b.UpdateNetmapDelta(muts)
			if !got {
				t.Error("got false from UpdateNetmapDelta")
			}
			startedGoroutine := b.goTracker.StartedGoroutines() != was

			wantChange := tt.exitNodeIDWant != tt.lastSuggestedExitNode
			if startedGoroutine != wantChange {
				t.Errorf("got startedGoroutine %v, want %v", startedGoroutine, wantChange)
			}
			if startedGoroutine {
				select {
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for goroutine to finish")
				case <-allDone:
				}
			}
			b.mu.Lock()
			gotExitNode := b.pm.prefs.ExitNodeID()
			b.mu.Unlock()
			if gotExitNode != tt.exitNodeIDWant {
				t.Fatalf("exit node ID after UpdateNetmapDelta = %v; want %v", gotExitNode, tt.exitNodeIDWant)
			}
		})
	}
}

func TestAutoExitNodeSetNetInfoCallback(t *testing.T) {
	polc := policytest.Config{
		pkey.ExitNodeID: "auto:any",
	}
	sys := tsd.NewSystem()
	sys.PolicyClient.Set(polc)

	b := newTestLocalBackendWithSys(t, sys)
	hi := hostinfo.New()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni
	b.hostinfo = hi
	k := key.NewMachine()
	var cc *mockControl
	opts := controlclient.Options{
		ServerURL: "https://example.com",
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return k, nil
		},
		Dialer:       tsdial.NewDialer(netmon.NewStatic()),
		Logf:         b.logf,
		PolicyClient: polc,
	}
	cc = newClient(t, opts)
	b.cc = cc
	peer1 := makePeer(1, withCap(26), withDERP(3), withSuggest(), withExitRoutes())
	peer2 := makePeer(2, withCap(26), withDERP(2), withSuggest(), withExitRoutes())
	selfNode := tailcfg.Node{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.1.1/32"),
			netip.MustParsePrefix("fe70::1/128"),
		},
		HomeDERP: 2,
	}
	defaultDERPMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "t1",
						RegionID: 1,
					},
				},
			},
			2: {
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "t2",
						RegionID: 2,
					},
				},
			},
			3: {
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "t3",
						RegionID: 3,
					},
				},
			},
		},
	}
	b.currentNode().SetNetMap(&netmap.NetworkMap{
		SelfNode: selfNode.View(),
		Peers: []tailcfg.NodeView{
			peer1,
			peer2,
		},
		DERPMap: defaultDERPMap,
	})
	b.lastSuggestedExitNode = peer1.StableID()
	b.SetPrefsForTest(b.pm.CurrentPrefs().AsStruct())
	if eid := b.Prefs().ExitNodeID(); eid != peer1.StableID() {
		t.Errorf("got initial exit node %v, want %v", eid, peer1.StableID())
	}
	b.refreshAutoExitNode = true
	b.sys.MagicSock.Get().SetLastNetcheckReportForTest(b.ctx, &netcheck.Report{
		RegionLatency: map[int]time.Duration{
			1: 10 * time.Millisecond,
			2: 5 * time.Millisecond,
			3: 30 * time.Millisecond,
		},
		PreferredDERP: 2,
	})
	b.setNetInfo(&ni)
	if eid := b.Prefs().ExitNodeID(); eid != peer2.StableID() {
		t.Errorf("got final exit node %v, want %v", eid, peer2.StableID())
	}
}

func TestSetControlClientStatusAutoExitNode(t *testing.T) {
	peer1 := makePeer(1, withCap(26), withSuggest(), withExitRoutes(), withOnline(true), withNodeKey())
	peer2 := makePeer(2, withCap(26), withSuggest(), withExitRoutes(), withOnline(true), withNodeKey())
	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "t1",
						RegionID: 1,
					},
				},
			},
			2: {
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "t2",
						RegionID: 2,
					},
				},
			},
		},
	}
	report := &netcheck.Report{
		RegionLatency: map[int]time.Duration{
			1: 10 * time.Millisecond,
			2: 5 * time.Millisecond,
			3: 30 * time.Millisecond,
		},
		PreferredDERP: 1,
	}
	nm := &netmap.NetworkMap{
		Peers: []tailcfg.NodeView{
			peer1,
			peer2,
		},
		DERPMap: derpMap,
	}

	polc := policytest.Config{
		pkey.ExitNodeID: "auto:any",
	}
	sys := tsd.NewSystem()
	sys.PolicyClient.Set(polc)

	b := newTestLocalBackendWithSys(t, sys)
	b.currentNode().SetNetMap(nm)
	// Peer 2 should be the initial exit node, as it's better than peer 1
	// in terms of latency and DERP region.
	b.lastSuggestedExitNode = peer2.StableID()
	b.sys.MagicSock.Get().SetLastNetcheckReportForTest(b.ctx, report)
	b.SetPrefsForTest(b.pm.CurrentPrefs().AsStruct())
	offlinePeer2 := makePeer(2, withCap(26), withSuggest(), withExitRoutes(), withOnline(false), withNodeKey())
	updatedNetmap := &netmap.NetworkMap{
		Peers: []tailcfg.NodeView{
			peer1,
			offlinePeer2,
		},
		DERPMap: derpMap,
	}
	b.SetControlClientStatus(b.cc, controlclient.Status{NetMap: updatedNetmap})
	// But now that peer 2 is offline, we should switch to peer 1.
	wantExitNode := peer1.StableID()
	gotExitNode := b.Prefs().ExitNodeID()
	if gotExitNode != wantExitNode {
		t.Errorf("did not switch exit nodes despite auto exit node going offline: got %q; want %q", gotExitNode, wantExitNode)
	}
}

func TestApplySysPolicy(t *testing.T) {
	tests := []struct {
		name           string
		prefs          ipn.Prefs
		wantPrefs      ipn.Prefs
		wantAnyChange  bool
		stringPolicies map[pkey.Key]string
	}{
		{
			name: "empty prefs without policies",
		},
		{
			name: "prefs set without policies",
			prefs: ipn.Prefs{
				ControlURL:             "1",
				ShieldsUp:              true,
				ForceDaemon:            true,
				ExitNodeAllowLANAccess: true,
				CorpDNS:                true,
				RouteAll:               true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:             "1",
				ShieldsUp:              true,
				ForceDaemon:            true,
				ExitNodeAllowLANAccess: true,
				CorpDNS:                true,
				RouteAll:               true,
			},
		},
		{
			name: "empty prefs with policies",
			wantPrefs: ipn.Prefs{
				ControlURL:             "1",
				ShieldsUp:              true,
				ForceDaemon:            true,
				ExitNodeAllowLANAccess: true,
				CorpDNS:                true,
				RouteAll:               true,
			},
			wantAnyChange: true,
			stringPolicies: map[pkey.Key]string{
				pkey.ControlURL:                "1",
				pkey.EnableIncomingConnections: "never",
				pkey.EnableServerMode:          "always",
				pkey.ExitNodeAllowLANAccess:    "always",
				pkey.EnableTailscaleDNS:        "always",
				pkey.EnableTailscaleSubnets:    "always",
			},
		},
		{
			name: "prefs set with matching policies",
			prefs: ipn.Prefs{
				ControlURL:  "1",
				ShieldsUp:   true,
				ForceDaemon: true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:  "1",
				ShieldsUp:   true,
				ForceDaemon: true,
			},
			stringPolicies: map[pkey.Key]string{
				pkey.ControlURL:                "1",
				pkey.EnableIncomingConnections: "never",
				pkey.EnableServerMode:          "always",
				pkey.ExitNodeAllowLANAccess:    "never",
				pkey.EnableTailscaleDNS:        "never",
				pkey.EnableTailscaleSubnets:    "never",
			},
		},
		{
			name: "prefs set with conflicting policies",
			prefs: ipn.Prefs{
				ControlURL:             "1",
				ShieldsUp:              true,
				ForceDaemon:            true,
				ExitNodeAllowLANAccess: false,
				CorpDNS:                true,
				RouteAll:               false,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:             "2",
				ShieldsUp:              false,
				ForceDaemon:            false,
				ExitNodeAllowLANAccess: true,
				CorpDNS:                false,
				RouteAll:               true,
			},
			wantAnyChange: true,
			stringPolicies: map[pkey.Key]string{
				pkey.ControlURL:                "2",
				pkey.EnableIncomingConnections: "always",
				pkey.EnableServerMode:          "never",
				pkey.ExitNodeAllowLANAccess:    "always",
				pkey.EnableTailscaleDNS:        "never",
				pkey.EnableTailscaleSubnets:    "always",
			},
		},
		{
			name: "prefs set with neutral policies",
			prefs: ipn.Prefs{
				ControlURL:             "1",
				ShieldsUp:              true,
				ForceDaemon:            true,
				ExitNodeAllowLANAccess: false,
				CorpDNS:                true,
				RouteAll:               true,
			},
			wantPrefs: ipn.Prefs{
				ControlURL:             "1",
				ShieldsUp:              true,
				ForceDaemon:            true,
				ExitNodeAllowLANAccess: false,
				CorpDNS:                true,
				RouteAll:               true,
			},
			stringPolicies: map[pkey.Key]string{
				pkey.EnableIncomingConnections: "user-decides",
				pkey.EnableServerMode:          "user-decides",
				pkey.ExitNodeAllowLANAccess:    "user-decides",
				pkey.EnableTailscaleDNS:        "user-decides",
				pkey.EnableTailscaleSubnets:    "user-decides",
			},
		},
		{
			name: "ControlURL",
			wantPrefs: ipn.Prefs{
				ControlURL: "set",
			},
			wantAnyChange: true,
			stringPolicies: map[pkey.Key]string{
				pkey.ControlURL: "set",
			},
		},
		{
			name: "enable AutoUpdate apply does not unset check",
			prefs: ipn.Prefs{
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
					Apply: opt.NewBool(false),
				},
			},
			wantPrefs: ipn.Prefs{
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
					Apply: opt.NewBool(true),
				},
			},
			wantAnyChange: true,
			stringPolicies: map[pkey.Key]string{
				pkey.ApplyUpdates: "always",
			},
		},
		{
			name: "disable AutoUpdate apply does not unset check",
			prefs: ipn.Prefs{
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
					Apply: opt.NewBool(true),
				},
			},
			wantPrefs: ipn.Prefs{
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
					Apply: opt.NewBool(false),
				},
			},
			wantAnyChange: true,
			stringPolicies: map[pkey.Key]string{
				pkey.ApplyUpdates: "never",
			},
		},
		{
			name: "enable AutoUpdate check does not unset apply",
			prefs: ipn.Prefs{
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: false,
					Apply: opt.NewBool(true),
				},
			},
			wantPrefs: ipn.Prefs{
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
					Apply: opt.NewBool(true),
				},
			},
			wantAnyChange: true,
			stringPolicies: map[pkey.Key]string{
				pkey.CheckUpdates: "always",
			},
		},
		{
			name: "disable AutoUpdate check does not unset apply",
			prefs: ipn.Prefs{
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: true,
					Apply: opt.NewBool(true),
				},
			},
			wantPrefs: ipn.Prefs{
				AutoUpdate: ipn.AutoUpdatePrefs{
					Check: false,
					Apply: opt.NewBool(true),
				},
			},
			wantAnyChange: true,
			stringPolicies: map[pkey.Key]string{
				pkey.CheckUpdates: "never",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var polc policytest.Config
			for k, v := range tt.stringPolicies {
				polc.Set(k, v)
			}

			t.Run("unit", func(t *testing.T) {
				prefs := tt.prefs.Clone()

				sys := tsd.NewSystem()
				sys.PolicyClient.Set(polc)

				lb := newTestLocalBackendWithSys(t, sys)
				gotAnyChange := lb.applySysPolicyLocked(prefs)

				if gotAnyChange && prefs.Equals(&tt.prefs) {
					t.Errorf("anyChange but prefs is unchanged: %v", prefs.Pretty())
				}
				if !gotAnyChange && !prefs.Equals(&tt.prefs) {
					t.Errorf("!anyChange but prefs changed from %v to %v", tt.prefs.Pretty(), prefs.Pretty())
				}
				if gotAnyChange != tt.wantAnyChange {
					t.Errorf("anyChange=%v, want %v", gotAnyChange, tt.wantAnyChange)
				}
				if !prefs.Equals(&tt.wantPrefs) {
					t.Errorf("prefs=%v, want %v", prefs.Pretty(), tt.wantPrefs.Pretty())
				}
			})

			t.Run("status update", func(t *testing.T) {
				// Profile manager fills in blank ControlURL but it's not set
				// in most test cases to avoid cluttering them, so adjust for
				// that.
				usePrefs := tt.prefs.Clone()
				if usePrefs.ControlURL == "" {
					usePrefs.ControlURL = ipn.DefaultControlURL
				}
				wantPrefs := tt.wantPrefs.Clone()
				if wantPrefs.ControlURL == "" {
					wantPrefs.ControlURL = ipn.DefaultControlURL
				}

				pm := must.Get(newProfileManager(new(mem.Store), t.Logf, health.NewTracker(eventbustest.NewBus(t))))
				pm.prefs = usePrefs.View()

				b := newTestBackend(t, polc)
				b.mu.Lock()
				b.pm = pm
				b.mu.Unlock()

				b.SetControlClientStatus(b.cc, controlclient.Status{})
				if !b.Prefs().Equals(wantPrefs.View()) {
					t.Errorf("prefs=%v, want %v", b.Prefs().Pretty(), wantPrefs.Pretty())
				}
			})
		})
	}
}

func TestPreferencePolicyInfo(t *testing.T) {
	tests := []struct {
		name         string
		initialValue bool
		wantValue    bool
		wantChange   bool
		policyValue  string
		policyError  error
	}{
		{
			name:         "force enable modify",
			initialValue: false,
			wantValue:    true,
			wantChange:   true,
			policyValue:  "always",
		},
		{
			name:         "force enable unchanged",
			initialValue: true,
			wantValue:    true,
			policyValue:  "always",
		},
		{
			name:         "force disable modify",
			initialValue: true,
			wantValue:    false,
			wantChange:   true,
			policyValue:  "never",
		},
		{
			name:         "force disable unchanged",
			initialValue: false,
			wantValue:    false,
			policyValue:  "never",
		},
		{
			name:         "unforced enabled",
			initialValue: true,
			wantValue:    true,
			policyValue:  "user-decides",
		},
		{
			name:         "unforced disabled",
			initialValue: false,
			wantValue:    false,
			policyValue:  "user-decides",
		},
		{
			name:         "blank enabled",
			initialValue: true,
			wantValue:    true,
			policyValue:  "",
		},
		{
			name:         "blank disabled",
			initialValue: false,
			wantValue:    false,
			policyValue:  "",
		},
		{
			name:         "unset enabled",
			initialValue: true,
			wantValue:    true,
			policyError:  syspolicy.ErrNoSuchKey,
		},
		{
			name:         "unset disabled",
			initialValue: false,
			wantValue:    false,
			policyError:  syspolicy.ErrNoSuchKey,
		},
		{
			name:         "error enabled",
			initialValue: true,
			wantValue:    true,
			policyError:  errors.New("test error"),
		},
		{
			name:         "error disabled",
			initialValue: false,
			wantValue:    false,
			policyError:  errors.New("test error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, pp := range preferencePolicies {
				t.Run(string(pp.key), func(t *testing.T) {
					t.Parallel()

					var polc policytest.Config
					if tt.policyError != nil {
						polc.Set(pp.key, tt.policyError)
					} else {
						polc.Set(pp.key, tt.policyValue)
					}

					prefs := defaultPrefs.AsStruct()
					pp.set(prefs, tt.initialValue)

					bus := eventbustest.NewBus(t)
					sys := tsd.NewSystemWithBus(bus)
					sys.PolicyClient.Set(polc)

					lb := newTestLocalBackendWithSys(t, sys)
					gotAnyChange := lb.applySysPolicyLocked(prefs)

					if gotAnyChange != tt.wantChange {
						t.Errorf("anyChange=%v, want %v", gotAnyChange, tt.wantChange)
					}
					got := pp.get(prefs.View())
					if got != tt.wantValue {
						t.Errorf("pref=%v, want %v", got, tt.wantValue)
					}
				})
			}
		})
	}
}

func TestOnTailnetDefaultAutoUpdate(t *testing.T) {
	tests := []struct {
		before, after  opt.Bool
		container      opt.Bool
		tailnetDefault bool
	}{
		{
			before:         opt.Bool(""),
			tailnetDefault: true,
			after:          opt.NewBool(true),
		},
		{
			before:         opt.Bool(""),
			tailnetDefault: false,
			after:          opt.NewBool(false),
		},
		{
			before:         opt.Bool("unset"),
			tailnetDefault: true,
			after:          opt.NewBool(true),
		},
		{
			before:         opt.Bool("unset"),
			tailnetDefault: false,
			after:          opt.NewBool(false),
		},
		{
			before:         opt.NewBool(false),
			tailnetDefault: true,
			after:          opt.NewBool(false),
		},
		{
			before:         opt.NewBool(true),
			tailnetDefault: false,
			after:          opt.NewBool(true),
		},
		{
			before:         opt.Bool(""),
			container:      opt.NewBool(true),
			tailnetDefault: true,
			after:          opt.Bool(""),
		},
		{
			before:         opt.NewBool(false),
			container:      opt.NewBool(true),
			tailnetDefault: true,
			after:          opt.NewBool(false),
		},
		{
			before:         opt.NewBool(true),
			container:      opt.NewBool(true),
			tailnetDefault: false,
			after:          opt.NewBool(true),
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("before=%s,after=%s", tt.before, tt.after), func(t *testing.T) {
			b := newTestBackend(t)
			b.hostinfo = hostinfo.New()
			b.hostinfo.Container = tt.container
			p := ipn.NewPrefs()
			p.AutoUpdate.Apply = tt.before
			if err := b.pm.setPrefsNoPermCheck(p.View()); err != nil {
				t.Fatal(err)
			}
			b.onTailnetDefaultAutoUpdate(tt.tailnetDefault)
			want := tt.after
			// On platforms that don't support auto-update we can never
			// transition to auto-updates being enabled. The value should
			// remain unchanged after onTailnetDefaultAutoUpdate.
			if !feature.CanAutoUpdate() {
				want = tt.before
			}
			if got := b.pm.CurrentPrefs().AutoUpdate().Apply; got != want {
				t.Errorf("got: %q, want %q", got, want)
			}
		})
	}
}

func TestTCPHandlerForDst(t *testing.T) {
	b := newTestBackend(t)
	tests := []struct {
		desc      string
		dst       string
		intercept bool
	}{
		{
			desc:      "intercept port 80 (Web UI) on quad100 IPv4",
			dst:       "100.100.100.100:80",
			intercept: true,
		},
		{
			desc:      "intercept port 80 (Web UI) on quad100 IPv6",
			dst:       "[fd7a:115c:a1e0::53]:80",
			intercept: true,
		},
		{
			desc:      "don't intercept port 80 on local ip",
			dst:       "100.100.103.100:80",
			intercept: false,
		},
		{
			desc:      "intercept port 8080 (Taildrive) on quad100 IPv4",
			dst:       "[fd7a:115c:a1e0::53]:8080",
			intercept: true,
		},
		{
			desc:      "don't intercept port 8080 on local ip",
			dst:       "100.100.103.100:8080",
			intercept: false,
		},
		{
			desc:      "don't intercept port 9080 on quad100 IPv4",
			dst:       "100.100.100.100:9080",
			intercept: false,
		},
		{
			desc:      "don't intercept port 9080 on quad100 IPv6",
			dst:       "[fd7a:115c:a1e0::53]:9080",
			intercept: false,
		},
		{
			desc:      "don't intercept port 9080 on local ip",
			dst:       "100.100.103.100:9080",
			intercept: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.dst, func(t *testing.T) {
			t.Log(tt.desc)
			src := netip.MustParseAddrPort("100.100.102.100:51234")
			h, _ := b.TCPHandlerForDst(src, netip.MustParseAddrPort(tt.dst))
			if !tt.intercept && h != nil {
				t.Error("intercepted traffic we shouldn't have")
			} else if tt.intercept && h == nil {
				t.Error("failed to intercept traffic we should have")
			}
		})
	}
}

func TestTCPHandlerForDstWithVIPService(t *testing.T) {
	b := newTestBackend(t)
	svcIPMap := tailcfg.ServiceIPMappings{
		"svc:foo": []netip.Addr{
			netip.MustParseAddr("100.101.101.101"),
			netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:cd96:6565:6565"),
		},
		"svc:bar": []netip.Addr{
			netip.MustParseAddr("100.99.99.99"),
			netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:cd96:626b:628b"),
		},
		"svc:baz": []netip.Addr{
			netip.MustParseAddr("100.133.133.133"),
			netip.MustParseAddr("fd7a:115c:a1e0:ab12:4843:cd96:8585:8585"),
		},
	}
	svcIPMapJSON, err := json.Marshal(svcIPMap)
	if err != nil {
		t.Fatal(err)
	}
	b.setNetMapLocked(
		&netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				Name: "example.ts.net",
				CapMap: tailcfg.NodeCapMap{
					tailcfg.NodeAttrServiceHost: []tailcfg.RawMessage{tailcfg.RawMessage(svcIPMapJSON)},
				},
			}).View(),
			UserProfiles: map[tailcfg.UserID]tailcfg.UserProfileView{
				tailcfg.UserID(1): (&tailcfg.UserProfile{
					LoginName:     "someone@example.com",
					DisplayName:   "Some One",
					ProfilePicURL: "https://example.com/photo.jpg",
				}).View(),
			},
		},
	)

	err = b.setServeConfigLocked(
		&ipn.ServeConfig{
			Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
				"svc:foo": {
					TCP: map[uint16]*ipn.TCPPortHandler{
						882: {HTTP: true},
						883: {HTTPS: true},
					},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"foo.example.ts.net:882": {
							Handlers: map[string]*ipn.HTTPHandler{
								"/": {Proxy: "http://127.0.0.1:3000"},
							},
						},
						"foo.example.ts.net:883": {
							Handlers: map[string]*ipn.HTTPHandler{
								"/": {Text: "test"},
							},
						},
					},
				},
				"svc:bar": {
					TCP: map[uint16]*ipn.TCPPortHandler{
						990: {TCPForward: "127.0.0.1:8443"},
						991: {TCPForward: "127.0.0.1:5432", TerminateTLS: "bar.test.ts.net"},
					},
				},
				"svc:qux": {
					TCP: map[uint16]*ipn.TCPPortHandler{
						600: {HTTPS: true},
					},
					Web: map[ipn.HostPort]*ipn.WebServerConfig{
						"qux.example.ts.net:600": {
							Handlers: map[string]*ipn.HTTPHandler{
								"/": {Text: "qux"},
							},
						},
					},
				},
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		desc      string
		dst       string
		intercept bool
	}{
		{
			desc:      "intercept port 80 (Web UI) on quad100 IPv4",
			dst:       "100.100.100.100:80",
			intercept: true,
		},
		{
			desc:      "intercept port 80 (Web UI) on quad100 IPv6",
			dst:       "[fd7a:115c:a1e0::53]:80",
			intercept: true,
		},
		{
			desc:      "don't intercept port 80 on local ip",
			dst:       "100.100.103.100:80",
			intercept: false,
		},
		{
			desc:      "intercept port 8080 (Taildrive) on quad100 IPv4",
			dst:       "100.100.100.100:8080",
			intercept: true,
		},
		{
			desc:      "intercept port 8080 (Taildrive) on quad100 IPv6",
			dst:       "[fd7a:115c:a1e0::53]:8080",
			intercept: true,
		},
		{
			desc:      "don't intercept port 8080 on local ip",
			dst:       "100.100.103.100:8080",
			intercept: false,
		},
		{
			desc:      "don't intercept port 9080 on quad100 IPv4",
			dst:       "100.100.100.100:9080",
			intercept: false,
		},
		{
			desc:      "don't intercept port 9080 on quad100 IPv6",
			dst:       "[fd7a:115c:a1e0::53]:9080",
			intercept: false,
		},
		{
			desc:      "don't intercept port 9080 on local ip",
			dst:       "100.100.103.100:9080",
			intercept: false,
		},
		// VIP service destinations
		{
			desc:      "intercept port 882 (HTTP) on service foo IPv4",
			dst:       "100.101.101.101:882",
			intercept: true,
		},
		{
			desc:      "intercept port 882 (HTTP) on service foo IPv6",
			dst:       "[fd7a:115c:a1e0:ab12:4843:cd96:6565:6565]:882",
			intercept: true,
		},
		{
			desc:      "intercept port 883 (HTTPS) on service foo IPv4",
			dst:       "100.101.101.101:883",
			intercept: true,
		},
		{
			desc:      "intercept port 883 (HTTPS) on service foo IPv6",
			dst:       "[fd7a:115c:a1e0:ab12:4843:cd96:6565:6565]:883",
			intercept: true,
		},
		{
			desc:      "intercept port 990 (TCPForward) on service bar IPv4",
			dst:       "100.99.99.99:990",
			intercept: true,
		},
		{
			desc:      "intercept port 990 (TCPForward) on service bar IPv6",
			dst:       "[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:990",
			intercept: true,
		},
		{
			desc:      "intercept port 991 (TCPForward with TerminateTLS) on service bar IPv4",
			dst:       "100.99.99.99:990",
			intercept: true,
		},
		{
			desc:      "intercept port 991 (TCPForward with TerminateTLS) on service bar IPv6",
			dst:       "[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:990",
			intercept: true,
		},
		{
			desc:      "don't intercept port 4444 on service foo IPv4",
			dst:       "100.101.101.101:4444",
			intercept: false,
		},
		{
			desc:      "don't intercept port 4444 on service foo IPv6",
			dst:       "[fd7a:115c:a1e0:ab12:4843:cd96:6565:6565]:4444",
			intercept: false,
		},
		{
			desc:      "don't intercept port 600 on unknown service IPv4",
			dst:       "100.22.22.22:883",
			intercept: false,
		},
		{
			desc:      "don't intercept port 600 on unknown service IPv6",
			dst:       "[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:883",
			intercept: false,
		},
		{
			desc:      "don't intercept port 600 (HTTPS) on service baz IPv4",
			dst:       "100.133.133.133:600",
			intercept: false,
		},
		{
			desc:      "don't intercept port 600 (HTTPS) on service baz IPv6",
			dst:       "[fd7a:115c:a1e0:ab12:4843:cd96:8585:8585]:600",
			intercept: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.dst, func(t *testing.T) {
			t.Log(tt.desc)
			src := netip.MustParseAddrPort("100.100.102.100:51234")
			h, _ := b.TCPHandlerForDst(src, netip.MustParseAddrPort(tt.dst))
			if !tt.intercept && h != nil {
				t.Error("intercepted traffic we shouldn't have")
			} else if tt.intercept && h == nil {
				t.Error("failed to intercept traffic we should have")
			}
		})
	}
}

func TestDriveManageShares(t *testing.T) {
	tests := []struct {
		name     string
		disabled bool
		existing []*drive.Share
		add      *drive.Share
		remove   string
		rename   [2]string
		expect   any
	}{
		{
			name: "append",
			existing: []*drive.Share{
				{Name: "b"},
				{Name: "d"},
			},
			add: &drive.Share{Name: "  E  "},
			expect: []*drive.Share{
				{Name: "b"},
				{Name: "d"},
				{Name: "e"},
			},
		},
		{
			name: "prepend",
			existing: []*drive.Share{
				{Name: "b"},
				{Name: "d"},
			},
			add: &drive.Share{Name: "  A  "},
			expect: []*drive.Share{
				{Name: "a"},
				{Name: "b"},
				{Name: "d"},
			},
		},
		{
			name: "insert",
			existing: []*drive.Share{
				{Name: "b"},
				{Name: "d"},
			},
			add: &drive.Share{Name: "  C  "},
			expect: []*drive.Share{
				{Name: "b"},
				{Name: "c"},
				{Name: "d"},
			},
		},
		{
			name: "replace",
			existing: []*drive.Share{
				{Name: "b", Path: "i"},
				{Name: "d"},
			},
			add: &drive.Share{Name: "  B  ", Path: "ii"},
			expect: []*drive.Share{
				{Name: "b", Path: "ii"},
				{Name: "d"},
			},
		},
		{
			name:   "add_bad_name",
			add:    &drive.Share{Name: "$"},
			expect: drive.ErrInvalidShareName,
		},
		{
			name:     "add_disabled",
			disabled: true,
			add:      &drive.Share{Name: "a"},
			expect:   drive.ErrDriveNotEnabled,
		},
		{
			name: "remove",
			existing: []*drive.Share{
				{Name: "a"},
				{Name: "b"},
				{Name: "c"},
			},
			remove: "b",
			expect: []*drive.Share{
				{Name: "a"},
				{Name: "c"},
			},
		},
		{
			name: "remove_non_existing",
			existing: []*drive.Share{
				{Name: "a"},
				{Name: "b"},
				{Name: "c"},
			},
			remove: "D",
			expect: os.ErrNotExist,
		},
		{
			name:     "remove_disabled",
			disabled: true,
			remove:   "b",
			expect:   drive.ErrDriveNotEnabled,
		},
		{
			name: "rename",
			existing: []*drive.Share{
				{Name: "a"},
				{Name: "b"},
			},
			rename: [2]string{"a", "  C  "},
			expect: []*drive.Share{
				{Name: "b"},
				{Name: "c"},
			},
		},
		{
			name: "rename_not_exist",
			existing: []*drive.Share{
				{Name: "a"},
				{Name: "b"},
			},
			rename: [2]string{"d", "c"},
			expect: os.ErrNotExist,
		},
		{
			name: "rename_exists",
			existing: []*drive.Share{
				{Name: "a"},
				{Name: "b"},
			},
			rename: [2]string{"a", "b"},
			expect: os.ErrExist,
		},
		{
			name:   "rename_bad_name",
			rename: [2]string{"a", "$"},
			expect: drive.ErrInvalidShareName,
		},
		{
			name:     "rename_disabled",
			disabled: true,
			rename:   [2]string{"a", "c"},
			expect:   drive.ErrDriveNotEnabled,
		},
	}

	drive.DisallowShareAs = true
	t.Cleanup(func() {
		drive.DisallowShareAs = false
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newTestBackend(t)
			b.mu.Lock()
			if tt.existing != nil {
				b.driveSetSharesLocked(tt.existing)
			}
			if !tt.disabled {
				nm := ptr.To(*b.currentNode().NetMap())
				self := nm.SelfNode.AsStruct()
				self.CapMap = tailcfg.NodeCapMap{tailcfg.NodeAttrsTaildriveShare: nil}
				nm.SelfNode = self.View()
				b.currentNode().SetNetMap(nm)
				b.sys.Set(driveimpl.NewFileSystemForRemote(b.logf))
			}
			b.mu.Unlock()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			t.Cleanup(cancel)

			result := make(chan views.SliceView[*drive.Share, drive.ShareView], 1)

			var wg sync.WaitGroup
			wg.Add(1)
			go b.WatchNotifications(
				ctx,
				0,
				func() { wg.Done() },
				func(n *ipn.Notify) bool {
					select {
					case result <- n.DriveShares:
					default:
						//
					}
					return false
				},
			)
			wg.Wait()

			var err error
			switch {
			case tt.add != nil:
				err = b.DriveSetShare(tt.add)
			case tt.remove != "":
				err = b.DriveRemoveShare(tt.remove)
			default:
				err = b.DriveRenameShare(tt.rename[0], tt.rename[1])
			}

			switch e := tt.expect.(type) {
			case error:
				if !errors.Is(err, e) {
					t.Errorf("expected error, want: %v got: %v", e, err)
				}
			case []*drive.Share:
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else {
					r := <-result

					got, err := json.MarshalIndent(r, "", "  ")
					if err != nil {
						t.Fatalf("can't marshal got: %v", err)
					}
					want, err := json.MarshalIndent(e, "", "  ")
					if err != nil {
						t.Fatalf("can't marshal want: %v", err)
					}
					if diff := cmp.Diff(string(got), string(want)); diff != "" {
						t.Errorf("wrong shares; (-got+want):%v", diff)
					}
				}
			}
		})
	}
}

func TestValidPopBrowserURL(t *testing.T) {
	b := newTestBackend(t)
	tests := []struct {
		desc          string
		controlURL    string
		popBrowserURL string
		want          bool
	}{
		{"saas_login", "https://login.tailscale.com", "https://login.tailscale.com/a/foo", true},
		{"saas_controlplane", "https://controlplane.tailscale.com", "https://controlplane.tailscale.com/a/foo", true},
		{"saas_root", "https://login.tailscale.com", "https://tailscale.com/", true},
		{"saas_bad_hostname", "https://login.tailscale.com", "https://example.com/a/foo", false},
		{"localhost", "http://localhost", "http://localhost/a/foo", true},
		{"custom_control_url_https", "https://example.com", "https://example.com/a/foo", true},
		{"custom_control_url_https_diff_domain", "https://example.com", "https://other.com/a/foo", true},
		{"custom_control_url_http", "http://example.com", "http://example.com/a/foo", true},
		{"custom_control_url_http_diff_domain", "http://example.com", "http://other.com/a/foo", true},
		{"bad_scheme", "https://example.com", "http://example.com/a/foo", false},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if _, err := b.EditPrefs(&ipn.MaskedPrefs{
				ControlURLSet: true,
				Prefs: ipn.Prefs{
					ControlURL: tt.controlURL,
				},
			}); err != nil {
				t.Fatal(err)
			}

			got := b.validPopBrowserURL(tt.popBrowserURL)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRoundTraffic(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  float64
	}{
		{name: "under 5 bytes", bytes: 4, want: 4},
		{name: "under 1000 bytes", bytes: 987, want: 990},
		{name: "under 10_000 bytes", bytes: 8875, want: 8900},
		{name: "under 100_000 bytes", bytes: 77777, want: 78000},
		{name: "under 1_000_000 bytes", bytes: 666523, want: 670000},
		{name: "under 10_000_000 bytes", bytes: 22556677, want: 23000000},
		{name: "under 1_000_000_000 bytes", bytes: 1234234234, want: 1200000000},
		{name: "under 1_000_000_000 bytes", bytes: 123423423499, want: 123400000000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := roundTraffic(tt.bytes); result != tt.want {
				t.Errorf("unexpected rounding got %v want %v", result, tt.want)
			}
		})
	}
}

func (b *LocalBackend) SetPrefsForTest(newp *ipn.Prefs) {
	if newp == nil {
		panic("SetPrefsForTest got nil prefs")
	}
	unlock := b.lockAndGetUnlock()
	defer unlock()
	b.setPrefsLockedOnEntry(newp, unlock)
}

type peerOptFunc func(*tailcfg.Node)

func makePeer(id tailcfg.NodeID, opts ...peerOptFunc) tailcfg.NodeView {
	node := &tailcfg.Node{
		ID:                id,
		Key:               makeNodeKeyFromID(id),
		DiscoKey:          makeDiscoKeyFromID(id),
		StableID:          tailcfg.StableNodeID(fmt.Sprintf("stable%d", id)),
		Name:              fmt.Sprintf("peer%d", id),
		Online:            ptr.To(true),
		MachineAuthorized: true,
		HomeDERP:          int(id),
	}
	for _, opt := range opts {
		opt(node)
	}
	return node.View()
}

func withName(name string) peerOptFunc {
	return func(n *tailcfg.Node) {
		n.Name = name
	}
}

func withDERP(region int) peerOptFunc {
	return func(n *tailcfg.Node) {
		n.HomeDERP = region
	}
}

func withoutDERP() peerOptFunc {
	return func(n *tailcfg.Node) {
		n.HomeDERP = 0
	}
}

func withLocation(loc tailcfg.LocationView) peerOptFunc {
	return func(n *tailcfg.Node) {
		var hi *tailcfg.Hostinfo
		if n.Hostinfo.Valid() {
			hi = n.Hostinfo.AsStruct()
		} else {
			hi = new(tailcfg.Hostinfo)
		}
		hi.Location = loc.AsStruct()

		n.Hostinfo = hi.View()
	}
}

func withLocationPriority(pri int) peerOptFunc {
	return func(n *tailcfg.Node) {
		var hi *tailcfg.Hostinfo
		if n.Hostinfo.Valid() {
			hi = n.Hostinfo.AsStruct()
		} else {
			hi = new(tailcfg.Hostinfo)
		}
		if hi.Location == nil {
			hi.Location = new(tailcfg.Location)
		}
		hi.Location.Priority = pri

		n.Hostinfo = hi.View()
	}
}

func withExitRoutes() peerOptFunc {
	return func(n *tailcfg.Node) {
		n.AllowedIPs = append(n.AllowedIPs, tsaddr.ExitRoutes()...)
	}
}

func withSuggest() peerOptFunc {
	return func(n *tailcfg.Node) {
		mak.Set(&n.CapMap, tailcfg.NodeAttrSuggestExitNode, []tailcfg.RawMessage{})
	}
}

func withCap(version tailcfg.CapabilityVersion) peerOptFunc {
	return func(n *tailcfg.Node) {
		n.Cap = version
	}
}

func withOnline(isOnline bool) peerOptFunc {
	return func(n *tailcfg.Node) {
		n.Online = &isOnline
	}
}

func withNodeKey() peerOptFunc {
	return func(n *tailcfg.Node) {
		n.Key = key.NewNode().Public()
	}
}

func withAddresses(addresses ...netip.Prefix) peerOptFunc {
	return func(n *tailcfg.Node) {
		n.Addresses = append(n.Addresses, addresses...)
	}
}

func deterministicRegionForTest(t testing.TB, want views.Slice[int], use int) selectRegionFunc {
	t.Helper()

	if !views.SliceContains(want, use) {
		t.Errorf("invalid test: use %v is not in want %v", use, want)
	}

	return func(got views.Slice[int]) int {
		if !views.SliceEqualAnyOrder(got, want) {
			t.Errorf("candidate regions = %v, want %v", got, want)
		}
		return use
	}
}

func deterministicNodeForTest(t testing.TB, want views.Slice[tailcfg.StableNodeID], wantLast tailcfg.StableNodeID, use tailcfg.StableNodeID) selectNodeFunc {
	t.Helper()

	if !views.SliceContains(want, use) {
		t.Errorf("invalid test: use %v is not in want %v", use, want)
	}

	return func(got views.Slice[tailcfg.NodeView], last tailcfg.StableNodeID) tailcfg.NodeView {
		var ret tailcfg.NodeView

		gotIDs := make([]tailcfg.StableNodeID, got.Len())
		for i, nv := range got.All() {
			if !nv.Valid() {
				t.Fatalf("invalid node at index %v", i)
			}
			gotIDs[i] = nv.StableID()
			if nv.StableID() == use {
				ret = nv
			}
		}
		if !views.SliceEqualAnyOrder(views.SliceOf(gotIDs), want) {
			t.Errorf("candidate nodes = %v, want %v", gotIDs, want)
		}
		if last != wantLast {
			t.Errorf("last node = %v, want %v", last, wantLast)
		}
		if !ret.Valid() {
			t.Fatalf("did not find matching node in %v, want %v", gotIDs, use)
		}

		return ret
	}
}

func TestSuggestExitNode(t *testing.T) {
	t.Parallel()

	defaultDERPMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				Latitude:  32,
				Longitude: -97,
			},
			2: {},
			3: {},
		},
	}

	preferred1Report := &netcheck.Report{
		RegionLatency: map[int]time.Duration{
			1: 10 * time.Millisecond,
			2: 20 * time.Millisecond,
			3: 30 * time.Millisecond,
		},
		PreferredDERP: 1,
	}
	noLatency1Report := &netcheck.Report{
		RegionLatency: map[int]time.Duration{
			1: 0,
			2: 0,
			3: 0,
		},
		PreferredDERP: 1,
	}
	preferredNoneReport := &netcheck.Report{
		RegionLatency: map[int]time.Duration{
			1: 10 * time.Millisecond,
			2: 20 * time.Millisecond,
			3: 30 * time.Millisecond,
		},
		PreferredDERP: 0,
	}

	dallas := tailcfg.Location{
		Latitude:  32.779167,
		Longitude: -96.808889,
		Priority:  100,
	}
	sanJose := tailcfg.Location{
		Latitude:  37.3382082,
		Longitude: -121.8863286,
		Priority:  20,
	}
	fortWorth := tailcfg.Location{
		Latitude:  32.756389,
		Longitude: -97.3325,
		Priority:  150,
	}
	fortWorthLowPriority := tailcfg.Location{
		Latitude:  32.756389,
		Longitude: -97.3325,
		Priority:  100,
	}

	peer1 := makePeer(1,
		withExitRoutes(),
		withSuggest())
	peer2DERP1 := makePeer(2,
		withDERP(1),
		withExitRoutes(),
		withSuggest())
	peer3 := makePeer(3,
		withExitRoutes(),
		withSuggest())
	peer4DERP3 := makePeer(4,
		withDERP(3),
		withExitRoutes(),
		withSuggest())
	dallasPeer5 := makePeer(5,
		withName("Dallas"),
		withoutDERP(),
		withExitRoutes(),
		withSuggest(),
		withLocation(dallas.View()))
	sanJosePeer6 := makePeer(6,
		withName("San Jose"),
		withoutDERP(),
		withExitRoutes(),
		withSuggest(),
		withLocation(sanJose.View()))
	fortWorthPeer7 := makePeer(7,
		withName("Fort Worth"),
		withoutDERP(),
		withExitRoutes(),
		withSuggest(),
		withLocation(fortWorth.View()))
	fortWorthPeer8LowPriority := makePeer(8,
		withName("Fort Worth Low"),
		withoutDERP(),
		withExitRoutes(),
		withSuggest(),
		withLocation(fortWorthLowPriority.View()))

	selfNode := tailcfg.Node{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.1.1/32"),
			netip.MustParsePrefix("fe70::1/128"),
		},
	}

	defaultNetmap := &netmap.NetworkMap{
		SelfNode: selfNode.View(),
		DERPMap:  defaultDERPMap,
		Peers: []tailcfg.NodeView{
			peer2DERP1,
			peer3,
		},
	}
	locationNetmap := &netmap.NetworkMap{
		SelfNode: selfNode.View(),
		DERPMap:  defaultDERPMap,
		Peers: []tailcfg.NodeView{
			dallasPeer5,
			sanJosePeer6,
		},
	}
	largeNetmap := &netmap.NetworkMap{
		SelfNode: selfNode.View(),
		DERPMap:  defaultDERPMap,
		Peers: []tailcfg.NodeView{
			peer1,
			peer2DERP1,
			peer3,
			peer4DERP3,
			dallasPeer5,
			sanJosePeer6,
			fortWorthPeer7,
		},
	}

	tests := []struct {
		name string

		lastReport     *netcheck.Report
		netMap         *netmap.NetworkMap
		lastSuggestion tailcfg.StableNodeID

		allowPolicy []tailcfg.StableNodeID

		wantRegions []int
		useRegion   int

		wantNodes []tailcfg.StableNodeID

		wantID       tailcfg.StableNodeID
		wantName     string
		wantLocation tailcfg.LocationView

		wantError error
	}{
		{
			name:       "2 exit nodes in same region",
			lastReport: preferred1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					peer1,
					peer2DERP1,
				},
			},
			wantNodes: []tailcfg.StableNodeID{
				"stable1",
				"stable2",
			},
			wantName: "peer1",
			wantID:   "stable1",
		},
		{
			name:        "2 exit nodes different regions unknown latency",
			lastReport:  noLatency1Report,
			netMap:      defaultNetmap,
			wantRegions: []int{1, 3}, // the only regions with peers
			useRegion:   1,
			wantName:    "peer2",
			wantID:      "stable2",
		},
		{
			name: "2 derp based exit nodes, different regions, equal latency",
			lastReport: &netcheck.Report{
				RegionLatency: map[int]time.Duration{
					1: 10,
					2: 20,
					3: 10,
				},
				PreferredDERP: 1,
			},
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					peer1,
					peer3,
				},
			},
			wantRegions: []int{1, 2},
			useRegion:   1,
			wantName:    "peer1",
			wantID:      "stable1",
		},
		{
			name:         "mullvad nodes, no derp based exit nodes",
			lastReport:   noLatency1Report,
			netMap:       locationNetmap,
			wantID:       "stable5",
			wantLocation: dallas.View(),
			wantName:     "Dallas",
		},
		{
			name:       "nearby mullvad nodes with different priorities",
			lastReport: noLatency1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					dallasPeer5,
					sanJosePeer6,
					fortWorthPeer7,
				},
			},
			wantID:       "stable7",
			wantLocation: fortWorth.View(),
			wantName:     "Fort Worth",
		},
		{
			name:       "nearby mullvad nodes with same priorities",
			lastReport: noLatency1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					dallasPeer5,
					sanJosePeer6,
					fortWorthPeer8LowPriority,
				},
			},
			wantNodes:    []tailcfg.StableNodeID{"stable5", "stable8"},
			wantID:       "stable5",
			wantLocation: dallas.View(),
			wantName:     "Dallas",
		},
		{
			name:       "mullvad nodes, remaining node is not in preferred derp",
			lastReport: noLatency1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					dallasPeer5,
					sanJosePeer6,
					peer4DERP3,
				},
			},
			useRegion: 3,
			wantID:    "stable4",
			wantName:  "peer4",
		},
		{
			name:       "no peers",
			lastReport: noLatency1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
			},
		},
		{
			name:       "nil report",
			lastReport: nil,
			netMap:     largeNetmap,
			wantError:  ErrNoPreferredDERP,
		},
		{
			name:       "no preferred derp region",
			lastReport: preferredNoneReport,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
			},
			wantError: ErrNoPreferredDERP,
		},
		{
			name:       "nil netmap",
			lastReport: noLatency1Report,
			netMap:     nil,
			wantError:  ErrNoPreferredDERP,
		},
		{
			name:       "nil derpmap",
			lastReport: noLatency1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  nil,
				Peers: []tailcfg.NodeView{
					dallasPeer5,
				},
			},
			wantError: ErrNoPreferredDERP,
		},
		{
			name:       "missing suggestion capability",
			lastReport: noLatency1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					makePeer(1, withExitRoutes()),
					makePeer(2, withLocation(dallas.View()), withExitRoutes()),
				},
			},
		},
		{
			name:       "prefer last node",
			lastReport: preferred1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					peer1,
					peer2DERP1,
				},
			},
			lastSuggestion: "stable2",
			wantNodes: []tailcfg.StableNodeID{
				"stable1",
				"stable2",
			},
			wantName: "peer2",
			wantID:   "stable2",
		},
		{
			name:           "found better derp node",
			lastSuggestion: "stable3",
			lastReport:     preferred1Report,
			netMap:         defaultNetmap,
			wantID:         "stable2",
			wantName:       "peer2",
		},
		{
			name:           "prefer last mullvad node",
			lastSuggestion: "stable2",
			lastReport:     preferred1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					dallasPeer5,
					sanJosePeer6,
					fortWorthPeer8LowPriority,
				},
			},
			wantNodes:    []tailcfg.StableNodeID{"stable5", "stable8"},
			wantID:       "stable5",
			wantName:     "Dallas",
			wantLocation: dallas.View(),
		},
		{
			name:           "prefer better mullvad node",
			lastSuggestion: "stable2",
			lastReport:     preferred1Report,
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				DERPMap:  defaultDERPMap,
				Peers: []tailcfg.NodeView{
					dallasPeer5,
					sanJosePeer6,
					fortWorthPeer7,
				},
			},
			wantNodes:    []tailcfg.StableNodeID{"stable7"},
			wantID:       "stable7",
			wantName:     "Fort Worth",
			wantLocation: fortWorth.View(),
		},
		{
			name:       "large netmap",
			lastReport: preferred1Report,
			netMap:     largeNetmap,
			wantNodes:  []tailcfg.StableNodeID{"stable1", "stable2"},
			wantID:     "stable2",
			wantName:   "peer2",
		},
		{
			name:        "no allowed suggestions",
			lastReport:  preferred1Report,
			netMap:      largeNetmap,
			allowPolicy: []tailcfg.StableNodeID{},
		},
		{
			name:        "only derp suggestions",
			lastReport:  preferred1Report,
			netMap:      largeNetmap,
			allowPolicy: []tailcfg.StableNodeID{"stable1", "stable2", "stable3"},
			wantNodes:   []tailcfg.StableNodeID{"stable1", "stable2"},
			wantID:      "stable2",
			wantName:    "peer2",
		},
		{
			name:         "only mullvad suggestions",
			lastReport:   preferred1Report,
			netMap:       largeNetmap,
			allowPolicy:  []tailcfg.StableNodeID{"stable5", "stable6", "stable7"},
			wantID:       "stable7",
			wantName:     "Fort Worth",
			wantLocation: fortWorth.View(),
		},
		{
			name:        "only worst derp",
			lastReport:  preferred1Report,
			netMap:      largeNetmap,
			allowPolicy: []tailcfg.StableNodeID{"stable3"},
			wantID:      "stable3",
			wantName:    "peer3",
		},
		{
			name:         "only worst mullvad",
			lastReport:   preferred1Report,
			netMap:       largeNetmap,
			allowPolicy:  []tailcfg.StableNodeID{"stable6"},
			wantID:       "stable6",
			wantName:     "San Jose",
			wantLocation: sanJose.View(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantRegions := tt.wantRegions
			if wantRegions == nil {
				wantRegions = []int{tt.useRegion}
			}
			selectRegion := deterministicRegionForTest(t, views.SliceOf(wantRegions), tt.useRegion)

			wantNodes := tt.wantNodes
			if wantNodes == nil {
				wantNodes = []tailcfg.StableNodeID{tt.wantID}
			}
			selectNode := deterministicNodeForTest(t, views.SliceOf(wantNodes), tt.lastSuggestion, tt.wantID)

			var allowList set.Set[tailcfg.StableNodeID]
			if tt.allowPolicy != nil {
				allowList = set.SetOf(tt.allowPolicy)
			}

			nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())
			defer nb.shutdown(errShutdown)
			nb.SetNetMap(tt.netMap)

			got, err := suggestExitNode(tt.lastReport, nb, tt.lastSuggestion, selectRegion, selectNode, allowList)
			if got.Name != tt.wantName {
				t.Errorf("name=%v, want %v", got.Name, tt.wantName)
			}
			if got.ID != tt.wantID {
				t.Errorf("ID=%v, want %v", got.ID, tt.wantID)
			}
			if tt.wantError == nil && err != nil {
				t.Errorf("err=%v, want no error", err)
			}
			if tt.wantError != nil && !errors.Is(err, tt.wantError) {
				t.Errorf("err=%v, want %v", err, tt.wantError)
			}
			if !reflect.DeepEqual(got.Location, tt.wantLocation) {
				t.Errorf("location=%v, want %v", got.Location, tt.wantLocation)
			}
		})
	}
}

func TestSuggestExitNodePickWeighted(t *testing.T) {
	location10 := tailcfg.Location{
		Priority: 10,
	}
	location20 := tailcfg.Location{
		Priority: 20,
	}

	tests := []struct {
		name       string
		candidates []tailcfg.NodeView
		wantIDs    []tailcfg.StableNodeID
	}{
		{
			name: "different priorities",
			candidates: []tailcfg.NodeView{
				makePeer(2, withExitRoutes(), withLocation(location20.View())),
				makePeer(3, withExitRoutes(), withLocation(location10.View())),
			},
			wantIDs: []tailcfg.StableNodeID{"stable2"},
		},
		{
			name: "same priorities",
			candidates: []tailcfg.NodeView{
				makePeer(2, withExitRoutes(), withLocation(location10.View())),
				makePeer(3, withExitRoutes(), withLocation(location10.View())),
			},
			wantIDs: []tailcfg.StableNodeID{"stable2", "stable3"},
		},
		{
			name:       "<1 candidates",
			candidates: []tailcfg.NodeView{},
		},
		{
			name: "1 candidate",
			candidates: []tailcfg.NodeView{
				makePeer(2, withExitRoutes(), withLocation(location20.View())),
			},
			wantIDs: []tailcfg.StableNodeID{"stable2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickWeighted(tt.candidates)
			gotIDs := make([]tailcfg.StableNodeID, 0, len(got))
			for _, n := range got {
				if !n.Valid() {
					gotIDs = append(gotIDs, "<invalid>")
					continue
				}
				gotIDs = append(gotIDs, n.StableID())
			}
			if !views.SliceEqualAnyOrder(views.SliceOf(gotIDs), views.SliceOf(tt.wantIDs)) {
				t.Errorf("node IDs = %v, want %v", gotIDs, tt.wantIDs)
			}
		})
	}
}

func TestSuggestExitNodeLongLatDistance(t *testing.T) {
	tests := []struct {
		name     string
		fromLat  float64
		fromLong float64
		toLat    float64
		toLong   float64
		want     float64
	}{
		{
			name:     "zero values",
			fromLat:  0,
			fromLong: 0,
			toLat:    0,
			toLong:   0,
			want:     0,
		},
		{
			name:     "valid values",
			fromLat:  40.73061,
			fromLong: -73.935242,
			toLat:    37.3382082,
			toLong:   -121.8863286,
			want:     4117266.873301274,
		},
		{
			name:     "valid values, locations in north and south of equator",
			fromLat:  40.73061,
			fromLong: -73.935242,
			toLat:    -33.861481,
			toLong:   151.205475,
			want:     15994089.144368416,
		},
	}
	// The wanted values are computed using a more precise algorithm using the WGS84 model but
	// longLatDistance uses a spherical approximation for simplicity. To account for this, we allow for
	// 10km of error.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := longLatDistance(tt.fromLat, tt.fromLong, tt.toLat, tt.toLong)
			const maxError = 10000 // 10km
			if math.Abs(got-tt.want) > maxError {
				t.Errorf("distance=%vm, want within %vm of %vm", got, maxError, tt.want)
			}
		})
	}
}

func TestSuggestExitNodeTrafficSteering(t *testing.T) {
	city := &tailcfg.Location{
		Country:     "Canada",
		CountryCode: "CA",
		City:        "Montreal",
		CityCode:    "MTR",
		Latitude:    45.5053,
		Longitude:   -73.5525,
	}
	noLatLng := &tailcfg.Location{
		Country:     "Canada",
		CountryCode: "CA",
		City:        "Montreal",
		CityCode:    "MTR",
	}

	selfNode := tailcfg.Node{
		ID: 0, // randomness is seeded off NetMap.SelfNode.ID
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.1.1/32"),
			netip.MustParsePrefix("fe70::1/128"),
		},
		CapMap: tailcfg.NodeCapMap{
			tailcfg.NodeAttrTrafficSteering: []tailcfg.RawMessage{},
		},
	}

	for _, tt := range []struct {
		name string

		netMap      *netmap.NetworkMap
		lastExit    tailcfg.StableNodeID
		allowPolicy []tailcfg.StableNodeID

		wantID   tailcfg.StableNodeID
		wantName string
		wantLoc  *tailcfg.Location
		wantPri  int

		wantErr error
	}{
		{
			name:    "no-netmap",
			netMap:  nil,
			wantErr: ErrNoNetMap,
		},
		{
			name: "no-nodes",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers:    []tailcfg.NodeView{},
			},
			wantID: "",
		},
		{
			name: "no-exit-nodes",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1),
				},
			},
			wantID: "",
		},
		{
			name: "exit-node-without-suggestion",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes()),
				},
			},
			wantID: "",
		},
		{
			name: "suggested-exit-node-without-routes",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withSuggest()),
				},
			},
			wantID: "",
		},
		{
			name: "suggested-exit-node",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest()),
				},
			},
			wantID:   "stable1",
			wantName: "peer1",
		},
		{
			name: "suggest-exit-node-stable-pick",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest()),
					makePeer(2,
						withExitRoutes(),
						withSuggest()),
					makePeer(3,
						withExitRoutes(),
						withSuggest()),
					makePeer(4,
						withExitRoutes(),
						withSuggest()),
				},
			},
			// Change this, if the hashing function changes.
			wantID:   "stable3",
			wantName: "peer3",
		},
		{
			name: "exit-nodes-with-and-without-priority",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(1)),
					makePeer(2,
						withExitRoutes(),
						withSuggest()),
				},
			},
			wantID:   "stable1",
			wantName: "peer1",
			wantPri:  1,
		},
		{
			name: "exit-nodes-without-and-with-priority",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest()),
					makePeer(2,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(1)),
				},
			},
			wantID:   "stable2",
			wantName: "peer2",
			wantPri:  1,
		},
		{
			name: "exit-nodes-with-negative-priority",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(-1)),
					makePeer(2,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(-2)),
					makePeer(3,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(-3)),
					makePeer(4,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(-4)),
				},
			},
			wantID:   "stable1",
			wantName: "peer1",
			wantPri:  -1,
		},
		{
			name: "exit-nodes-no-priority-beats-negative-priority",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(-1)),
					makePeer(2,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(-2)),
					makePeer(3,
						withExitRoutes(),
						withSuggest()),
				},
			},
			wantID:   "stable3",
			wantName: "peer3",
		},
		{
			name: "exit-nodes-same-priority",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(1)),
					makePeer(2,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(2)), // top
					makePeer(3,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(1)),
					makePeer(4,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(2)), // top
					makePeer(5,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(2)), // top
					makePeer(6,
						withExitRoutes(),
						withSuggest()),
					makePeer(7,
						withExitRoutes(),
						withSuggest(),
						withLocationPriority(2)), // top
				},
			},
			wantID:   "stable5",
			wantName: "peer5",
			wantPri:  2,
		},
		{
			name: "suggested-exit-node-with-city",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest(),
						withLocation(city.View())),
				},
			},
			wantID:   "stable1",
			wantName: "peer1",
			wantLoc:  city,
		},
		{
			name: "suggested-exit-node-with-city-and-priority",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest(),
						withLocation(city.View()),
						withLocationPriority(1)),
				},
			},
			wantID:   "stable1",
			wantName: "peer1",
			wantLoc:  city,
			wantPri:  1,
		},
		{
			name: "suggested-exit-node-without-latlng",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest(),
						withLocation(noLatLng.View())),
				},
			},
			wantID:   "stable1",
			wantName: "peer1",
			wantLoc:  noLatLng,
		},
		{
			name: "suggested-exit-node-without-latlng-with-priority",
			netMap: &netmap.NetworkMap{
				SelfNode: selfNode.View(),
				Peers: []tailcfg.NodeView{
					makePeer(1,
						withExitRoutes(),
						withSuggest(),
						withLocation(noLatLng.View()),
						withLocationPriority(1)),
				},
			},
			wantID:   "stable1",
			wantName: "peer1",
			wantLoc:  noLatLng,
			wantPri:  1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var allowList set.Set[tailcfg.StableNodeID]
			if tt.allowPolicy != nil {
				allowList = set.SetOf(tt.allowPolicy)
			}

			// HACK: NetMap.AllCaps is populated by Control:
			if tt.netMap != nil {
				caps := maps.Keys(tt.netMap.SelfNode.CapMap().AsMap())
				tt.netMap.AllCaps = set.SetOf(slices.Collect(caps))
			}

			nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())
			defer nb.shutdown(errShutdown)
			nb.SetNetMap(tt.netMap)

			got, err := suggestExitNodeUsingTrafficSteering(nb, allowList)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("err=%v, want nil", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err=%v, want %v", err, tt.wantErr)
			}

			if got.Name != tt.wantName {
				t.Errorf("name=%q, want %q", got.Name, tt.wantName)
			}

			if got.ID != tt.wantID {
				t.Errorf("ID=%q, want %q", got.ID, tt.wantID)
			}

			wantLoc := tt.wantLoc
			if tt.wantPri != 0 {
				if wantLoc == nil {
					wantLoc = new(tailcfg.Location)
				}
				wantLoc.Priority = tt.wantPri
			}
			if diff := cmp.Diff(got.Location.AsStruct(), wantLoc); diff != "" {
				t.Errorf("location mismatch (+want -got)\n%s", diff)
			}
		})
	}
}

func TestMinLatencyDERPregion(t *testing.T) {
	tests := []struct {
		name       string
		regions    []int
		report     *netcheck.Report
		wantRegion int
	}{
		{
			name:       "regions, no latency values",
			regions:    []int{1, 2, 3},
			wantRegion: 0,
			report:     &netcheck.Report{},
		},
		{
			name:       "regions, different latency values",
			regions:    []int{1, 2, 3},
			wantRegion: 2,
			report: &netcheck.Report{
				RegionLatency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 5 * time.Millisecond,
					3: 30 * time.Millisecond,
				},
			},
		},
		{
			name:       "regions, same values",
			regions:    []int{1, 2, 3},
			wantRegion: 1,
			report: &netcheck.Report{
				RegionLatency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 10 * time.Millisecond,
					3: 10 * time.Millisecond,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := minLatencyDERPRegion(tt.regions, tt.report)
			if got != tt.wantRegion {
				t.Errorf("got region %v want region %v", got, tt.wantRegion)
			}
		})
	}
}

func TestEnableAutoUpdates(t *testing.T) {
	lb := newTestLocalBackend(t)

	_, err := lb.EditPrefs(&ipn.MaskedPrefs{
		AutoUpdateSet: ipn.AutoUpdatePrefsMask{
			ApplySet: true,
		},
		Prefs: ipn.Prefs{
			AutoUpdate: ipn.AutoUpdatePrefs{
				Apply: opt.NewBool(true),
			},
		},
	})
	// Enabling may fail, depending on which environment we are running this
	// test in.
	wantErr := !feature.CanAutoUpdate()
	gotErr := err != nil
	if gotErr != wantErr {
		t.Fatalf("enabling auto-updates: got error: %v (%v); want error: %v", gotErr, err, wantErr)
	}

	// Disabling should always succeed.
	if _, err := lb.EditPrefs(&ipn.MaskedPrefs{
		AutoUpdateSet: ipn.AutoUpdatePrefsMask{
			ApplySet: true,
		},
		Prefs: ipn.Prefs{
			AutoUpdate: ipn.AutoUpdatePrefs{
				Apply: opt.NewBool(false),
			},
		},
	}); err != nil {
		t.Fatalf("disabling auto-updates: got error: %v", err)
	}
}

func TestReadWriteRouteInfo(t *testing.T) {
	// set up a backend with more than one profile
	b := newTestBackend(t)
	prof1 := ipn.LoginProfile{ID: "id1", Key: "key1"}
	prof2 := ipn.LoginProfile{ID: "id2", Key: "key2"}
	b.pm.knownProfiles["id1"] = prof1.View()
	b.pm.knownProfiles["id2"] = prof2.View()
	b.pm.currentProfile = prof1.View()

	// set up routeInfo
	ri1 := &appc.RouteInfo{}
	ri1.Wildcards = []string{"1"}

	ri2 := &appc.RouteInfo{}
	ri2.Wildcards = []string{"2"}

	// read before write
	readRi, err := b.readRouteInfoLocked()
	if readRi != nil {
		t.Fatalf("read before writing: want nil, got %v", readRi)
	}
	if err != ipn.ErrStateNotExist {
		t.Fatalf("read before writing: want %v, got %v", ipn.ErrStateNotExist, err)
	}

	// write the first routeInfo
	if err := b.storeRouteInfo(ri1); err != nil {
		t.Fatal(err)
	}

	// write the other routeInfo as the other profile
	if _, _, err := b.pm.SwitchToProfileByID("id2"); err != nil {
		t.Fatal(err)
	}
	if err := b.storeRouteInfo(ri2); err != nil {
		t.Fatal(err)
	}

	// read the routeInfo of the first profile
	if _, _, err := b.pm.SwitchToProfileByID("id1"); err != nil {
		t.Fatal(err)
	}
	readRi, err = b.readRouteInfoLocked()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(readRi.Wildcards, ri1.Wildcards) {
		t.Fatalf("read prof1 routeInfo wildcards:  want %v, got %v", ri1.Wildcards, readRi.Wildcards)
	}

	// read the routeInfo of the second profile
	if _, _, err := b.pm.SwitchToProfileByID("id2"); err != nil {
		t.Fatal(err)
	}
	readRi, err = b.readRouteInfoLocked()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(readRi.Wildcards, ri2.Wildcards) {
		t.Fatalf("read prof2 routeInfo wildcards:  want %v, got %v", ri2.Wildcards, readRi.Wildcards)
	}
}

func TestFillAllowedSuggestions(t *testing.T) {
	tests := []struct {
		name        string
		allowPolicy []string
		want        []tailcfg.StableNodeID
	}{
		{
			name: "unset",
		},
		{
			name:        "zero",
			allowPolicy: []string{},
			want:        []tailcfg.StableNodeID{},
		},
		{
			name:        "one",
			allowPolicy: []string{"one"},
			want:        []tailcfg.StableNodeID{"one"},
		},
		{
			name:        "many",
			allowPolicy: []string{"one", "two", "three", "four"},
			want:        []tailcfg.StableNodeID{"one", "three", "four", "two"}, // order should not matter
		},
		{
			name:        "preserve case",
			allowPolicy: []string{"ABC", "def", "gHiJ"},
			want:        []tailcfg.StableNodeID{"ABC", "def", "gHiJ"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pol policytest.Config
			pol.Set(pkey.AllowedSuggestedExitNodes, tt.allowPolicy)

			got := fillAllowedSuggestions(pol)
			if got == nil {
				if tt.want == nil {
					return
				}
				t.Errorf("got nil, want %v", tt.want)
			}
			if tt.want == nil {
				t.Errorf("got %v, want nil", got)
			}

			if !got.Equal(set.SetOf(tt.want)) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotificationTargetMatch(t *testing.T) {
	tests := []struct {
		name      string
		target    notificationTarget
		actor     ipnauth.Actor
		wantMatch bool
	}{
		{
			name:      "AllClients/Nil",
			target:    allClients,
			actor:     nil,
			wantMatch: true,
		},
		{
			name:      "AllClients/NoUID/NoCID",
			target:    allClients,
			actor:     &ipnauth.TestActor{},
			wantMatch: true,
		},
		{
			name:      "AllClients/WithUID/NoCID",
			target:    allClients,
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4", CID: ipnauth.NoClientID},
			wantMatch: true,
		},
		{
			name:      "AllClients/NoUID/WithCID",
			target:    allClients,
			actor:     &ipnauth.TestActor{CID: ipnauth.ClientIDFrom("A")},
			wantMatch: true,
		},
		{
			name:      "AllClients/WithUID/WithCID",
			target:    allClients,
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4", CID: ipnauth.ClientIDFrom("A")},
			wantMatch: true,
		},
		{
			name:      "FilterByUID/Nil",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4"},
			actor:     nil,
			wantMatch: false,
		},
		{
			name:      "FilterByUID/NoUID/NoCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4"},
			actor:     &ipnauth.TestActor{},
			wantMatch: false,
		},
		{
			name:      "FilterByUID/NoUID/WithCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4"},
			actor:     &ipnauth.TestActor{CID: ipnauth.ClientIDFrom("A")},
			wantMatch: false,
		},
		{
			name:      "FilterByUID/SameUID/NoCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4"},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4"},
			wantMatch: true,
		},
		{
			name:      "FilterByUID/DifferentUID/NoCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4"},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-5-6-7-8"},
			wantMatch: false,
		},
		{
			name:      "FilterByUID/SameUID/WithCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4"},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4", CID: ipnauth.ClientIDFrom("A")},
			wantMatch: true,
		},
		{
			name:      "FilterByUID/DifferentUID/WithCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4"},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-5-6-7-8", CID: ipnauth.ClientIDFrom("A")},
			wantMatch: false,
		},
		{
			name:      "FilterByCID/Nil",
			target:    notificationTarget{clientID: ipnauth.ClientIDFrom("A")},
			actor:     nil,
			wantMatch: false,
		},
		{
			name:      "FilterByCID/NoUID/NoCID",
			target:    notificationTarget{clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{},
			wantMatch: false,
		},
		{
			name:      "FilterByCID/NoUID/SameCID",
			target:    notificationTarget{clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{CID: ipnauth.ClientIDFrom("A")},
			wantMatch: true,
		},
		{
			name:      "FilterByCID/NoUID/DifferentCID",
			target:    notificationTarget{clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{CID: ipnauth.ClientIDFrom("B")},
			wantMatch: false,
		},
		{
			name:      "FilterByCID/WithUID/NoCID",
			target:    notificationTarget{clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4"},
			wantMatch: false,
		},
		{
			name:      "FilterByCID/WithUID/SameCID",
			target:    notificationTarget{clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4", CID: ipnauth.ClientIDFrom("A")},
			wantMatch: true,
		},
		{
			name:      "FilterByCID/WithUID/DifferentCID",
			target:    notificationTarget{clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4", CID: ipnauth.ClientIDFrom("B")},
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/Nil",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4"},
			actor:     nil,
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/NoUID/NoCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{},
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/NoUID/SameCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{CID: ipnauth.ClientIDFrom("A")},
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/NoUID/DifferentCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{CID: ipnauth.ClientIDFrom("B")},
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/SameUID/NoCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4"},
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/SameUID/SameCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4", CID: ipnauth.ClientIDFrom("A")},
			wantMatch: true,
		},
		{
			name:      "FilterByUID+CID/SameUID/DifferentCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-1-2-3-4", CID: ipnauth.ClientIDFrom("B")},
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/DifferentUID/NoCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-5-6-7-8"},
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/DifferentUID/SameCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-5-6-7-8", CID: ipnauth.ClientIDFrom("A")},
			wantMatch: false,
		},
		{
			name:      "FilterByUID+CID/DifferentUID/DifferentCID",
			target:    notificationTarget{userID: "S-1-5-21-1-2-3-4", clientID: ipnauth.ClientIDFrom("A")},
			actor:     &ipnauth.TestActor{UID: "S-1-5-21-5-6-7-8", CID: ipnauth.ClientIDFrom("B")},
			wantMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatch := tt.target.match(tt.actor)
			if gotMatch != tt.wantMatch {
				t.Errorf("match: got %v; want %v", gotMatch, tt.wantMatch)
			}
		})
	}
}

type newTestControlFn func(tb testing.TB, opts controlclient.Options) controlclient.Client

func newLocalBackendWithTestControl(t *testing.T, enableLogging bool, newControl newTestControlFn) *LocalBackend {
	bus := eventbustest.NewBus(t)
	return newLocalBackendWithSysAndTestControl(t, enableLogging, tsd.NewSystemWithBus(bus), newControl)
}

func newLocalBackendWithSysAndTestControl(t *testing.T, enableLogging bool, sys *tsd.System, newControl newTestControlFn) *LocalBackend {
	logf := logger.Discard
	if enableLogging {
		logf = tstest.WhileTestRunningLogger(t)
	}

	if _, hasStore := sys.StateStore.GetOK(); !hasStore {
		store := new(mem.Store)
		sys.Set(store)
	}
	if _, hasEngine := sys.Engine.GetOK(); !hasEngine {
		e, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
		if err != nil {
			t.Fatalf("NewFakeUserspaceEngine: %v", err)
		}
		t.Cleanup(e.Close)
		sys.Set(e)
	}

	b, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(b.Shutdown)

	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		return newControl(t, opts), nil
	})
	return b
}

// notificationHandler is any function that can process (e.g., check) a notification.
// It returns whether the notification has been handled or should be passed to the next handler.
// The handler may be called from any goroutine, so it must avoid calling functions
// that are restricted to the goroutine running the test or benchmark function,
// such as [testing.common.FailNow] and [testing.common.Fatalf].
type notificationHandler func(testing.TB, ipnauth.Actor, *ipn.Notify) bool

// wantedNotification names a [notificationHandler] that processes a notification
// the test expects and wants to receive. The name is used to report notifications
// that haven't been received within the expected timeout.
type wantedNotification struct {
	name string
	cond notificationHandler
}

// notificationWatcher observes [LocalBackend] notifications as the specified actor,
// reporting missing but expected notifications using [testing.common.Error],
// and delegating the handling of unexpected notifications to the [notificationHandler]s.
type notificationWatcher struct {
	tb    testing.TB
	lb    *LocalBackend
	actor ipnauth.Actor

	mu          sync.Mutex
	mask        ipn.NotifyWatchOpt
	want        []wantedNotification  // notifications we want to receive
	unexpected  []notificationHandler // funcs that are called to check any other notifications
	ctxCancel   context.CancelFunc    // cancels the outstanding [LocalBackend.WatchNotificationsAs] call
	got         []*ipn.Notify         // all notifications, both wanted and unexpected, we've received so far
	gotWanted   []*ipn.Notify         // only the expected notifications; holds nil for any notification that hasn't been received
	gotWantedCh chan struct{}         // closed when we have received the last wanted notification
	doneCh      chan struct{}         // closed when [LocalBackend.WatchNotificationsAs] returns
}

func newNotificationWatcher(tb testing.TB, lb *LocalBackend, actor ipnauth.Actor) *notificationWatcher {
	return &notificationWatcher{tb: tb, lb: lb, actor: actor}
}

func (w *notificationWatcher) watch(mask ipn.NotifyWatchOpt, wanted []wantedNotification, unexpected ...notificationHandler) {
	w.tb.Helper()

	// Cancel any outstanding [LocalBackend.WatchNotificationsAs] calls.
	w.mu.Lock()
	ctxCancel := w.ctxCancel
	doneCh := w.doneCh
	w.mu.Unlock()
	if doneCh != nil {
		ctxCancel()
		<-doneCh
	}

	doneCh = make(chan struct{})
	gotWantedCh := make(chan struct{})
	ctx, ctxCancel := context.WithCancel(context.Background())
	w.tb.Cleanup(func() {
		ctxCancel()
		<-doneCh
	})

	w.mu.Lock()
	w.mask = mask
	w.want = wanted
	w.unexpected = unexpected
	w.ctxCancel = ctxCancel
	w.got = nil
	w.gotWanted = make([]*ipn.Notify, len(wanted))
	w.gotWantedCh = gotWantedCh
	w.doneCh = doneCh
	w.mu.Unlock()

	watchAddedCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		if len(wanted) == 0 {
			close(gotWantedCh)
			if len(unexpected) == 0 {
				close(watchAddedCh)
				return
			}
		}

		var nextWantIdx int
		w.lb.WatchNotificationsAs(ctx, w.actor, w.mask, func() { close(watchAddedCh) }, func(notify *ipn.Notify) (keepGoing bool) {
			w.tb.Helper()

			w.mu.Lock()
			defer w.mu.Unlock()
			w.got = append(w.got, notify)

			wanted := false
			for i := nextWantIdx; i < len(w.want); i++ {
				if wanted = w.want[i].cond(w.tb, w.actor, notify); wanted {
					w.gotWanted[i] = notify
					nextWantIdx = i + 1
					break
				}
			}

			if wanted && nextWantIdx == len(w.want) {
				close(w.gotWantedCh)
				if len(w.unexpected) == 0 {
					// If we have received the last wanted notification,
					// and we don't have any handlers for the unexpected notifications,
					// we can stop the watcher right away.
					return false
				}

			}

			if !wanted {
				// If we've received a notification we didn't expect,
				// it could either be an unwanted notification caused by a bug
				// or just a miscellaneous one that's irrelevant for the current test.
				// Call unexpected notification handlers, if any, to
				// check and fail the test if necessary.
				for _, h := range w.unexpected {
					if h(w.tb, w.actor, notify) {
						break
					}
				}
			}

			return true
		})
	}()
	<-watchAddedCh
}

func (w *notificationWatcher) check() []*ipn.Notify {
	w.tb.Helper()

	w.mu.Lock()
	cancel := w.ctxCancel
	gotWantedCh := w.gotWantedCh
	checkUnexpected := len(w.unexpected) != 0
	doneCh := w.doneCh
	w.mu.Unlock()

	// Wait for up to 10 seconds to receive expected notifications.
	timeout := 10 * time.Second
	for {
		select {
		case <-gotWantedCh:
			if checkUnexpected {
				gotWantedCh = nil
				// But do not wait longer than 500ms for unexpected notifications after
				// the expected notifications have been received.
				timeout = 500 * time.Millisecond
				continue
			}
		case <-doneCh:
			// [LocalBackend.WatchNotificationsAs] has already returned, so no further
			// notifications will be received. There's no reason to wait any longer.
		case <-time.After(timeout):
		}
		cancel()
		<-doneCh
		break
	}

	// Report missing notifications, if any, and log all received notifications,
	// including both expected and unexpected ones.
	w.mu.Lock()
	defer w.mu.Unlock()
	if hasMissing := slices.Contains(w.gotWanted, nil); hasMissing {
		want := make([]string, len(w.want))
		got := make([]string, 0, len(w.want))
		for i, wn := range w.want {
			want[i] = wn.name
			if w.gotWanted[i] != nil {
				got = append(got, wn.name)
			}
		}
		w.tb.Errorf("Notifications(%s): got %q; want %q", actorDescriptionForTest(w.actor), strings.Join(got, ", "), strings.Join(want, ", "))
		for i, n := range w.got {
			w.tb.Logf("%d. %v", i, n)
		}
		return nil
	}

	return w.gotWanted
}

func actorDescriptionForTest(actor ipnauth.Actor) string {
	var parts []string
	if actor != nil {
		if name, _ := actor.Username(); name != "" {
			parts = append(parts, name)
		}
		if uid := actor.UserID(); uid != "" {
			parts = append(parts, string(uid))
		}
		if clientID, _ := actor.ClientID(); clientID != ipnauth.NoClientID {
			parts = append(parts, clientID.String())
		}
	}
	return fmt.Sprintf("Actor{%s}", strings.Join(parts, ", "))
}

func TestLoginNotifications(t *testing.T) {
	const (
		enableLogging = true
		controlURL    = "https://localhost:1/"
		loginURL      = "https://localhost:1/1"
	)

	wantBrowseToURL := wantedNotification{
		name: "BrowseToURL",
		cond: func(t testing.TB, actor ipnauth.Actor, n *ipn.Notify) bool {
			if n.BrowseToURL != nil && *n.BrowseToURL != loginURL {
				t.Errorf("BrowseToURL (%s): got %q; want %q", actorDescriptionForTest(actor), *n.BrowseToURL, loginURL)
				return false
			}
			return n.BrowseToURL != nil
		},
	}
	unexpectedBrowseToURL := func(t testing.TB, actor ipnauth.Actor, n *ipn.Notify) bool {
		if n.BrowseToURL != nil {
			t.Errorf("Unexpected BrowseToURL(%s): %v", actorDescriptionForTest(actor), n)
			return true
		}
		return false
	}

	tests := []struct {
		name            string
		logInAs         ipnauth.Actor
		urlExpectedBy   []ipnauth.Actor
		urlUnexpectedBy []ipnauth.Actor
	}{
		{
			name:          "NoObservers",
			logInAs:       &ipnauth.TestActor{UID: "A"},
			urlExpectedBy: []ipnauth.Actor{}, // ensure that it does not panic if no one is watching
		},
		{
			name:          "SingleUser",
			logInAs:       &ipnauth.TestActor{UID: "A"},
			urlExpectedBy: []ipnauth.Actor{&ipnauth.TestActor{UID: "A"}},
		},
		{
			name:          "SameUser/TwoSessions/NoCID",
			logInAs:       &ipnauth.TestActor{UID: "A"},
			urlExpectedBy: []ipnauth.Actor{&ipnauth.TestActor{UID: "A"}, &ipnauth.TestActor{UID: "A"}},
		},
		{
			name:            "SameUser/TwoSessions/OneWithCID",
			logInAs:         &ipnauth.TestActor{UID: "A", CID: ipnauth.ClientIDFrom("123")},
			urlExpectedBy:   []ipnauth.Actor{&ipnauth.TestActor{UID: "A", CID: ipnauth.ClientIDFrom("123")}},
			urlUnexpectedBy: []ipnauth.Actor{&ipnauth.TestActor{UID: "A"}},
		},
		{
			name:            "SameUser/TwoSessions/BothWithCID",
			logInAs:         &ipnauth.TestActor{UID: "A", CID: ipnauth.ClientIDFrom("123")},
			urlExpectedBy:   []ipnauth.Actor{&ipnauth.TestActor{UID: "A", CID: ipnauth.ClientIDFrom("123")}},
			urlUnexpectedBy: []ipnauth.Actor{&ipnauth.TestActor{UID: "A", CID: ipnauth.ClientIDFrom("456")}},
		},
		{
			name:            "DifferentUsers/NoCID",
			logInAs:         &ipnauth.TestActor{UID: "A"},
			urlExpectedBy:   []ipnauth.Actor{&ipnauth.TestActor{UID: "A"}},
			urlUnexpectedBy: []ipnauth.Actor{&ipnauth.TestActor{UID: "B"}},
		},
		{
			name:            "DifferentUsers/SameCID",
			logInAs:         &ipnauth.TestActor{UID: "A"},
			urlExpectedBy:   []ipnauth.Actor{&ipnauth.TestActor{UID: "A", CID: ipnauth.ClientIDFrom("123")}},
			urlUnexpectedBy: []ipnauth.Actor{&ipnauth.TestActor{UID: "B", CID: ipnauth.ClientIDFrom("123")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lb := newLocalBackendWithTestControl(t, enableLogging, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
				return newClient(tb, opts)
			})
			if _, err := lb.EditPrefs(&ipn.MaskedPrefs{ControlURLSet: true, Prefs: ipn.Prefs{ControlURL: controlURL}}); err != nil {
				t.Fatalf("(*EditPrefs).Start(): %v", err)
			}
			if err := lb.Start(ipn.Options{}); err != nil {
				t.Fatalf("(*LocalBackend).Start(): %v", err)
			}

			sessions := make([]*notificationWatcher, 0, len(tt.urlExpectedBy)+len(tt.urlUnexpectedBy))
			for _, actor := range tt.urlExpectedBy {
				session := newNotificationWatcher(t, lb, actor)
				session.watch(0, []wantedNotification{wantBrowseToURL})
				sessions = append(sessions, session)
			}
			for _, actor := range tt.urlUnexpectedBy {
				session := newNotificationWatcher(t, lb, actor)
				session.watch(0, nil, unexpectedBrowseToURL)
				sessions = append(sessions, session)
			}

			if err := lb.StartLoginInteractiveAs(context.Background(), tt.logInAs); err != nil {
				t.Fatal(err)
			}

			lb.cc.(*mockControl).send(nil, loginURL, false, nil)

			var wg sync.WaitGroup
			wg.Add(len(sessions))
			for _, sess := range sessions {
				go func() { // check all sessions in parallel
					sess.check()
					wg.Done()
				}()
			}
			wg.Wait()
		})
	}
}

// TestConfigFileReload tests that the LocalBackend reloads its configuration
// when the configuration file changes.
func TestConfigFileReload(t *testing.T) {
	type testCase struct {
		name    string
		initial *conffile.Config
		updated *conffile.Config
		checkFn func(*testing.T, *LocalBackend)
	}

	tests := []testCase{
		{
			name: "hostname_change",
			initial: &conffile.Config{
				Parsed: ipn.ConfigVAlpha{
					Version:  "alpha0",
					Hostname: ptr.To("initial-host"),
				},
			},
			updated: &conffile.Config{
				Parsed: ipn.ConfigVAlpha{
					Version:  "alpha0",
					Hostname: ptr.To("updated-host"),
				},
			},
			checkFn: func(t *testing.T, b *LocalBackend) {
				if got := b.Prefs().Hostname(); got != "updated-host" {
					t.Errorf("hostname = %q; want updated-host", got)
				}
			},
		},
		{
			name: "start_advertising_services",
			initial: &conffile.Config{
				Parsed: ipn.ConfigVAlpha{
					Version: "alpha0",
				},
			},
			updated: &conffile.Config{
				Parsed: ipn.ConfigVAlpha{
					Version:           "alpha0",
					AdvertiseServices: []string{"svc:abc", "svc:def"},
				},
			},
			checkFn: func(t *testing.T, b *LocalBackend) {
				if got := b.Prefs().AdvertiseServices().AsSlice(); !reflect.DeepEqual(got, []string{"svc:abc", "svc:def"}) {
					t.Errorf("AdvertiseServices = %v; want [svc:abc, svc:def]", got)
				}
			},
		},
		{
			name: "change_advertised_services",
			initial: &conffile.Config{
				Parsed: ipn.ConfigVAlpha{
					Version:           "alpha0",
					AdvertiseServices: []string{"svc:abc", "svc:def"},
				},
			},
			updated: &conffile.Config{
				Parsed: ipn.ConfigVAlpha{
					Version:           "alpha0",
					AdvertiseServices: []string{"svc:abc", "svc:ghi"},
				},
			},
			checkFn: func(t *testing.T, b *LocalBackend) {
				if got := b.Prefs().AdvertiseServices().AsSlice(); !reflect.DeepEqual(got, []string{"svc:abc", "svc:ghi"}) {
					t.Errorf("AdvertiseServices = %v; want [svc:abc, svc:ghi]", got)
				}
			},
		},
		{
			name: "unset_advertised_services",
			initial: &conffile.Config{
				Parsed: ipn.ConfigVAlpha{
					Version:           "alpha0",
					AdvertiseServices: []string{"svc:abc"},
				},
			},
			updated: &conffile.Config{
				Parsed: ipn.ConfigVAlpha{
					Version: "alpha0",
				},
			},
			checkFn: func(t *testing.T, b *LocalBackend) {
				if b.Prefs().AdvertiseServices().Len() != 0 {
					t.Errorf("got %d AdvertiseServices wants none", b.Prefs().AdvertiseServices().Len())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "tailscale.conf")

			// Write initial config
			initialJSON, err := json.Marshal(tc.initial.Parsed)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, initialJSON, 0644); err != nil {
				t.Fatal(err)
			}

			// Create backend with initial config
			tc.initial.Path = path
			tc.initial.Raw = initialJSON
			sys := tsd.NewSystem()
			sys.InitialConfig = tc.initial
			b := newTestLocalBackendWithSys(t, sys)

			// Update config file
			updatedJSON, err := json.Marshal(tc.updated.Parsed)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, updatedJSON, 0644); err != nil {
				t.Fatal(err)
			}

			// Trigger reload
			if ok, err := b.ReloadConfig(); !ok || err != nil {
				t.Fatalf("ReloadConfig() = %v, %v; want true, nil", ok, err)
			}

			// Check outcome
			tc.checkFn(t, b)
		})
	}
}

func TestGetVIPServices(t *testing.T) {
	tests := []struct {
		name        string
		advertised  []string
		serveConfig *ipn.ServeConfig
		want        []*tailcfg.VIPService
	}{
		{
			"advertised-only",
			[]string{"svc:abc", "svc:def"},
			&ipn.ServeConfig{},
			[]*tailcfg.VIPService{
				{
					Name:   "svc:abc",
					Active: true,
				},
				{
					Name:   "svc:def",
					Active: true,
				},
			},
		},
		{
			"served-only",
			[]string{},
			&ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {Tun: true},
				},
			},
			[]*tailcfg.VIPService{
				{
					Name:  "svc:abc",
					Ports: []tailcfg.ProtoPortRange{{Ports: tailcfg.PortRangeAny}},
				},
			},
		},
		{
			"served-and-advertised",
			[]string{"svc:abc"},
			&ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {Tun: true},
				},
			},
			[]*tailcfg.VIPService{
				{
					Name:   "svc:abc",
					Active: true,
					Ports:  []tailcfg.ProtoPortRange{{Ports: tailcfg.PortRangeAny}},
				},
			},
		},
		{
			"served-and-advertised-different-service",
			[]string{"svc:def"},
			&ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {Tun: true},
				},
			},
			[]*tailcfg.VIPService{
				{
					Name:  "svc:abc",
					Ports: []tailcfg.ProtoPortRange{{Ports: tailcfg.PortRangeAny}},
				},
				{
					Name:   "svc:def",
					Active: true,
				},
			},
		},
		{
			"served-with-port-ranges-one-range-single",
			[]string{},
			&ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {TCP: map[uint16]*ipn.TCPPortHandler{
						80: {HTTPS: true},
					}},
				},
			},
			[]*tailcfg.VIPService{
				{
					Name:  "svc:abc",
					Ports: []tailcfg.ProtoPortRange{{Proto: 6, Ports: tailcfg.PortRange{First: 80, Last: 80}}},
				},
			},
		},
		{
			"served-with-port-ranges-one-range-multiple",
			[]string{},
			&ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {TCP: map[uint16]*ipn.TCPPortHandler{
						80: {HTTPS: true},
						81: {HTTPS: true},
						82: {HTTPS: true},
					}},
				},
			},
			[]*tailcfg.VIPService{
				{
					Name:  "svc:abc",
					Ports: []tailcfg.ProtoPortRange{{Proto: 6, Ports: tailcfg.PortRange{First: 80, Last: 82}}},
				},
			},
		},
		{
			"served-with-port-ranges-multiple-ranges",
			[]string{},
			&ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {TCP: map[uint16]*ipn.TCPPortHandler{
						80:   {HTTPS: true},
						81:   {HTTPS: true},
						82:   {HTTPS: true},
						1212: {HTTPS: true},
						1213: {HTTPS: true},
						1214: {HTTPS: true},
					}},
				},
			},
			[]*tailcfg.VIPService{
				{
					Name: "svc:abc",
					Ports: []tailcfg.ProtoPortRange{
						{Proto: 6, Ports: tailcfg.PortRange{First: 80, Last: 82}},
						{Proto: 6, Ports: tailcfg.PortRange{First: 1212, Last: 1214}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lb := newLocalBackendWithTestControl(t, false, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
				return newClient(tb, opts)
			})
			lb.serveConfig = tt.serveConfig.View()
			prefs := &ipn.Prefs{
				AdvertiseServices: tt.advertised,
			}
			got := lb.vipServicesFromPrefsLocked(prefs.View())
			slices.SortFunc(got, func(a, b *tailcfg.VIPService) int {
				return strings.Compare(a.Name.String(), b.Name.String())
			})
			if !reflect.DeepEqual(tt.want, got) {
				t.Logf("want:")
				for _, s := range tt.want {
					t.Logf("%+v", s)
				}
				t.Logf("got:")
				for _, s := range got {
					t.Logf("%+v", s)
				}
				t.Fail()
				return
			}
		})
	}
}

func TestUpdatePrefsOnSysPolicyChange(t *testing.T) {
	const enableLogging = false

	type fieldChange struct {
		name string
		want any
	}

	wantPrefsChanges := func(want ...fieldChange) *wantedNotification {
		return &wantedNotification{
			name: "Prefs",
			cond: func(t testing.TB, actor ipnauth.Actor, n *ipn.Notify) bool {
				if n.Prefs != nil {
					prefs := reflect.Indirect(reflect.ValueOf(n.Prefs.AsStruct()))
					for _, f := range want {
						got := prefs.FieldByName(f.name).Interface()
						if !reflect.DeepEqual(got, f.want) {
							t.Errorf("%v: got %v; want %v", f.name, got, f.want)
						}
					}
				}
				return n.Prefs != nil
			},
		}
	}

	unexpectedPrefsChange := func(t testing.TB, _ ipnauth.Actor, n *ipn.Notify) bool {
		if n.Prefs != nil {
			t.Errorf("Unexpected Prefs: %v", n.Prefs.Pretty())
			return true
		}
		return false
	}

	tests := []struct {
		name           string
		initialPrefs   *ipn.Prefs
		stringSettings []source.TestSetting[string]
		want           *wantedNotification
	}{
		{
			name:           "ShieldsUp/True",
			stringSettings: []source.TestSetting[string]{source.TestSettingOf(pkey.EnableIncomingConnections, "never")},
			want:           wantPrefsChanges(fieldChange{"ShieldsUp", true}),
		},
		{
			name:           "ShieldsUp/False",
			initialPrefs:   &ipn.Prefs{ShieldsUp: true},
			stringSettings: []source.TestSetting[string]{source.TestSettingOf(pkey.EnableIncomingConnections, "always")},
			want:           wantPrefsChanges(fieldChange{"ShieldsUp", false}),
		},
		{
			name:           "ExitNodeID",
			stringSettings: []source.TestSetting[string]{source.TestSettingOf(pkey.ExitNodeID, "foo")},
			want:           wantPrefsChanges(fieldChange{"ExitNodeID", tailcfg.StableNodeID("foo")}),
		},
		{
			name:           "EnableRunExitNode",
			stringSettings: []source.TestSetting[string]{source.TestSettingOf(pkey.EnableRunExitNode, "always")},
			want:           wantPrefsChanges(fieldChange{"AdvertiseRoutes", []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()}}),
		},
		{
			name: "Multiple",
			initialPrefs: &ipn.Prefs{
				ExitNodeAllowLANAccess: true,
			},
			stringSettings: []source.TestSetting[string]{
				source.TestSettingOf(pkey.EnableServerMode, "always"),
				source.TestSettingOf(pkey.ExitNodeAllowLANAccess, "never"),
				source.TestSettingOf(pkey.ExitNodeIP, "127.0.0.1"),
			},
			want: wantPrefsChanges(
				fieldChange{"ForceDaemon", true},
				fieldChange{"ExitNodeAllowLANAccess", false},
				fieldChange{"ExitNodeIP", netip.MustParseAddr("127.0.0.1")},
			),
		},
		{
			name: "NoChange",
			initialPrefs: &ipn.Prefs{
				CorpDNS:         true,
				ExitNodeID:      "foo",
				AdvertiseRoutes: []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()},
			},
			stringSettings: []source.TestSetting[string]{
				source.TestSettingOf(pkey.EnableTailscaleDNS, "always"),
				source.TestSettingOf(pkey.ExitNodeID, "foo"),
				source.TestSettingOf(pkey.EnableRunExitNode, "always"),
			},
			want: nil, // syspolicy settings match the preferences; no change notification is expected.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var polc policytest.Config
			polc.EnableRegisterChangeCallback()

			sys := tsd.NewSystem()
			sys.PolicyClient.Set(polc)
			lb := newLocalBackendWithSysAndTestControl(t, enableLogging, sys, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
				opts.PolicyClient = polc
				return newClient(tb, opts)
			})
			if tt.initialPrefs != nil {
				lb.SetPrefsForTest(tt.initialPrefs)
			}
			if err := lb.Start(ipn.Options{}); err != nil {
				t.Fatalf("(*LocalBackend).Start(): %v", err)
			}

			nw := newNotificationWatcher(t, lb, &ipnauth.TestActor{})
			if tt.want != nil {
				nw.watch(0, []wantedNotification{*tt.want})
			} else {
				nw.watch(0, nil, unexpectedPrefsChange)
			}

			var batch policytest.Config
			for _, ss := range tt.stringSettings {
				batch.Set(ss.Key, ss.Value)
			}
			polc.SetMultiple(batch)

			nw.check()
		})
	}
}

func TestUpdateIngressAndServiceHashLocked(t *testing.T) {
	prefs := ipn.NewPrefs().View()
	previousSC := &ipn.ServeConfig{
		Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
			"svc:abc": {Tun: true},
		},
	}
	tests := []struct {
		name              string
		hi                *tailcfg.Hostinfo
		hasPreviousSC     bool // whether to overwrite the ServeConfig hash in the Hostinfo using previousSC
		sc                *ipn.ServeConfig
		wantIngress       bool
		wantWireIngress   bool
		wantControlUpdate bool
	}{
		{
			name: "no_hostinfo_no_serve_config",
			hi:   nil,
		},
		{
			name: "empty_hostinfo_no_serve_config",
			hi:   &tailcfg.Hostinfo{},
		},
		{
			name: "empty_hostinfo_funnel_enabled",
			hi:   &tailcfg.Hostinfo{},
			sc: &ipn.ServeConfig{
				AllowFunnel: map[ipn.HostPort]bool{
					"tailnet.xyz:443": true,
				},
			},
			wantIngress:       true,
			wantWireIngress:   false, // implied by wantIngress
			wantControlUpdate: true,
		},
		{
			name: "empty_hostinfo_service_configured",
			hi:   &tailcfg.Hostinfo{},
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {Tun: true},
				},
			},
			wantControlUpdate: true,
		},
		{
			name: "empty_hostinfo_funnel_disabled",
			hi:   &tailcfg.Hostinfo{},
			sc: &ipn.ServeConfig{
				AllowFunnel: map[ipn.HostPort]bool{
					"tailnet.xyz:443": false,
				},
			},
			wantWireIngress:   true, // true if there is any AllowFunnel block
			wantControlUpdate: true,
		},
		{
			name: "empty_hostinfo_no_funnel_no_service",
			hi:   &tailcfg.Hostinfo{},
			sc: &ipn.ServeConfig{
				TCP: map[uint16]*ipn.TCPPortHandler{
					80: {HTTPS: true},
				},
			},
		},
		{
			name: "funnel_enabled_no_change",
			hi: &tailcfg.Hostinfo{
				IngressEnabled: true,
			},
			sc: &ipn.ServeConfig{
				AllowFunnel: map[ipn.HostPort]bool{
					"tailnet.xyz:443": true,
				},
			},
			wantIngress:     true,
			wantWireIngress: false, // implied by wantIngress
		},
		{
			name:          "service_hash_no_change",
			hi:            &tailcfg.Hostinfo{},
			hasPreviousSC: true,
			sc: &ipn.ServeConfig{
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {Tun: true},
				},
			},
		},
		{
			name: "funnel_disabled_no_change",
			hi: &tailcfg.Hostinfo{
				WireIngress: true,
			},
			sc: &ipn.ServeConfig{
				AllowFunnel: map[ipn.HostPort]bool{
					"tailnet.xyz:443": false,
				},
			},
			wantWireIngress: true, // true if there is any AllowFunnel block
		},
		{
			name:              "service_got_removed",
			hi:                &tailcfg.Hostinfo{},
			hasPreviousSC:     true,
			sc:                &ipn.ServeConfig{},
			wantControlUpdate: true,
		},
		{
			name: "funnel_changes_to_disabled",
			hi: &tailcfg.Hostinfo{
				IngressEnabled: true,
			},
			sc: &ipn.ServeConfig{
				AllowFunnel: map[ipn.HostPort]bool{
					"tailnet.xyz:443": false,
				},
			},
			wantWireIngress:   true, // true if there is any AllowFunnel block
			wantControlUpdate: true,
		},
		{
			name: "funnel_changes_to_enabled",
			hi: &tailcfg.Hostinfo{
				WireIngress: true,
			},
			sc: &ipn.ServeConfig{
				AllowFunnel: map[ipn.HostPort]bool{
					"tailnet.xyz:443": true,
				},
			},
			wantIngress:       true,
			wantWireIngress:   false, // implied by wantIngress
			wantControlUpdate: true,
		},
		{
			name: "both_funnel_and_service_changes",
			hi: &tailcfg.Hostinfo{
				IngressEnabled: true,
			},
			sc: &ipn.ServeConfig{
				AllowFunnel: map[ipn.HostPort]bool{
					"tailnet.xyz:443": false,
				},
				Services: map[tailcfg.ServiceName]*ipn.ServiceConfig{
					"svc:abc": {Tun: true},
				},
			},
			wantWireIngress:   true, // true if there is any AllowFunnel block
			wantControlUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := newTestLocalBackend(t)
			b.hostinfo = tt.hi
			if tt.hasPreviousSC {
				b.mu.Lock()
				b.serveConfig = previousSC.View()
				b.hostinfo.ServicesHash = b.vipServiceHash(b.vipServicesFromPrefsLocked(prefs))
				b.mu.Unlock()
			}
			b.serveConfig = tt.sc.View()
			allDone := make(chan bool, 1)
			defer b.goTracker.AddDoneCallback(func() {
				b.mu.Lock()
				defer b.mu.Unlock()
				if b.goTracker.RunningGoroutines() > 0 {
					return
				}
				select {
				case allDone <- true:
				default:
				}
			})()

			was := b.goTracker.StartedGoroutines()
			b.updateIngressAndServiceHashLocked(prefs)

			if tt.hi != nil {
				if tt.hi.IngressEnabled != tt.wantIngress {
					t.Errorf("IngressEnabled = %v, want %v", tt.hi.IngressEnabled, tt.wantIngress)
				}
				if tt.hi.WireIngress != tt.wantWireIngress {
					t.Errorf("WireIngress = %v, want %v", tt.hi.WireIngress, tt.wantWireIngress)
				}
				b.mu.Lock()
				svcHash := b.vipServiceHash(b.vipServicesFromPrefsLocked(prefs))
				b.mu.Unlock()
				if tt.hi.ServicesHash != svcHash {
					t.Errorf("ServicesHash = %v, want %v", tt.hi.ServicesHash, svcHash)
				}
			}

			startedGoroutine := b.goTracker.StartedGoroutines() != was
			if startedGoroutine != tt.wantControlUpdate {
				t.Errorf("control update triggered = %v, want %v", startedGoroutine, tt.wantControlUpdate)
			}

			if startedGoroutine {
				select {
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for goroutine to finish")
				case <-allDone:
				}
			}
		})
	}
}

// TestSrcCapPacketFilter tests that LocalBackend handles packet filters with
// SrcCaps instead of Srcs (IPs)
func TestSrcCapPacketFilter(t *testing.T) {
	lb := newLocalBackendWithTestControl(t, false, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		return newClient(tb, opts)
	})
	if err := lb.Start(ipn.Options{}); err != nil {
		t.Fatalf("(*LocalBackend).Start(): %v", err)
	}

	var k key.NodePublic
	must.Do(k.UnmarshalText([]byte("nodekey:5c8f86d5fc70d924e55f02446165a5dae8f822994ad26bcf4b08fd841f9bf261")))

	controlClient := lb.cc.(*mockControl)
	controlClient.send(nil, "", false, &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				Addresses: []netip.Prefix{netip.MustParsePrefix("2.2.2.2/32")},
				ID:        2,
				Key:       k,
				CapMap:    tailcfg.NodeCapMap{"cap-X": nil}, // node 2 has cap
			}).View(),
			(&tailcfg.Node{
				Addresses: []netip.Prefix{netip.MustParsePrefix("3.3.3.3/32")},
				ID:        3,
				Key:       k,
				CapMap:    tailcfg.NodeCapMap{}, // node 3 does not have the cap
			}).View(),
		},
		PacketFilter: []filtertype.Match{{
			IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP}),
			SrcCaps: []tailcfg.NodeCapability{"cap-X"}, // cap in packet filter rule
			Dsts: []filtertype.NetPortRange{{
				Net: netip.MustParsePrefix("1.1.1.1/32"),
				Ports: filtertype.PortRange{
					First: 22,
					Last:  22,
				},
			}},
		}},
	})

	f := lb.GetFilterForTest()
	res := f.Check(netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("1.1.1.1"), 22, ipproto.TCP)
	if res != filter.Accept {
		t.Errorf("Check(2.2.2.2, ...) = %s, want %s", res, filter.Accept)
	}

	res = f.Check(netip.MustParseAddr("3.3.3.3"), netip.MustParseAddr("1.1.1.1"), 22, ipproto.TCP)
	if !res.IsDrop() {
		t.Error("IsDrop() for node without cap = false, want true")
	}
}

func TestDisplayMessages(t *testing.T) {
	b := newTestLocalBackend(t)

	// Pretend we're in a map poll so health updates get processed
	ht := b.HealthTracker()
	ht.SetIPNState("NeedsLogin", true)
	ht.GotStreamedMapResponse()

	b.mu.Lock()
	defer b.mu.Unlock()
	b.setNetMapLocked(&netmap.NetworkMap{
		DisplayMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
			"test-message": {
				Title: "Testing",
			},
		},
	})

	state := ht.CurrentState()
	wantID := health.WarnableCode("control-health.test-message")
	_, ok := state.Warnings[wantID]

	if !ok {
		t.Errorf("no warning found with id %q", wantID)
	}
}

// TestDisplayMessagesURLFilter tests that we filter out any URLs that are not
// valid as a pop browser URL (see [LocalBackend.validPopBrowserURL]).
func TestDisplayMessagesURLFilter(t *testing.T) {
	b := newTestLocalBackend(t)

	// Pretend we're in a map poll so health updates get processed
	ht := b.HealthTracker()
	ht.SetIPNState("NeedsLogin", true)
	ht.GotStreamedMapResponse()

	b.mu.Lock()
	defer b.mu.Unlock()
	b.setNetMapLocked(&netmap.NetworkMap{
		DisplayMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
			"test-message": {
				Title:    "Testing",
				Severity: tailcfg.SeverityHigh,
				PrimaryAction: &tailcfg.DisplayMessageAction{
					URL:   "https://www.evil.com",
					Label: "Phishing Link",
				},
			},
		},
	})

	state := ht.CurrentState()
	wantID := health.WarnableCode("control-health.test-message")
	got, ok := state.Warnings[wantID]

	if !ok {
		t.Fatalf("no warning found with id %q", wantID)
	}

	want := health.UnhealthyState{
		WarnableCode: wantID,
		Title:        "Testing",
		Severity:     health.SeverityHigh,
	}

	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(health.UnhealthyState{}, "ETag")); diff != "" {
		t.Errorf("Unexpected message content (-want/+got):\n%s", diff)
	}
}

// TestDisplayMessageIPNBus checks that we send health messages appropriately
// based on whether the watcher has sent the [ipn.NotifyHealthActions] watch
// option or not.
func TestDisplayMessageIPNBus(t *testing.T) {
	type test struct {
		name        string
		mask        ipn.NotifyWatchOpt
		wantWarning health.UnhealthyState
	}

	msgs := map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
		"test-message": {
			Title:    "Message title",
			Text:     "Message text.",
			Severity: tailcfg.SeverityMedium,
			PrimaryAction: &tailcfg.DisplayMessageAction{
				URL:   "https://example.com",
				Label: "Learn more",
			},
		},
	}

	wantID := health.WarnableCode("control-health.test-message")

	for _, tt := range []test{
		{
			name: "older-client-no-actions",
			mask: 0,
			wantWarning: health.UnhealthyState{
				WarnableCode:  wantID,
				Severity:      health.SeverityMedium,
				Title:         "Message title",
				Text:          "Message text. Learn more: https://example.com", // PrimaryAction appended to text
				PrimaryAction: nil,                                             // PrimaryAction not included
			},
		},
		{
			name: "new-client-with-actions",
			mask: ipn.NotifyHealthActions,
			wantWarning: health.UnhealthyState{
				WarnableCode: wantID,
				Severity:     health.SeverityMedium,
				Title:        "Message title",
				Text:         "Message text.",
				PrimaryAction: &health.UnhealthyStateAction{
					URL:   "https://example.com",
					Label: "Learn more",
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lb := newLocalBackendWithTestControl(t, false, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
				return newClient(tb, opts)
			})

			ipnWatcher := newNotificationWatcher(t, lb, nil)
			ipnWatcher.watch(tt.mask, []wantedNotification{{
				name: fmt.Sprintf("warning with ID %q", wantID),
				cond: func(_ testing.TB, _ ipnauth.Actor, n *ipn.Notify) bool {
					if n.Health == nil {
						return false
					}
					got, ok := n.Health.Warnings[wantID]
					if ok {
						if diff := cmp.Diff(tt.wantWarning, got, cmpopts.IgnoreFields(health.UnhealthyState{}, "ETag")); diff != "" {
							t.Errorf("unexpected warning details (-want/+got):\n%s", diff)
							return true // we failed the test so tell the watcher we've seen what we need to to stop it waiting
						}
					} else {
						got := slices.Collect(maps.Keys(n.Health.Warnings))
						t.Logf("saw warnings: %v", got)
					}
					return ok
				},
			}})

			lb.SetPrefsForTest(&ipn.Prefs{
				ControlURL:  "https://localhost:1/",
				WantRunning: true,
				LoggedOut:   false,
			})
			if err := lb.Start(ipn.Options{}); err != nil {
				t.Fatalf("(*LocalBackend).Start(): %v", err)
			}

			cc := lb.cc.(*mockControl)

			// Assert that we are logged in and authorized, and also send our DisplayMessages
			cc.send(nil, "", true, &netmap.NetworkMap{
				SelfNode:        (&tailcfg.Node{MachineAuthorized: true}).View(),
				DisplayMessages: msgs,
			})

			// Tell the health tracker that we are in a map poll because
			// mockControl doesn't tell it
			lb.HealthTracker().GotStreamedMapResponse()

			// Assert that we got the expected notification
			ipnWatcher.check()
		})
	}
}

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		OnImport: func(pkg string) {
			switch pkg {
			case "tailscale.com/util/syspolicy",
				"tailscale.com/util/syspolicy/setting",
				"tailscale.com/util/syspolicy/rsop":
				t.Errorf("ipn/ipnlocal: importing syspolicy package %q is not allowed; only policyclient and its deps should be used by ipn/ipnlocal", pkg)
			}
		},
	}.Check(t)
}

func checkError(tb testing.TB, got, want error, fatal bool) {
	tb.Helper()
	f := tb.Errorf
	if fatal {
		f = tb.Fatalf
	}
	if (want == nil) != (got == nil) ||
		(want != nil && got != nil && want.Error() != got.Error() && !errors.Is(got, want)) {
		f("gotErr: %v; wantErr: %v", got, want)
	}
}

func toStrings[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}
