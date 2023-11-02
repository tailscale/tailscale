// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/wgcfg"
)

func inRemove(ip netip.Addr) bool {
	for _, pfx := range removeFromDefaultRoute {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
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
	var logf logger.Logf = logger.Discard
	sys := new(tsd.System)
	store := new(mem.Store)
	sys.Set(store)
	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set)
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(eng.Close)
	sys.Set(eng)
	lb, err := NewLocalBackend(logf, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
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

func TestFileTargets(t *testing.T) {
	b := new(LocalBackend)
	_, err := b.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("before connect: got %q; want %q", got, want)
	}

	b.netMap = new(netmap.NetworkMap)
	_, err = b.FileTargets()
	if got, want := fmt.Sprint(err), "not connected to the tailnet"; got != want {
		t.Errorf("non-running netmap: got %q; want %q", got, want)
	}

	b.state = ipn.Running
	_, err = b.FileTargets()
	if got, want := fmt.Sprint(err), "file sharing not enabled by Tailscale admin"; got != want {
		t.Errorf("without cap: got %q; want %q", got, want)
	}

	b.capFileSharing = true
	got, err := b.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}

	var peerMap map[tailcfg.NodeID]tailcfg.NodeView
	mak.NonNil(&peerMap)
	var nodeID tailcfg.NodeID
	nodeID = 1234
	peer := &tailcfg.Node{
		ID:       1234,
		Hostinfo: (&tailcfg.Hostinfo{OS: "tvOS"}).View(),
	}
	peerMap[nodeID] = peer.View()
	b.peers = peerMap
	got, err = b.FileTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected %d peers", len(got))
	}
	// (other cases handled by TestPeerAPIBase above)
}

func TestInternalAndExternalInterfaces(t *testing.T) {
	type interfacePrefix struct {
		i   interfaces.Interface
		pfx netip.Prefix
	}

	masked := func(ips ...interfacePrefix) (pfxs []netip.Prefix) {
		for _, ip := range ips {
			pfxs = append(pfxs, ip.pfx.Masked())
		}
		return pfxs
	}
	iList := func(ips ...interfacePrefix) (il interfaces.List) {
		for _, ip := range ips {
			il = append(il, ip.i)
		}
		return il
	}
	newInterface := func(name, pfx string, wsl2, loopback bool) interfacePrefix {
		ippfx := netip.MustParsePrefix(pfx)
		ip := interfaces.Interface{
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
		il      interfaces.List
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

func TestStatusWithoutPeers(t *testing.T) {
	b := newTestLocalBackend(t)

	var cc *mockControl
	b.SetControlClientGetterForTesting(func(opts controlclient.Options) (controlclient.Client, error) {
		cc = newClient(t, opts)

		t.Logf("ccGen: new mockControl.")
		cc.called("New")
		return cc, nil
	})
	b.Start(ipn.Options{})
	b.Login(nil)
	cc.send(nil, "", false, &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			MachineAuthorized: true,
			Addresses:         ipps("100.101.101.101"),
		}).View(),
	})
	got := b.StatusWithoutPeers()
	if got.TailscaleIPs == nil {
		t.Errorf("got nil, expected TailscaleIPs value to not be nil")
	}
	if !reflect.DeepEqual(got.TailscaleIPs, got.Self.TailscaleIPs) {
		t.Errorf("got %v, expected %v", got.TailscaleIPs, got.Self.TailscaleIPs)
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
	// StartLoginInteractive requests to start a new interactive login
	// flow. This should trigger a new BrowseToURL notification
	// eventually.
	StartLoginInteractive()
	// Login logs in with an OAuth2 token.
	Login(token *tailcfg.Oauth2Token)
	// SetPrefs installs a new set of user preferences, including
	// WantRunning. This may cause the wireguard engine to
	// reconfigure or stop.
	SetPrefs(*ipn.Prefs)
	// RequestEngineStatus polls for an update from the wireguard
	// engine. Only needed if you want to display byte
	// counts. Connection events are emitted automatically without
	// polling.
	RequestEngineStatus()
}

// Verify that LocalBackend still implements the legacyBackend interface
// for now, at least until the macOS and iOS clients move off of it.
var _ legacyBackend = (*LocalBackend)(nil)

func TestWatchNotificationsCallbacks(t *testing.T) {
	b := new(LocalBackend)
	// activeWatchSessions is typically set in NewLocalBackend
	// so WatchNotifications expects it to be non-empty.
	b.activeWatchSessions = make(set.Set[string])
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
	var b LocalBackend
	if b.updateNetmapDeltaLocked(nil) {
		t.Errorf("updateNetmapDeltaLocked() = true, want false with nil netmap")
	}

	b.netMap = &netmap.NetworkMap{}
	for i := 0; i < 5; i++ {
		b.netMap.Peers = append(b.netMap.Peers, (&tailcfg.Node{ID: (tailcfg.NodeID(i) + 1)}).View())
	}
	b.updatePeersFromNetmapLocked(b.netMap)

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

	if !b.updateNetmapDeltaLocked(muts) {
		t.Fatalf("updateNetmapDeltaLocked() = false, want true with new netmap")
	}

	wants := []*tailcfg.Node{
		{
			ID:   1,
			DERP: "127.3.3.40:1",
		},
		{
			ID:     2,
			Online: ptr.To(true),
		},
		{
			ID:     3,
			Online: ptr.To(false),
		},
		{
			ID:       4,
			LastSeen: ptr.To(someTime),
		},
	}
	for _, want := range wants {
		gotv, ok := b.peers[want.ID]
		if !ok {
			t.Errorf("netmap.Peer %v missing from b.peers", want.ID)
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
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.101.102.103/32")},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:        2,
				User:      20,
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.200.200.200/32")},
			}).View(),
		},
		UserProfiles: map[tailcfg.UserID]tailcfg.UserProfile{
			10: {
				DisplayName: "Myself",
			},
			20: {
				DisplayName: "Peer",
			},
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
			nv, up, ok := b.WhoIs(netip.MustParseAddrPort(tt.q))
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

	defaultResolvers := []*dnstype.Resolver{{Addr: "default.example.com"}}
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
	routes := map[dnsname.FQDN][]*dnstype.Resolver{
		"route.example.com.": {{Addr: "route.example.com"}},
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

		// The following two cases may need to be revisited. For a shared-in
		// exit node split-DNS may effectively break, furthermore in the future
		// if different nodes observe different DNS configurations, even a
		// tailnet local exit node may present a different DNS configuration,
		// which may not meet expectations in some use cases.
		// In the case where a default resolver is set, the default resolver
		// should also perhaps take precedence also.
		{
			name:                 "tsExit/routes/noResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(routes)},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           nil,
		},
		{
			name:                 "tsExit/routes/defaultResolver",
			exitNode:             "ts",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(routes), Resolvers: defaultResolvers},
			wantDefaultResolvers: []*dnstype.Resolver{{Addr: exitDOH}},
			wantRoutes:           nil,
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
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(routes), Resolvers: defaultResolvers},
			wantDefaultResolvers: defaultResolvers,
			wantRoutes:           routes,
		},
		{
			name:                 "wgExit/routes/noResolver",
			exitNode:             "wg",
			peers:                peers,
			dnsConfig:            &tailcfg.DNSConfig{Routes: stringifyRoutes(routes)},
			wantDefaultResolvers: wgResolvers,
			wantRoutes:           routes,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nm := &netmap.NetworkMap{
				Peers: tc.peers,
				DNS:   *tc.dnsConfig,
			}

			prefs := &ipn.Prefs{ExitNodeID: tc.exitNode, CorpDNS: true}
			got := dnsConfigForNetmap(nm, peersMap(tc.peers), prefs.View(), t.Logf, "")
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
	b := newTestBackend(t)
	if b.OfferingAppConnector() {
		t.Fatal("unexpected offering app connector")
	}
	b.appConnector = appc.NewEmbeddedAppConnector(t.Logf, nil)
	if !b.OfferingAppConnector() {
		t.Fatal("unexpected not offering app connector")
	}
}

func TestAppConnectorHostinfoService(t *testing.T) {
	hasAppConnectorService := func(s []tailcfg.Service) bool {
		for _, s := range s {
			if s.Proto == tailcfg.AppConnector && s.Port == 1 {
				return true
			}
		}
		return false
	}

	b := newTestBackend(t)
	b.mu.Lock()
	defer b.mu.Unlock()
	if hasAppConnectorService(b.peerAPIServicesLocked()) {
		t.Fatal("unexpected app connector service")
	}
	b.appConnector = appc.NewEmbeddedAppConnector(t.Logf, nil)
	if !hasAppConnectorService(b.peerAPIServicesLocked()) {
		t.Fatal("expected app connector service")
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
}

func TestObserveDNSResponse(t *testing.T) {
	b := newTestBackend(t)

	// ensure no error when no app connector is configured
	b.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))

	rc := &routeCollector{}
	b.appConnector = appc.NewEmbeddedAppConnector(t.Logf, rc)
	b.appConnector.UpdateDomains([]string{"example.com"})

	b.ObserveDNSResponse(dnsResponse("example.com.", "192.0.0.8"))
	wantRoutes := []netip.Prefix{netip.MustParsePrefix("192.0.0.8/32")}
	if !slices.Equal(rc.routes, wantRoutes) {
		t.Fatalf("got routes %v, want %v", rc.routes, wantRoutes)
	}
}

func TestReconfigureAppConnector(t *testing.T) {
	b := newTestBackend(t)
	b.reconfigAppConnectorLocked(b.netMap, b.pm.prefs)
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
	b.reconfigAppConnectorLocked(b.netMap, b.pm.prefs)
	if b.appConnector == nil {
		t.Fatal("expected app connector")
	}

	appCfg := `{
		"name": "example",
		"domains": ["example.com"],
		"connectors": ["tag:example"]
	}`

	b.netMap.SelfNode = (&tailcfg.Node{
		Name: "example.ts.net",
		Tags: []string{"tag:example"},
		CapMap: (tailcfg.NodeCapMap)(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
			"tailscale.com/app-connectors": {tailcfg.RawMessage(appCfg)},
		}),
	}).View()

	b.reconfigAppConnectorLocked(b.netMap, b.pm.prefs)

	want := []string{"example.com"}
	if !slices.Equal(b.appConnector.Domains().AsSlice(), want) {
		t.Fatalf("got domains %v, want %v", b.appConnector.Domains(), want)
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

// routeCollector is a test helper that collects the list of routes advertised
type routeCollector struct {
	routes []netip.Prefix
}

func (rc *routeCollector) AdvertiseRoute(pfx netip.Prefix) error {
	rc.routes = append(rc.routes, pfx)
	return nil
}
