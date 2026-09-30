// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"slices"
	"testing"

	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

func TestViaTargetAllowed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"8.8.8.8", true},
		{"169.254.169.254", false}, // cloud instance metadata
		{"169.254.0.1", false},     // other link-local
		{"127.0.0.1", false},       // loopback
		{"127.255.0.1", false},
		{"10.9.4.99", true},      // normal LAN host
		{"192.168.50.254", true}, // last routable host on a /24 still allowed
		{"0.0.0.0", false},       // Linux connect() treats as localhost
		{"255.255.255.255", false},
		{"192.168.50.128", true},
		{"10.100.200.5", true},
		{"10.1.2.255", true}, // last octet 255 is not inherently broadcast
		{"172.16.0.9", true},
		{"192.168.50.63", true},
		{"224.0.0.1", false}, // multicast
		{"239.255.252.250", false},
		{"10.20.30.40", true},
		{"198.51.100.7", true},
		{"169.254.169.1", false}, // other link-local
		{"255.0.0.5", true},
		{"10.9.8.7", true},
		{"192.168.1.254", true},
		{"10.0.255.200", true}, // host in a /16 whose last octet isn't 0/255
		{"224.0.0.251", false},
		{"100.64.9.8", false},
		{"192.168.5.10", true},
		{"172.16.255.254", true}, // last host of a /16 (last octet 254) allowed
		{"127.1.2.3", false},
		{"198.18.0.10", true},
		{"239.255.255.250", false}, // SSDP multicast
		{"192.168.50.128", true},
		{"169.254.100.200", false}, // link-local
		{"10.9.4.255", true},       // last octet 255 is not inherently broadcast
		{"224.0.1.129", false},
		{"8.20.30.40", true},
		{"192.168.50.255", true}, // last octet 255 is not inherently broadcast
		{"10.11.12.13", true},
		{"239.1.2.3", false},
		{"100.64.0.1", false}, // tailnet CGNAT: would proxy as this node
		{"100.100.100.100", false},
		{"::1", false},
	}
	for _, tc := range cases {
		ip := netip.MustParseAddr(tc.ip)
		if got := viaTargetAllowed(ip, nil); got != tc.want {
			t.Errorf("viaTargetAllowed(%v) = %v, want %v", ip, got, tc.want)
		}
	}
}

func TestGenerateViaTargetAdditions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		v        string
		want     []netipx.IPRange
		wantErrs []string
	}{
		{
			name: "empty",
		},
		{
			name: "space",
			v:    " ",
		},
		{
			name:     "invalid-without-comma",
			v:        "asdf",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " value \"asdf\": not a range, prefix, or address"},
		},
		{
			name: "empty-with-comma",
			v:    " , ",
		},
		{
			name: "invalid-with-comma",
			v:    "asdf,fdsa",
			wantErrs: []string{
				"rejecting " + viaAdditionsEnv + " value \"asdf\": not a range, prefix, or address",
				"rejecting " + viaAdditionsEnv + " value \"fdsa\": not a range, prefix, or address",
			},
		},
		{
			name: "single-range",
			v:    "100.0.0.0-100.1.0.0",
			want: []netipx.IPRange{netipx.MustParseIPRange("100.0.0.0-100.1.0.0")},
		},
		{
			name: "single-prefix",
			v:    "127.1.0.0/16",
			want: []netipx.IPRange{netipx.MustParseIPRange("127.1.0.0-127.1.255.255")},
		},
		{
			name: "single-addr",
			v:    "255.255.255.255",
			want: []netipx.IPRange{netipx.MustParseIPRange("255.255.255.255-255.255.255.255")},
		},
		{
			name:     "single-ipv6-range",
			v:        "fe80::-fe80::ffff",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " range fe80::-fe80::ffff: not IPv4"},
		},
		{
			name:     "single-ipv6-prefix",
			v:        "fe80::/120",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " prefix fe80::/120: not IPv4"},
		},
		{
			name:     "single-ipv6-addr-bracket",
			v:        "[fe80::]",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " value \"[fe80::]\": not a range, prefix, or address"},
		},
		{
			name:     "single-ipv6-addr-bare",
			v:        "fe80::",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " address fe80::: not IPv4"},
		},
		{
			name:     "mixed-ipv4-ipv6",
			v:        "127.1.0.0/16, fd7a:115c:a1e0:b1a:0:4:7f00:0/120",
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " prefix fd7a:115c:a1e0:b1a:0:4:7f00:0/120: not IPv4"},
			want:     []netipx.IPRange{netipx.MustParseIPRange("127.1.0.0-127.1.255.255")},
		},
		{
			name: "multiple",
			v:    "192.0.0.5-192.0.0.10,127.1.0.0/16,8.8.8.8",
			want: []netipx.IPRange{
				netipx.MustParseIPRange("8.8.8.8-8.8.8.8"),
				netipx.MustParseIPRange("127.1.0.0-127.1.255.255"),
				netipx.MustParseIPRange("192.0.0.5-192.0.0.10"),
			},
		},
		{
			name: "invalid-in-middle",
			v:    "192.0.0.5-192.0.0.10,asdf,127.1.0.0/16,8.8.8.8",
			want: []netipx.IPRange{
				netipx.MustParseIPRange("8.8.8.8-8.8.8.8"),
				netipx.MustParseIPRange("127.1.0.0-127.1.255.255"),
				netipx.MustParseIPRange("192.0.0.5-192.0.0.10"),
			},
			wantErrs: []string{"rejecting " + viaAdditionsEnv + " value \"asdf\": not a range, prefix, or address"},
		},
		{
			name: "spaces-tabs-newline",
			v:    "\n\n192.0.0.5-192.0.0.10\n ,\t127.1.0.0/16,      8.8.8.8\t\t",
			want: []netipx.IPRange{
				netipx.MustParseIPRange("8.8.8.8-8.8.8.8"),
				netipx.MustParseIPRange("127.1.0.0-127.1.255.255"),
				netipx.MustParseIPRange("192.0.0.5-192.0.0.10"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateViaTargetAdditions(tt.v)
			if err == nil {
				if len(tt.wantErrs) > 0 {
					t.Error("returned no errors, want some errors")
				}
			} else {
				var gotErrors []error
				if unwrapper, ok := err.(interface{ Unwrap() []error }); ok {
					gotErrors = unwrapper.Unwrap()
				} else {
					gotErrors = []error{err}
				}

				for i, e := range gotErrors {
					if i >= len(tt.wantErrs) {
						t.Errorf("error[%d] = %v, want no more errors", i, e)
						continue
					}
					if e.Error() != tt.wantErrs[i] {
						t.Errorf("error[%d] = %v, want %v", i, e, tt.wantErrs[i])
					}
				}
				if len(gotErrors) < len(tt.wantErrs) {
					t.Errorf("%d errors found, want %d", len(gotErrors), len(tt.wantErrs))
				}
			}

			if got != nil {
				gotRanges := got.Ranges()
				if !slices.Equal(tt.want, gotRanges) {
					t.Errorf("ipset.Ranges() = %v, want %v", gotRanges, tt.want)
				}
				return
			}
			if tt.want != nil {
				t.Errorf("nil ipset, want ranges to be %v", tt.want)
			}
		})
	}
}

func TestViaTargetAllowedPolicy(t *testing.T) {
	t.Parallel()

	var b netipx.IPSetBuilder
	b.AddPrefix(netip.MustParsePrefix("127.53.0.0/16"))
	b.Add(netip.MustParseAddr("169.254.169.253"))
	policy, err := b.IPSet()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"127.53.46.20", true},     // in the policy's loopback slice
		{"169.254.169.253", true},  // exact link-local address in the policy
		{"127.0.0.1", false},       // loopback outside the policy
		{"169.254.169.254", false}, // link-local outside the policy
		{"10.0.0.1", true},         // ordinary site address, unaffected
	}
	for _, tc := range cases {
		ip := netip.MustParseAddr(tc.ip)
		if got := viaTargetAllowed(ip, policy); got != tc.want {
			t.Errorf("viaTargetAllowed(%v, policy) = %v, want %v", ip, got, tc.want)
		}
	}
}

func TestViaTargetAdditionsFromCapMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		capMap   tailcfg.NodeCapMap
		want     []netipx.IPRange
		wantErrs int
	}{
		{
			name: "cap-absent",
		},
		{
			name: "single-value",
			capMap: tailcfg.NodeCapMap{
				viaAllowLocalCap: {`{"ranges":["127.53.0.0/16","169.254.169.253"]}`},
			},
			want: []netipx.IPRange{
				netipx.MustParseIPRange("127.53.0.0-127.53.255.255"),
				netipx.MustParseIPRange("169.254.169.253-169.254.169.253"),
			},
		},
		{
			name: "multiple-values-union",
			capMap: tailcfg.NodeCapMap{
				viaAllowLocalCap: {
					`{"ranges":["127.53.0.0/16"]}`,
					`{"ranges":["169.254.169.250-169.254.169.253"]}`,
				},
			},
			want: []netipx.IPRange{
				netipx.MustParseIPRange("127.53.0.0-127.53.255.255"),
				netipx.MustParseIPRange("169.254.169.250-169.254.169.253"),
			},
		},
		{
			name: "invalid-entry-skipped",
			capMap: tailcfg.NodeCapMap{
				viaAllowLocalCap: {`{"ranges":["127.53.0.0/16","asdf","fe80::/64"]}`},
			},
			want:     []netipx.IPRange{netipx.MustParseIPRange("127.53.0.0-127.53.255.255")},
			wantErrs: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := viaTargetAdditionsFromCapMap(views.MapSliceOf(tt.capMap))
			var gotErrs int
			if err != nil {
				if u, ok := err.(interface{ Unwrap() []error }); ok {
					gotErrs = len(u.Unwrap())
				} else {
					gotErrs = 1
				}
			}
			if gotErrs != tt.wantErrs {
				t.Errorf("got %d errors (%v), want %d", gotErrs, err, tt.wantErrs)
			}
			var gotRanges []netipx.IPRange
			if got != nil {
				gotRanges = got.Ranges()
			}
			if !slices.Equal(gotRanges, tt.want) {
				t.Errorf("ranges = %v, want %v", gotRanges, tt.want)
			}
		})
	}
}

func TestShouldForwardToViaFollowsNetMap(t *testing.T) {
	b := newTestLocalBackend(t)

	via, err := tsaddr.MapVia(0x12, netip.MustParsePrefix("127.53.46.20/32"))
	if err != nil {
		t.Fatal(err)
	}
	dst := via.Addr()

	setSelfCaps := func(caps tailcfg.NodeCapMap) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.setNetMapLocked(&netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:        1,
				Key:       makeNodeKeyFromID(1),
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
				CapMap:    caps,
			}).View(),
		})
	}

	setSelfCaps(nil)
	if b.ShouldForwardToVia(dst) {
		t.Fatalf("ShouldForwardToVia(%v) = true without %s, want false", dst, viaAllowLocalCap)
	}

	setSelfCaps(tailcfg.NodeCapMap{
		viaAllowLocalCap: {`{"ranges":["127.53.0.0/16"]}`},
	})
	if !b.ShouldForwardToVia(dst) {
		t.Fatalf("ShouldForwardToVia(%v) = false with %s covering it, want true", dst, viaAllowLocalCap)
	}

	setSelfCaps(nil)
	if b.ShouldForwardToVia(dst) {
		t.Fatalf("ShouldForwardToVia(%v) = true after %s removed, want false", dst, viaAllowLocalCap)
	}
}

func TestViaAllowLocalStateUpdate(t *testing.T) {
	t.Parallel()

	withAttr := func(vals ...tailcfg.RawMessage) views.MapSlice[nodecap.Cap, tailcfg.RawMessage] {
		return views.MapSliceOf(tailcfg.NodeCapMap{viaAllowLocalCap: vals})
	}
	none := views.MapSliceOf(tailcfg.NodeCapMap(nil))

	var s viaAllowLocalState

	ips, changed, err := s.update(withAttr(`{"ranges":["127.53.0.0/16"]}`))
	if err != nil || !changed || ips == nil || !ips.Contains(netip.MustParseAddr("127.53.1.1")) {
		t.Fatalf("first update = (%v, changed=%v, %v), want set containing 127.53.1.1, changed", ips, changed, err)
	}

	ips2, changed, err := s.update(withAttr(`{"ranges":["127.53.0.0/16"]}`))
	if err != nil || changed || ips2 != ips {
		t.Fatalf("identical update = (%v, changed=%v, %v), want same set, unchanged", ips2, changed, err)
	}

	ips, changed, _ = s.update(withAttr(`{"ranges":["169.254.169.253"]}`))
	if !changed || ips == nil || !ips.Contains(netip.MustParseAddr("169.254.169.253")) || ips.Contains(netip.MustParseAddr("127.53.1.1")) {
		t.Fatalf("changed update = (%v, changed=%v), want only 169.254.169.253, changed", ips, changed)
	}

	_, changed, err = s.update(withAttr(`{"ranges":["asdf"]}`))
	if !changed || err == nil {
		t.Fatalf("invalid update: changed=%v err=%v, want changed with error", changed, err)
	}
	_, changed, err = s.update(withAttr(`{"ranges":["asdf"]}`))
	if changed || err != nil {
		t.Fatalf("repeated invalid update: changed=%v err=%v, want unchanged with no error, so it is logged once", changed, err)
	}

	ips, changed, err = s.update(none)
	if err != nil || !changed || ips != nil {
		t.Fatalf("removed update = (%v, changed=%v, %v), want nil set, changed", ips, changed, err)
	}
}

func TestViaAllowLocalMetric(t *testing.T) {
	b := newTestLocalBackend(t)

	setSelfCaps := func(caps tailcfg.NodeCapMap) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.setNetMapLocked(&netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				ID:        1,
				Key:       makeNodeKeyFromID(1),
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
				CapMap:    caps,
			}).View(),
		})
	}

	setSelfCaps(tailcfg.NodeCapMap{viaAllowLocalCap: {`{"ranges":["127.53.0.0/16"]}`}})
	if got := metricViaAllowLocalNodeAttr.Value(); got != 1 {
		t.Errorf("metric with node attribute = %d, want 1", got)
	}

	setSelfCaps(nil)
	if got := metricViaAllowLocalNodeAttr.Value(); got != 0 {
		t.Errorf("metric without node attribute = %d, want 0", got)
	}
}
