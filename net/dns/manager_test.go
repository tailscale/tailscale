// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

type fakeOSConfigurator struct {
	SplitDNS   bool
	BaseConfig OSConfig

	OSConfig         OSConfig
	ResolverConfig   resolver.Config
	GetBaseConfigErr *error
}

func (c *fakeOSConfigurator) SetDNS(cfg OSConfig) error {
	if !c.SplitDNS && len(cfg.MatchDomains) > 0 {
		panic("split DNS config passed to non-split OSConfigurator")
	}
	c.OSConfig = cfg
	return nil
}

func (c *fakeOSConfigurator) SetResolver(cfg resolver.Config) {
	c.ResolverConfig = cfg
}

func (c *fakeOSConfigurator) SupportsSplitDNS() bool {
	return c.SplitDNS
}

func (c *fakeOSConfigurator) GetBaseConfig() (OSConfig, error) {
	if c.GetBaseConfigErr != nil {
		return OSConfig{}, *c.GetBaseConfigErr
	}
	return c.BaseConfig, nil
}

func (c *fakeOSConfigurator) Close() error { return nil }

func TestCompileHostEntries(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want []*HostEntry
	}{
		{
			name: "empty",
		},
		{
			name: "no-search-domains",
			cfg: Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"a.b.c.": {netip.MustParseAddr("1.1.1.1")},
				},
			},
		},
		{
			name: "search-domains",
			cfg: Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"a.foo.ts.net.":             {netip.MustParseAddr("1.1.1.1")},
					"b.foo.ts.net.":             {netip.MustParseAddr("1.1.1.2")},
					"c.foo.ts.net.":             {netip.MustParseAddr("1.1.1.3")},
					"d.foo.beta.tailscale.net.": {netip.MustParseAddr("1.1.1.4")},
					"d.foo.ts.net.":             {netip.MustParseAddr("1.1.1.4")},
					"e.foo.beta.tailscale.net.": {netip.MustParseAddr("1.1.1.5")},
					"random.example.com.":       {netip.MustParseAddr("1.1.1.1")},
					"other.example.com.":        {netip.MustParseAddr("1.1.1.2")},
					"othertoo.example.com.":     {netip.MustParseAddr("1.1.5.2")},
				},
				SearchDomains: []dnsname.FQDN{"foo.ts.net.", "foo.beta.tailscale.net."},
			},
			want: []*HostEntry{
				{Addr: netip.MustParseAddr("1.1.1.1"), Hosts: []string{"a.foo.ts.net.", "a"}},
				{Addr: netip.MustParseAddr("1.1.1.2"), Hosts: []string{"b.foo.ts.net.", "b"}},
				{Addr: netip.MustParseAddr("1.1.1.3"), Hosts: []string{"c.foo.ts.net.", "c"}},
				{Addr: netip.MustParseAddr("1.1.1.4"), Hosts: []string{"d.foo.ts.net.", "d", "d.foo.beta.tailscale.net."}},
				{Addr: netip.MustParseAddr("1.1.1.5"), Hosts: []string{"e.foo.beta.tailscale.net.", "e"}},
			},
		},
		{
			name: "only-exact-subdomain-match",
			cfg: Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"e.foo.ts.net.":                     {netip.MustParseAddr("1.1.1.5")},
					"e.foo.beta.tailscale.net.":         {netip.MustParseAddr("1.1.1.5")},
					"e.ignored.foo.beta.tailscale.net.": {netip.MustParseAddr("1.1.1.6")},
				},
				SearchDomains: []dnsname.FQDN{"foo.ts.net.", "foo.beta.tailscale.net."},
			},
			want: []*HostEntry{
				{Addr: netip.MustParseAddr("1.1.1.5"), Hosts: []string{"e.foo.ts.net.", "e", "e.foo.beta.tailscale.net."}},
			},
		},
		{
			name: "unmatched-domains",
			cfg: Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"d.foo.beta.tailscale.net.": {netip.MustParseAddr("1.1.1.4")},
					"d.foo.ts.net.":             {netip.MustParseAddr("1.1.1.4")},
					"random.example.com.":       {netip.MustParseAddr("1.1.1.1")},
					"other.example.com.":        {netip.MustParseAddr("1.1.1.2")},
					"othertoo.example.com.":     {netip.MustParseAddr("1.1.5.2")},
				},
				SearchDomains: []dnsname.FQDN{"foo.ts.net.", "foo.beta.tailscale.net."},
			},
			want: []*HostEntry{
				{Addr: netip.MustParseAddr("1.1.1.4"), Hosts: []string{"d.foo.ts.net.", "d", "d.foo.beta.tailscale.net."}},
			},
		},
		{
			name: "overlaps",
			cfg: Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"h1.foo.ts.net.":             {netip.MustParseAddr("1.1.1.3")},
					"h1.foo.beta.tailscale.net.": {netip.MustParseAddr("1.1.1.2")},
					"h2.foo.ts.net.":             {netip.MustParseAddr("1.1.1.1")},
					"h2.foo.beta.tailscale.net.": {netip.MustParseAddr("1.1.1.1")},
					"example.com":                {netip.MustParseAddr("1.1.1.1")},
				},
				SearchDomains: []dnsname.FQDN{"foo.ts.net.", "foo.beta.tailscale.net."},
			},
			want: []*HostEntry{
				{Addr: netip.MustParseAddr("1.1.1.2"), Hosts: []string{"h1.foo.beta.tailscale.net."}},
				{Addr: netip.MustParseAddr("1.1.1.3"), Hosts: []string{"h1.foo.ts.net.", "h1"}},
				{Addr: netip.MustParseAddr("1.1.1.1"), Hosts: []string{"h2.foo.ts.net.", "h2", "h2.foo.beta.tailscale.net."}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := compileHostEntries(tc.cfg)
			if diff := cmp.Diff(tc.want, got, cmp.Comparer(func(a, b netip.Addr) bool {
				return a == b
			})); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestManager(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("test's assumptions break because of https://github.com/tailscale/corp/issues/1662")
	}

	// Note: these tests assume that it's safe to switch the
	// OSConfigurator's split-dns support on and off between Set
	// calls. Empirically this is currently true, because we reprobe
	// the support every time we generate configs. It would be
	// reasonable to make this unsupported as well, in which case
	// these tests will need tweaking.
	tests := []struct {
		name  string
		in    Config
		split bool
		bs    OSConfig
		os    OSConfig
		rs    resolver.Config
		goos  string // empty means "linux"
	}{
		{
			name: "empty",
		},
		{
			name: "search-only",
			in: Config{
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
		},
		{
			// Regression test for https://github.com/tailscale/tailscale/issues/1886
			name: "hosts-only",
			in: Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
			},
			rs: resolver.Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
			},
		},
		{
			// If Hosts are specified (i.e. ExtraRecords) that aren't a split
			// DNS route and a global resolver is specified, then make
			// everything go via 100.100.100.100.
			name:  "hosts-with-global-dns-uses-quad100",
			split: true,
			in: Config{
				DefaultResolvers: mustRes("1.1.1.1", "9.9.9.9"),
				Hosts: hosts(
					"foo.tld.", "1.2.3.4",
					"bar.tld.", "2.3.4.5"),
			},
			os: OSConfig{
				Nameservers: mustIPs("100.100.100.100"),
			},
			rs: resolver.Config{
				Hosts: hosts(
					"foo.tld.", "1.2.3.4",
					"bar.tld.", "2.3.4.5"),
				Routes: upstreams(".", "1.1.1.1", "9.9.9.9"),
			},
		},
		{
			// This is the above hosts-with-global-dns-uses-quad100 test but
			// verifying that if global DNS servers aren't set (the 1.1.1.1 and
			// 9.9.9.9 above), then we don't configure 100.100.100.100 as the
			// resolver.
			name:  "hosts-without-global-dns-not-use-quad100",
			split: true,
			in: Config{
				Hosts: hosts(
					"foo.tld.", "1.2.3.4",
					"bar.tld.", "2.3.4.5"),
			},
			os: OSConfig{},
			rs: resolver.Config{
				Hosts: hosts(
					"foo.tld.", "1.2.3.4",
					"bar.tld.", "2.3.4.5"),
			},
		},
		{
			// This tests that ExtraRecords (foo.tld and bar.tld here) don't trigger forcing
			// traffic through 100.100.100.100 if there's Split DNS support and the extra
			// records are part of a split DNS route.
			name:  "hosts-with-extrarecord-hosts-with-routes-no-quad100",
			split: true,
			in: Config{
				Routes: upstreams(
					"tld.", "4.4.4.4",
				),
				Hosts: hosts(
					"foo.tld.", "1.2.3.4",
					"bar.tld.", "2.3.4.5"),
			},
			os: OSConfig{
				Nameservers:  mustIPs("4.4.4.4"),
				MatchDomains: fqdns("tld."),
			},
			rs: resolver.Config{
				Hosts: hosts(
					"foo.tld.", "1.2.3.4",
					"bar.tld.", "2.3.4.5"),
			},
		},
		{
			name: "corp",
			in: Config{
				DefaultResolvers: mustRes("1.1.1.1", "9.9.9.9"),
				SearchDomains:    fqdns("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("1.1.1.1", "9.9.9.9"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
		},
		{
			name: "corp-split",
			in: Config{
				DefaultResolvers: mustRes("1.1.1.1", "9.9.9.9"),
				SearchDomains:    fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("1.1.1.1", "9.9.9.9"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
		},
		{
			name: "corp-magic",
			in: Config{
				DefaultResolvers: mustRes("1.1.1.1", "9.9.9.9"),
				SearchDomains:    fqdns("tailscale.com", "universe.tf"),
				Routes:           upstreams("ts.com", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "1.1.1.1", "9.9.9.9"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
		},
		{
			name: "corp-magic-split",
			in: Config{
				DefaultResolvers: mustRes("1.1.1.1", "9.9.9.9"),
				SearchDomains:    fqdns("tailscale.com", "universe.tf"),
				Routes:           upstreams("ts.com", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "1.1.1.1", "9.9.9.9"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
		},
		{
			name: "corp-routes",
			in: Config{
				DefaultResolvers: mustRes("1.1.1.1", "9.9.9.9"),
				Routes:           upstreams("corp.com", "2.2.2.2"),
				SearchDomains:    fqdns("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "1.1.1.1", "9.9.9.9",
					"corp.com.", "2.2.2.2"),
			},
		},
		{
			name: "corp-routes-split",
			in: Config{
				DefaultResolvers: mustRes("1.1.1.1", "9.9.9.9"),
				Routes:           upstreams("corp.com", "2.2.2.2"),
				SearchDomains:    fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "1.1.1.1", "9.9.9.9",
					"corp.com.", "2.2.2.2"),
			},
		},
		{
			name: "routes",
			in: Config{
				Routes:        upstreams("corp.com", "2.2.2.2"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			bs: OSConfig{
				Nameservers:   mustIPs("8.8.8.8"),
				SearchDomains: fqdns("coffee.shop"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf", "coffee.shop"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "8.8.8.8",
					"corp.com.", "2.2.2.2"),
			},
		},
		{
			name: "routes-split",
			in: Config{
				Routes:        upstreams("corp.com", "2.2.2.2"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("2.2.2.2"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
				MatchDomains:  fqdns("corp.com"),
			},
		},
		{
			name: "routes-multi",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"bigco.net", "3.3.3.3"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			bs: OSConfig{
				Nameservers:   mustIPs("8.8.8.8"),
				SearchDomains: fqdns("coffee.shop"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf", "coffee.shop"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "8.8.8.8",
					"corp.com.", "2.2.2.2",
					"bigco.net.", "3.3.3.3"),
			},
		},
		{
			name: "routes-multi-split-linux",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"bigco.net", "3.3.3.3"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
				MatchDomains:  fqdns("bigco.net", "corp.com"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					"corp.com.", "2.2.2.2",
					"bigco.net.", "3.3.3.3"),
			},
			goos: "linux",
		},
		{
			// The `routes-multi-split-linux` test case above on Darwin should NOT result in a split
			// DNS configuration.
			// Check that MatchDomains is empty. Due to Apple limitations, we cannot set MatchDomains
			// without those domains also being SearchDomains.
			name: "routes-multi-does-not-split-on-darwin",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"bigco.net", "3.3.3.3"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: false,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "",
					"corp.com.", "2.2.2.2",
					"bigco.net.", "3.3.3.3"),
			},
			goos: "darwin",
		},
		{
			// The `routes-multi-split-linux` test case above on iOS should NOT result in a split
			// DNS configuration.
			// Check that MatchDomains is empty. Due to Apple limitations, we cannot set MatchDomains
			// without those domains also being SearchDomains.
			name: "routes-multi-does-not-split-on-ios",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"bigco.net", "3.3.3.3"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: false,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "",
					"corp.com.", "2.2.2.2",
					"bigco.net.", "3.3.3.3"),
			},
			goos: "ios",
		},
		{
			name: "magic",
			in: Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				Routes:        upstreams("ts.com", ""),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			bs: OSConfig{
				Nameservers:   mustIPs("8.8.8.8"),
				SearchDomains: fqdns("coffee.shop"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf", "coffee.shop"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "8.8.8.8"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
		},
		{
			name: "magic-split",
			in: Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				Routes:        upstreams("ts.com", ""),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
				MatchDomains:  fqdns("ts.com"),
			},
			rs: resolver.Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
			goos: "linux",
		},
		{
			// The `magic-split` test case above on Darwin should NOT result in a split DNS configuration.
			// Check that MatchDomains is empty. Due to Apple limitations, we cannot set MatchDomains
			// without those domains also being SearchDomains.
			name: "magic-split-does-not-split-on-darwin",
			in: Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				Routes:        upstreams("ts.com", ""),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: false,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
			goos: "darwin",
		},
		{
			// The `magic-split` test case above on iOS should NOT result in a split DNS configuration.
			// Check that MatchDomains is empty. Due to Apple limitations, we cannot set MatchDomains
			// without those domains also being SearchDomains.
			name: "magic-split-does-not-split-on-ios",
			in: Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				Routes:        upstreams("ts.com", ""),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: false,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
			goos: "ios",
		},
		{
			name: "routes-magic",
			in: Config{
				Routes: upstreams("corp.com", "2.2.2.2", "ts.com", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			bs: OSConfig{
				Nameservers:   mustIPs("8.8.8.8"),
				SearchDomains: fqdns("coffee.shop"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf", "coffee.shop"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					"corp.com.", "2.2.2.2",
					".", "8.8.8.8"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
		},
		{
			name: "routes-magic-split-linux",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"ts.com", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
				MatchDomains:  fqdns("corp.com", "ts.com"),
			},
			rs: resolver.Config{
				Routes: upstreams("corp.com.", "2.2.2.2"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
			goos: "linux",
		},
		{
			// The `routes-magic-split-linux` test case above on Darwin should NOT result in a
			// split DNS configuration.
			// Check that MatchDomains is empty. Due to Apple limitations, we cannot set MatchDomains
			// without those domains also being SearchDomains.
			name: "routes-magic-does-not-split-on-darwin",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"ts.com", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "",
					"corp.com.", "2.2.2.2",
				),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
			goos: "darwin",
		},
		{
			// The `routes-magic-split-linux` test case above on Darwin should NOT result in a
			// split DNS configuration.
			// Check that MatchDomains is empty. Due to Apple limitations, we cannot set MatchDomains
			// without those domains also being SearchDomains.
			name: "routes-magic-does-not-split-on-ios",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"ts.com", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "",
					"corp.com.", "2.2.2.2",
				),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
			goos: "ios",
		},
		{
			name: "exit-node-forward",
			in: Config{
				DefaultResolvers: mustRes("http://[fd7a:115c:a1e0:ab12:4843:cd96:6245:7a66]:2982/doh"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "http://[fd7a:115c:a1e0:ab12:4843:cd96:6245:7a66]:2982/doh"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
			},
		},
		{
			name: "corp-v6",
			in: Config{
				DefaultResolvers: mustRes("1::1"),
			},
			os: OSConfig{
				Nameservers: mustIPs("1::1"),
			},
		},
		{
			// This one's structurally the same as the previous one (corp-v6), but
			// instead of 1::1 as the IPv6 address, it uses a NextDNS IPv6 address which
			// is specially recognized.
			name: "corp-v6-nextdns",
			in: Config{
				DefaultResolvers: mustRes("2a07:a8c0::c3:a884"),
			},
			os: OSConfig{
				Nameservers: mustIPs("100.100.100.100"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "2a07:a8c0::c3:a884"),
			},
		},
		{
			name: "nextdns-doh",
			in: Config{
				DefaultResolvers: mustRes("https://dns.nextdns.io/c3a884"),
			},
			os: OSConfig{
				Nameservers: mustIPs("100.100.100.100"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "https://dns.nextdns.io/c3a884"),
			},
		},
		{
			// on iOS exclusively, tests the split DNS behavior for battery life optimization added in
			// https://github.com/tailscale/tailscale/pull/10576
			name: "ios-use-split-dns-when-no-custom-resolvers",
			in: Config{
				Routes:        upstreams("ts.net", "199.247.155.52", "optimistic-display.ts.net", ""),
				SearchDomains: fqdns("optimistic-display.ts.net"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("optimistic-display.ts.net"),
				MatchDomains:  fqdns("ts.net"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "",
					"ts.net", "199.247.155.52",
				),
				LocalDomains: fqdns("optimistic-display.ts.net."),
			},
			goos: "ios",
		},
		{
			// if using app connectors, the battery life optimization above should not be applied
			name: "ios-dont-use-split-dns-when-app-connector-resolver-needed",
			in: Config{
				Routes: upstreams(
					"ts.net", "199.247.155.52",
					"optimistic-display.ts.net", "",
					"github.com", "https://dnsresolver.bigcorp.com/2f143"),
				SearchDomains: fqdns("optimistic-display.ts.net"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("optimistic-display.ts.net"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "",
					"github.com", "https://dnsresolver.bigcorp.com/2f143",
					"ts.net", "199.247.155.52",
				),
				LocalDomains: fqdns("optimistic-display.ts.net."),
			},
			goos: "ios",
		},
		{
			// on darwin, verify that with the same config as in ios-use-split-dns-when-no-custom-resolvers,
			// MatchDomains are NOT set.
			name: "darwin-dont-use-split-dns-when-no-custom-resolvers",
			in: Config{
				Routes:        upstreams("ts.net", "199.247.155.52", "optimistic-display.ts.net", ""),
				SearchDomains: fqdns("optimistic-display.ts.net"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("optimistic-display.ts.net"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "",
					"ts.net", "199.247.155.52",
				),
				LocalDomains: fqdns("optimistic-display.ts.net."),
			},
			goos: "darwin",
		},
		{
			name: "populate-hosts-magicdns",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"ts.com", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				SearchDomains: fqdns("ts.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Hosts: []*HostEntry{
					{
						Addr: netip.MustParseAddr("2.3.4.5"),
						Hosts: []string{
							"bradfitz.ts.com.",
							"bradfitz",
						},
					},
					{
						Addr: netip.MustParseAddr("1.2.3.4"),
						Hosts: []string{
							"dave.ts.com.",
							"dave",
						},
					},
				},
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("ts.com", "universe.tf"),
				MatchDomains:  fqdns("corp.com", "ts.com"),
			},
			rs: resolver.Config{
				Routes: upstreams("corp.com.", "2.2.2.2"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: fqdns("ts.com."),
			},
			goos: "windows",
		},
		{
			// Regression test for https://github.com/tailscale/tailscale/issues/14428
			name: "nopopulate-hosts-nomagicdns",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"ts.com", "1.1.1.1"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				SearchDomains: fqdns("ts.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: fqdns("ts.com", "universe.tf"),
				MatchDomains:  fqdns("corp.com", "ts.com"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					"corp.com.", "2.2.2.2",
					"ts.com", "1.1.1.1"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
			},
			goos: "windows",
		},
	}

	trIP := cmp.Transformer("ipStr", func(ip netip.Addr) string { return ip.String() })
	trIPPort := cmp.Transformer("ippStr", func(ipp netip.AddrPort) string {
		if ipp.Port() == 53 {
			return ipp.Addr().String()
		}
		return ipp.String()
	})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := fakeOSConfigurator{
				SplitDNS:   test.split,
				BaseConfig: test.bs,
			}
			goos := test.goos
			if goos == "" {
				goos = "linux"
			}
			knobs := &controlknobs.Knobs{}
			bus := eventbustest.NewBus(t)
			dialer := tsdial.NewDialer(netmon.NewStatic())
			dialer.SetBus(bus)
			m := NewManager(t.Logf, &f, health.NewTracker(bus), dialer, nil, knobs, goos)
			m.resolver.TestOnlySetHook(f.SetResolver)

			if err := m.Set(test.in); err != nil {
				t.Fatalf("m.Set: %v", err)
			}
			if diff := cmp.Diff(f.OSConfig, test.os, trIP, trIPPort, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("wrong OSConfig (-got+want)\n%s", diff)
			}
			if diff := cmp.Diff(f.ResolverConfig, test.rs, trIP, trIPPort, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("wrong resolver.Config (-got+want)\n%s", diff)
			}
		})
	}
}

func mustIPs(strs ...string) (ret []netip.Addr) {
	for _, s := range strs {
		ret = append(ret, netip.MustParseAddr(s))
	}
	return ret
}

func mustRes(strs ...string) (ret []*dnstype.Resolver) {
	for _, s := range strs {
		ret = append(ret, &dnstype.Resolver{Addr: s})
	}
	return ret
}

func fqdns(strs ...string) (ret []dnsname.FQDN) {
	for _, s := range strs {
		fqdn, err := dnsname.ToFQDN(s)
		if err != nil {
			panic(err)
		}
		ret = append(ret, fqdn)
	}
	return ret
}

func hosts(strs ...string) (ret map[dnsname.FQDN][]netip.Addr) {
	var key dnsname.FQDN
	ret = map[dnsname.FQDN][]netip.Addr{}
	for _, s := range strs {
		if ip, err := netip.ParseAddr(s); err == nil {
			if key == "" {
				panic("IP provided before name")
			}
			ret[key] = append(ret[key], ip)
		} else {
			fqdn, err := dnsname.ToFQDN(s)
			if err != nil {
				panic(err)
			}
			key = fqdn
		}
	}
	return ret
}

func upstreams(strs ...string) (ret map[dnsname.FQDN][]*dnstype.Resolver) {
	var key dnsname.FQDN
	ret = map[dnsname.FQDN][]*dnstype.Resolver{}
	for _, s := range strs {
		if s == "" {
			if key == "" {
				panic("IPPort provided before suffix")
			}
			ret[key] = nil
		} else if ipp, err := netip.ParseAddrPort(s); err == nil {
			if key == "" {
				panic("IPPort provided before suffix")
			}
			ret[key] = append(ret[key], &dnstype.Resolver{Addr: ipp.String()})
		} else if _, err := netip.ParseAddr(s); err == nil {
			if key == "" {
				panic("IPPort provided before suffix")
			}
			ret[key] = append(ret[key], &dnstype.Resolver{Addr: s})
		} else if strings.HasPrefix(s, "http") {
			ret[key] = append(ret[key], &dnstype.Resolver{Addr: s})
		} else {
			fqdn, err := dnsname.ToFQDN(s)
			if err != nil {
				panic(err)
			}
			key = fqdn
		}
	}
	return ret
}

func TestConfigRecompilation(t *testing.T) {
	fakeErr := errors.New("fake os configurator error")
	f := &fakeOSConfigurator{}
	f.GetBaseConfigErr = &fakeErr
	f.BaseConfig = OSConfig{
		Nameservers: mustIPs("1.1.1.1"),
	}

	config := Config{
		Routes:        upstreams("ts.net", "69.4.2.0", "foo.ts.net", ""),
		SearchDomains: fqdns("foo.ts.net"),
	}

	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	m := NewManager(t.Logf, f, health.NewTracker(bus), dialer, nil, nil, "darwin")

	var managerConfig *resolver.Config
	m.resolver.TestOnlySetHook(func(cfg resolver.Config) {
		managerConfig = &cfg
	})

	// Initial set should error out and store the config
	if err := m.Set(config); err == nil {
		t.Fatalf("Want non-nil error.  Got nil")
	}
	if m.config == nil {
		t.Fatalf("Want persisted config.  Got nil.")
	}
	if managerConfig != nil {
		t.Fatalf("Want nil managerConfig.  Got %v", managerConfig)
	}

	// Clear the error.  We should take the happy path now and
	// set m.manager's Config.
	f.GetBaseConfigErr = nil

	// Recompilation without an error should succeed and set m.config and m.manager's [resolver.Config]
	if err := m.RecompileDNSConfig(); err != nil {
		t.Fatalf("Want nil error.  Got err %v", err)
	}
	if m.config == nil {
		t.Fatalf("Want non-nil config.  Got nil")
	}
	if managerConfig == nil {
		t.Fatalf("Want non nil managerConfig.  Got nil")
	}
}
