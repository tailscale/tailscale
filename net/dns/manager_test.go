// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/httpm"
)

type fakeOSConfigurator struct {
	SplitDNS bool

	mu                sync.Mutex // guards BaseConfig/baseConfigErrOnce; only contended in concurrent (synctest) tests
	BaseConfig        OSConfig
	baseConfigErrOnce error // if non-nil, returned by the next GetBaseConfig then cleared
	OSConfig          OSConfig
	ResolverConfig    resolver.Config
	GetBaseConfigErr  *error
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

// setBaseConfig updates BaseConfig safely for tests where a background
// re-probe goroutine may read it concurrently via GetBaseConfig.
func (c *fakeOSConfigurator) setBaseConfig(cfg OSConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BaseConfig = cfg
}

// setBaseConfigErrOnce arms GetBaseConfig to return err exactly once (then
// resume returning BaseConfig), simulating a transient read failure.
func (c *fakeOSConfigurator) setBaseConfigErrOnce(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseConfigErrOnce = err
}

func (c *fakeOSConfigurator) GetBaseConfig() (OSConfig, error) {
	if c.GetBaseConfigErr != nil {
		return OSConfig{}, *c.GetBaseConfigErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.baseConfigErrOnce; err != nil {
		c.baseConfigErrOnce = nil
		return OSConfig{}, err
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

var serviceAddr46 = []netip.Addr{tsaddr.TailscaleServiceIP(), tsaddr.TailscaleServiceIPv6()}

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
		name           string
		in             Config
		split          bool
		bs             OSConfig
		os             OSConfig
		knobs          *controlknobs.Knobs
		rs             resolver.Config
		goos           string // empty means "linux"
		sandboxedMacOS bool
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
				Nameservers: serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "1.1.1.1", "9.9.9.9",
					"corp.com.", "2.2.2.2"),
			},
		},
		{
			name: "controlknob-disable-v6-registration",
			in: Config{
				DefaultResolvers: mustRes("1.1.1.1", "9.9.9.9"),
				SearchDomains:    fqdns("tailscale.com", "universe.tf"),
				Routes:           upstreams("ts.com", ""),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
			},
			knobs: (func() *controlknobs.Knobs {
				k := new(controlknobs.Knobs)
				k.ForceRegisterMagicDNSIPv4Only.Store(true)
				return k
			})(),
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"), // without IPv6
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
				Nameservers:   serviceAddr46,
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
			// Sandboxed macOS app builds use NetworkExtension DNS settings, not
			// tailscaled's /etc/resolver configurator, so they keep the older
			// Apple base-config behavior.
			name: "routes-split-sandboxed-darwin",
			in: Config{
				Routes:        upstreams("corp.com", "2.2.2.2"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			bs: OSConfig{
				Nameservers:   mustIPs("8.8.8.8"),
				SearchDomains: fqdns("coffee.shop"),
			},
			os: OSConfig{
				Nameservers:   serviceAddr46,
				SearchDomains: fqdns("tailscale.com", "universe.tf", "coffee.shop"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "8.8.8.8",
					"corp.com.", "2.2.2.2"),
			},
			goos:           "darwin",
			sandboxedMacOS: true,
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
			// The `routes-multi-split-linux` test case above should match on
			// macOS, where tailscaled configures split DNS via /etc/resolver.
			name: "routes-multi-split-darwin",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2",
					"bigco.net", "3.3.3.3"),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   serviceAddr46,
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
				MatchDomains:  fqdns("bigco.net", "corp.com"),
			},
			rs: resolver.Config{
				Routes: upstreams(
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
			// The `magic-split` test case above should match on macOS, where
			// tailscaled configures split DNS via /etc/resolver.
			name: "magic-split-darwin",
			in: Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				Routes:        upstreams("ts.com", ""),
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   serviceAddr46,
				SearchDomains: fqdns("tailscale.com", "universe.tf"),
				MatchDomains:  fqdns("ts.com"),
			},
			rs: resolver.Config{
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
			// The `routes-magic-split-linux` test case above should match on
			// macOS, where tailscaled configures split DNS via /etc/resolver.
			name: "routes-magic-split-darwin",
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
				Nameservers: serviceAddr46,
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
				Nameservers: serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
			// macOS should match Linux here. iOS remains special-cased above
			// for battery-life behavior.
			name: "darwin-use-split-dns-when-no-custom-resolvers",
			in: Config{
				Routes:        upstreams("ts.net", "199.247.155.52", "optimistic-display.ts.net", ""),
				SearchDomains: fqdns("optimistic-display.ts.net"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   serviceAddr46,
				SearchDomains: fqdns("optimistic-display.ts.net"),
				MatchDomains:  fqdns("optimistic-display.ts.net", "ts.net"),
			},
			rs: resolver.Config{
				Routes:       upstreams("ts.net", "199.247.155.52"),
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
				Nameservers:   serviceAddr46,
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
				Nameservers:   serviceAddr46,
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
		{
			// Regression test for #19834
			name: "single-doh-splitdns-no-magicdns",
			in: Config{
				Routes: upstreams(
					"example.com", "http://100.101.102.103:1234/dns-query"),
			},
			split: true,
			os: OSConfig{
				Nameservers:  serviceAddr46,
				MatchDomains: fqdns("example.com"),
			},
			rs: resolver.Config{
				Routes: upstreams("example.com.", "http://100.101.102.103:1234/dns-query"),
			},
			goos: "linux",
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
			tstest.Replace(t, &isSandboxedMacOS, func() bool { return test.sandboxedMacOS })
			f := fakeOSConfigurator{
				SplitDNS:   test.split,
				BaseConfig: test.bs,
			}
			goos := test.goos
			if goos == "" {
				goos = "linux"
			}
			knobs := test.knobs
			if knobs == nil {
				knobs = &controlknobs.Knobs{}
			}
			bus := eventbustest.NewBus(t)
			dialer := tsdial.NewDialer(netmon.NewStatic())
			dialer.SetBus(bus)
			m := NewManager(t.Logf, &f, health.NewTracker(bus), dialer, nil, knobs, goos, bus)
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
	m := NewManager(t.Logf, f, health.NewTracker(bus), dialer, nil, nil, "darwin", bus)

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

// TestBaseConfigEmptyWithholdsTakeover is a regression test for
// https://github.com/tailscale/tailscale/issues/20341: when the OS can't do
// split DNS and the system base config has no upstream nameservers (e.g.
// tailscaled started before NetworkManager/systemd-resolved populated
// /etc/resolv.conf), the Manager must withhold takeover rather than point the
// OS at 100.100.100.100 with an empty "." route, which would SERVFAIL all
// non-Tailscale DNS. The healthy path (a populated base config) is covered by
// TestManager's "routes-multi" case.
func TestBaseConfigEmptyWithholdsTakeover(t *testing.T) {
	f := &fakeOSConfigurator{
		SplitDNS:   false,      // can't split at OS -> blend base config path
		BaseConfig: OSConfig{}, // empty: no upstream nameservers
	}
	bus := eventbustest.NewBus(t)
	ht := health.NewTracker(bus)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	m := NewManager(t.Logf, f, ht, dialer, nil, nil, "linux", bus)
	m.resolver.TestOnlySetHook(f.SetResolver)

	// Split-DNS-only tailnet config: a route plus MagicDNS, no DefaultResolvers.
	cfg := Config{
		Routes:        upstreams("ts.net", "199.247.155.53"),
		SearchDomains: fqdns("foo.ts.net"),
	}
	if err := m.Set(cfg); err == nil {
		t.Fatal("m.Set: want error for empty base config, got nil")
	}
	// Must not have installed a self-referential OS config that funnels all DNS
	// to 100.100.100.100 with no upstream to forward to.
	if len(f.OSConfig.Nameservers) != 0 {
		t.Errorf("OSConfig.Nameservers = %v; want none (should not hijack OS DNS)", f.OSConfig.Nameservers)
	}
	m.mu.Lock()
	gotStatus := m.baseStatus
	m.mu.Unlock()
	if gotStatus != baseConfigEmpty {
		t.Errorf("baseStatus = %v; want baseConfigEmpty", gotStatus)
	}
	if _, ok := ht.CurrentState().Warnings[dnsBaseConfigNotReadyWarnable.Code]; !ok {
		t.Error("dnsBaseConfigNotReadyWarnable not set; want set while withholding takeover")
	}
}

// TestBaseConfigBecomesReady verifies that once the OS publishes upstream
// resolvers, an OSDNSConfigChanged event drives the Manager out of the
// withheld state and into a normal takeover, clearing the health warning.
func TestBaseConfigBecomesReady(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeOSConfigurator{
			SplitDNS:   false,
			BaseConfig: OSConfig{}, // start empty
		}
		bus := eventbustest.NewBus(t)
		ht := health.NewTracker(bus)
		dialer := tsdial.NewDialer(netmon.NewStatic())
		dialer.SetBus(bus)
		m := NewManager(t.Logf, f, ht, dialer, nil, nil, "linux", bus)
		m.resolver.TestOnlySetHook(f.SetResolver)

		cfg := Config{
			Routes:        upstreams("ts.net", "199.247.155.53"),
			SearchDomains: fqdns("foo.ts.net"),
		}
		if err := m.Set(cfg); err == nil {
			t.Fatal("m.Set: want error for empty base config, got nil")
		}

		// The OS finally publishes its resolvers.
		f.setBaseConfig(OSConfig{Nameservers: mustIPs("8.8.8.8")})

		inj := eventbustest.NewInjector(t, bus)
		eventbustest.Inject(inj, OSDNSConfigChanged{})
		synctest.Wait()

		if len(f.OSConfig.Nameservers) == 0 {
			t.Error("OSConfig.Nameservers empty after base config became ready; want takeover")
		}
		m.mu.Lock()
		gotStatus := m.baseStatus
		m.mu.Unlock()
		if gotStatus != baseConfigReady {
			t.Errorf("baseStatus = %v; want baseConfigReady", gotStatus)
		}
		if _, ok := ht.CurrentState().Warnings[dnsBaseConfigNotReadyWarnable.Code]; ok {
			t.Error("dnsBaseConfigNotReadyWarnable still set after takeover; want cleared")
		}
	})
}

// TestBaseConfigTimeoutReprobe verifies the fixed-interval retry timer (which
// backs up the best-effort resolv.conf watch) re-probes and takes over once
// the OS base config becomes available, even with no OSDNSConfigChanged event.
// This is the convergence path for backends without a file watch (BSDs,
// resolvconf family).
func TestBaseConfigTimeoutReprobe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeOSConfigurator{
			SplitDNS:   false,
			BaseConfig: OSConfig{}, // start empty
		}
		bus := eventbustest.NewBus(t)
		dialer := tsdial.NewDialer(netmon.NewStatic())
		dialer.SetBus(bus)
		m := NewManager(t.Logf, f, health.NewTracker(bus), dialer, nil, nil, "linux", bus)
		m.resolver.TestOnlySetHook(f.SetResolver)

		cfg := Config{
			Routes:        upstreams("ts.net", "199.247.155.53"),
			SearchDomains: fqdns("foo.ts.net"),
		}
		if err := m.Set(cfg); err == nil {
			t.Fatal("m.Set: want error for empty base config, got nil")
		}

		// Base config becomes available with no event; only the timer will notice.
		f.setBaseConfig(OSConfig{Nameservers: mustIPs("8.8.8.8")})

		time.Sleep(baseConfigRetryInterval + time.Second)
		synctest.Wait()

		if len(f.OSConfig.Nameservers) == 0 {
			t.Error("OSConfig.Nameservers empty after retry timer; want takeover")
		}
		m.mu.Lock()
		gotStatus := m.baseStatus
		gotTimer := m.baseRetryTimer
		m.mu.Unlock()
		if gotStatus != baseConfigReady {
			t.Errorf("baseStatus = %v; want baseConfigReady", gotStatus)
		}
		if gotTimer != nil {
			t.Error("baseRetryTimer still armed after reaching ready; want stopped")
		}
	})
}

// TestBaseConfigTransientErrorKeepsRetrying is a regression test: a transient
// GetBaseConfig error during a timer re-probe must not permanently drop the
// retry timer (issue #20341 review finding). After the transient error, the
// timer must re-arm and eventually converge once the base config is available.
func TestBaseConfigTransientErrorKeepsRetrying(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeOSConfigurator{
			SplitDNS:   false,
			BaseConfig: OSConfig{}, // start empty -> withhold + arm timer
		}
		bus := eventbustest.NewBus(t)
		dialer := tsdial.NewDialer(netmon.NewStatic())
		dialer.SetBus(bus)
		m := NewManager(t.Logf, f, health.NewTracker(bus), dialer, nil, nil, "linux", bus)
		m.resolver.TestOnlySetHook(f.SetResolver)

		cfg := Config{
			Routes:        upstreams("ts.net", "199.247.155.53"),
			SearchDomains: fqdns("foo.ts.net"),
		}
		if err := m.Set(cfg); err == nil {
			t.Fatal("m.Set: want error for empty base config, got nil")
		}

		// The next re-probe hits a transient GetBaseConfig error.
		f.setBaseConfigErrOnce(errors.New("transient resolvconf failure"))
		time.Sleep(baseConfigRetryInterval + time.Second)
		synctest.Wait()

		// The transient error must not have dropped the retry: still withholding,
		// timer re-armed.
		m.mu.Lock()
		gotStatus := m.baseStatus
		gotTimer := m.baseRetryTimer
		m.mu.Unlock()
		if gotStatus != baseConfigEmpty {
			t.Errorf("after transient error: baseStatus = %v; want baseConfigEmpty", gotStatus)
		}
		if gotTimer == nil {
			t.Fatal("after transient error: baseRetryTimer is nil; want re-armed (would be stuck forever)")
		}

		// Now the base config becomes available; the re-armed (backed-off) timer
		// should converge.
		f.setBaseConfig(OSConfig{Nameservers: mustIPs("8.8.8.8")})
		time.Sleep(maxBaseConfigRetryInterval + time.Second)
		synctest.Wait()

		if len(f.OSConfig.Nameservers) == 0 {
			t.Error("OSConfig.Nameservers empty after recovery; want takeover")
		}
		m.mu.Lock()
		gotStatus = m.baseStatus
		m.mu.Unlock()
		if gotStatus != baseConfigReady {
			t.Errorf("baseStatus = %v; want baseConfigReady", gotStatus)
		}
	})
}

// TestBaseConfigReadyStaysReady verifies the healthy path never enters the
// withheld state or arms the retry timer.
func TestBaseConfigReadyStaysReady(t *testing.T) {
	f := &fakeOSConfigurator{
		SplitDNS:   false,
		BaseConfig: OSConfig{Nameservers: mustIPs("8.8.8.8")},
	}
	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	m := NewManager(t.Logf, f, health.NewTracker(bus), dialer, nil, nil, "linux", bus)
	m.resolver.TestOnlySetHook(f.SetResolver)

	cfg := Config{
		Routes:        upstreams("ts.net", "199.247.155.53"),
		SearchDomains: fqdns("foo.ts.net"),
	}
	if err := m.Set(cfg); err != nil {
		t.Fatalf("m.Set: %v", err)
	}
	m.mu.Lock()
	gotStatus := m.baseStatus
	gotTimer := m.baseRetryTimer
	m.mu.Unlock()
	if gotStatus != baseConfigReady {
		t.Errorf("baseStatus = %v; want baseConfigReady", gotStatus)
	}
	if gotTimer != nil {
		t.Error("baseRetryTimer armed on healthy path; want none")
	}
}

// TestBaseConfigNoReprobeAfterDown is a regression test: after Down() cancels
// the Manager's context, a racing retry-timer fire or OSDNSConfigChanged event
// must not re-apply DNS takeover on the (now closed) OSConfigurator
// (issue #20341 review finding).
func TestBaseConfigNoReprobeAfterDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeOSConfigurator{
			SplitDNS:   false,
			BaseConfig: OSConfig{}, // empty -> withhold + arm timer
		}
		bus := eventbustest.NewBus(t)
		dialer := tsdial.NewDialer(netmon.NewStatic())
		dialer.SetBus(bus)
		m := NewManager(t.Logf, f, health.NewTracker(bus), dialer, nil, nil, "linux", bus)
		m.resolver.TestOnlySetHook(f.SetResolver)

		cfg := Config{
			Routes:        upstreams("ts.net", "199.247.155.53"),
			SearchDomains: fqdns("foo.ts.net"),
		}
		if err := m.Set(cfg); err == nil {
			t.Fatal("m.Set: want error for empty base config, got nil")
		}

		// Shut down while withholding, then make the base config "ready" and
		// try to drive a reprobe via both paths. Neither should take over.
		if err := m.Down(); err != nil {
			t.Fatalf("Down: %v", err)
		}
		f.setBaseConfig(OSConfig{Nameservers: mustIPs("8.8.8.8")})

		m.mu.Lock()
		m.reprobeBaseConfigLocked("post-down test")
		m.mu.Unlock()

		time.Sleep(maxBaseConfigRetryInterval + time.Second)
		synctest.Wait()

		if len(f.OSConfig.Nameservers) != 0 {
			t.Errorf("OSConfig.Nameservers = %v after Down; want none (no takeover after shutdown)", f.OSConfig.Nameservers)
		}
		m.mu.Lock()
		gotTimer := m.baseRetryTimer
		m.mu.Unlock()
		if gotTimer != nil {
			t.Error("baseRetryTimer re-armed after Down; want none")
		}
	})
}

func TestTrampleRetrample(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := &fakeOSConfigurator{}
		f.BaseConfig = OSConfig{
			Nameservers: mustIPs("1.1.1.1")}

		config := Config{
			Routes:        upstreams("ts.net", "69.4.2.0", "foo.ts.net", ""),
			SearchDomains: fqdns("foo.ts.net"),
		}

		bus := eventbustest.NewBus(t)
		dialer := tsdial.NewDialer(netmon.NewStatic())
		dialer.SetBus(bus)
		m := NewManager(t.Logf, f, health.NewTracker(bus), dialer, nil, nil, "linux", bus)

		// Initial set should error out and store the config
		if err := m.Set(config); err != nil {
			t.Fatalf("Want nil error. Got non-nil")
		}

		// Set no config
		f.OSConfig = OSConfig{}

		inj := eventbustest.NewInjector(t, bus)
		eventbustest.Inject(inj, TrampleDNS{})
		synctest.Wait()

		t.Logf("OSConfig: %+v", f.OSConfig)
		if reflect.DeepEqual(f.OSConfig, OSConfig{}) {
			t.Errorf("Expected config to be set, got empty config")
		}
	})
}

// TestSystemDNSDoHUpgrade tests that if the user doesn't configure DNS servers
// in their tailnet, and the system DNS happens to be a known DoH provider,
// queries will use DNS-over-HTTPS.
func TestSystemDNSDoHUpgrade(t *testing.T) {
	var (
		// This is a non-routable TEST-NET-2 IP (RFC 5737).
		testDoHResolverIP = netip.MustParseAddr("198.51.100.1")
		// This is a non-routable TEST-NET-1 IP (RFC 5737).
		testResponseIP = netip.MustParseAddr("192.0.2.1")
	)
	const testDomain = "test.example.com."

	var (
		mu             sync.Mutex
		dohRequestSeen bool
		receivedQuery  []byte
	)
	dohServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("[DoH Server] received request: %v %v", r.Method, r.URL)

		if r.Method != httpm.POST {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		dohRequestSeen = true
		receivedQuery = body

		// Build a DNS response
		response := buildTestDNSResponse(t, testDomain, testResponseIP)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(response)
	}))
	t.Cleanup(dohServer.Close)

	// Register the test IP to route to our mock DoH server
	cleanup := publicdns.RegisterTestDoHEndpoint(testDoHResolverIP, dohServer.URL)
	t.Cleanup(cleanup)

	// This simulates a system with the single DoH-capable DNS server
	// configured.
	f := &fakeOSConfigurator{
		SplitDNS: false, // non-split DNS required to use the forwarder
		BaseConfig: OSConfig{
			Nameservers: []netip.Addr{testDoHResolverIP},
		},
	}

	logf := tstest.WhileTestRunningLogger(t)
	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	m := NewManager(logf, f, health.NewTracker(bus), dialer, nil, &controlknobs.Knobs{}, "linux", bus)
	t.Cleanup(func() { m.Down() })

	// Set up hook to capture the resolver config
	m.resolver.TestOnlySetHook(f.SetResolver)

	// Configure the manager with routes but no default resolvers, which
	// reads BaseConfig from the OS configurator.
	config := Config{
		Routes:        upstreams("tailscale.com.", "10.0.0.1"),
		SearchDomains: fqdns("tailscale.com."),
	}
	if err := m.Set(config); err != nil {
		t.Fatal(err)
	}

	// Verify the resolver config has our test IP in Routes["."]
	if f.ResolverConfig.Routes == nil {
		t.Fatal("ResolverConfig.Routes is nil (SetResolver hook not called)")
	}

	const defaultRouteKey = "."
	defaultRoute, ok := f.ResolverConfig.Routes[defaultRouteKey]
	if !ok {
		t.Fatalf("ResolverConfig.Routes[%q] not found", defaultRouteKey)
	}
	if !slices.ContainsFunc(defaultRoute, func(r *dnstype.Resolver) bool {
		return r.Addr == testDoHResolverIP.String()
	}) {
		t.Errorf("test IP %v not found in Routes[%q], got: %v", testDoHResolverIP, defaultRouteKey, defaultRoute)
	}

	// Build a DNS query to something not handled by our split DNS route
	// (tailscale.com) above.
	query := buildTestDNSQuery(t, testDomain)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, err := m.Query(ctx, query, "udp", netip.MustParseAddrPort("127.0.0.1:12345"))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response")
	}

	// Parse the response to verify we get our test IP back.
	var parser dns.Parser
	if _, err := parser.Start(resp); err != nil {
		t.Fatalf("parsing response header: %v", err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatalf("skipping questions: %v", err)
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		t.Fatalf("parsing answers: %v", err)
	}
	if len(answers) == 0 {
		t.Fatal("no answers in response")
	}
	aRecord, ok := answers[0].Body.(*dns.AResource)
	if !ok {
		t.Fatalf("first answer is not A record: %T", answers[0].Body)
	}
	gotIP := netip.AddrFrom4(aRecord.A)
	if gotIP != testResponseIP {
		t.Errorf("wrong A record IP: got %v, want %v", gotIP, testResponseIP)
	}

	// Also verify that our DoH server received the query.
	mu.Lock()
	defer mu.Unlock()
	if !dohRequestSeen {
		t.Error("DoH server never received request")
	}
	if !bytes.Equal(receivedQuery, query) {
		t.Errorf("DoH server received wrong query:\ngot:  %x\nwant: %x", receivedQuery, query)
	}
}

// buildTestDNSQuery builds a simple DNS A query for the given domain.
func buildTestDNSQuery(t *testing.T, domain string) []byte {
	t.Helper()

	builder := dns.NewBuilder(nil, dns.Header{})
	builder.StartQuestions()
	builder.Question(dns.Question{
		Name:  dns.MustNewName(domain),
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	})
	msg, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}

	return msg
}

// buildTestDNSResponse builds a DNS response for the given query with the specified IP.
func buildTestDNSResponse(t *testing.T, domain string, ip netip.Addr) []byte {
	t.Helper()

	builder := dns.NewBuilder(nil, dns.Header{Response: true})
	builder.StartQuestions()
	builder.Question(dns.Question{
		Name:  dns.MustNewName(domain),
		Type:  dns.TypeA,
		Class: dns.ClassINET,
	})

	builder.StartAnswers()
	builder.AResource(dns.ResourceHeader{
		Name:  dns.MustNewName(domain),
		Class: dns.ClassINET,
		TTL:   300,
	}, dns.AResource{A: ip.As4()})

	msg, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}

	return msg
}
