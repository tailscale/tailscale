// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"inet.af/netaddr"
	"tailscale.com/net/dns/resolver"
)

type fakeOSConfigurator struct {
	SplitDNS bool

	OSConfig       OSConfig
	ResolverConfig resolver.Config
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
	// TODO
	return OSConfig{}, nil
}

func (c *fakeOSConfigurator) Close() error { return nil }

func TestManager(t *testing.T) {
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
		os    OSConfig
		rs    resolver.Config
	}{
		{
			name: "empty",
		},
		{
			name: "search-only",
			in: Config{
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
		},
		{
			name: "corp",
			in: Config{
				DefaultResolvers: mustIPPs("1.1.1.1:53", "9.9.9.9:53"),
				SearchDomains:    strs("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("1.1.1.1", "9.9.9.9"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
		},
		{
			name: "corp-split",
			in: Config{
				DefaultResolvers: mustIPPs("1.1.1.1:53", "9.9.9.9:53"),
				SearchDomains:    strs("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("1.1.1.1", "9.9.9.9"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
		},
		{
			name: "corp-magic",
			in: Config{
				DefaultResolvers: mustIPPs("1.1.1.1:53", "9.9.9.9:53"),
				SearchDomains:    strs("tailscale.com", "universe.tf"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				AuthoritativeSuffixes: strs("ts.com"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "1.1.1.1:53", "9.9.9.9:53"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: strs("ts.com."),
			},
		},
		{
			name: "corp-magic-split",
			in: Config{
				DefaultResolvers: mustIPPs("1.1.1.1:53", "9.9.9.9:53"),
				SearchDomains:    strs("tailscale.com", "universe.tf"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				AuthoritativeSuffixes: strs("ts.com"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "1.1.1.1:53", "9.9.9.9:53"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: strs("ts.com."),
			},
		},
		{
			name: "corp-routes",
			in: Config{
				DefaultResolvers: mustIPPs("1.1.1.1:53", "9.9.9.9:53"),
				Routes:           upstreams("corp.com", "2.2.2.2:53"),
				SearchDomains:    strs("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "1.1.1.1:53", "9.9.9.9:53",
					"corp.com.", "2.2.2.2:53"),
			},
		},
		{
			name: "corp-routes-split",
			in: Config{
				DefaultResolvers: mustIPPs("1.1.1.1:53", "9.9.9.9:53"),
				Routes:           upstreams("corp.com", "2.2.2.2:53"),
				SearchDomains:    strs("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "1.1.1.1:53", "9.9.9.9:53",
					"corp.com.", "2.2.2.2:53"),
			},
		},
		{
			name: "routes",
			in: Config{
				Routes:        upstreams("corp.com", "2.2.2.2:53"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "8.8.8.8:53",
					"corp.com.", "2.2.2.2:53"),
			},
		},
		{
			name: "routes-split",
			in: Config{
				Routes:        upstreams("corp.com", "2.2.2.2:53"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("2.2.2.2"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
				MatchDomains:  strs("corp.com"),
			},
		},
		{
			name: "routes-multi",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2:53",
					"bigco.net", "3.3.3.3:53"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					".", "8.8.8.8:53",
					"corp.com.", "2.2.2.2:53",
					"bigco.net.", "3.3.3.3:53"),
			},
		},
		{
			name: "routes-multi-split",
			in: Config{
				Routes: upstreams(
					"corp.com", "2.2.2.2:53",
					"bigco.net", "3.3.3.3:53"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
				MatchDomains:  strs("corp.com", "bigco.net"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					"corp.com.", "2.2.2.2:53",
					"bigco.net.", "3.3.3.3:53"),
			},
		},
		{
			name: "magic",
			in: Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				AuthoritativeSuffixes: strs("ts.com"),
				SearchDomains:         strs("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(".", "8.8.8.8:53"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: strs("ts.com."),
			},
		},
		{
			name: "magic-split",
			in: Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				AuthoritativeSuffixes: strs("ts.com"),
				SearchDomains:         strs("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
				MatchDomains:  strs("ts.com"),
			},
			rs: resolver.Config{
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: strs("ts.com."),
			},
		},
		{
			name: "routes-magic",
			in: Config{
				Routes: upstreams("corp.com", "2.2.2.2:53"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				AuthoritativeSuffixes: strs("ts.com"),
				SearchDomains:         strs("tailscale.com", "universe.tf"),
			},
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
			},
			rs: resolver.Config{
				Routes: upstreams(
					"corp.com.", "2.2.2.2:53",
					".", "8.8.8.8:53"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: strs("ts.com."),
			},
		},
		{
			name: "routes-magic-split",
			in: Config{
				Routes: upstreams("corp.com", "2.2.2.2:53"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				AuthoritativeSuffixes: strs("ts.com"),
				SearchDomains:         strs("tailscale.com", "universe.tf"),
			},
			split: true,
			os: OSConfig{
				Nameservers:   mustIPs("100.100.100.100"),
				SearchDomains: strs("tailscale.com", "universe.tf"),
				MatchDomains:  strs("ts.com", "corp.com"),
			},
			rs: resolver.Config{
				Routes: upstreams("corp.com.", "2.2.2.2:53"),
				Hosts: hosts(
					"dave.ts.com.", "1.2.3.4",
					"bradfitz.ts.com.", "2.3.4.5"),
				LocalDomains: strs("ts.com."),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := fakeOSConfigurator{SplitDNS: test.split}
			m := NewManager(t.Logf, &f, nil)
			m.resolver.TestOnlySetHook(f.SetResolver)

			if err := m.Set(test.in); err != nil {
				t.Fatalf("m.Set: %v", err)
			}
			tr := cmp.Transformer("ipStr", func(ip netaddr.IP) string { return ip.String() })
			if diff := cmp.Diff(f.OSConfig, test.os, tr, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("wrong OSConfig (-got+want)\n%s", diff)
			}
			if diff := cmp.Diff(f.ResolverConfig, test.rs, tr, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("wrong resolver.Config (-got+want)\n%s", diff)
			}
		})
	}
}

func mustIPs(strs ...string) (ret []netaddr.IP) {
	for _, s := range strs {
		ret = append(ret, netaddr.MustParseIP(s))
	}
	return ret
}

func mustIPPs(strs ...string) (ret []netaddr.IPPort) {
	for _, s := range strs {
		ret = append(ret, netaddr.MustParseIPPort(s))
	}
	return ret
}

func strs(strs ...string) []string { return strs }

func hosts(strs ...string) (ret map[string][]netaddr.IP) {
	var key string
	ret = map[string][]netaddr.IP{}
	for _, s := range strs {
		if ip, err := netaddr.ParseIP(s); err == nil {
			if key == "" {
				panic("IP provided before name")
			}
			ret[key] = append(ret[key], ip)
		} else {
			key = s
		}
	}
	return ret
}

func upstreams(strs ...string) (ret map[string][]netaddr.IPPort) {
	var key string
	ret = map[string][]netaddr.IPPort{}
	for _, s := range strs {
		if ipp, err := netaddr.ParseIPPort(s); err == nil {
			if key == "" {
				panic("IPPort provided before suffix")
			}
			ret[key] = append(ret[key], ipp)
		} else {
			key = s
		}
	}
	return ret
}
