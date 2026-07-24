// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"net/netip"
	"testing"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

// Repro of the real macsys netmap shapes through compileConfig, mirroring
// dnsConfigForNetmap (see ipn/ipnlocal/dnsconfig_test.go "corp_dns_misc").
func runCompile(t *testing.T, in Config) OSConfig {
	t.Helper()
	tstest.Replace(t, &isSandboxedMacOS, func() bool { return true })
	f := &fakeOSConfigurator{SplitDNS: true, BaseConfig: OSConfig{Nameservers: mustIPs("192.168.1.1")}}
	bus := eventbustest.NewBus(t)
	dialer := tsdial.NewDialer(netmon.NewStatic())
	dialer.SetBus(bus)
	m := NewManager(t.Logf, f, health.NewTracker(bus), dialer, nil, &controlknobs.Knobs{}, "darwin", bus)
	m.resolver.TestOnlySetHook(f.SetResolver)
	if err := m.Set(in); err != nil {
		t.Fatalf("Set: %v", err)
	}
	return f.OSConfig
}

func report(t *testing.T, oc OSConfig) {
	if len(oc.MatchDomains) == 0 {
		t.Logf(">>> UNSCOPED (leak): MatchDomains empty, quad-100 primary")
	} else {
		t.Logf(">>> SCOPED (ok): MatchDomains=%v", oc.MatchDomains)
	}
}

func TestDoHMagicDNSOn(t *testing.T) {
	in := Config{
		AcceptDNS:     true,
		Hosts:         map[dnsname.FQDN][]netip.Addr{},
		Routes:        map[dnsname.FQDN][]*dnstype.Resolver{"corp.ts.net.": nil, "100.100.in-addr.arpa.": nil},
		SearchDomains: fqdns("corp.ts.net"),
	}
	report(t, runCompile(t, in))
}

func TestDoHMagicDNSOff(t *testing.T) {
	in := Config{
		AcceptDNS:             true,
		Hosts:                 map[dnsname.FQDN][]netip.Addr{},
		Routes:                map[dnsname.FQDN][]*dnstype.Resolver{"corp.ts.net.": {&dnstype.Resolver{Addr: "100.100.100.100"}}},
		SearchDomains:         fqdns("corp.ts.net"),
		MagicDNSHostsUnrouted: true,
	}
	report(t, runCompile(t, in))
}

// MagicDNS on with an uncovered ExtraRecord: expect scoping, with the extra
// host in MatchDomains so quad-100 still answers it.
func TestDoHMagicDNSOnWithExtraRecord(t *testing.T) {
	oc := runCompile(t, Config{
		AcceptDNS:     true,
		Hosts:         map[dnsname.FQDN][]netip.Addr{"extra.example.com.": mustIPs("100.64.0.9")},
		Routes:        map[dnsname.FQDN][]*dnstype.Resolver{"corp.ts.net.": nil, "100.100.in-addr.arpa.": nil},
		SearchDomains: fqdns("corp.ts.net"),
	})
	report(t, oc)
	found := false
	for _, d := range oc.MatchDomains {
		if d == "extra.example.com." {
			found = true
		}
	}
	if !found {
		t.Errorf("extra.example.com. missing from MatchDomains %v; its records would stop resolving", oc.MatchDomains)
	}
}

// Exit node proxying DNS sets DefaultResolvers, so compileConfig proxies
// through quad-100 (the hasDefaultResolvers case) and never reaches the
// scoping path. quad-100 must stay primary or DNS breaks on the exit node.
func TestDoHExitNodeStaysPrimary(t *testing.T) {
	oc := runCompile(t, Config{
		AcceptDNS:        true,
		DefaultResolvers: []*dnstype.Resolver{{Addr: "https://exit.example.ts.net/dns-query"}},
		Routes:           map[dnsname.FQDN][]*dnstype.Resolver{"corp.ts.net.": nil},
		SearchDomains:    fqdns("corp.ts.net"),
	})
	if len(oc.MatchDomains) != 0 {
		t.Errorf("MatchDomains=%v; want empty (quad-100 primary) when exit node proxies DNS", oc.MatchDomains)
	}
}
