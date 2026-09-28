// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

// TestManagerAppleDNSModes exercises the two modes in corp#48693. Apple uses
// match domains as the global search list (except reverse zones), so custom
// split suffixes must stay internal to quad-100 in Mode B. Search-only suffixes
// deliberately do not become routing domains in Mode A.
func TestManagerAppleDNSModes(t *testing.T) {
	for _, goos := range []string{"ios", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			tstest.Replace(t, &isSandboxedMacOS, func() bool { return goos == "darwin" })
			for _, tt := range []struct {
				name         string
				edit         func(*Config)
				primary      bool
				disableScope bool
				macEnv       string
				noBase       bool
				emptyBase    bool
				// baseResolvers populates BaseConfig.Resolvers and expects the
				// blended catch-all route to use them verbatim.
				baseResolvers []*dnstype.Resolver
			}{
				{name: "mode-a-magicdns-forward-reverse-and-search-only"},
				{
					name: "mode-a-conventional-ts-net-upstream",
					edit: func(c *Config) { c.Routes["ts.net."] = mustRes("199.247.155.52") },
				},
				{
					name:    "mode-b-custom-split-resolver",
					edit:    func(c *Config) { c.Routes["split.example."] = mustRes("192.0.2.53") },
					primary: true,
				},
				{
					name:    "mode-b-uncovered-forward-host",
					edit:    func(c *Config) { c.Hosts["extra.example."] = mustIPs("100.64.0.9") },
					primary: true,
				},
				{
					name:    "mode-b-magicdns-hosts-unrouted",
					edit:    func(c *Config) { c.MagicDNSHostsUnrouted = true },
					primary: true,
				},
				{
					name:    "mode-b-default-resolvers",
					edit:    func(c *Config) { c.DefaultResolvers = mustRes("192.0.2.54") },
					primary: true,
				},
				{
					name:    "mode-b-uncovered-ipv4-ptr",
					edit:    func(c *Config) { c.Hosts["printer.corp.ts.net."] = mustIPs("192.168.1.10") },
					primary: true,
				},
				{
					name:    "mode-b-uncovered-ipv6-ptr",
					edit:    func(c *Config) { c.Hosts["printer.corp.ts.net."] = mustIPs("2001:db8::1") },
					primary: true,
				},
				{
					name: "mode-b-mixed-covered-and-uncovered-ptrs",
					edit: func(c *Config) {
						c.Hosts["printer.corp.ts.net."] = mustIPs("100.64.0.9", "2001:db8::1")
					},
					primary: true,
				},
				{
					name: "mode-a-covered-ipv4-ptr",
					edit: func(c *Config) {
						c.Hosts["printer.corp.ts.net."] = mustIPs("192.168.1.10")
						c.Routes["1.168.192.in-addr.arpa."] = nil
					},
				},
				{
					name: "mode-a-covered-ipv6-ptr",
					edit: func(c *Config) {
						c.Hosts["printer.corp.ts.net."] = mustIPs("2001:db8::1")
						c.Routes["8.b.d.0.1.0.0.2.ip6.arpa."] = nil
					},
				},
				{
					name: "mode-a-exact-ptr-route",
					edit: func(c *Config) {
						c.Hosts["printer.corp.ts.net."] = mustIPs("192.168.1.10")
						c.Routes["10.1.168.192.in-addr.arpa."] = nil
					},
				},
				{
					name:         "mode-b-control-disables-scoping",
					disableScope: true,
					primary:      true,
				},
				{name: "mac-env-opt-out", macEnv: "false", primary: goos == "darwin"},
				{name: "mac-env-opt-in", macEnv: "true", disableScope: true, primary: goos == "ios"},
				{
					name:    "mac-env-cannot-bypass-mode-b",
					macEnv:  "true",
					edit:    func(c *Config) { c.Routes["split.example."] = mustRes("192.0.2.53") },
					primary: true,
				},
				{name: "no-base-mode-a", noBase: true},
				{
					name:    "no-base-custom-split-resolver",
					edit:    func(c *Config) { c.Routes["split.example."] = mustRes("192.0.2.53") },
					primary: true,
					noBase:  true,
				},
				{
					name:    "no-base-unrouted-host",
					edit:    func(c *Config) { c.MagicDNSHostsUnrouted = true },
					primary: true,
					noBase:  true,
				},
				{
					name:    "no-base-uncovered-forward-host",
					edit:    func(c *Config) { c.Hosts["extra.example."] = mustIPs("100.64.0.9") },
					primary: true,
					noBase:  true,
				},
				{
					name:    "no-base-uncovered-ptr",
					edit:    func(c *Config) { c.Hosts["printer.corp.ts.net."] = mustIPs("192.168.1.10") },
					primary: true,
					noBase:  true,
				},
				{
					name: "no-base-scoping-disabled", primary: true, disableScope: true, noBase: true},
				{name: "empty-base-mode-a", emptyBase: true},
				{
					name:      "empty-base-mode-b-errors",
					primary:   true,
					emptyBase: true,
					edit:      func(c *Config) { c.Routes["split.example."] = mustRes("192.0.2.53") },
				},
				{
					name: "base-resolvers-ports-and-doh",
					edit: func(c *Config) { c.Routes["split.example."] = mustRes("192.0.2.53") },
					baseResolvers: []*dnstype.Resolver{
						{Addr: "192.168.1.1:5353"},
						{Addr: "https://doh.corp.example/query", BootstrapResolution: mustIPs("192.168.1.53")},
					},
					primary: true,
				},
			} {
				t.Run(tt.name, func(t *testing.T) {
					envknob.SetenvForTest(t, "TS_DEBUG_SCOPE_QUAD100_MACOS", tt.macEnv)
					c := Config{
						Routes:        upstreams("corp.ts.net", "", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa", ""),
						Hosts:         hosts("laptop.corp.ts.net", "100.64.0.1", "fd7a:115c:a1e0::1"),
						SearchDomains: fqdns("corp.ts.net", "office.example"),
					}
					// Match the actual IPv4 MagicDNS roots emitted by ipnlocal.
					for i := 64; i <= 127; i++ {
						c.Routes[dnsname.FQDN(fmt.Sprintf("%d.100.in-addr.arpa.", i))] = nil
					}
					if tt.edit != nil {
						tt.edit(&c)
					}
					knobs := scopeQuad100Knobs()
					knobs.ScopeQuad100OnMacOS.Store(!tt.disableScope)
					knobs.DisableSplitDNSWhenNoCustomResolvers.Store(tt.disableScope)
					f := &fakeOSConfigurator{
						SplitDNS: true,
						BaseConfig: OSConfig{
							Nameservers:   mustIPs("192.168.1.1"),
							SearchDomains: fqdns("lan.example"),
						},
					}
					if tt.noBase {
						err := ErrGetBaseConfigNotSupported
						f.GetBaseConfigErr = &err
					}
					if tt.emptyBase {
						f.BaseConfig = OSConfig{}
					}
					if tt.baseResolvers != nil {
						f.BaseConfig.Resolvers = tt.baseResolvers
					}
					m := &Manager{
						goos:   goos,
						os:     f,
						knobs:  knobs,
						health: health.NewTracker(eventbustest.NewBus(t)),
						logf:   t.Logf,
					}
					rcfg, ocfg, err := m.compileConfig(c)
					if tt.noBase && tt.primary {
						// A catch-all without a forwarding resolver would break public
						// DNS. Fail rather than bypassing Mode B or control opt-outs.
						if !errors.Is(err, ErrGetBaseConfigNotSupported) {
							t.Fatalf("compileConfig error = %v; want ErrGetBaseConfigNotSupported", err)
						}
						if len(ocfg.Nameservers) != 0 || len(ocfg.MatchDomains) != 0 {
							t.Fatalf("failed compile returned OS config: %+v", ocfg)
						}
						if !m.health.IsUnhealthy(OSConfigurationReadWarnable) {
							t.Error("failed base config read did not set health warning")
						}
						return
					}
					if tt.emptyBase && tt.primary {
						// A base read that succeeds but yields no resolvers is just as
						// unusable for a catch-all as an unsupported read.
						if !errors.Is(err, errEmptyBaseConfig) {
							t.Fatalf("compileConfig error = %v; want errEmptyBaseConfig", err)
						}
						if len(ocfg.Nameservers) != 0 || len(ocfg.MatchDomains) != 0 {
							t.Fatalf("failed compile returned OS config: %+v", ocfg)
						}
						if !m.health.IsUnhealthy(EmptyBaseConfigWarnable) {
							t.Error("empty base config read did not set health warning")
						}
						if m.health.IsUnhealthy(OSConfigurationReadWarnable) {
							t.Error("empty base config incorrectly reported a read failure")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if m.health.IsUnhealthy(OSConfigurationReadWarnable) {
						t.Error("successful compile left a base config read warning")
					}
					wantOS := OSConfig{Nameservers: serviceAddr46, SearchDomains: slices.Clone(c.SearchDomains)}
					if !tt.primary {
						wantOS.MatchDomains = c.matchDomains()
					}
					wantDefault := c.DefaultResolvers
					if tt.baseResolvers != nil {
						wantDefault = tt.baseResolvers
						wantOS.SearchDomains = append(wantOS.SearchDomains, "lan.example.")
					} else if len(wantDefault) == 0 && !tt.noBase && !tt.emptyBase && (goos == "ios" || tt.primary) {
						wantDefault = mustRes("192.168.1.1")
						wantOS.SearchDomains = append(wantOS.SearchDomains, "lan.example.")
					}
					if diff := cmp.Diff(wantOS, ocfg, cmpopts.EquateEmpty(), cmpopts.EquateComparable(netip.Addr{})); diff != "" {
						t.Errorf("OS config (-want +got):\n%s", diff)
					}
					if diff := cmp.Diff(wantDefault, rcfg.Routes["."], cmpopts.EquateEmpty()); diff != "" {
						t.Errorf("default forwarding route (-want +got):\n%s", diff)
					}
					for suffix, upstream := range c.Routes {
						if len(upstream) == 0 {
							if !slices.Contains(rcfg.LocalDomains, suffix) {
								t.Errorf("authoritative suffix %q missing from resolver", suffix)
							}
						} else if diff := cmp.Diff(upstream, rcfg.Routes[suffix]); diff != "" {
							t.Errorf("route %q lost (-want +got):\n%s", suffix, diff)
						}
					}
					if diff := cmp.Diff(c.Hosts, rcfg.Hosts, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
						t.Errorf("host records lost (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}

// TestAppleBaseConfigWarningRecovery checks the same warning is used for an
// empty read and a bridge-reported absence of resolvers, without masking actual
// read failures or leaving stale warnings after recovery.
func TestAppleBaseConfigWarningRecovery(t *testing.T) {
	for _, goos := range []string{"ios", "darwin"} {
		for _, bridgeError := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/bridgeError=%v", goos, bridgeError), func(t *testing.T) {
				tstest.Replace(t, &isSandboxedMacOS, func() bool { return goos == "darwin" })
				f := &fakeOSConfigurator{SplitDNS: true}
				bus := eventbustest.NewBus(t)
				ht := health.NewTracker(bus)
				dialer := tsdial.NewDialer(netmon.NewStatic())
				dialer.SetBus(bus)
				m := NewManager(t.Logf, f, ht, dialer, nil, nil, goos, bus)
				m.resolver.TestOnlySetHook(f.SetResolver)
				t.Cleanup(func() { m.Down() })
				cfg := Config{Routes: upstreams("split.example", "192.0.2.53")}

				readErr := errors.New("dnsinfo read failed")
				f.GetBaseConfigErr = &readErr
				if err := m.Set(cfg); !errors.Is(err, readErr) {
					t.Fatalf("Set error = %v; want read error", err)
				}
				if !ht.IsUnhealthy(OSConfigurationReadWarnable) || ht.IsUnhealthy(EmptyBaseConfigWarnable) {
					t.Fatal("read failure did not produce only the read warning")
				}

				f.GetBaseConfigErr = nil
				if bridgeError {
					err := fmt.Errorf("bridge: %w", ErrGetBaseConfigNoResolvers)
					f.GetBaseConfigErr = &err
				}
				if err := m.Set(cfg); !errors.Is(err, errEmptyBaseConfig) {
					t.Fatalf("Set error = %v; want empty-base error", err)
				}
				if !ht.IsUnhealthy(EmptyBaseConfigWarnable) || ht.IsUnhealthy(OSConfigurationReadWarnable) {
					t.Fatal("missing resolvers did not produce only the upstream empty-base warning")
				}
				if len(f.OSConfig.Nameservers) != 0 {
					t.Fatal("took over DNS without upstreams")
				}
				m.mu.Lock()
				waiting := m.waitingForBaseCfg
				m.mu.Unlock()
				if waiting {
					t.Fatal("Apple should wait for extension-triggered recompilation, not start retries")
				}

				f.GetBaseConfigErr = nil
				f.setBaseConfig(OSConfig{Nameservers: mustIPs("192.0.2.54")})
				if err := m.RecompileDNSConfig(); err != nil {
					t.Fatal(err)
				}
				if ht.IsUnhealthy(EmptyBaseConfigWarnable) || ht.IsUnhealthy(OSConfigurationReadWarnable) {
					t.Fatal("successful recompile left a stale warning")
				}
			})
		}
	}
}

func TestReverseDNSName(t *testing.T) {
	for _, tt := range []struct{ ip, want string }{
		{"192.168.1.10", "10.1.168.192.in-addr.arpa."},
		{"100.64.0.9", "9.0.64.100.in-addr.arpa."},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"fd7a:115c:a1e0::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."},
	} {
		t.Run(tt.ip, func(t *testing.T) {
			if got := reverseDNSName(netip.MustParseAddr(tt.ip)); got != dnsname.FQDN(tt.want) {
				t.Errorf("reverseDNSName = %q; want %q", got, tt.want)
			}
		})
	}
}
