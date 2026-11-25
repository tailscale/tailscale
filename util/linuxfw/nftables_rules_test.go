// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"tailscale.com/net/tsaddr"
)

// TestFamilyMatch checks that rules that depend on the IP family only match
// it explicitly in inet tables, and are otherwise unchanged.
func TestFamilyMatch(t *testing.T) {
	v4, v6 := nftables.TableFamilyIPv4, nftables.TableFamilyIPv6
	ip := &nftables.Table{Family: v4, Name: "filter"}
	ip6 := &nftables.Table{Family: v6, Name: "filter"}
	inet := &nftables.Table{Family: nftables.TableFamilyINet, Name: "tailscale"}
	chain := func(table *nftables.Table) *nftables.Chain { return &nftables.Chain{Name: "test", Table: table} }

	for _, tt := range []struct {
		name  string
		ipTbl *nftables.Table      // the ip or ip6 table to compare with
		fam   nftables.TableFamily // the family the rule matches in inet tables
		build func(*nftables.Table) (*nftables.Rule, error)
	}{
		{"loopback-v4", ip, v4, func(tb *nftables.Table) (*nftables.Rule, error) {
			return createLoopbackRule(v4, tb, chain(tb), netip.MustParseAddr("100.101.102.103"))
		}},
		{"loopback-v6", ip6, v6, func(tb *nftables.Table) (*nftables.Rule, error) {
			return createLoopbackRule(v6, tb, chain(tb), netip.MustParseAddr("fd7a:115c:a1e0::1"))
		}},
		{"range", ip, v4, func(tb *nftables.Table) (*nftables.Rule, error) {
			return createRangeRule(tb, chain(tb), "tailscale0", tsaddr.CGNATRange(), expr.VerdictDrop)
		}},
		{"drop-cgnat-to-tun", ip, v4, func(tb *nftables.Table) (*nftables.Rule, error) {
			return createDropOutgoingPacketFromCGNATRangeRuleWithTunname(tb, chain(tb), "tailscale0")
		}},
		{"udp-port-v6", ip6, v6, func(tb *nftables.Table) (*nftables.Rule, error) {
			return createAcceptOnPortRule(tb, chain(tb), v6, 41641), nil
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ipRule, err := tt.build(tt.ipTbl)
			if err != nil {
				t.Fatal(err)
			}
			inetRule, err := tt.build(inet)
			if err != nil {
				t.Fatal(err)
			}
			if fm := familyMatch(tt.ipTbl, tt.fam); fm != nil {
				t.Errorf("familyMatch(%v table) = %v, want nil", tt.ipTbl.Family, fm)
			}
			if _, ok := ipRule.Exprs[0].(*expr.Meta); ok && ipRule.Exprs[0].(*expr.Meta).Key == expr.MetaKeyNFPROTO {
				t.Errorf("rule in %v table starts with a family match: %v", tt.ipTbl.Family, ipRule.Exprs)
			}
			want := append(familyMatch(inet, tt.fam), ipRule.Exprs...)
			if !reflect.DeepEqual(inetRule.Exprs, want) {
				t.Errorf("rule in inet table =\n%#v\nwant the %v rule with a family match:\n%#v", inetRule.Exprs, tt.ipTbl.Family, want)
			}
		})
	}
}
