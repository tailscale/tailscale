// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/tailscale/netlink"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsconst"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/linuxfw"
	"tailscale.com/version/distro"
)

func TestRouterStates(t *testing.T) {
	basic := `
ip rule add -4 pref 5210 fwmark 0x80000/0xff0000 table main
ip rule add -4 pref 5230 fwmark 0x80000/0xff0000 table default
ip rule add -4 pref 5250 fwmark 0x80000/0xff0000 type unreachable
ip rule add -4 pref 5270 table 52
ip rule add -6 pref 5210 fwmark 0x80000/0xff0000 table main
ip rule add -6 pref 5230 fwmark 0x80000/0xff0000 table default
ip rule add -6 pref 5250 fwmark 0x80000/0xff0000 type unreachable
ip rule add -6 pref 5270 table 52
`
	states := []struct {
		name string
		in   *Config
		want string
	}{
		{
			name: "no config",
			in:   nil,
			want: `
up` + basic,
		},
		{
			name: "local addr only",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				NetfilterMode: netfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0` + basic,
		},

		{
			name: "addr and routes",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "192.168.16.0/24"),
				NetfilterMode: netfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 table 52
ip route add 192.168.16.0/24 dev tailscale0 table 52` + basic,
		},

		{
			name: "addr and routes and subnet routes",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "192.168.16.0/24"),
				SubnetRoutes:  mustCIDRs("200.0.0.0/8"),
				NetfilterMode: netfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 table 52
ip route add 192.168.16.0/24 dev tailscale0 table 52` + basic,
		},

		{
			name: "addr and routes and subnet routes with netfilter",
			in: &Config{
				LocalAddrs:        mustCIDRs("100.101.102.104/10"),
				Routes:            mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				SubnetRoutes:      mustCIDRs("200.0.0.0/8"),
				SNATSubnetRoutes:  true,
				StatefulFiltering: true,
				NetfilterMode:     netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/nat/POSTROUTING -j ts-postrouting
v4/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/nat/POSTROUTING -j ts-postrouting
v6/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
`,
		},
		{
			name: "addr and routes and subnet routes with netfilter but no stateful filtering",
			in: &Config{
				LocalAddrs:        mustCIDRs("100.101.102.104/10"),
				Routes:            mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				SubnetRoutes:      mustCIDRs("200.0.0.0/8"),
				SNATSubnetRoutes:  true,
				StatefulFiltering: false,
				NetfilterMode:     netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/nat/POSTROUTING -j ts-postrouting
v4/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/nat/POSTROUTING -j ts-postrouting
v6/nat/ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
`,
		},
		{
			name: "addr and routes with netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/nat/POSTROUTING -j ts-postrouting
`,
		},

		{
			name: "addr and routes and subnet routes with netfilter but no SNAT",
			in: &Config{
				LocalAddrs:       mustCIDRs("100.101.102.104/10"),
				Routes:           mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				SubnetRoutes:     mustCIDRs("200.0.0.0/8"),
				SNATSubnetRoutes: false,
				NetfilterMode:    netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/nat/POSTROUTING -j ts-postrouting
`,
		},
		{
			name: "addr and routes with netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/nat/POSTROUTING -j ts-postrouting
`,
		},

		{
			name: "addr and routes with half netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: netfilterNoDivert,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
`,
		},
		{
			name: "addr and routes with netfilter2",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/nat/POSTROUTING -j ts-postrouting
`,
		},
		{
			name: "addr, routes, and local routes with netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "0.0.0.0/0"),
				LocalRoutes:   mustCIDRs("10.0.0.0/8"),
				NetfilterMode: netfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 0.0.0.0/0 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52
ip route add throw 10.0.0.0/8 table 52` + basic +
				`v4/filter/FORWARD -j ts-forward
v4/filter/INPUT -j ts-input
v4/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v4/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v4/filter/ts-forward -o tailscale0 -s 100.64.0.0/10 -j DROP
v4/filter/ts-forward -o tailscale0 -j ACCEPT
v4/filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
v4/filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -j RETURN
v4/filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
v4/nat/POSTROUTING -j ts-postrouting
v6/filter/FORWARD -j ts-forward
v6/filter/INPUT -j ts-input
v6/filter/ts-forward -i tailscale0 -j MARK --set-mark 0x40000/0xff0000
v6/filter/ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT
v6/filter/ts-forward -o tailscale0 -j ACCEPT
v6/nat/POSTROUTING -j ts-postrouting
`,
		},
		{
			name: "addr, routes, and local routes with no netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "0.0.0.0/0"),
				LocalRoutes:   mustCIDRs("10.0.0.0/8", "192.168.0.0/24"),
				NetfilterMode: netfilterOff,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 0.0.0.0/0 dev tailscale0 table 52
ip route add 100.100.100.100/32 dev tailscale0 table 52
ip route add throw 10.0.0.0/8 table 52
ip route add throw 192.168.0.0/24 table 52` + basic,
		},
	}

	bus := eventbus.New()
	defer bus.Close()
	mon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	defer mon.Close()

	fake := NewFakeOS(t)
	ht := health.NewTracker(bus)
	router, err := newUserspaceRouterAdvanced(t.Logf, "tailscale0", mon, fake, ht, bus)
	router.(*linuxRouter).nfr = fake.nfr
	if err != nil {
		t.Fatalf("failed to create router: %v", err)
	}
	if err := router.Up(); err != nil {
		t.Fatalf("failed to up router: %v", err)
	}

	testState := func(t *testing.T, i int) {
		t.Helper()
		if err := router.Set(states[i].in); err != nil {
			t.Fatalf("failed to set router config: %v", err)
		}
		got := fake.String()
		want := adjustFwmask(t, strings.TrimSpace(states[i].want))
		if diff := cmp.Diff(got, want); diff != "" {
			t.Fatalf("unexpected OS state (-got+want):\n%s", diff)
		}
	}

	for i, state := range states {
		t.Run(state.name, func(t *testing.T) { testState(t, i) })
	}

	// Cycle through a bunch of states in pseudorandom order, to
	// verify that we transition cleanly from state to state no matter
	// the order.
	for randRun := 0; randRun < 5*len(states); randRun++ {
		i := rand.Intn(len(states))
		state := states[i]
		t.Run(state.name, func(t *testing.T) { testState(t, i) })
	}
}

type fakeIPTablesRunner struct {
	t    *testing.T
	ipt4 map[string][]string
	ipt6 map[string][]string
	// we always assume ipv6 and ipv6 nat are enabled when testing
}

func newIPTablesRunner(t *testing.T) linuxfw.NetfilterRunner {
	return &fakeIPTablesRunner{
		t: t,
		ipt4: map[string][]string{
			"filter/INPUT":    nil,
			"filter/OUTPUT":   nil,
			"filter/FORWARD":  nil,
			"nat/PREROUTING":  nil,
			"nat/OUTPUT":      nil,
			"nat/POSTROUTING": nil,
		},
		ipt6: map[string][]string{
			"filter/INPUT":    nil,
			"filter/OUTPUT":   nil,
			"filter/FORWARD":  nil,
			"nat/PREROUTING":  nil,
			"nat/OUTPUT":      nil,
			"nat/POSTROUTING": nil,
		},
	}
}

func insertRule(n *fakeIPTablesRunner, curIPT map[string][]string, chain, newRule string) error {
	// Get current rules for filter/ts-input chain with according IP version
	curTSInputRules, ok := curIPT[chain]
	if !ok {
		n.t.Fatalf("no %s chain exists", chain)
		return fmt.Errorf("no %s chain exists", chain)
	}

	// Add new rule to top of filter/ts-input
	curTSInputRules = append(curTSInputRules, "")
	copy(curTSInputRules[1:], curTSInputRules)
	curTSInputRules[0] = newRule
	curIPT[chain] = curTSInputRules
	return nil
}

func insertRuleAt(n *fakeIPTablesRunner, curIPT map[string][]string, chain string, pos int, newRule string) {
	rules, ok := curIPT[chain]
	if !ok {
		n.t.Fatalf("no %s chain exists", chain)
	}

	// If the given position is after the end of the chain, error.
	if pos > len(rules) {
		n.t.Fatalf("position %d > len(chain %s) %d", pos, chain, len(chain))
	}

	// Insert the rule at the given position
	rules = slices.Insert(rules, pos, newRule)
	curIPT[chain] = rules
}

func appendRule(n *fakeIPTablesRunner, curIPT map[string][]string, chain, newRule string) error {
	// Get current rules for filter/ts-input chain with according IP version
	curTSInputRules, ok := curIPT[chain]
	if !ok {
		n.t.Fatalf("no %s chain exists", chain)
		return fmt.Errorf("no %s chain exists", chain)
	}

	// Add new rule to end of filter/ts-input
	curTSInputRules = append(curTSInputRules, newRule)
	curIPT[chain] = curTSInputRules
	return nil
}

func deleteRule(n *fakeIPTablesRunner, curIPT map[string][]string, chain, delRule string) error {
	// Get current rules for filter/ts-input chain with according IP version
	curTSInputRules, ok := curIPT[chain]
	if !ok {
		n.t.Fatalf("no %s chain exists", chain)
		return fmt.Errorf("no %s chain exists", chain)
	}

	// Remove rule from filter/ts-input
	for i, rule := range curTSInputRules {
		if rule == delRule {
			curTSInputRules = append(curTSInputRules[:i], curTSInputRules[i+1:]...)
			break
		}
	}
	curIPT[chain] = curTSInputRules
	return nil
}

func (n *fakeIPTablesRunner) AddLoopbackRule(addr netip.Addr) error {
	curIPT := n.ipt4
	if addr.Is6() {
		curIPT = n.ipt6
	}
	newRule := fmt.Sprintf("-i lo -s %s -j ACCEPT", addr.String())

	return insertRule(n, curIPT, "filter/ts-input", newRule)
}

func (n *fakeIPTablesRunner) AddBase(tunname string) error {
	if err := n.addBase4(tunname); err != nil {
		return err
	}
	if n.HasIPV6() {
		if err := n.addBase6(tunname); err != nil {
			return err
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) AddDNATRule(origDst, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DNATWithLoadBalancer(netip.Addr, []netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) EnsureSNATForDst(src, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DNATNonTailscaleTraffic(exemptInterface string, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) EnsurePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm linuxfw.PortMap) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DeletePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm linuxfw.PortMap) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DeleteSvc(svc, tun string, targetIPs []netip.Addr, pm []linuxfw.PortMap) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) ClampMSSToPMTU(tun string, addr netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) EnsureDNATRuleForSvc(svcName string, origDst, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) DeleteDNATRuleForSvc(svcName string, origDst, dst netip.Addr) error {
	return errors.New("not implemented")
}

func (n *fakeIPTablesRunner) addBase4(tunname string) error {
	curIPT := n.ipt4
	newRules := []struct{ chain, rule string }{
		{"filter/ts-input", fmt.Sprintf("! -i %s -s %s -j RETURN", tunname, tsaddr.ChromeOSVMRange().String())},
		{"filter/ts-input", fmt.Sprintf("! -i %s -s %s -j DROP", tunname, tsaddr.CGNATRange().String())},
		{"filter/ts-forward", fmt.Sprintf("-i %s -j MARK --set-mark %s/%s", tunname, tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)},
		{"filter/ts-forward", fmt.Sprintf("-m mark --mark %s/%s -j ACCEPT", tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)},
		{"filter/ts-forward", fmt.Sprintf("-o %s -s %s -j DROP", tunname, tsaddr.CGNATRange().String())},
		{"filter/ts-forward", fmt.Sprintf("-o %s -j ACCEPT", tunname)},
	}
	for _, rule := range newRules {
		if err := appendRule(n, curIPT, rule.chain, rule.rule); err != nil {
			return fmt.Errorf("add rule %q to chain %q: %w", rule.rule, rule.chain, err)
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) addBase6(tunname string) error {
	curIPT := n.ipt6
	newRules := []struct{ chain, rule string }{
		{"filter/ts-forward", fmt.Sprintf("-i %s -j MARK --set-mark %s/%s", tunname, tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)},
		{"filter/ts-forward", fmt.Sprintf("-m mark --mark %s/%s -j ACCEPT", tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)},
		{"filter/ts-forward", fmt.Sprintf("-o %s -j ACCEPT", tunname)},
	}
	for _, rule := range newRules {
		if err := appendRule(n, curIPT, rule.chain, rule.rule); err != nil {
			return fmt.Errorf("add rule %q to chain %q: %w", rule.rule, rule.chain, err)
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelLoopbackRule(addr netip.Addr) error {
	curIPT := n.ipt4
	if addr.Is6() {
		curIPT = n.ipt6
	}

	delRule := fmt.Sprintf("-i lo -s %s -j ACCEPT", addr.String())

	return deleteRule(n, curIPT, "filter/ts-input", delRule)
}

func (n *fakeIPTablesRunner) AddHooks() error {
	newRules := []struct{ chain, rule string }{
		{"filter/INPUT", "-j ts-input"},
		{"filter/FORWARD", "-j ts-forward"},
		{"nat/POSTROUTING", "-j ts-postrouting"},
	}
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for _, r := range newRules {
			if err := insertRule(n, ipt, r.chain, r.rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelHooks(logf logger.Logf) error {
	delRules := []struct{ chain, rule string }{
		{"filter/INPUT", "-j ts-input"},
		{"filter/FORWARD", "-j ts-forward"},
		{"nat/POSTROUTING", "-j ts-postrouting"},
	}
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for _, r := range delRules {
			if err := deleteRule(n, ipt, r.chain, r.rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) AddChains() error {
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for _, chain := range []string{"filter/ts-input", "filter/ts-forward", "nat/ts-postrouting"} {
			ipt[chain] = nil
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelChains() error {
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for chain := range ipt {
			if strings.HasPrefix(chain, "filter/ts-") || strings.HasPrefix(chain, "nat/ts-") {
				delete(ipt, chain)
			}
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelBase() error {
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		for _, chain := range []string{"filter/ts-input", "filter/ts-forward", "nat/ts-postrouting"} {
			ipt[chain] = nil
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) AddSNATRule() error {
	newRule := fmt.Sprintf("-m mark --mark %s/%s -j MASQUERADE", tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		if err := appendRule(n, ipt, "nat/ts-postrouting", newRule); err != nil {
			return err
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) DelSNATRule() error {
	delRule := fmt.Sprintf("-m mark --mark %s/%s -j MASQUERADE", tsconst.LinuxSubnetRouteMark, tsconst.LinuxFwmarkMask)
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		if err := deleteRule(n, ipt, "nat/ts-postrouting", delRule); err != nil {
			return err
		}
	}
	return nil
}

func (n *fakeIPTablesRunner) AddStatefulRule(tunname string) error {
	newRule := fmt.Sprintf("-o %s -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP", tunname)
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		// Mimic the real runner and insert after the 'accept all' rule
		wantRule := fmt.Sprintf("-o %s -j ACCEPT", tunname)

		const chain = "filter/ts-forward"
		pos := slices.Index(ipt[chain], wantRule)
		if pos < 0 {
			n.t.Fatalf("no rule %q in chain %s", wantRule, chain)
		}

		insertRuleAt(n, ipt, chain, pos, newRule)
	}
	return nil
}

func (n *fakeIPTablesRunner) DelStatefulRule(tunname string) error {
	delRule := fmt.Sprintf("-o %s -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP", tunname)
	for _, ipt := range []map[string][]string{n.ipt4, n.ipt6} {
		if err := deleteRule(n, ipt, "filter/ts-forward", delRule); err != nil {
			return err
		}
	}
	return nil
}

// buildMagicsockPortRule builds a fake rule to use in AddMagicsockPortRule and
// DelMagicsockPortRule below.
func buildMagicsockPortRule(port uint16) string {
	return fmt.Sprintf("-p udp --dport %v -j ACCEPT", port)
}

// AddMagicsockPortRule implements the NetfilterRunner interface, but stores
// rules in fakeIPTablesRunner's internal maps rather than actually calling out
// to iptables. This is mainly to test the linux router implementation.
func (n *fakeIPTablesRunner) AddMagicsockPortRule(port uint16, network string) error {
	var ipt map[string][]string
	switch network {
	case "udp4":
		ipt = n.ipt4
	case "udp6":
		ipt = n.ipt6
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	rule := buildMagicsockPortRule(port)

	if err := appendRule(n, ipt, "filter/ts-input", rule); err != nil {
		return err
	}

	return nil
}

// DelMagicsockPortRule implements the NetfilterRunner interface, but removes
// rules from fakeIPTablesRunner's internal maps rather than actually calling
// out to iptables. This is mainly to test the linux router implementation.
func (n *fakeIPTablesRunner) DelMagicsockPortRule(port uint16, network string) error {
	var ipt map[string][]string
	switch network {
	case "udp4":
		ipt = n.ipt4
	case "udp6":
		ipt = n.ipt6
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	rule := buildMagicsockPortRule(port)

	if err := deleteRule(n, ipt, "filter/ts-input", rule); err != nil {
		return err
	}

	return nil
}

func (n *fakeIPTablesRunner) HasIPV6() bool       { return true }
func (n *fakeIPTablesRunner) HasIPV6NAT() bool    { return true }
func (n *fakeIPTablesRunner) HasIPV6Filter() bool { return true }

// fakeOS implements commandRunner and provides v4 and v6
// netfilterRunners, but captures changes without touching the OS.
type fakeOS struct {
	t      *testing.T
	up     bool
	ips    []string
	routes []string
	rules  []string
	// This test tests on the router level, so we will not bother
	// with using iptables or nftables, chose the simpler one.
	nfr linuxfw.NetfilterRunner
}

func NewFakeOS(t *testing.T) *fakeOS {
	return &fakeOS{
		t:   t,
		nfr: newIPTablesRunner(t),
	}
}

var errExec = errors.New("execution failed")

func (o *fakeOS) String() string {
	var b strings.Builder
	if o.up {
		b.WriteString("up\n")
	} else {
		b.WriteString("down\n")
	}

	for _, ip := range o.ips {
		fmt.Fprintf(&b, "ip addr add %s\n", ip)
	}

	for _, route := range o.routes {
		fmt.Fprintf(&b, "ip route add %s\n", route)
	}

	for _, rule := range o.rules {
		fmt.Fprintf(&b, "ip rule add %s\n", rule)
	}

	var chains []string
	for chain := range o.nfr.(*fakeIPTablesRunner).ipt4 {
		chains = append(chains, chain)
	}
	sort.Strings(chains)
	for _, chain := range chains {
		for _, rule := range o.nfr.(*fakeIPTablesRunner).ipt4[chain] {
			fmt.Fprintf(&b, "v4/%s %s\n", chain, rule)
		}
	}

	chains = nil
	for chain := range o.nfr.(*fakeIPTablesRunner).ipt6 {
		chains = append(chains, chain)
	}
	sort.Strings(chains)
	for _, chain := range chains {
		for _, rule := range o.nfr.(*fakeIPTablesRunner).ipt6[chain] {
			fmt.Fprintf(&b, "v6/%s %s\n", chain, rule)
		}
	}

	return b.String()[:len(b.String())-1]
}

func (o *fakeOS) run(args ...string) error {
	unexpected := func() error {
		o.t.Errorf("unexpected invocation %q", strings.Join(args, " "))
		return errors.New("unrecognized invocation")
	}
	if args[0] != "ip" {
		return unexpected()
	}

	if len(args) == 2 && args[1] == "rule" {
		// naked invocation of `ip rule` is a feature test. Return
		// successfully.
		return nil
	}

	family := ""
	rest := strings.Join(args[3:], " ")
	if args[1] == "-4" || args[1] == "-6" {
		family = args[1]
		copy(args[1:], args[2:])
		args = args[:len(args)-1]
		rest = family + " " + strings.Join(args[3:], " ")
	}

	var l *[]string
	switch args[1] {
	case "link":
		got := strings.Join(args[2:], " ")
		switch got {
		case "set dev tailscale0 up":
			o.up = true
		case "set dev tailscale0 down":
			o.up = false
		default:
			return unexpected()
		}
		return nil
	case "addr":
		l = &o.ips
	case "route":
		l = &o.routes
	case "rule":
		l = &o.rules
	default:
		return unexpected()
	}

	switch args[2] {
	case "add":
		for _, el := range *l {
			if el == rest {
				o.t.Errorf("can't add %q, already present", rest)
				return errors.New("already exists")
			}
		}
		*l = append(*l, rest)
		sort.Strings(*l)
	case "del":
		found := false
		for i, el := range *l {
			if el == rest {
				found = true
				*l = append((*l)[:i], (*l)[i+1:]...)
				break
			}
		}
		if !found {
			o.t.Logf("note: can't delete %q, not present", rest)
			// 'ip rule del' exits with code 2 when a row is
			// missing. We don't want to consider that an error,
			// for cleanup purposes.

			// TODO(apenwarr): this is a hack.
			// I'd like to return an exec.ExitError(2) here, but
			// I can't, because the ExitCode is implemented in
			// os.ProcessState, which is an opaque object I can't
			// instantiate or modify. Go's 75 levels of abstraction
			// between me and an 8-bit int are really paying off
			// here, as you can see.
			return errors.New("exitcode:2")
		}
	default:
		return unexpected()
	}

	return nil
}

func (o *fakeOS) output(args ...string) ([]byte, error) {
	want := "ip rule list priority 10000"
	got := strings.Join(args, " ")
	if got != want {
		o.t.Errorf("unexpected command that wants output: %v", got)
		return nil, errExec
	}

	var ret []string
	for _, rule := range o.rules {
		if strings.Contains(rule, "10000") {
			ret = append(ret, rule)
		}
	}
	return []byte(strings.Join(ret, "\n")), nil
}

var tunTestNum int64

func createTestTUN(t *testing.T) tun.Device {
	const minimalMTU = 1280
	tunName := fmt.Sprintf("tuntest%d", atomic.AddInt64(&tunTestNum, 1))
	tun, err := tun.CreateTUN(tunName, minimalMTU)
	if err != nil {
		t.Fatalf("CreateTUN(%q): %v", tunName, err)
	}
	return tun
}

type linuxTest struct {
	tun       tun.Device
	mon       *netmon.Monitor
	r         *linuxRouter
	logOutput tstest.MemLogger
}

func (lt *linuxTest) Close() error {
	if lt.tun != nil {
		lt.tun.Close()
	}
	if lt.mon != nil {
		lt.mon.Close()
	}
	return nil
}

func newLinuxRootTest(t *testing.T) (*linuxTest, *eventbus.Bus) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	lt := new(linuxTest)
	lt.tun = createTestTUN(t)

	logf := lt.logOutput.Logf

	bus := eventbustest.NewBus(t)

	mon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		lt.Close()
		t.Fatal(err)
	}
	mon.Start()
	lt.mon = mon

	r, err := newUserspaceRouter(logf, lt.tun, mon, nil, bus)
	if err != nil {
		lt.Close()
		t.Fatal(err)
	}
	lr := r.(*linuxRouter)
	if err := lr.upInterface(); err != nil {
		lt.Close()
		t.Fatal(err)
	}
	lt.r = lr
	return lt, bus
}

func TestRuleDeletedEvent(t *testing.T) {
	fake := NewFakeOS(t)
	lt, bus := newLinuxRootTest(t)
	lt.r.nfr = fake.nfr
	defer lt.Close()
	event := netmon.RuleDeleted{
		Table:    52,
		Priority: 5210,
	}
	tw := eventbustest.NewWatcher(t, bus)

	t.Logf("Value before: %t", lt.r.ruleRestorePending.Load())
	if lt.r.ruleRestorePending.Load() {
		t.Errorf("rule deletion already ongoing")
	}
	injector := eventbustest.NewInjector(t, bus)
	eventbustest.Inject(injector, event)
	eventbustest.Expect(tw, eventbustest.Type[AddIPRules]())
}

func TestDelRouteIdempotent(t *testing.T) {
	lt, _ := newLinuxRootTest(t)
	defer lt.Close()

	for _, s := range []string{
		"192.0.2.0/24",  // RFC 5737
		"2001:DB8::/32", // RFC 3849
	} {
		cidr := netip.MustParsePrefix(s)
		if err := lt.r.addRoute(cidr); err != nil {
			t.Error(err)
			continue
		}
		for i := range 2 {
			if err := lt.r.delRoute(cidr); err != nil {
				t.Errorf("delRoute(i=%d): %v", i, err)
			}
		}
	}

	if t.Failed() {
		out := lt.logOutput.String()
		t.Logf("Log output:\n%s", out)
	}
}

func TestAddRemoveRules(t *testing.T) {
	lt, _ := newLinuxRootTest(t)
	defer lt.Close()
	r := lt.r

	step := func(name string, f func() error) {
		t.Logf("Doing %v ...", name)
		if err := f(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rules, err := netlink.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if r.Priority >= 5000 && r.Priority <= 5999 {
				t.Logf("Rule: %+v", r)
			}
		}
	}

	step("init_del_and_add", r.addIPRules)
	step("dup_add", r.justAddIPRules)
	step("del", r.delIPRules)
	step("dup_del", r.delIPRules)
}

func TestDebugListLinks(t *testing.T) {
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range links {
		t.Logf("Link: %+v", ln)
	}
}

func TestDebugListRoutes(t *testing.T) {
	// We need to pass a non-nil route to RouteListFiltered, along
	// with the netlink.RT_FILTER_TABLE bit set in the filter
	// mask, otherwise it ignores non-main routes.
	filter := &netlink.Route{}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		t.Logf("Route: %+v", r)
	}
}

var famName = map[int]string{
	netlink.FAMILY_ALL: "all",
	netlink.FAMILY_V4:  "v4",
	netlink.FAMILY_V6:  "v6",
}

func TestDebugListRules(t *testing.T) {
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6, netlink.FAMILY_ALL} {
		t.Run(famName[fam], func(t *testing.T) {
			rules, err := netlink.RuleList(fam)
			if err != nil {
				t.Skipf("skip; RuleList fails with: %v", err)
			}
			for _, r := range rules {
				t.Logf("Rule: %+v", r)
			}
		})
	}
}

func TestCheckIPRuleSupportsV6(t *testing.T) {
	err := linuxfw.CheckIPRuleSupportsV6(t.Logf)
	if err != nil && os.Getuid() != 0 {
		t.Skipf("skipping, error when not root: %v", err)
	}
	// Just log it. For interactive testing only.
	// Some machines running our tests might not have IPv6.
	t.Logf("Got: %v", err)
}

func TestBusyboxParseVersion(t *testing.T) {
	input := `BusyBox v1.34.1 (2022-09-01 16:10:29 UTC) multi-call binary.
BusyBox is copyrighted by many authors between 1998-2015.
Licensed under GPLv2. See source distribution for detailed
copyright notices.

Usage: busybox [function [arguments]...]
   or: busybox --list[-full]
   or: busybox --show SCRIPT
   or: busybox --install [-s] [DIR]
   or: function [arguments]...

	BusyBox is a multi-call binary that combines many common Unix
	utilities into a single executable.  Most people will create a
	link to busybox for each function they wish to use and BusyBox
	will act like whatever it was invoked as.
`

	v1, v2, v3, err := busyboxParseVersion(input)
	if err != nil {
		t.Fatalf("busyboxParseVersion() failed: %v", err)
	}

	if got, want := fmt.Sprintf("%d.%d.%d", v1, v2, v3), "1.34.1"; got != want {
		t.Errorf("version = %q, want %q", got, want)
	}
}

func TestCIDRDiff(t *testing.T) {
	pfx := func(p ...string) []netip.Prefix {
		var ret []netip.Prefix
		for _, s := range p {
			ret = append(ret, netip.MustParsePrefix(s))
		}
		return ret
	}
	tests := []struct {
		old     []netip.Prefix
		new     []netip.Prefix
		wantAdd []netip.Prefix
		wantDel []netip.Prefix
		final   []netip.Prefix
	}{
		{
			old:     nil,
			new:     pfx("1.1.1.1/32"),
			wantAdd: pfx("1.1.1.1/32"),
			final:   pfx("1.1.1.1/32"),
		},
		{
			old:   pfx("1.1.1.1/32"),
			new:   pfx("1.1.1.1/32"),
			final: pfx("1.1.1.1/32"),
		},
		{
			old:     pfx("1.1.1.1/32", "2.3.4.5/32"),
			new:     pfx("1.1.1.1/32"),
			wantDel: pfx("2.3.4.5/32"),
			final:   pfx("1.1.1.1/32"),
		},
		{
			old:     pfx("1.1.1.1/32", "2.3.4.5/32"),
			new:     pfx("1.0.0.0/32", "3.4.5.6/32"),
			wantDel: pfx("1.1.1.1/32", "2.3.4.5/32"),
			wantAdd: pfx("1.0.0.0/32", "3.4.5.6/32"),
			final:   pfx("1.0.0.0/32", "3.4.5.6/32"),
		},
	}
	for _, tc := range tests {
		om := make(map[netip.Prefix]bool)
		for _, p := range tc.old {
			om[p] = true
		}
		var added []netip.Prefix
		var deleted []netip.Prefix
		fm, err := cidrDiff("test", om, tc.new, func(p netip.Prefix) error {
			if len(deleted) > 0 {
				t.Error("delete called before add")
			}
			added = append(added, p)
			return nil
		}, func(p netip.Prefix) error {
			deleted = append(deleted, p)
			return nil
		}, t.Logf)
		if err != nil {
			t.Fatal(err)
		}
		slices.SortFunc(added, netipx.ComparePrefix)
		slices.SortFunc(deleted, netipx.ComparePrefix)
		if !reflect.DeepEqual(added, tc.wantAdd) {
			t.Errorf("added = %v, want %v", added, tc.wantAdd)
		}
		if !reflect.DeepEqual(deleted, tc.wantDel) {
			t.Errorf("deleted = %v, want %v", deleted, tc.wantDel)
		}

		// Check that the final state is correct.
		if len(fm) != len(tc.final) {
			t.Fatalf("final state = %v, want %v", fm, tc.final)
		}
		for _, p := range tc.final {
			if !fm[p] {
				t.Errorf("final state = %v, want %v", fm, tc.final)
			}
		}
	}
}

var (
	fwmaskSupported     bool
	fwmaskSupportedOnce sync.Once
	fwmaskAdjustRe      = regexp.MustCompile(`(?m)(fwmark 0x[0-9a-f]+)/0x[0-9a-f]+`)
)

// adjustFwmask removes the "/0xmask" string from fwmask stanzas if the
// installed 'ip' binary does not support that format.
func adjustFwmask(t *testing.T, s string) string {
	t.Helper()
	fwmaskSupportedOnce.Do(func() {
		fwmaskSupported, _ = ipCmdSupportsFwmask()
	})
	if fwmaskSupported {
		return s
	}

	return fwmaskAdjustRe.ReplaceAllString(s, "$1")
}

func TestIPRulesForUBNT(t *testing.T) {
	// Override the global getDistroFunc
	getDistroFunc = func() distro.Distro {
		return distro.UBNT
	}
	defer func() { getDistroFunc = distro.Get }() // Restore original after the test

	expected := ubntIPRules
	actual := ipRules()

	if len(expected) != len(actual) {
		t.Fatalf("Expected %d rules, got %d", len(expected), len(actual))
	}

	for i, rule := range expected {
		if rule != actual[i] {
			t.Errorf("Rule mismatch at index %d: expected %+v, got %+v", i, rule, actual[i])
		}
	}
}
