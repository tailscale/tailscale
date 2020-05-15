// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
)

func mustCIDR(s string) netaddr.IPPrefix {
	pfx, err := netaddr.ParseIPPrefix(s)
	if err != nil {
		panic(err)
	}
	return pfx
}

func mustCIDRs(ss ...string) []netaddr.IPPrefix {
	var ret []netaddr.IPPrefix
	for _, s := range ss {
		ret = append(ret, mustCIDR(s))
	}
	return ret
}

func TestRouterStates(t *testing.T) {
	states := []struct {
		name string
		in   *Config
		want string
	}{
		{
			name: "no config",
			in:   nil,
			want: `
up
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
`,
		},
		{
			name: "local addr only",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				NetfilterMode: NetfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
`,
		},

		{
			name: "addr and routes",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "192.168.16.0/24"),
				NetfilterMode: NetfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 scope global
ip route add 192.168.16.0/24 dev tailscale0 scope global
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
`,
		},

		{
			name: "addr and routes and subnet routes",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.103/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "192.168.16.0/24"),
				SubnetRoutes:  mustCIDRs("200.0.0.0/8"),
				NetfilterMode: NetfilterOff,
			},
			want: `
up
ip addr add 100.101.102.103/10 dev tailscale0
ip route add 100.100.100.100/32 dev tailscale0 scope global
ip route add 192.168.16.0/24 dev tailscale0 scope global
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
`,
		},

		{
			name: "addr and routes and subnet routes with netfilter",
			in: &Config{
				LocalAddrs:       mustCIDRs("100.101.102.104/10"),
				Routes:           mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				SubnetRoutes:     mustCIDRs("200.0.0.0/8"),
				SNATSubnetRoutes: true,
				NetfilterMode:    NetfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 scope global
ip route add 100.100.100.100/32 dev tailscale0 scope global
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
filter/FORWARD -j ts-forward
filter/INPUT -j ts-input
filter/ts-forward -o tailscale0 -s 200.0.0.0/8 -j ACCEPT
filter/ts-forward -i tailscale0 -d 200.0.0.0/8 -j MARK --set-mark 0x10000/0x10000
filter/ts-forward -m mark --mark 0x10000/0x10000 -j ACCEPT
filter/ts-forward -i tailscale0 -j DROP
filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -m comment --comment ChromeOS VM connectivity -j RETURN
filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
nat/POSTROUTING -j ts-postrouting
nat/ts-postrouting -m mark --mark 0x10000/0x10000 -j MASQUERADE
`,
		},
		{
			name: "addr and routes with netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: NetfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 scope global
ip route add 100.100.100.100/32 dev tailscale0 scope global
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
filter/FORWARD -j ts-forward
filter/INPUT -j ts-input
filter/ts-forward -m mark --mark 0x10000/0x10000 -j ACCEPT
filter/ts-forward -i tailscale0 -j DROP
filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -m comment --comment ChromeOS VM connectivity -j RETURN
filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
nat/POSTROUTING -j ts-postrouting
`,
		},

		{
			name: "addr and routes and subnet routes with netfilter but no SNAT",
			in: &Config{
				LocalAddrs:       mustCIDRs("100.101.102.104/10"),
				Routes:           mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				SubnetRoutes:     mustCIDRs("200.0.0.0/8"),
				SNATSubnetRoutes: false,
				NetfilterMode:    NetfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 scope global
ip route add 100.100.100.100/32 dev tailscale0 scope global
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
filter/FORWARD -j ts-forward
filter/INPUT -j ts-input
filter/ts-forward -o tailscale0 -s 200.0.0.0/8 -j ACCEPT
filter/ts-forward -i tailscale0 -d 200.0.0.0/8 -j MARK --set-mark 0x10000/0x10000
filter/ts-forward -m mark --mark 0x10000/0x10000 -j ACCEPT
filter/ts-forward -i tailscale0 -j DROP
filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -m comment --comment ChromeOS VM connectivity -j RETURN
filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
nat/POSTROUTING -j ts-postrouting
`,
		},
		{
			name: "addr and routes with netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: NetfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 scope global
ip route add 100.100.100.100/32 dev tailscale0 scope global
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
filter/FORWARD -j ts-forward
filter/INPUT -j ts-input
filter/ts-forward -m mark --mark 0x10000/0x10000 -j ACCEPT
filter/ts-forward -i tailscale0 -j DROP
filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -m comment --comment ChromeOS VM connectivity -j RETURN
filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
nat/POSTROUTING -j ts-postrouting
`,
		},

		{
			name: "addr and routes with half netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: NetfilterNoDivert,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 scope global
ip route add 100.100.100.100/32 dev tailscale0 scope global
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
filter/ts-forward -m mark --mark 0x10000/0x10000 -j ACCEPT
filter/ts-forward -i tailscale0 -j DROP
filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -m comment --comment ChromeOS VM connectivity -j RETURN
filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
`,
		},
		{
			name: "addr and routes with netfilter",
			in: &Config{
				LocalAddrs:    mustCIDRs("100.101.102.104/10"),
				Routes:        mustCIDRs("100.100.100.100/32", "10.0.0.0/8"),
				NetfilterMode: NetfilterOn,
			},
			want: `
up
ip addr add 100.101.102.104/10 dev tailscale0
ip route add 10.0.0.0/8 dev tailscale0 scope global
ip route add 100.100.100.100/32 dev tailscale0 scope global
ip rule add fwmark 0x20000/0x20000 priority 10000 table main suppress_ifgroup 10000
filter/FORWARD -j ts-forward
filter/INPUT -j ts-input
filter/ts-forward -m mark --mark 0x10000/0x10000 -j ACCEPT
filter/ts-forward -i tailscale0 -j DROP
filter/ts-input -i lo -s 100.101.102.104 -j ACCEPT
filter/ts-input ! -i tailscale0 -s 100.115.92.0/23 -m comment --comment ChromeOS VM connectivity -j RETURN
filter/ts-input ! -i tailscale0 -s 100.64.0.0/10 -j DROP
nat/POSTROUTING -j ts-postrouting
`,
		},
	}

	fake := NewFakeOS(t)
	router, err := newUserspaceRouterAdvanced(t.Logf, "tailscale0", fake, fake)
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
		want := strings.TrimSpace(states[i].want)
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

// fakeOS implements netfilterRunner and commandRunner, but captures
// changes without touching the OS.
type fakeOS struct {
	t         *testing.T
	up        bool
	ips       []string
	routes    []string
	rules     []string
	netfilter map[string][]string
}

func NewFakeOS(t *testing.T) *fakeOS {
	return &fakeOS{
		t: t,
		netfilter: map[string][]string{
			"filter/INPUT":    nil,
			"filter/OUTPUT":   nil,
			"filter/FORWARD":  nil,
			"nat/PREROUTING":  nil,
			"nat/OUTPUT":      nil,
			"nat/POSTROUTING": nil,
		},
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
	for chain := range o.netfilter {
		chains = append(chains, chain)
	}
	sort.Strings(chains)
	for _, chain := range chains {
		for _, rule := range o.netfilter[chain] {
			fmt.Fprintf(&b, "%s %s\n", chain, rule)
		}
	}
	return b.String()[:len(b.String())-1]
}

func (o *fakeOS) Insert(table, chain string, pos int, args ...string) error {
	k := table + "/" + chain
	if rules, ok := o.netfilter[k]; ok {
		if pos > len(rules)+1 {
			o.t.Errorf("bad position %d in %s", pos, k)
			return errExec
		}
		rules = append(rules, "")
		copy(rules[pos:], rules[pos-1:])
		rules[pos-1] = strings.Join(args, " ")
		o.netfilter[k] = rules
	} else {
		o.t.Errorf("unknown table/chain %s", k)
		return errExec
	}
	return nil
}

func (o *fakeOS) Append(table, chain string, args ...string) error {
	k := table + "/" + chain
	return o.Insert(table, chain, len(o.netfilter[k])+1, args...)
}

func (o *fakeOS) Exists(table, chain string, args ...string) (bool, error) {
	k := table + "/" + chain
	if rules, ok := o.netfilter[k]; ok {
		for _, rule := range rules {
			if rule == strings.Join(args, " ") {
				return true, nil
			}
		}
		return false, nil
	} else {
		o.t.Errorf("unknown table/chain %s", k)
		return false, errExec
	}
}

func (o *fakeOS) Delete(table, chain string, args ...string) error {
	k := table + "/" + chain
	if rules, ok := o.netfilter[k]; ok {
		for i, rule := range rules {
			if rule == strings.Join(args, " ") {
				rules = append(rules[:i], rules[i+1:]...)
				o.netfilter[k] = rules
				return nil
			}
		}
		o.t.Errorf("delete of unknown rule %q from %s", strings.Join(args, " "), k)
		return errExec
	} else {
		o.t.Errorf("unknown table/chain %s", k)
		return errExec
	}
}

func (o *fakeOS) ListChains(table string) (ret []string, err error) {
	for chain := range o.netfilter {
		pfx := table + "/"
		if strings.HasPrefix(chain, pfx) {
			ret = append(ret, chain[len(pfx):])
		}
	}
	return ret, nil
}

func (o *fakeOS) ClearChain(table, chain string) error {
	k := table + "/" + chain
	if _, ok := o.netfilter[k]; ok {
		o.netfilter[k] = nil
		return nil
	} else {
		o.t.Errorf("unknown table/chain %s", k)
		return errExec
	}
}

func (o *fakeOS) NewChain(table, chain string) error {
	k := table + "/" + chain
	if _, ok := o.netfilter[k]; ok {
		o.t.Errorf("table/chain %s already exists", k)
		return errExec
	}
	o.netfilter[k] = nil
	return nil
}

func (o *fakeOS) DeleteChain(table, chain string) error {
	k := table + "/" + chain
	if rules, ok := o.netfilter[k]; ok {
		if len(rules) != 0 {
			o.t.Errorf("%s is not empty", k)
			return errExec
		}
		delete(o.netfilter, k)
		return nil
	} else {
		o.t.Errorf("%s does not exist", k)
		return errExec
	}
}

func (o *fakeOS) run(args ...string) error {
	unexpected := func() error {
		o.t.Errorf("unexpected invocation %q", strings.Join(args, " "))
		return errors.New("unrecognized invocation")
	}
	if args[0] != "ip" {
		return unexpected()
	}

	rest := strings.Join(args[3:], " ")

	var l *[]string
	switch args[1] {
	case "link":
		got := strings.Join(args[2:], " ")
		switch got {
		case "set dev tailscale0 group 10000 up":
			o.up = true
		case "set dev tailscale0 group 0 down":
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
			o.t.Errorf("can't delete %q, not present", rest)
			return errors.New("not present")
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
