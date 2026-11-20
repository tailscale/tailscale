// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package osrouter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	mdnetlink "github.com/mdlayher/netlink"
	"github.com/tailscale/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/router"
)

// testUnderlayAddrs is a fixed underlay address set used by fake-OS router
// tests so results don't depend on the host's interfaces. It deliberately
// includes one of the test configs' Tailscale addresses, which must never get
// a rule.
var testUnderlayAddrs = []netip.Addr{
	netip.MustParseAddr("10.1.2.3"),
	netip.MustParseAddr("100.101.102.104"), // a Tailscale LocalAddr in tests; excluded
	netip.MustParseAddr("192.168.1.5"),
	netip.MustParseAddr("2001:db8::5"),
	netip.MustParseAddr("fe80::5"),
}

func setTestUnderlayAddrs(r *linuxRouter, addrs []netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.underlayAddrs = func() []netip.Addr { return slices.Clone(addrs) }
}

// testUnderlayPri and testSuppressPri are the underlay rule priorities for
// routers using the default ipPolicyPrefBase, as newTestLinuxRouter does.
const (
	testUnderlayPri = defaultIPPolicyPrefBase + underlaySrcRuleOffset
	testSuppressPri = defaultIPPolicyPrefBase + underlaySuppressRuleOffset
)

// underlayRules returns the fake OS's rules at the underlay rule priorities.
func underlayRules(fake *fakeOS) []string {
	var out []string
	for _, ru := range fake.rules {
		if strings.Contains(ru, fmt.Sprintf(" pref %d ", testUnderlayPri)) ||
			strings.Contains(ru, fmt.Sprintf(" pref %d ", testSuppressPri)) {
			out = append(out, ru)
		}
	}
	return out
}

// underlaySrcRuleCount counts the fake OS's underlay source rules for the
// family given as "-4" or "-6".
func underlaySrcRuleCount(fake *fakeOS, fam string) int {
	n := 0
	for _, ru := range underlayRules(fake) {
		if strings.HasPrefix(ru, fam+" ") && strings.Contains(ru, " from ") {
			n++
		}
	}
	return n
}

// wantUnderlayRules returns the fake OS rules expected for underlay source
// addresses addrs: one source rule each, plus the suppress rule for each
// family that has any.
func wantUnderlayRules(addrs ...string) []string {
	var out []string
	fams := set.Set[string]{}
	for _, a := range addrs {
		fam := "-4"
		if strings.Contains(a, ":") {
			fam = "-6"
		}
		fams.Add(fam)
		out = append(out, fmt.Sprintf("%s pref %d from %s uidrange 0-0 table main protocol 52", fam, testUnderlayPri, a))
	}
	for fam := range fams {
		out = append(out, fmt.Sprintf("%s pref %d not fwmark 0x80000/0xff0000 table 52 suppress_prefixlength 0 protocol 52", fam, testSuppressPri))
	}
	slices.Sort(out)
	return out
}

func checkUnderlayRules(t *testing.T, fake *fakeOS, want ...string) {
	t.Helper()
	got := underlayRules(fake)
	w := strings.Split(adjustFwmask(t, strings.Join(wantUnderlayRules(want...), "\n")), "\n")
	if len(want) == 0 {
		w = nil
	}
	if !slices.Equal(got, w) {
		t.Fatalf("underlay source rules:\n got %q\nwant %q", got, w)
	}
}

func exitConfig(routes ...string) *router.Config {
	return &router.Config{
		LocalAddrs:    mustCIDRs("100.101.102.104/10"),
		Routes:        mustCIDRs(routes...),
		NetfilterMode: netfilterOff,
	}
}

func TestUnderlayAddrsFromState(t *testing.T) {
	const up = net.FlagUp
	ifc := func(name string, flags net.Flags) netmon.Interface {
		return netmon.Interface{Interface: &net.Interface{Name: name, Flags: flags}}
	}
	st := &netmon.State{
		DefaultRouteInterface: "eth0",
		Interface: map[string]netmon.Interface{
			"eth0":       ifc("eth0", up),
			"lo":         ifc("lo", up|net.FlagLoopback),
			"tailscale0": ifc("tailscale0", up),
			"ts-custom":  ifc("ts-custom", up),
			"docker0":    ifc("docker0", 0), // down
			"wg0":        ifc("wg0", up),
			"kube-ipvs0": ifc("kube-ipvs0", up),
			"empty0":     ifc("empty0", up),
		},
		InterfaceIPs: map[string][]netip.Prefix{
			"eth0": {
				netip.MustParsePrefix("fe80::5/64"),
				netip.MustParsePrefix("192.168.1.5/24"),
				netip.MustParsePrefix("2001:db8::5/64"),
				netip.MustParsePrefix("192.168.1.5/24"), // dup
			},
			"lo": {
				netip.MustParsePrefix("127.0.0.1/8"),
				netip.MustParsePrefix("::1/128"),
				netip.MustParsePrefix("10.9.9.9/32"), // service VIP on lo
			},
			"tailscale0": {netip.MustParsePrefix("100.64.0.1/32")},
			"ts-custom":  {netip.MustParsePrefix("100.64.0.2/32")},
			"docker0":    {netip.MustParsePrefix("172.17.0.1/16")},
			"wg0":        {netip.MustParsePrefix("10.200.0.2/32")},
			"kube-ipvs0": {
				netip.MustParsePrefix("10.96.0.1/32"),
				netip.MustParsePrefix("10.96.0.10/32"),
				netip.MustParsePrefix("10.200.0.2/32"), // also on wg0; keep first
			},
		},
	}
	got := underlayAddrsFromState(st, "ts-custom")
	want := []netip.Addr{
		// Default route interface first.
		netip.MustParseAddr("192.168.1.5"),
		netip.MustParseAddr("2001:db8::5"),
		netip.MustParseAddr("fe80::5"),
		// Then by address count (1 each), then name.
		netip.MustParseAddr("10.9.9.9"),   // lo
		netip.MustParseAddr("10.200.0.2"), // wg0
		// Then the many-address interface, minus the dup already listed.
		netip.MustParseAddr("10.96.0.1"),
		netip.MustParseAddr("10.96.0.10"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("underlayAddrsFromState:\n got %v\nwant %v", got, want)
	}
	if got := underlayAddrsFromState(nil, "tailscale0"); got != nil {
		t.Errorf("nil state: got %v, want nil", got)
	}
}

// TestUnderlaySrcRulesCapKeepsPrimary is a regression test for the cap
// filling up with service VIPs (numerically lower than the NIC address) on a
// kube-proxy IPVS node and leaving the address tailscaled actually uses
// without a rule.
func TestUnderlaySrcRulesCapKeepsPrimary(t *testing.T) {
	const up = net.FlagUp
	ifc := func(name string) netmon.Interface {
		return netmon.Interface{Interface: &net.Interface{Name: name, Flags: up}}
	}
	var vips []netip.Prefix
	a := netip.MustParseAddr("10.96.0.1")
	for range 3 * maxUnderlaySrcRulesPerFamily {
		vips = append(vips, netip.PrefixFrom(a, 32))
		a = a.Next()
	}
	st := &netmon.State{
		DefaultRouteInterface: "eth0",
		Interface: map[string]netmon.Interface{
			"eth0":       ifc("eth0"),
			"eth1":       ifc("eth1"),
			"kube-ipvs0": ifc("kube-ipvs0"),
		},
		InterfaceIPs: map[string][]netip.Prefix{
			"eth0":       {netip.MustParsePrefix("192.168.1.5/24")},
			"eth1":       {netip.MustParsePrefix("172.16.0.5/24")},
			"kube-ipvs0": vips,
		},
	}
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, underlayAddrsFromState(st, "tailscale0"))
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	rules := underlayRules(fake)
	if n := underlaySrcRuleCount(fake, "-4"); n != maxUnderlaySrcRulesPerFamily {
		t.Fatalf("got %d source rules, want %d", n, maxUnderlaySrcRulesPerFamily)
	}
	for _, want := range wantUnderlayRules("192.168.1.5", "172.16.0.5") {
		if !slices.Contains(rules, want) {
			t.Errorf("missing %q; cap crowded out a NIC address", want)
		}
	}
}

func TestUnderlaySrcRulesNilAddrFunc(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	lr.mu.Lock()
	lr.underlayAddrs = nil
	lr.mu.Unlock()
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake)
}

// TestUnderlaySrcRulesLifecycle walks the rules through exit node on/off,
// per-family gating, address changes, and Close.
func TestUnderlaySrcRulesLifecycle(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	addrs := []netip.Addr{
		netip.MustParseAddr("192.168.1.5"),
		netip.MustParseAddr("2001:db8::5"),
	}
	setTestUnderlayAddrs(lr, addrs)

	// No exit node: no rules.
	if err := lr.Set(exitConfig("100.100.100.100/32", "192.168.16.0/24")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake)

	// IPv4 exit route only.
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.5")

	// Dual-stack exit routes.
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.5", "2001:db8::5")

	// DHCP renumbering plus a new IPv6 privacy address: rules follow
	// on the next network change without a Set.
	setTestUnderlayAddrs(lr, []netip.Addr{
		netip.MustParseAddr("192.168.1.77"),
		netip.MustParseAddr("2001:db8::5"),
		netip.MustParseAddr("2001:db8::abcd"),
	})
	lr.onNetworkChange()
	checkUnderlayRules(t, fake, "192.168.1.77", "2001:db8::5", "2001:db8::abcd")

	// Idempotent: repeated changes and Sets with no difference don't
	// re-add (fakeOS fails the test on a duplicate add).
	lr.onNetworkChange()
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.77", "2001:db8::5", "2001:db8::abcd")

	// Exit node off: everything removed.
	if err := lr.Set(exitConfig("100.100.100.100/32")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake)

	// Back on, then Close removes them.
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.77", "2001:db8::5", "2001:db8::abcd")
	if err := lr.Close(); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake)

	// Network changes after Close are ignored.
	lr.onNetworkChange()
	checkUnderlayRules(t, fake)
}

func TestUnderlaySrcRulesNilConfigRemoves(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.5")
	if err := lr.Set(nil); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake)
}

func TestUnderlaySrcRulesSkipV6WhenUnavailable(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	fake.nfr.(*fakeIPTablesRunner).noV6 = true
	setTestUnderlayAddrs(lr, []netip.Addr{
		netip.MustParseAddr("192.168.1.5"),
		netip.MustParseAddr("2001:db8::5"),
	})
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.5")
}

func TestUnderlaySrcRulesExcludeTailscaleAddrs(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{
		netip.MustParseAddr("100.101.102.104"), // our Tailscale address
		netip.MustParseAddr("100.72.1.1"),      // carrier-grade NAT underlay; keep
	})
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "100.72.1.1")
}

func TestUnderlaySrcRulesCap(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	var addrs []netip.Addr
	a := netip.MustParseAddr("10.0.0.1")
	for range maxUnderlaySrcRulesPerFamily + 10 {
		addrs = append(addrs, a)
		a = a.Next()
	}
	addrs = append(addrs, netip.MustParseAddr("2001:db8::5"))
	setTestUnderlayAddrs(lr, addrs)
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	n4, n6 := underlaySrcRuleCount(fake, "-4"), underlaySrcRuleCount(fake, "-6")
	if n4 != maxUnderlaySrcRulesPerFamily || n6 != 1 {
		t.Errorf("got %d v4 and %d v6 rules; want %d and 1", n4, n6, maxUnderlaySrcRulesPerFamily)
	}
	if !lr.underlaySrcRulesCapped {
		t.Error("underlaySrcRulesCapped = false; want true")
	}
}

// TestUnderlaySrcRulesInRestoreRange ensures the rule priority is inside the
// range onIPRuleDeleted reacts to and below the table 52 catch-all.
func TestUnderlaySrcRulesInRestoreRange(t *testing.T) {
	for _, base := range []int{defaultIPPolicyPrefBase, mwan3IPPolicyPrefBase} {
		r := &linuxRouter{routerFixed: routerFixed{ipPolicyPrefBase: base}}
		pri := r.underlaySrcRulePriority()
		if pri < base || pri >= base+100 {
			t.Errorf("base %d: priority %d outside onIPRuleDeleted range", base, pri)
		}
		for _, ru := range append(slices.Clone(baseIPRules), ubntIPRules...) {
			if ru.Table == tailscaleRouteTable.Num && pri >= base+ru.Priority {
				t.Errorf("base %d: priority %d not below table 52 rule at %d", base, pri, base+ru.Priority)
			}
		}
	}
}

func TestIsOurUnderlayRule(t *testing.T) {
	base := defaultIPPolicyPrefBase
	r := &linuxRouter{routerFixed: routerFixed{ipPolicyPrefBase: base}}
	// srcRule, supRule and portRule are ours as listed by a kernel
	// without rule protocol support (pre-4.17), so only their shape
	// identifies them.
	noProto := func(u underlayRule) func() ipRule {
		return func() ipRule {
			ru := r.underlayIPRule(u)
			ru.protocol = 0
			return ru
		}
	}
	srcRule := noProto(underlayRule{fam: v4, src: netip.MustParseAddr("192.168.1.5")})
	supRule := noProto(underlayRule{fam: v6})
	portRule := noProto(underlayRule{fam: v4, src: netip.MustParseAddr("192.168.1.5"), port: 41641})
	mod := func(ru ipRule, f func(*ipRule)) ipRule { f(&ru); return ru }
	noUID := func(ru *ipRule) { ru.uidRange = nil }
	// An administrator's "ip rule add pref 5260 from 192.0.2.50 lookup main".
	admin := ipRule{family: v4, priority: uint32(base + underlaySrcRuleOffset), table: uint32(mainRouteTable.Num), src: netip.MustParseAddr("192.0.2.50"), suppressPrefixlen: -1}

	tests := []struct {
		name string
		ru   ipRule
		// want is the result on kernels 4.10-4.16 (uidrange, no rule
		// protocol) and wantPre410 on older ones. Rules with a protocol
		// are only reported by 4.17+, where both agree.
		want, wantPre410 bool
	}{
		// Kernel 4.17+: the protocol decides, whatever the shape.
		{"protocol-ours", mod(srcRule(), func(ru *ipRule) { ru.hasProtocol = true; ru.protocol = ruleProtocolTailscale }), true, true},
		{"protocol-ours-odd-shape", mod(srcRule(), func(ru *ipRule) { ru.hasProtocol = true; ru.protocol = ruleProtocolTailscale; ru.other = true }), true, true},
		{"protocol-ours-suppress", mod(supRule(), func(ru *ipRule) { ru.hasProtocol = true; ru.protocol = ruleProtocolTailscale }), true, true},
		{"protocol-ours-port", mod(portRule(), func(ru *ipRule) { ru.hasProtocol = true; ru.protocol = ruleProtocolTailscale }), true, true},
		{"protocol-admin-same-shape", mod(srcRule(), func(ru *ipRule) { ru.hasProtocol = true; ru.protocol = 0 }), false, false},
		{"protocol-other-daemon", mod(srcRule(), func(ru *ipRule) { ru.hasProtocol = true; ru.protocol = 186 }), false, false},
		{"protocol-ours-other-priority", mod(srcRule(), func(ru *ipRule) { ru.hasProtocol = true; ru.protocol = ruleProtocolTailscale; ru.priority++ }), false, false},

		// Older kernels: exact shape. Our source rule has uidrange 0-0
		// from 4.10, and none before (the kernel drops it).
		{"shape-src", srcRule(), true, false},
		{"shape-src-no-uidrange", mod(srcRule(), noUID), false, true},
		{"shape-admin-rule (review finding 4)", admin, false, true},
		{"shape-src-v6", mod(srcRule(), func(ru *ipRule) { ru.family = v6; ru.src = netip.MustParseAddr("2001:db8::5") }), true, false},
		{"shape-src-other-uidrange", mod(srcRule(), func(ru *ipRule) { ru.uidRange = &[2]uint32{1000, 1000} }), false, false},
		{"shape-src-other-table", mod(srcRule(), func(ru *ipRule) { ru.table = 100 }), false, false},
		{"shape-src-no-src", mod(srcRule(), func(ru *ipRule) { ru.src = netip.Addr{} }), false, false},
		{"shape-src-invert", mod(srcRule(), func(ru *ipRule) { ru.invert = true }), false, false},
		{"shape-src-fwmark", mod(srcRule(), func(ru *ipRule) { ru.fwmark, ru.fwmask = 1, 1 }), false, false},
		{"shape-src-suppress", mod(srcRule(), func(ru *ipRule) { ru.suppressPrefixlen = 0 }), false, false},
		{"shape-src-ipproto", mod(srcRule(), func(ru *ipRule) { ru.ipProto = unix.IPPROTO_TCP }), false, false},
		{"shape-src-other-selectors", mod(srcRule(), func(ru *ipRule) { ru.other = true }), false, false},
		{"shape-other-priority", mod(srcRule(), func(ru *ipRule) { ru.priority = 5261 }), false, false},
		{"shape-suppress", supRule(), true, true},
		{"shape-suppress-no-invert", mod(supRule(), func(ru *ipRule) { ru.invert = false }), false, false},
		{"shape-suppress-other-mark", mod(supRule(), func(ru *ipRule) { ru.fwmark = 0x40000 }), false, false},
		{"shape-suppress-other-prefixlen", mod(supRule(), func(ru *ipRule) { ru.suppressPrefixlen = 8 }), false, false},
		{"shape-suppress-other-table", mod(supRule(), func(ru *ipRule) { ru.table = 254 }), false, false},
		{"shape-suppress-with-src", mod(supRule(), func(ru *ipRule) { ru.src = netip.MustParseAddr("2001:db8::5") }), false, false},
		// Port rules only exist from 4.17 (with a protocol); before
		// that a leftover has lost its selectors and must be swept.
		{"shape-port-selectors-dropped", mod(portRule(), func(ru *ipRule) { ru.ipProto = 0; ru.sportRange = nil }), true, false},
		{"shape-port-selectors-dropped-pre410", mod(portRule(), func(ru *ipRule) { ru.ipProto = 0; ru.sportRange = nil; ru.uidRange = nil }), false, true},
		{"shape-port-tcp", mod(portRule(), func(ru *ipRule) { ru.ipProto = unix.IPPROTO_TCP }), false, false},
		{"shape-port-without-src", mod(portRule(), func(ru *ipRule) { ru.src = netip.Addr{} }), false, false},
		{"shape-port-without-suppress", mod(portRule(), func(ru *ipRule) { ru.suppressPrefixlen = -1 }), false, false},
	}
	for _, tt := range tests {
		if got := isOurUnderlayRuleFor(tt.ru, base, true); got != tt.want {
			t.Errorf("%s (kernel 4.10-4.16): got %v, want %v", tt.name, got, tt.want)
		}
		if got := isOurUnderlayRuleFor(tt.ru, base, false); got != tt.wantPre410 {
			t.Errorf("%s (kernel < 4.10): got %v, want %v", tt.name, got, tt.wantPre410)
		}
	}
}

// TestIPRuleMarshalRoundTrip checks that our rules survive encoding to the
// kernel's wire format and back, including uidrange's 32-bit fields.
func TestIPRuleMarshalRoundTrip(t *testing.T) {
	r := &linuxRouter{routerFixed: routerFixed{ipPolicyPrefBase: defaultIPPolicyPrefBase}}
	for _, u := range []underlayRule{
		{fam: v4, src: netip.MustParseAddr("192.168.1.5")},
		{fam: v6, src: netip.MustParseAddr("2001:db8::5")},
		{fam: v4},
		{fam: v6},
		{fam: v4, src: netip.MustParseAddr("192.168.1.5"), port: 41641},
		{fam: v6, src: netip.MustParseAddr("2001:db8::5"), port: 65535},
	} {
		want := r.underlayIPRule(u)
		b, err := want.marshal()
		if err != nil {
			t.Fatalf("%v: marshal: %v", u, err)
		}
		got, err := unmarshalIPRule(b)
		if err != nil {
			t.Fatalf("%v: unmarshal: %v", u, err)
		}
		want.hasProtocol = true // set by decoding when the protocol is present
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%v: round trip:\n got %+v\nwant %+v", u, got, want)
		}
		if !isOurUnderlayRule(got, defaultIPPolicyPrefBase) {
			t.Errorf("%v: decoded rule not recognized as ours", u)
		}
	}
	// A kernel-format uidrange with values above 16 bits decodes intact.
	big := r.underlayIPRule(underlayRule{fam: v4, src: netip.MustParseAddr("10.0.0.1")})
	big.uidRange = &[2]uint32{70000, 4000000000}
	b, _ := big.marshal()
	got, err := unmarshalIPRule(b)
	if err != nil || got.uidRange == nil || *got.uidRange != [2]uint32{70000, 4000000000} {
		t.Errorf("large uidrange round trip: %+v, %v", got.uidRange, err)
	}
}

// netnsChildEnv marks the re-executed test process running inside a private
// network namespace.
const netnsChildEnv = "TS_TEST_RPFILTER_NETNS_CHILD"

// TestUnderlaySrcRulesKernel is an end-to-end test against the real kernel.
// It re-executes itself in a fresh network namespace (so nothing touches the
// host's rules), builds a minimal exit-node topology with strict rp_filter,
// and uses the kernel's own input route lookup (RTM_GETROUTE with iif, which
// runs fib_validate_source) to verify replies to tailscaled's sockets are no
// longer rejected as martians. It also checks outbound traffic still uses the
// exit node, rules follow address changes, and stale rules are swept.
func TestUnderlaySrcRulesKernel(t *testing.T) {
	if os.Getenv(netnsChildEnv) == "" {
		tstest.RequireRoot(t)
		cmd := exec.Command(os.Args[0], "-test.run=^TestUnderlaySrcRulesKernel$", "-test.v")
		cmd.Env = append(os.Environ(), netnsChildEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		out, err := cmd.CombinedOutput()
		if err != nil {
			if errors.Is(err, syscall.EPERM) {
				t.Skipf("can't create network namespace: %v", err)
			}
			t.Fatalf("netns child failed: %v\n%s", err, out)
		}
		t.Logf("netns child output:\n%s", out)
		return
	}
	underlayRulesKernelChild(t)
}

func underlayRulesKernelChild(t *testing.T) {
	var (
		local4  = netip.MustParseAddr("172.31.0.44")
		local6  = netip.MustParseAddr("2001:db8:1::44")
		gw4     = netip.MustParseAddr("172.31.0.1")
		gw6     = netip.MustParseAddr("2001:db8:1::1")
		remote4 = netip.MustParseAddr("1.2.3.4")             // exit node / DERP underlay
		remote6 = netip.MustParseAddr("2001:db8:ffff::1234") // ditto, IPv6
	)
	mustSysctl := func(k, v string) {
		t.Helper()
		if err := writeSysctl(k, v); err != nil {
			t.Fatal(err)
		}
	}

	// Underlay "NIC": a dummy interface with a default route in main.
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	ul := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ul0"}}
	if err := netlink.LinkAdd(ul); err != nil {
		t.Skipf("can't create dummy link (no dummy module?): %v", err)
	}
	mustSysctl("net.ipv6.conf.ul0.disable_ipv6", "0")
	mustSysctl("net.ipv6.conf.ul0.accept_dad", "0")
	if err := netlink.LinkSetUp(ul); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"172.31.0.44/20", "2001:db8:1::44/64"} {
		if err := netlink.AddrAdd(ul, &netlink.Addr{IPNet: netipx.PrefixIPNet(netip.MustParsePrefix(p))}); err != nil {
			t.Fatal(err)
		}
	}
	for _, gw := range []netip.Addr{gw4, gw6} {
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: ul.Attrs().Index, Gw: gw.AsSlice()}); err != nil {
			t.Fatalf("default via %v: %v", gw, err)
		}
	}
	// A network behind this node (like a container bridge), which ipnlocal
	// passes as a local (throw) route.
	lan0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lan0"}}
	if err := netlink.LinkAdd(lan0); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lan0); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(lan0, &netlink.Addr{IPNet: netipx.PrefixIPNet(netip.MustParsePrefix("192.168.5.1/24"))}); err != nil {
		t.Fatal(err)
	}
	mustSysctl("net.ipv4.ip_forward", "1")
	// Strict reverse path filtering; src_valid_mark left at its default of 0.
	for _, k := range []string{"all", "default", "ul0", "lan0"} {
		mustSysctl("net.ipv4.conf."+k+".rp_filter", "1")
		mustSysctl("net.ipv4.conf."+k+".src_valid_mark", "0")
	}

	// A real router on a real TUN, with the real netmon.
	tunDev := createTestTUN(t)
	defer tunDev.Close()
	bus := eventbus.New()
	defer bus.Close()
	mon, err := netmon.New(bus, logger.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mon.Start()
	defer mon.Close()
	// Count rule restores so we can detect restore feedback loops.
	var restores atomic.Int32
	logf := func(format string, args ...any) {
		if strings.Contains(format, "deleted ip rules; restoring") {
			restores.Add(1)
		}
		t.Logf(format, args...)
	}
	tunName, err := tunDev.Name()
	if err != nil {
		t.Fatal(err)
	}
	// Capture the router's timers instead of letting them run on the wall
	// clock, so the assertions below can run them and wait for them rather
	// than sleep.
	var timers routerTimers
	lr := newTestRouter(logf, tunName, mon, osCommandRunner{}, nil, bus, func(r *linuxRouter) {
		r.nfr = NewFakeOS(t).nfr // netfilter isn't under test
		r.interfaceV6Usable = func() bool { return true }
		r.afterFunc = timers.afterFunc
	})

	// Stale rules from a "crashed" previous instance, to be swept by Up,
	// and an administrator's look-alike rules at our priority and at the
	// mwan3 base's priority, which must survive every sweep.
	stale := []underlayRule{{fam: v4, src: netip.MustParseAddr("192.0.2.99")}, {fam: v4}}
	for _, u := range stale {
		if err := addIPRule(lr.underlayIPRule(u)); err != nil {
			t.Fatal(err)
		}
	}
	admin := []ipRule{
		{family: v4, priority: uint32(lr.underlaySrcRulePriority()), table: uint32(mainRouteTable.Num), src: netip.MustParseAddr("192.0.2.50"), suppressPrefixlen: -1},
		{family: v4, priority: uint32(mwan3IPPolicyPrefBase + underlaySrcRuleOffset), table: uint32(mainRouteTable.Num), src: netip.MustParseAddr("192.0.2.51"), suppressPrefixlen: -1},
	}
	for _, ru := range admin {
		if err := addIPRule(ru); err != nil {
			t.Fatal(err)
		}
	}
	// Leftovers installed with the ip command (TS_DEBUG_USE_IP_COMMAND),
	// which must be swept too (review finding: they lacked the protocol).
	for _, u := range []underlayRule{
		{fam: v4, src: netip.MustParseAddr("192.0.2.98")},
		{fam: v4, src: netip.MustParseAddr("192.0.2.98"), port: 41641},
		{fam: v6},
	} {
		if err := (osCommandRunner{}).run(lr.underlayIPCommandArgs("add", u)...); err != nil {
			t.Fatalf("ip rule add for %v: %v", u, err)
		}
	}
	checkAdminRules := func(when string) {
		t.Helper()
		rules, err := listIPRules(v4)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range admin {
			if !slices.ContainsFunc(rules, func(ru ipRule) bool { return ru.priority == want.priority && ru.src == want.src }) {
				t.Fatalf("%s: administrator's rule (pref %d from %v) was deleted", when, want.priority, want.src)
			}
		}
	}
	if err := lr.Up(); err != nil {
		t.Fatal(err)
	}
	defer lr.Close()
	if got, sup, port := kernelUnderlayRules(t, lr), kernelSuppressRules(t, lr), kernelPortRules(t, lr); len(got) != 0 || len(sup) != 0 || len(port) != 0 {
		t.Fatalf("after Up, stale rules not swept: %v %v %v", got, sup, port)
	}
	checkAdminRules("after Up's sweep")

	// replyPasses reports whether a reply from remote4 to local4 arriving
	// on ul0 passes the kernel's input route lookup and source validation.
	replyPasses := func() error {
		_, err := netlink.RouteGetWithOptions(local4.AsSlice(), &netlink.RouteGetOptions{Iif: "ul0", SrcAddr: remote4.AsSlice()})
		return err
	}
	// routeDev returns the output interface for dst from src (src may be
	// invalid for an unbound socket).
	routeDev := func(dst, src netip.Addr) string {
		t.Helper()
		var opts *netlink.RouteGetOptions
		if src.IsValid() {
			opts = &netlink.RouteGetOptions{SrcAddr: src.AsSlice()}
		}
		rs, err := netlink.RouteGetWithOptions(dst.AsSlice(), opts)
		if err != nil || len(rs) == 0 {
			return fmt.Sprintf("error(%v)", err)
		}
		l, err := netlink.LinkByIndex(rs[0].LinkIndex)
		if err != nil {
			return fmt.Sprintf("error(%v)", err)
		}
		return l.Attrs().Name
	}

	cfg := &router.Config{
		LocalAddrs:    mustCIDRs("100.101.102.104/32", "fd7a:115c:a1e0::104/128"),
		Routes:        mustCIDRs("100.64.0.0/10", "fd7a:115c:a1e0::/48", "0.0.0.0/0", "::/0"),
		NetfilterMode: netfilterOff,
	}
	noExit := &router.Config{
		LocalAddrs:    cfg.LocalAddrs,
		Routes:        mustCIDRs("100.64.0.0/10", "fd7a:115c:a1e0::/48"),
		NetfilterMode: netfilterOff,
	}
	// With ExitNodeAllowLANAccess off, ipnlocal adds the LAN prefixes to
	// Routes; with it on, to LocalRoutes (throw routes).
	lan := mustCIDRs("172.31.0.0/20", "2001:db8:1::/64")
	cfgLANBlocked := &router.Config{
		LocalAddrs:    cfg.LocalAddrs,
		Routes:        append(slices.Clone(cfg.Routes), lan...),
		LocalRoutes:   mustCIDRs("192.168.5.0/24"), // the network behind us
		NetfilterMode: netfilterOff,
	}
	cfgLANAllowed := &router.Config{
		LocalAddrs:    cfg.LocalAddrs,
		Routes:        cfg.Routes,
		LocalRoutes:   append(slices.Clone(lan), netip.MustParsePrefix("192.168.5.0/24")),
		NetfilterMode: netfilterOff,
	}

	// Install the exit node routes with the address source disabled
	// first, to prove the topology reproduces #3310.
	setTestUnderlayAddrs(lr, nil)
	if err := lr.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if got := kernelUnderlayRules(t, lr); len(got) != 0 {
		t.Fatalf("unexpected rules with address source disabled: %v", got)
	}
	if err := replyPasses(); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("without underlay rules: reply validation = %v; want EINVAL (martian), topology doesn't reproduce #3310", err)
	}

	// Now with the real netmon-backed address source.
	lr.mu.Lock()
	lr.underlayAddrs = lr.underlayAddrsFromNetMon
	lr.mu.Unlock()
	lr.onNetworkChange()
	got := kernelUnderlayRules(t, lr)
	if !slices.Contains(got, local4) || !slices.Contains(got, local6) {
		t.Fatalf("underlay rules = %v; want %v and %v", got, local4, local6)
	}
	if sup := kernelSuppressRules(t, lr); !slices.Equal(sup, []addrFamily{v4, v6}) {
		t.Fatalf("suppress rules for families %v; want v4 and v6", sup)
	}
	for _, a := range got {
		if a == netip.MustParseAddr("100.101.102.104") || a == netip.MustParseAddr("fd7a:115c:a1e0::104") {
			t.Fatalf("rule installed for Tailscale address %v", a)
		}
	}
	if err := replyPasses(); err != nil {
		t.Fatalf("with underlay rules: reply validation failed: %v", err)
	}
	// Outbound from unbound sockets and from the Tailscale address still
	// goes via the exit node; only underlay-sourced lookups use main.
	for _, tc := range []struct {
		dst, src netip.Addr
		want     string
	}{
		{remote4, netip.Addr{}, tunName},
		{remote4, netip.MustParseAddr("100.101.102.104"), tunName},
		{remote4, local4, "ul0"},
		{remote6, netip.Addr{}, tunName},
		{remote6, netip.MustParseAddr("fd7a:115c:a1e0::104"), tunName},
		{remote6, local6, "ul0"},
	} {
		if got := routeDev(tc.dst, tc.src); got != tc.want {
			t.Errorf("route to %v from %v: dev %s, want %s", tc.dst, tc.src, got, tc.want)
		}
	}

	// Tailnet peers keep reaching the underlay addresses through the
	// tunnel: inbound passes strict rp_filter on the Tailscale interface,
	// and replies go back through it (review finding: without the table
	// 52 suppress rule, both went to the physical interface).
	peer4 := netip.MustParseAddr("100.64.0.2")
	peer6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
	for _, tc := range []struct{ peer, local netip.Addr }{{peer4, local4}, {peer6, local6}} {
		if _, err := kernelRouteGet(tc.local, tc.peer, tunName, -1); err != nil {
			t.Errorf("tailnet peer %v -> %v arriving on %s: rejected: %v", tc.peer, tc.local, tunName, err)
		}
		if got, err := kernelRouteGet(tc.peer, tc.local, "", 0); got != tunName {
			t.Errorf("reply %v -> %v: dev %q (%v), want %s", tc.local, tc.peer, got, err, tunName)
		}
	}

	// Only lookups as uid 0 (which the kernel's reverse-path check uses)
	// match the source rules: a non-root socket bound to an underlay
	// address still goes through the exit node.
	for _, tc := range []struct {
		dst, src netip.Addr
		uid      int
		want     string
	}{
		{remote4, local4, 0, "ul0"},
		{remote4, local4, 65534, tunName},
		{remote6, local6, 0, "ul0"},
		{remote6, local6, 65534, tunName},
	} {
		if got, err := kernelRouteGet(tc.dst, tc.src, "", tc.uid); got != tc.want {
			t.Errorf("route to %v from %v as uid %d: dev %q (%v), want %s", tc.dst, tc.src, tc.uid, got, err, tc.want)
		}
	}

	// LAN traffic with ExitNodeAllowLANAccess off stays blocked as before:
	// table 52 claims the LAN prefix, so a LAN host's packet to an underlay
	// address fails reverse-path validation and the reply would go into the
	// tunnel. With it on (throw routes), the LAN works.
	lanHost4 := netip.MustParseAddr("172.31.0.9")
	if err := lr.Set(cfgLANBlocked); err != nil {
		t.Fatal(err)
	}
	if _, err := kernelRouteGet(local4, lanHost4, "ul0", -1); !errors.Is(err, unix.EINVAL) {
		t.Errorf("LAN blocked: LAN host packet passed reverse-path validation (%v); want EINVAL", err)
	}
	if got, _ := kernelRouteGet(lanHost4, local4, "", 0); got != tunName {
		t.Errorf("LAN blocked: reply to LAN host via %q; want %s", got, tunName)
	}
	if err := replyPasses(); err != nil {
		t.Errorf("LAN blocked: reply from exit node rejected: %v", err)
	}
	// ...except replies to tailscaled's magicsock port, so direct paths to
	// peers on the LAN keep working (review finding: they fell back to
	// DERP). Other LAN traffic to the same address stays blocked.
	const msPort = 41641
	// The IPv4 port comes through the eventbus, as from magicsock.
	portPub := eventbus.Publish[router.PortUpdate](bus.Client("test-magicsock"))
	portPub.Publish(router.PortUpdate{UDPPort: msPort, EndpointNetwork: "udp4"})
	if err := lr.updateMagicsockPort(msPort, "udp6"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "magicsock port rule via PortUpdate", func() bool {
		return slices.Equal(kernelPortRules(t, lr), []addrFamily{v4})
	})
	if got := kernelPortRules(t, lr); !slices.Equal(got, []addrFamily{v4}) {
		t.Fatalf("magicsock port rules for families %v; want v4 only", got)
	}
	if _, err := kernelRouteGetPorts(local4, lanHost4, "ul0", -1, unix.IPPROTO_UDP, msPort, msPort); err != nil {
		t.Errorf("LAN blocked: LAN peer reply to magicsock port rejected: %v", err)
	}
	if got, _ := kernelRouteGetPorts(lanHost4, local4, "", 0, unix.IPPROTO_UDP, msPort, msPort); got != "ul0" {
		t.Errorf("LAN blocked: magicsock packet to LAN host via %q; want ul0", got)
	}
	if got, _ := kernelRouteGetPorts(lanHost4, local4, "", 0, unix.IPPROTO_UDP, 5555, msPort); got != tunName {
		t.Errorf("LAN blocked: other root UDP to LAN host via %q; want %s", got, tunName)
	}
	if _, err := kernelRouteGetPorts(local4, lanHost4, "ul0", -1, unix.IPPROTO_TCP, 40000, 22); !errors.Is(err, unix.EINVAL) {
		t.Errorf("LAN blocked: LAN-initiated TCP to a local service passed reverse-path validation (%v); want EINVAL", err)
	}
	// No IPv6 port rules: the IPv6 LAN block applies to magicsock too.
	lanHost6 := netip.MustParseAddr("2001:db8:1::9")
	if got, _ := kernelRouteGetPorts(lanHost6, local6, "", 0, unix.IPPROTO_UDP, msPort, msPort); got != tunName {
		t.Errorf("LAN blocked: unmarked IPv6 UDP from the magicsock port via %q; want %s", got, tunName)
	}

	// Known limitation, pinned so a change to it is deliberate: with LAN
	// access off, replies from the LAN to tailscaled sockets other than
	// magicsock's (the gateway's NAT-PMP or DNS, a control or DERP server
	// on the LAN) still fail strict rp_filter. Table 52 holds the LAN
	// prefix, the suppress rule keeps it ahead of the source rule, and only
	// the magicsock port is exempt. The reverted src_valid_mark=1 let these
	// through on hosts with netfilter on.
	for _, sport := range []uint16{53, 5351, 443} { // the LAN gateway's DNS, NAT-PMP, a LAN control server
		if _, err := kernelRouteGetPorts(local4, gw4, "ul0", -1, unix.IPPROTO_UDP, sport, 40000); !errors.Is(err, unix.EINVAL) {
			t.Errorf("LAN blocked: reply from LAN %v:%d to a non-magicsock socket: %v; want EINVAL (known limitation; update the commit message if fixed)", gw4, sport, err)
		}
	}

	// Forwarded traffic from the network behind us with the magicsock
	// port as source port isn't affected (review finding: without "from
	// A" it went out the physical interface, past the exit node, the
	// tailnet routes and the LAN block).
	behind := netip.MustParseAddr("192.168.5.7")
	for _, sport := range []uint16{5555, msPort} {
		for _, dst := range []netip.Addr{remote4, peer4, lanHost4} {
			if got, err := kernelRouteGetPorts(dst, behind, "lan0", -1, unix.IPPROTO_UDP, sport, 9); got != tunName {
				t.Errorf("forwarded UDP %v:%d -> %v: dev %q (%v), want %s", behind, sport, dst, got, err, tunName)
			}
		}
	}
	// Peers sending to the magicsock port through the tunnel still pass
	// reverse-path validation (review finding: the port rule sent their
	// reverse lookup to main's default route).
	for _, dst := range []netip.Addr{netip.MustParseAddr("100.101.102.104"), local4, behind} {
		if _, err := kernelRouteGetPorts(dst, peer4, tunName, -1, unix.IPPROTO_UDP, 9, msPort); err != nil {
			t.Errorf("tailnet UDP %v -> %v:%d arriving on %s rejected: %v", peer4, dst, msPort, tunName, err)
		}
	}
	// The rule follows magicsock port changes.
	if err := lr.updateMagicsockPort(msPort+1, "udp4"); err != nil {
		t.Fatal(err)
	}
	lr.onNetworkChange()
	if _, err := kernelRouteGetPorts(local4, lanHost4, "ul0", -1, unix.IPPROTO_UDP, msPort+1, msPort+1); err != nil {
		t.Errorf("after port change: reply to new magicsock port rejected: %v", err)
	}
	if _, err := kernelRouteGetPorts(local4, lanHost4, "ul0", -1, unix.IPPROTO_UDP, msPort, msPort); !errors.Is(err, unix.EINVAL) {
		t.Errorf("after port change: reply to old magicsock port still exempt (%v)", err)
	}
	if err := lr.Set(cfgLANAllowed); err != nil {
		t.Fatal(err)
	}
	if _, err := kernelRouteGet(local4, lanHost4, "ul0", -1); err != nil {
		t.Errorf("LAN allowed: LAN host packet rejected: %v", err)
	}
	if got, _ := kernelRouteGet(lanHost4, local4, "", 0); got != "ul0" {
		t.Errorf("LAN allowed: reply to LAN host via %q; want ul0", got)
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatal(err)
	}

	// Known limitation, pinned: an accepted subnet route in table 52 that
	// covers an Internet remote (a DERP or control server, say) is more
	// specific than ::/0 or 0.0.0.0/0, so the suppress rule sends the
	// reverse path lookup to the tunnel and the remote's replies fail
	// strict rp_filter.
	cfgSubnet := &router.Config{
		LocalAddrs:    cfg.LocalAddrs,
		Routes:        append(slices.Clone(cfg.Routes), netip.PrefixFrom(remote4, 24).Masked()),
		NetfilterMode: netfilterOff,
	}
	if err := lr.Set(cfgSubnet); err != nil {
		t.Fatal(err)
	}
	if _, err := kernelRouteGet(local4, remote4, "ul0", -1); !errors.Is(err, unix.EINVAL) {
		t.Errorf("subnet route covering %v: reply validation = %v; want EINVAL (known limitation; update the commit message if fixed)", remote4, err)
	}
	if err := lr.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if err := replyPasses(); err != nil {
		t.Fatalf("after dropping the subnet route: reply validation failed: %v", err)
	}

	// Address changes are followed via netmon without a Set.
	newAddr := netip.MustParseAddr("172.31.0.45")
	if err := netlink.AddrAdd(ul, &netlink.Addr{IPNet: netipx.PrefixIPNet(netip.PrefixFrom(newAddr, 20))}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "rule for added address", func() bool {
		return slices.Contains(kernelUnderlayRules(t, lr), newAddr)
	})
	if err := netlink.AddrDel(ul, &netlink.Addr{IPNet: netipx.PrefixIPNet(netip.PrefixFrom(newAddr, 20))}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "rule removal for deleted address", func() bool {
		return !slices.Contains(kernelUnderlayRules(t, lr), newAddr)
	})

	// Same for a carrier-grade NAT underlay address, which is in the
	// Tailscale CGNAT range but not on the Tailscale interface (review
	// finding: netmon ignored it, so no rule appeared).
	cgnat := netip.MustParsePrefix("100.72.1.1/24")
	if err := netlink.AddrAdd(ul, &netlink.Addr{IPNet: netipx.PrefixIPNet(cgnat)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "rule for added CGNAT underlay address", func() bool {
		return slices.Contains(kernelUnderlayRules(t, lr), cgnat.Addr())
	})
	if err := netlink.AddrDel(ul, &netlink.Addr{IPNet: netipx.PrefixIPNet(cgnat)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "rule removal for deleted CGNAT underlay address", func() bool {
		return !slices.Contains(kernelUnderlayRules(t, lr), cgnat.Addr())
	})

	// Our own add/remove churn above must not have triggered the
	// "somebody deleted ip rules" restore path. quiesce runs everything
	// the router scheduled and waits for every event the bus has for it,
	// so a non-zero count is a real feedback loop, not work in flight.
	quiesce(t, lr, bus, &timers)
	if n := restores.Load(); n != 0 {
		t.Fatalf("%d rule restores triggered by our own rule churn; want 0", n)
	}

	// With a loose (or no) kernel rp_filter, the IPv4 rules aren't needed
	// and aren't installed; IPv6 has no kernel rp_filter, so its stay.
	// A sysctl write raises no event: the router's periodic recheck (run
	// here by draining its timers, with no Set or network change) is what
	// notices, in both directions.
	for _, k := range []string{"all", "ul0", "lan0"} {
		mustSysctl("net.ipv4.conf."+k+".rp_filter", "2")
	}
	waitForTimers(t, &timers, "IPv4 rules removed after rp_filter went loose", func() bool {
		return !slices.ContainsFunc(kernelUnderlayRules(t, lr), netip.Addr.Is4)
	})
	if got := kernelUnderlayRules(t, lr); !slices.Contains(got, local6) {
		t.Fatalf("with loose rp_filter: rules for %v; want IPv6 only", got)
	}
	if got := kernelSuppressRules(t, lr); !slices.Equal(got, []addrFamily{v6}) {
		t.Fatalf("with loose rp_filter: suppress rules for %v; want v6 only", got)
	}
	for _, k := range []string{"all", "ul0", "lan0"} {
		mustSysctl("net.ipv4.conf."+k+".rp_filter", "1")
	}
	waitForTimers(t, &timers, "IPv4 rules back after rp_filter went strict", func() bool {
		return slices.Contains(kernelUnderlayRules(t, lr), local4)
	})
	if err := replyPasses(); err != nil {
		t.Fatalf("back to strict rp_filter: reply validation failed: %v", err)
	}

	// Exit node off: rules removed.
	if err := lr.Set(noExit); err != nil {
		t.Fatal(err)
	}
	if got, sup := kernelUnderlayRules(t, lr), kernelSuppressRules(t, lr); len(got) != 0 || len(sup) != 0 {
		t.Fatalf("after exit node off: rules %v %v remain", got, sup)
	}

	// Close removes them too.
	if err := lr.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if len(kernelUnderlayRules(t, lr)) == 0 {
		t.Fatal("rules not re-installed")
	}
	if err := lr.Close(); err != nil {
		t.Fatal(err)
	}
	if got, sup := kernelUnderlayRules(t, lr), kernelSuppressRules(t, lr); len(got) != 0 || len(sup) != 0 {
		t.Fatalf("after Close: rules %v %v remain", got, sup)
	}

	// The cleanup tailscaled runs at every start removes our leftovers
	// but not the administrator's rules, including the one at the mwan3
	// base's priority on this non-mwan3 host.
	for _, u := range stale {
		if err := addIPRule(lr.underlayIPRule(u)); err != nil {
			t.Fatal(err)
		}
	}
	removeUnderlaySrcRulesForCleanup(t.Logf)
	if got, sup := kernelUnderlayRules(t, lr), kernelSuppressRules(t, lr); len(got) != 0 || len(sup) != 0 {
		t.Fatalf("after cleanup: rules %v %v remain", got, sup)
	}
	checkAdminRules("after cleanup")
}

// kernelUnderlayRules lists the source addresses of our underlay source
// rules currently installed in the kernel.
func kernelUnderlayRules(t *testing.T, lr *linuxRouter) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, fam := range []addrFamily{v4, v6} {
		rules, err := listIPRules(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, ru := range rules {
			if isOurUnderlayRule(ru, lr.ipPolicyPrefBase) && int(ru.priority) == lr.underlaySrcRulePriority() && !slices.Contains(out, ru.src) {
				out = append(out, ru.src)
			}
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// kernelSuppressRules lists the families that have our table 52 suppress
// rule installed in the kernel.
func kernelSuppressRules(t *testing.T, lr *linuxRouter) []addrFamily {
	t.Helper()
	var out []addrFamily
	for _, fam := range []addrFamily{v4, v6} {
		rules, err := listIPRules(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, ru := range rules {
			if isOurUnderlayRule(ru, lr.ipPolicyPrefBase) && int(ru.priority) == lr.underlaySuppressRulePriority() && !slices.Contains(out, fam) {
				out = append(out, fam)
			}
		}
	}
	return out
}

// kernelPortRules lists the families that have our magicsock port rule
// installed in the kernel.
func kernelPortRules(t *testing.T, lr *linuxRouter) []addrFamily {
	t.Helper()
	var out []addrFamily
	for _, fam := range []addrFamily{v4, v6} {
		rules, err := listIPRules(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, ru := range rules {
			if isOurUnderlayRule(ru, lr.ipPolicyPrefBase) && int(ru.priority) == lr.underlayPortRulePriority() && !slices.Contains(out, fam) {
				out = append(out, fam)
			}
		}
	}
	return out
}

// kernelRouteGet asks the kernel, like 'ip route get', for the route to dst
// from src, returning the output interface name. If iif is set it does an
// input lookup as if the packet arrived on iif, which includes reverse-path
// source validation (EINVAL for a martian). If uid >= 0, the lookup is made
// as that uid. (The netlink package we use elsewhere can't set the uid.)
func kernelRouteGet(dst, src netip.Addr, iif string, uid int) (string, error) {
	return kernelRouteGetPorts(dst, src, iif, uid, 0, 0, 0)
}

// kernelRouteGetPorts is kernelRouteGet for a flow with the given IP
// protocol and ports (as 'ip route get ... ipproto P sport S dport D').
func kernelRouteGetPorts(dst, src netip.Addr, iif string, uid int, ipProto uint8, sport, dport uint16) (string, error) {
	hdr := make([]byte, 12) // struct rtmsg
	if dst.Is4() {
		hdr[0] = unix.AF_INET
	} else {
		hdr[0] = unix.AF_INET6
	}
	hdr[1] = uint8(dst.BitLen())
	ae := mdnetlink.NewAttributeEncoder()
	ae.Bytes(unix.RTA_DST, dst.AsSlice())
	if src.IsValid() {
		hdr[2] = uint8(src.BitLen())
		ae.Bytes(unix.RTA_SRC, src.AsSlice())
	}
	if iif != "" {
		l, err := netlink.LinkByName(iif)
		if err != nil {
			return "", err
		}
		ae.Uint32(unix.RTA_IIF, uint32(l.Attrs().Index))
	}
	if uid >= 0 {
		ae.Uint32(unix.RTA_UID, uint32(uid))
	}
	if ipProto != 0 {
		ae.Uint8(unix.RTA_IP_PROTO, ipProto)
		// Unlike rule port ranges, route query ports are __be16.
		ae.Bytes(unix.RTA_SPORT, binary.BigEndian.AppendUint16(nil, sport))
		ae.Bytes(unix.RTA_DPORT, binary.BigEndian.AppendUint16(nil, dport))
	}
	attrs, err := ae.Encode()
	if err != nil {
		return "", err
	}
	c, err := mdnetlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return "", err
	}
	defer c.Close()
	msgs, err := c.Execute(mdnetlink.Message{
		Header: mdnetlink.Header{Type: unix.RTM_GETROUTE, Flags: mdnetlink.Request},
		Data:   append(hdr, attrs...),
	})
	if err != nil {
		return "", err
	}
	if len(msgs) == 0 || len(msgs[0].Data) < 12 {
		return "", errors.New("no route returned")
	}
	ad, err := mdnetlink.NewAttributeDecoder(msgs[0].Data[12:])
	if err != nil {
		return "", err
	}
	for ad.Next() {
		if ad.Type() == unix.RTA_OIF {
			l, err := netlink.LinkByIndex(int(ad.Uint32()))
			if err != nil {
				return "", err
			}
			return l.Attrs().Name, nil
		}
	}
	return "", errors.New("route has no output interface")
}

// waitFor polls cond until it holds. The interval is a poll of real kernel
// state, which nothing in this test can be notified about; it isn't a wait
// for one of the router's own timers, which routerTimers makes deterministic.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	waitForPoll(t, what, cond)
}

func waitForPoll(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForTimers is waitFor for a condition that the router's own timers
// bring about: it drains them on every pass, so what the router scheduled
// runs instead of waiting out its delay on the wall clock.
func waitForTimers(t *testing.T, timers *routerTimers, what string, cond func() bool) {
	t.Helper()
	waitForPoll(t, what, func() bool {
		timers.drain()
		return cond()
	})
}

// routerTimers records the timers a router schedules through
// routerFixed.afterFunc instead of arming them on the wall clock, so a test
// runs them exactly when it needs their effect. A func that reschedules
// itself (a recheck) stays queued for the next drain, which is what the
// router would do in production.
type routerTimers struct {
	mu      sync.Mutex
	pending []func()
}

func (rt *routerTimers) afterFunc(_ time.Duration, f func()) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.pending = append(rt.pending, f)
}

// len reports how many funcs are scheduled and not yet run.
func (rt *routerTimers) len() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.pending)
}

// drain runs every func scheduled so far, once each, on the calling
// goroutine.
func (rt *routerTimers) drain() {
	rt.mu.Lock()
	pending := rt.pending
	rt.pending = nil
	rt.mu.Unlock()
	for _, f := range pending {
		f()
	}
}

// quiesce settles lr before assertions that count what it did: it runs every
// timer lr has scheduled, and waits until the bus has delivered
// every event published so far to lr's callbacks. What remains in flight
// after that is only a netlink event the kernel hasn't delivered yet, which
// waitFor's polling bounds; the wall-clock sleeps this replaced bounded
// nothing and cost seconds apiece.
func quiesce(t *testing.T, lr *linuxRouter, bus *eventbus.Bus, timers *routerTimers) {
	t.Helper()
	dbg := bus.Debugger()
	waitForTimers(t, timers, "router to quiesce", func() bool {
		return len(dbg.PublishQueue()) == 0 && len(dbg.SubscribeQueue(lr.eventClient)) == 0
	})
}

func TestUnderlaySrcRulesKillSwitch(t *testing.T) {
	// envknob.Setenv isn't synchronized with readers of the knob, so set
	// it before the router (and its goroutines) exist, and reset it only
	// after the router is closed. t.Cleanup runs last-registered first,
	// so register the reset before creating the router.
	envknob.Setenv("TS_DEBUG_DISABLE_RPFILTER_SRC_RULES", "true")
	t.Cleanup(func() { envknob.Setenv("TS_DEBUG_DISABLE_RPFILTER_SRC_RULES", "") })

	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake)
	lr.onNetworkChange()
	checkUnderlayRules(t, fake)
}

func TestIsIPRuleNotFound(t *testing.T) {
	// realErr runs a shell through the production osCommandRunner so the
	// error has exactly the shape (wrapped *exec.ExitError plus iproute2's
	// output) that 'ip rule del' failures have in production.
	realErr := func(code int, msg string) error {
		return osCommandRunner{}.run("sh", "-c", fmt.Sprintf("echo %q >&2; exit %d", msg, code))
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"fake-not-found", errors.New("exitcode:2"), true},
		{"fake-not-found-old-iproute2", errors.New("exitcode:254"), true},
		{"real-not-found", realErr(2, "RTNETLINK answers: No such file or directory"), true},
		{"real-not-found-old-iproute2", realErr(254, "RTNETLINK answers: No such file or directory"), true},
		{"real-eperm", realErr(2, "RTNETLINK answers: Operation not permitted"), false},
		{"real-other-code", realErr(1, "RTNETLINK answers: No such file or directory"), false},
		{"fake-other-code", errors.New("exitcode:1"), false},
		{"unrelated", errors.New("boom"), false},
	}
	for _, tt := range tests {
		if got := isIPRuleNotFound(tt.err); got != tt.want {
			t.Errorf("%s: got %v, want %v (err: %v)", tt.name, got, tt.want, tt.err)
		}
	}
}

// TestQueueNetworkChangeCoalesces checks that the ChangeDelta callback never
// blocks on r.mu and that a burst of changes while a reconcile is pending
// collapses into that one reconcile.
func TestQueueNetworkChangeCoalesces(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	var calls atomic.Int32
	addrs := []netip.Addr{netip.MustParseAddr("192.168.1.5")}
	lr.mu.Lock()
	lr.underlayAddrs = func() []netip.Addr { calls.Add(1); return slices.Clone(addrs) }
	lr.mu.Unlock()
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.5")
	calls.Store(0)

	// Hold mu, as a long Set would, and fire a burst of changes. Each
	// callback must return immediately.
	lr.mu.Lock()
	addrs = []netip.Addr{netip.MustParseAddr("192.168.1.77")}
	done := make(chan struct{})
	go func() {
		for range 100 {
			lr.queueNetworkChange()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		lr.mu.Unlock()
		t.Fatal("queueNetworkChange blocked while r.mu was held")
	}
	lr.mu.Unlock()

	waitFor(t, "coalesced reconcile", func() bool {
		lr.mu.Lock()
		defer lr.mu.Unlock()
		return !lr.netChangePending.Load() && lr.underlaySrcRules.Contains(underlayRule{fam: v4, src: netip.MustParseAddr("192.168.1.77")})
	})
	checkUnderlayRules(t, fake, "192.168.1.77")
	if n := calls.Load(); n != 1 {
		t.Errorf("burst of 100 changes ran %d reconciles; want 1", n)
	}
}

// TestUnderlaySrcRulesBeforeExitRoute checks that enabling an exit node
// installs the underlay rules before the default route, so there is no
// window in which replies to tailscaled's sockets are dropped, and that
// disabling it removes them after the route.
func TestUnderlaySrcRulesBeforeExitRoute(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	idx := func(prefix string) int {
		t.Helper()
		i := slices.IndexFunc(fake.cmds, func(c string) bool { return strings.HasPrefix(c, prefix) })
		if i < 0 {
			t.Fatalf("no %q command; ran %q", prefix, fake.cmds)
		}
		return i
	}
	fake.cmds = nil
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	sup := idx("ip -4 rule add pref 5255 ")
	src := idx("ip -4 rule add pref 5260 ")
	route := idx("ip route add 0.0.0.0/0 ")
	if !(sup < src && src < route) {
		t.Errorf("enable order: suppress rule %d, source rule %d, default route %d; want rules first, suppress before source", sup, src, route)
	}

	fake.cmds = nil
	if err := lr.Set(exitConfig("100.100.100.100/32")); err != nil {
		t.Fatal(err)
	}
	route = idx("ip route del 0.0.0.0/0 ")
	src = idx("ip -4 rule del pref 5260 ")
	sup = idx("ip -4 rule del pref 5255 ")
	if !(route < src && src < sup) {
		t.Errorf("disable order: default route %d, source rule %d, suppress rule %d; want route first, source before suppress", route, src, sup)
	}
}

// TestUnderlayPortRules checks the magicsock port rules: one per IPv4
// underlay address (none for IPv6, whose netfilter reverse-path checks
// carry no ports), installed with the exit node, following port changes,
// removed with the exit node.
func TestUnderlayPortRules(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("2001:db8::5")})
	for _, nw := range []string{"udp4", "udp6"} {
		if err := lr.updateMagicsockPort(41641, nw); err != nil {
			t.Fatal(err)
		}
	}
	portRules := func() []string {
		var out []string
		for _, ru := range fake.rules {
			if strings.Contains(ru, fmt.Sprintf(" pref %d ", defaultIPPolicyPrefBase+underlayPortRuleOffset)) {
				out = append(out, ru)
			}
		}
		return out
	}
	want := func(port int, addrs ...string) []string {
		var out []string
		for _, a := range addrs {
			out = append(out, fmt.Sprintf("-4 pref 5252 from %s ipproto udp sport %d uidrange 0-0 table main suppress_prefixlength 0 protocol 52", a, port))
		}
		slices.Sort(out)
		return out
	}
	if err := lr.Set(exitConfig("100.100.100.100/32")); err != nil {
		t.Fatal(err)
	}
	if got := portRules(); len(got) != 0 {
		t.Fatalf("port rules without exit node: %q", got)
	}
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	if got, w := portRules(), want(41641, "10.1.2.3", "192.168.1.5"); !slices.Equal(got, w) {
		t.Fatalf("port rules:\n got %q\nwant %q", got, w)
	}
	if err := lr.updateMagicsockPort(41700, "udp4"); err != nil {
		t.Fatal(err)
	}
	lr.onNetworkChange()
	if got, w := portRules(), want(41700, "10.1.2.3", "192.168.1.5"); !slices.Equal(got, w) {
		t.Fatalf("after port change:\n got %q\nwant %q", got, w)
	}
	if err := lr.Set(exitConfig("100.100.100.100/32")); err != nil {
		t.Fatal(err)
	}
	if got := portRules(); len(got) != 0 {
		t.Fatalf("port rules after exit node off: %q", got)
	}
}

// TestUnderlaySrcRulesFailures covers the reconcile's failure paths: a
// failed suppress rule add skips its source rules without failing Set, a
// failed delete stays tracked and is retried, and "File exists" from the ip
// command counts as success.
func TestUnderlaySrcRulesFailures(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	realErr := func(code int, msg string) error {
		return osCommandRunner{}.run("sh", "-c", fmt.Sprintf("echo %q >&2; exit %d", msg, code))
	}

	// Suppress rule add fails: no source rule either, and Set succeeds
	// (the rules are best effort and mustn't mark the router unhealthy).
	fake.failRun = func(args []string) error {
		if strings.Contains(strings.Join(args, " "), "rule add pref 5255") {
			return realErr(2, "RTNETLINK answers: Operation not permitted")
		}
		return nil
	}
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatalf("Set failed because of an rp_filter rule: %v", err)
	}
	checkUnderlayRules(t, fake)

	// Once it works, the next reconcile installs both.
	fake.failRun = nil
	lr.onNetworkChange()
	checkUnderlayRules(t, fake, "192.168.1.5")

	// Delete fails: the rule stays tracked and is retried.
	fake.failRun = func(args []string) error {
		if strings.Contains(strings.Join(args, " "), "rule del pref 5260") {
			return realErr(2, "RTNETLINK answers: Operation not permitted")
		}
		return nil
	}
	if err := lr.Set(exitConfig("100.100.100.100/32")); err != nil {
		t.Fatalf("Set failed because of an rp_filter rule: %v", err)
	}
	if !lr.underlaySrcRules.Contains(underlayRule{fam: v4, src: netip.MustParseAddr("192.168.1.5")}) {
		t.Fatal("source rule whose delete failed is no longer tracked")
	}
	if got := underlaySrcRuleCount(fake, "-4"); got != 1 {
		t.Fatalf("source rules after failed delete: %d, want 1", got)
	}
	// The suppress rule stays too: it's removed after its source rules.
	fake.failRun = nil
	lr.onNetworkChange()
	checkUnderlayRules(t, fake)

	// "File exists" from 'ip rule add' (e.g. left by a previous run in
	// ip command mode) counts as installed.
	fake.failRun = func(args []string) error {
		if strings.Contains(strings.Join(args, " "), "rule add pref 5260") {
			return realErr(2, "RTNETLINK answers: File exists")
		}
		return nil
	}
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	if !lr.underlaySrcRules.Contains(underlayRule{fam: v4, src: netip.MustParseAddr("192.168.1.5")}) {
		t.Error(`source rule not tracked after "File exists"`)
	}
}

// TestUnderlayRulesFollowInstalledRoutes checks that the rules stay while
// the exit node default route does, even when the config no longer has it
// because deleting it failed.
func TestUnderlayRulesFollowInstalledRoutes(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.5")
	fake.failRun = func(args []string) error {
		if strings.HasPrefix(strings.Join(args, " "), "ip route del 0.0.0.0/0") {
			return errors.New("exitcode:1")
		}
		return nil
	}
	lr.Set(exitConfig("100.100.100.100/32")) // fails to remove the default route
	if !lr.routes[netip.MustParsePrefix("0.0.0.0/0")] {
		t.Fatal("test setup: default route delete didn't fail")
	}
	checkUnderlayRules(t, fake, "192.168.1.5")
	fake.failRun = nil
	if err := lr.Set(exitConfig("100.100.100.100/32")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake)
}

// TestUnderlayRulesRemovedLastOnClose checks that Close removes the rules
// after taking the interface (and so the exit node default route) down.
func TestUnderlayRulesRemovedLastOnClose(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	fake.cmds = nil
	if err := lr.Close(); err != nil {
		t.Fatal(err)
	}
	down := slices.Index(fake.cmds, "ip link set dev tailscale0 down")
	del := slices.IndexFunc(fake.cmds, func(c string) bool { return strings.HasPrefix(c, "ip -4 rule del pref 5260 ") })
	if down < 0 || del < 0 || del < down {
		t.Errorf("Close: interface down at %d, rule removal at %d; want removal after down; ran %q", down, del, fake.cmds)
	}
	checkUnderlayRules(t, fake)
}

// TestUnderlayPortRuleWithoutNetfilter checks that the magicsock port rule
// follows the port even when the netfilter magicsock rule fails (review
// finding: the port was only recorded after netfilter succeeded, so no
// rule was installed).
func TestUnderlayPortRuleWithoutNetfilter(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	cfg := exitConfig("0.0.0.0/0")
	cfg.NetfilterMode = netfilterOn
	if err := lr.Set(cfg); err != nil {
		t.Fatal(err)
	}
	fake.nfr.(*fakeIPTablesRunner).addMagicsockPortErr = errors.New("ts-input chain flushed by a firewall reload")
	if err := lr.updateMagicsockPort(41641, "udp4"); err == nil {
		t.Fatal("test setup: netfilter magicsock rule didn't fail")
	}
	lr.onNetworkChange()
	want := "-4 pref 5252 from 192.168.1.5 ipproto udp sport 41641 uidrange 0-0 table main suppress_prefixlength 0 protocol 52"
	if !slices.Contains(fake.rules, want) {
		t.Errorf("no magicsock port rule after a failed netfilter update; rules: %q", underlayRules(fake))
	}
}

// TestUnderlayAddrsLinkLocalLast is a regression test for the per-family cap
// filling up with the fe80:: addresses of many container veths and leaving
// another NIC's global addresses without rules.
func TestUnderlayAddrsLinkLocalLast(t *testing.T) {
	ifc := func(name string) netmon.Interface {
		return netmon.Interface{Interface: &net.Interface{Name: name, Flags: net.FlagUp}}
	}
	st := &netmon.State{
		DefaultRouteInterface: "eth0",
		Interface:             map[string]netmon.Interface{"eth0": ifc("eth0"), "eth1": ifc("eth1")},
		InterfaceIPs: map[string][]netip.Prefix{
			"eth0": {netip.MustParsePrefix("192.168.1.5/24"), netip.MustParsePrefix("2001:db8::5/64"), netip.MustParsePrefix("fe80::5/64")},
			"eth1": {netip.MustParsePrefix("10.0.0.5/24"), netip.MustParsePrefix("2001:db8:1::5/64"), netip.MustParsePrefix("fe80::6/64")},
		},
	}
	ll := netip.MustParseAddr("fe80::1:0")
	for i := range maxUnderlaySrcRulesPerFamily + 2 {
		name := fmt.Sprintf("veth%03d", i)
		st.Interface[name] = ifc(name)
		st.InterfaceIPs[name] = []netip.Prefix{netip.PrefixFrom(ll, 64)}
		ll = ll.Next()
	}
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, underlayAddrsFromState(st, "tailscale0"))
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	rules := underlayRules(fake)
	for _, a := range []string{"192.168.1.5", "2001:db8::5", "fe80::5", "10.0.0.5", "2001:db8:1::5"} {
		if w := wantUnderlayRules(a)[0]; !slices.ContainsFunc(rules, func(r string) bool { return strings.Contains(r, " from "+a+" ") }) {
			t.Errorf("no rule for %s (want %q); veth link-locals crowded it out", a, w)
		}
	}
	if n := underlaySrcRuleCount(fake, "-6"); n != maxUnderlaySrcRulesPerFamily {
		t.Errorf("got %d IPv6 source rules, want the cap %d", n, maxUnderlaySrcRulesPerFamily)
	}
}

// TestUnderlayRulesNeedStrictRPFilter checks that the IPv4 rules are only
// installed while the kernel's IPv4 rp_filter is strict, so hosts without
// the problem don't get the behavior change for root sockets bound to an
// underlay address. IPv6 has no kernel rp_filter; its rules stay.
func TestUnderlayRulesNeedStrictRPFilter(t *testing.T) {
	var strict atomic.Bool
	lr, fake := newTestLinuxRouter(t, func(r *linuxRouter) {
		r.rpFilterStrictV4 = strict.Load
	})
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("2001:db8::5")})
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "2001:db8::5")
	strict.Store(true)
	lr.onNetworkChange()
	checkUnderlayRules(t, fake, "192.168.1.5", "2001:db8::5")
	strict.Store(false)
	lr.onNetworkChange()
	checkUnderlayRules(t, fake, "2001:db8::5")
}

// TestRPFilterRecheck checks that a change of the IPv4 rp_filter mode is
// picked up while an exit node is in use without any Set or network change,
// since a sysctl write raises no event (review finding: switching to strict
// mode left the IPv4 rules out until something unrelated happened).
func TestRPFilterRecheck(t *testing.T) {
	var strict atomic.Bool
	var timers routerTimers
	var reads atomic.Int32
	lr, fake := newTestLinuxRouter(t, func(r *linuxRouter) {
		r.rpFilterStrictV4 = func() bool { reads.Add(1); return strict.Load() }
		r.afterFunc = timers.afterFunc
	})
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("2001:db8::5")})

	// No exit node: nothing to gate, so nothing is scheduled.
	if err := lr.Set(exitConfig()); err != nil {
		t.Fatal(err)
	}
	if n := timers.len(); n != 0 {
		t.Fatalf("%d timers scheduled without an exit node; want 0", n)
	}

	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "2001:db8::5")
	if n := timers.len(); n != 1 {
		t.Fatalf("%d rechecks scheduled with an exit node; want 1", n)
	}

	// Unchanged: the recheck only reads the sysctls and schedules the next.
	reads.Store(0)
	timers.drain()
	checkUnderlayRules(t, fake, "2001:db8::5")
	if n, r := timers.len(), reads.Load(); n != 1 || r != 1 {
		t.Fatalf("after an unchanged recheck: %d timers, %d sysctl reads; want 1 and 1", n, r)
	}

	// Strict, with no Set or network change: the next recheck adds the
	// IPv4 rules, and loose again removes them.
	strict.Store(true)
	timers.drain()
	checkUnderlayRules(t, fake, "192.168.1.5", "2001:db8::5")
	strict.Store(false)
	timers.drain()
	checkUnderlayRules(t, fake, "2001:db8::5")

	// Exit node off: the pending recheck finds nothing to do and stops.
	if err := lr.Set(exitConfig()); err != nil {
		t.Fatal(err)
	}
	timers.drain()
	if n := timers.len(); n != 0 {
		t.Fatalf("%d timers still scheduled after the exit node went away; want 0", n)
	}
}

// TestCheckPortRule checks the port rule verification: a rule the kernel
// installed without its selectors means it doesn't support them, but a
// rule that's simply gone (deleted by someone else meanwhile) doesn't
// (review finding: that disabled port rules until restart).
func TestCheckPortRule(t *testing.T) {
	r := &linuxRouter{routerFixed: routerFixed{ipPolicyPrefBase: defaultIPPolicyPrefBase}}
	want := r.underlayIPRule(underlayRule{fam: v4, src: netip.MustParseAddr("192.168.1.5"), port: 41641})
	stripped := want
	stripped.ipProto, stripped.sportRange = 0, nil
	otherSrc := want
	otherSrc.src = netip.MustParseAddr("192.168.1.6")
	otherPort := want
	otherPort.sportRange = &[2]uint16{41642, 41642}
	for _, tt := range []struct {
		name  string
		rules []ipRule
		want  portRuleCheck
	}{
		{"installed", []ipRule{otherSrc, want}, portRuleOK},
		{"stripped", []ipRule{stripped}, portRuleStripped},
		{"gone", []ipRule{otherSrc}, portRuleMissing},
		{"gone-other-port-present", []ipRule{otherPort}, portRuleMissing},
		{"empty", nil, portRuleMissing},
	} {
		if got := checkPortRule(tt.rules, want); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestRPFilterStrictV4FromSysctl checks the sysctl reading against the
// host: the result must match a direct computation of max(all, iface) == 1.
func TestRPFilterStrictV4FromSysctl(t *testing.T) {
	lr, _ := newTestLinuxRouter(t)
	read := func(dev string) int {
		b, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + dev + "/rp_filter")
		if err != nil {
			return 0
		}
		v, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return v
	}
	want := false
	for name, ifc := range lr.netMon.InterfaceState().Interface {
		if !ifc.IsUp() || ifc.IsLoopback() || strings.HasPrefix(name, "tailscale") {
			continue
		}
		if max(read("all"), read(name)) == 1 {
			want = true
		}
	}
	if got := lr.rpFilterStrictV4FromSysctl(); got != want {
		t.Errorf("rpFilterStrictV4FromSysctl = %v, want %v", got, want)
	}
}

// TestUnderlayErrorLoggedOnce checks that a rule that keeps failing to add
// is logged once, not on every network change.
func TestUnderlayErrorLoggedOnce(t *testing.T) {
	var mu sync.Mutex
	var warnings int
	lr, fake := newTestLinuxRouter(t, func(r *linuxRouter) {
		r.logf = func(format string, args ...any) {
			if strings.Contains(format, "warning: rp_filter underlay rules") {
				mu.Lock()
				warnings++
				mu.Unlock()
			}
		}
	})
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	fake.failRun = func(args []string) error {
		if strings.Contains(strings.Join(args, " "), "rule add pref 5255") {
			return errors.New("exitcode:1")
		}
		return nil
	}
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		lr.onNetworkChange()
	}
	mu.Lock()
	got := warnings
	mu.Unlock()
	if got != 1 {
		t.Errorf("persistent failure logged %d times, want 1", got)
	}
	// Once it works, a new failure is logged again.
	fake.failRun = nil
	lr.onNetworkChange()
	fake.failRun = func(args []string) error {
		if strings.Contains(strings.Join(args, " "), "rule del pref 5260") {
			return errors.New("exitcode:1")
		}
		return nil
	}
	lr.Set(exitConfig("100.100.100.100/32"))
	mu.Lock()
	got = warnings
	mu.Unlock()
	if got != 2 {
		t.Errorf("after recovery and a new failure: logged %d times, want 2", got)
	}
}
