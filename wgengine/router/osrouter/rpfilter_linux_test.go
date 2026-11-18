// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package osrouter

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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

// testUnderlayPri is the underlay source rule priority for routers using
// the default ipPolicyPrefBase, as newTestLinuxRouter does.
const testUnderlayPri = defaultIPPolicyPrefBase + underlaySrcRuleOffset

// underlayRules returns the fake OS's rules at the underlay source priority.
func underlayRules(fake *fakeOS) []string {
	var out []string
	for _, ru := range fake.rules {
		if strings.Contains(ru, fmt.Sprintf(" pref %d ", testUnderlayPri)) {
			out = append(out, ru)
		}
	}
	return out
}

func wantUnderlayRules(addrs ...string) []string {
	var out []string
	for _, a := range addrs {
		fam := "-4"
		if strings.Contains(a, ":") {
			fam = "-6"
		}
		out = append(out, fmt.Sprintf("%s pref %d from %s table main", fam, testUnderlayPri, a))
	}
	slices.Sort(out)
	return out
}

func checkUnderlayRules(t *testing.T, fake *fakeOS, want ...string) {
	t.Helper()
	got := underlayRules(fake)
	w := wantUnderlayRules(want...)
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
	if len(rules) != maxUnderlaySrcRulesPerFamily {
		t.Fatalf("got %d rules, want %d", len(rules), maxUnderlaySrcRulesPerFamily)
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
	var n4, n6 int
	for _, ru := range underlayRules(fake) {
		if strings.HasPrefix(ru, "-6") {
			n6++
		} else {
			n4++
		}
	}
	if n4 != maxUnderlaySrcRulesPerFamily || n6 != 1 {
		t.Errorf("got %d v4 and %d v6 rules; want %d and 1", n4, n6, maxUnderlaySrcRulesPerFamily)
	}
	if !lr.underlaySrcRulesCapped {
		t.Error("underlaySrcRulesCapped = false; want true")
	}
}

// TestUnderlaySrcRulesRestore checks that rules deleted by another process
// (e.g. systemd-networkd flushing foreign rules) are re-installed, and that
// restoring while they still exist doesn't duplicate them.
func TestUnderlaySrcRulesRestore(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{
		netip.MustParseAddr("192.168.1.5"),
		netip.MustParseAddr("2001:db8::5"),
	})
	if err := lr.Set(exitConfig("0.0.0.0/0", "::/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.5", "2001:db8::5")

	// Restore with everything present: no duplicates.
	lr.restoreUnderlaySrcRules()
	checkUnderlayRules(t, fake, "192.168.1.5", "2001:db8::5")

	// External flush of one rule.
	fake.rules = slices.DeleteFunc(fake.rules, func(s string) bool {
		return strings.Contains(s, "from 192.168.1.5 ")
	})
	lr.restoreUnderlaySrcRules()
	checkUnderlayRules(t, fake, "192.168.1.5", "2001:db8::5")
}

// TestUnderlaySrcRulesInRestoreRange ensures the rule priority is inside the
// range onIPRuleDeleted reacts to and below the table 52 catch-all.
func TestUnderlaySrcRulesInRestoreRange(t *testing.T) {
	for _, base := range []int{defaultIPPolicyPrefBase, mwan3IPPolicyPrefBase} {
		r := &linuxRouter{ipPolicyPrefBase: base}
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

func TestIsUnderlaySrcRule(t *testing.T) {
	r := &linuxRouter{ipPolicyPrefBase: defaultIPPolicyPrefBase}
	pri := r.underlaySrcRulePriority()
	ours := func() netlink.Rule { return *r.underlaySrcNetlinkRule(netip.MustParseAddr("192.168.1.5")) }
	mod := func(f func(*netlink.Rule)) netlink.Rule { ru := ours(); f(&ru); return ru }

	tests := []struct {
		name string
		ru   netlink.Rule
		want bool
	}{
		{"ours", ours(), true},
		{"ours-v6", *r.underlaySrcNetlinkRule(netip.MustParseAddr("2001:db8::5")), true},
		{"other-priority", mod(func(ru *netlink.Rule) { ru.Priority = pri + 1 }), false},
		{"other-table", mod(func(ru *netlink.Rule) { ru.Table = 100 }), false},
		{"no-src", mod(func(ru *netlink.Rule) { ru.Src = nil }), false},
		{"subnet-src", mod(func(ru *netlink.Rule) { ru.Src = netipx.PrefixIPNet(netip.MustParsePrefix("192.168.1.0/24")) }), false},
		{"iif", mod(func(ru *netlink.Rule) { ru.IifName = "eth0" }), false},
		{"oif", mod(func(ru *netlink.Rule) { ru.OifName = "eth0" }), false},
		{"fwmark", mod(func(ru *netlink.Rule) { ru.Mark = 0x80000 }), false},
		{"dst", mod(func(ru *netlink.Rule) { ru.Dst = netipx.AddrIPNet(netip.MustParseAddr("1.2.3.4")) }), false},
		{"invert", mod(func(ru *netlink.Rule) { ru.Invert = true }), false},
		{"sport", mod(func(ru *netlink.Rule) { ru.Sport = netlink.NewRulePortRange(1, 2) }), false},
		{"type-unicast", mod(func(ru *netlink.Rule) { ru.Type = unix.RTN_UNICAST }), true},
		{"type-unreachable", mod(func(ru *netlink.Rule) { ru.Type = unix.RTN_UNREACHABLE }), false},
		{"type-prohibit", mod(func(ru *netlink.Rule) { ru.Type = unix.RTN_PROHIBIT }), false},
		{"tos", mod(func(ru *netlink.Rule) { ru.Tos = 0x10 }), false},
		{"suppress-prefixlen", mod(func(ru *netlink.Rule) { ru.SuppressPrefixlen = 0 }), false},
		{"suppress-ifgroup", mod(func(ru *netlink.Rule) { ru.SuppressIfgroup = 1 }), false},
		{"goto", mod(func(ru *netlink.Rule) { ru.Goto = 32766 }), false},
		{"realm", mod(func(ru *netlink.Rule) { ru.Flow = 5 }), false},
		{"fwmark-zero-with-mask", mod(func(ru *netlink.Rule) { ru.Mark = 0; ru.Mask = 0xff }), false},
		{"tun-id", mod(func(ru *netlink.Rule) { ru.TunID = 7 }), false},
	}
	for _, tt := range tests {
		if got := isUnderlaySrcRule(tt.ru, pri); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
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
	// Strict reverse path filtering; src_valid_mark left at its default of 0.
	for _, k := range []string{"all", "default", "ul0"} {
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
	var restores, repairs atomic.Int32
	logf := func(format string, args ...any) {
		if strings.Contains(format, "deleted ip rules; restoring") {
			restores.Add(1)
		}
		if strings.Contains(format, "rp_filter source rule(s) deleted by another process") {
			repairs.Add(1)
		}
		t.Logf(format, args...)
	}
	tunName, err := tunDev.Name()
	if err != nil {
		t.Fatal(err)
	}
	lr := newTestRouter(logf, tunName, mon, osCommandRunner{}, nil, bus, func(r *linuxRouter) {
		r.nfr = NewFakeOS(t).nfr // netfilter isn't under test
		r.interfaceV6Usable = func() bool { return true }
	})

	// A stale rule from a "crashed" previous instance, to be swept by Up.
	stale := lr.underlaySrcNetlinkRule(netip.MustParseAddr("192.0.2.99"))
	if err := netlink.RuleAdd(stale); err != nil {
		t.Fatal(err)
	}
	if err := lr.Up(); err != nil {
		t.Fatal(err)
	}
	defer lr.Close()
	if got := kernelUnderlayRules(t, lr); len(got) != 0 {
		t.Fatalf("after Up, stale rules not swept: %v", got)
	}

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
		Routes:        mustCIDRs("100.64.0.0/10", "0.0.0.0/0", "::/0"),
		NetfilterMode: netfilterOff,
	}
	noExit := &router.Config{
		LocalAddrs:    cfg.LocalAddrs,
		Routes:        mustCIDRs("100.64.0.0/10"),
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

	// Our own add/remove churn above must not have triggered the
	// "somebody deleted ip rules" restore path. Give any in-flight
	// restore timer (250ms+) time to fire before checking.
	time.Sleep(time.Second)
	if n := restores.Load(); n != 0 {
		t.Fatalf("%d rule restores triggered by our own rule churn; want 0", n)
	}
	if n := repairs.Load(); n != 0 {
		t.Fatalf("%d rule repairs re-added rules after our own churn; want 0", n)
	}

	// A lone external deletion of just one underlay rule (base rules
	// untouched, so no full restore) is repaired by the add-only path.
	if err := netlink.RuleDel(lr.underlaySrcNetlinkRule(local6)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "repair after lone external delete", func() bool {
		return slices.Contains(kernelUnderlayRules(t, lr), local6)
	})
	time.Sleep(time.Second)
	if r, p := restores.Load(), repairs.Load(); r != 0 || p != 1 {
		t.Fatalf("after lone delete: %d restores, %d repairs; want 0 and 1", r, p)
	}

	// An external flush (as systemd-networkd's
	// ManageForeignRoutingPolicyRules does) removes the base rules and the
	// underlay source rules; both are repaired.
	catchAll := netlink.NewRule()
	catchAll.Priority = lr.ipPolicyPrefBase + 70
	catchAll.Family = netlink.FAMILY_V4
	catchAll.Table = tailscaleRouteTable.Num
	if err := netlink.RuleDel(catchAll); err != nil {
		t.Fatal(err)
	}
	catchAll6 := *catchAll
	catchAll6.Family = netlink.FAMILY_V6
	if err := netlink.RuleDel(&catchAll6); err != nil {
		t.Fatal(err)
	}
	if err := netlink.RuleDel(lr.underlaySrcNetlinkRule(local4)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "restore after external flush", func() bool {
		return slices.Contains(kernelUnderlayRules(t, lr), local4)
	})
	if err := replyPasses(); err != nil {
		t.Fatalf("after restore: reply validation failed: %v", err)
	}
	for _, dst := range []netip.Addr{remote4, remote6} {
		if got := routeDev(dst, netip.Addr{}); got != tunName {
			t.Fatalf("after restore: route to %v via %s, want %s (catch-all not restored?)", dst, got, tunName)
		}
	}
	time.Sleep(time.Second)
	if n := restores.Load(); n != 1 {
		t.Fatalf("got %d rule restores after one external flush; want exactly 1 (feedback loop?)", n)
	}

	// Exit node off: rules removed.
	if err := lr.Set(noExit); err != nil {
		t.Fatal(err)
	}
	if got := kernelUnderlayRules(t, lr); len(got) != 0 {
		t.Fatalf("after exit node off: rules %v remain", got)
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
	if got := kernelUnderlayRules(t, lr); len(got) != 0 {
		t.Fatalf("after Close: rules %v remain", got)
	}
}

// kernelUnderlayRules lists the source addresses of underlay source rules
// currently installed in the kernel.
func kernelUnderlayRules(t *testing.T, lr *linuxRouter) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	seen := set.Set[netip.Addr]{}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, ru := range rules {
			if !isUnderlaySrcRule(ru, lr.underlaySrcRulePriority()) {
				continue
			}
			a, ok := netipx.FromStdIP(ru.Src.IP)
			if ok && !seen.Contains(a) {
				seen.Add(a)
				out = append(out, a)
			}
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestUnderlaySrcRulesKillSwitch(t *testing.T) {
	lr, fake := newTestLinuxRouter(t)
	setTestUnderlayAddrs(lr, []netip.Addr{netip.MustParseAddr("192.168.1.5")})
	if err := lr.Set(exitConfig("0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	checkUnderlayRules(t, fake, "192.168.1.5")

	envknob.Setenv("TS_DEBUG_DISABLE_RPFILTER_SRC_RULES", "true")
	t.Cleanup(func() { envknob.Setenv("TS_DEBUG_DISABLE_RPFILTER_SRC_RULES", "") })
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
		return !lr.netChangePending.Load() && lr.underlaySrcRules.Contains(netip.MustParseAddr("192.168.1.77"))
	})
	checkUnderlayRules(t, fake, "192.168.1.77")
	if n := calls.Load(); n != 1 {
		t.Errorf("burst of 100 changes ran %d reconciles; want 1", n)
	}
}
