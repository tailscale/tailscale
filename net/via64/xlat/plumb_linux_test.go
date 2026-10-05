// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package xlat

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/tailscale/netlink"
	"tailscale.com/net/via64"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/preftype"
)

func TestPairAndRoutes(t *testing.T) {
	tstest.RequireRoot(t)
	ns := addNetNS(t, "via64-plumb")
	x4 := netip.MustParseAddr("192.0.0.6")
	// Only t.Error inside inNS: t.Fatal (and so sh) on its goroutine would hang the test.
	var pair Pair
	if err := inNS(ns, func() (err error) { pair, err = createPair(); return err }); err != nil {
		t.Fatal(err)
	}
	for _, dev := range []string{PrimaryName, PeerName} {
		if out := sh(t, "ip netns exec via64-plumb ethtool -k "+dev); !strings.Contains(out, "tx-udp-segmentation: off") {
			t.Errorf("%s: UDP segmentation still on:\n%s", dev, out)
		}
	}
	if out := sh(t, "ip -n via64-plumb -d link show "+PrimaryName); !strings.Contains(out, "netkit") || !strings.Contains(out, "mtu 1280") {
		t.Errorf("%s is not a netkit device with MTU 1280:\n%s", PrimaryName, out)
	}
	err := inNS(ns, func() error {
		if pair.PrimaryIndex == 0 || pair.PeerIndex == 0 {
			t.Errorf("pair indexes not set: %+v", pair)
		}
		if got := readSysctl("net/ipv6/conf/" + PrimaryName + "/forwarding"); got != "1" {
			t.Errorf("%s IPv6 forwarding = %q; want 1", PrimaryName, got)
		}

		if err := netlink.RouteReplace(steeringRoute(pair, 5264)); err != nil {
			return err
		}
		r := steeringRule(5264, 5190)
		if err := netlink.RuleAdd(r); err != nil {
			return err
		}
		if ok, err := ruleExists(r); err != nil || !ok {
			t.Errorf("ruleExists = %v, %v; want true", ok, err)
		}
		if err := netlink.RuleAdd(x4Rule(x4, 5264, 5190)); err != nil {
			return err
		}
		if err := delRulesTo(5264); err != nil {
			return err
		}
		if ok, _ := ruleExists(r); ok {
			t.Error("rule still present after delRulesTo")
		}
		if ok, err := routeExists(steeringRoute(pair, 5264)); err != nil || !ok {
			t.Errorf("routeExists for the steering route = %v, %v; want true", ok, err)
		}
		if ok, err := routeExists(steeringRoute(pair, 5265)); err != nil || ok {
			t.Errorf("routeExists in another table = %v, %v; want false", ok, err)
		}
		if err := delPair(); err != nil {
			return err
		}
		if ok, err := routeExists(steeringRoute(pair, 5264)); err != nil || ok {
			t.Errorf("routeExists after delPair = %v, %v; want false (the route goes with the device)", ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if out := sh(t, "ip -n via64-plumb link"); strings.Contains(out, PrimaryName) {
		t.Errorf("%s still exists after delPair:\n%s", PrimaryName, out)
	}
}

func TestNAT(t *testing.T) {
	tstest.RequireRoot(t)
	ns := addNetNS(t, "via64-nat")
	prefixes := []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7::/96"), netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1790::/96")}
	x := Xlat{X4: netip.MustParseAddr("192.0.0.6")}
	supported := true
	err := inNS(ns, func() error {
		if supported = ctTimeoutSupported(); !supported {
			return nil
		}
		return installNAT("tailscale0", prefixes, x, natOpts{timeouts: true})
	})
	if !supported {
		t.Skip("the kernel lacks conntrack timeout policies")
	}
	if err != nil {
		t.Fatal(err)
	}
	out := sh(t, "ip netns exec via64-nat nft list ruleset")
	for _, want := range []string{
		"table ip6 ts-via64",
		`iifname "tailscale0" ip6 daddr fd7a:115c:a1e0:b1a:0:7::/96 dnat prefix to fd7a:115c:a1e0:b1a:ff:ffff::/96`,
		`iifname "tailscale0" ip6 daddr fd7a:115c:a1e0:b1a:0:1790::/96 dnat prefix to fd7a:115c:a1e0:b1a:ff:ffff::/96`,
		"ct timeout via64-udp",
		"ct timeout via64-dns",
		`ct timeout set "via64-dns"`,
		`ct timeout set "via64-udp"`,
		`meta l4proto tcp ct timeout set "via64-tcp"`,
		"table ip ts-via64",
		`ip saddr 192.0.0.6 oifname != "tsvia1" masquerade`,
		"priority srcnat - 1",
		`iifname != "tsvia0" ip6 daddr fd7a:115c:a1e0:b1a:ff:ffff::/96 drop`,
		`iifname != "tsvia1" ip saddr 192.0.0.6 drop`,
		`ip6 daddr fd7a:115c:a1e0:b1a:ff:ffff::/96 oifname != "tsvia0" drop`,
		`oifname "tsvia0" ct status dnat snat to fd7a:115c:a1e0:b1a:ff:ffff:c000:6`,
		`ip daddr 192.0.0.6 meta mark set meta mark & 0xff04ffff | 0x00040000`,
		`ip daddr 192.0.0.6 ip frag-off & 0x4000 == 0x0 ip length > 1260 meta mark set meta mark | 0x01000000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, out)
		}
	}
	// Installing again replaces rather than duplicates.
	if err := inNS(ns, func() error { return installNAT("tailscale0", prefixes[:1], x, natOpts{timeouts: true}) }); err != nil {
		t.Fatal(err)
	}
	out = sh(t, "ip netns exec via64-nat nft list ruleset")
	if strings.Count(out, "dnat prefix to") != 1 || strings.Count(out, "snat to") != 1 {
		t.Errorf("reinstall did not replace the tables:\n%s", out)
	}
	if err := inNS(ns, deleteNAT); err != nil {
		t.Fatal(err)
	}
	if out := sh(t, "ip netns exec via64-nat nft list ruleset"); strings.Contains(out, natTable) {
		t.Errorf("tables remain after deleteNAT:\n%s", out)
	}
}

// TestReassertLeavesFailedInstalls checks that a failed install is retried by the next Update, not by Reassert, and that nothing runs after Close.
func TestReassertLeavesFailedInstalls(t *testing.T) {
	tstest.RequireRoot(t)
	ns := addNetNS(t, "via64-retry")
	sh(t, "ip netns exec via64-retry sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1")
	tries := 0
	ctl := NewController(Config{
		Ingress:      "lo",
		RulePriority: 5190,
		Table:        5264,
		X4:           netip.MustParseAddr("192.0.0.6"),
		NewBackend: func() (Backend, error) {
			tries++
			return nil, errors.New("no backend here")
		},
		Logf: t.Logf,
	})
	d := Desired{Netfilter: preftype.NetfilterOn, SNAT: true, TunIPv6: true, Advertised: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7::/96")}}
	inNS(ns, func() error {
		if _, err := ctl.Update(d); err == nil {
			t.Error("Update succeeded with a failing backend")
		}
		ctl.Reassert()
		ctl.Reassert()
		if tries != 1 {
			t.Errorf("backend created %d times after one Update and two Reasserts; want 1", tries)
		}
		ctl.Update(d)
		if tries != 2 {
			t.Errorf("backend created %d times after a second Update; want 2", tries)
		}
		ctl.Close()
		ctl.Reassert()
		if tries != 2 {
			t.Errorf("backend created %d times after Close and Reassert; want 2", tries)
		}
		return nil
	})
}

// TestNATNetstackUDP checks the ruleset with UDP left to netstack, which needs no timeout policies.
func TestNATNetstackUDP(t *testing.T) {
	tstest.RequireRoot(t)
	ns := addNetNS(t, "via64-natudp")
	prefixes := []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7::/96")}
	x := Xlat{X4: netip.MustParseAddr("192.0.0.6")}
	var timeouts bool // false on Raspberry Pi kernels, where this ruleset must still install
	if err := inNS(ns, func() error {
		timeouts = ctTimeoutSupported()
		return installNAT("tailscale0", prefixes, x, natOpts{netstackUDP: true, timeouts: timeouts})
	}); err != nil {
		t.Fatal(err)
	}
	out := sh(t, "ip netns exec via64-natudp nft list ruleset")
	if !strings.Contains(out, `iifname "tailscale0" ip6 daddr fd7a:115c:a1e0:b1a:0:7::/96 meta l4proto != udp dnat prefix to fd7a:115c:a1e0:b1a:ff:ffff::/96`) {
		t.Errorf("DNAT does not leave UDP out:\n%s", out)
	}
	if strings.Contains(out, "via64-udp") || strings.Contains(out, "via64-dns") || timeouts != strings.Contains(out, `ct timeout set "via64-tcp"`) {
		t.Errorf("want the TCP timeout policy and no UDP ones with UDP on netstack:\n%s", out)
	}
}

// stubBackend stands in for the BPF translator, which this package cannot import.
type stubBackend struct{}

func (stubBackend) Install(Pair, Xlat) error { return nil }
func (stubBackend) Close() error             { return nil }

// TestNoConntrackTimeoutsKeepsUDPOnNetstack checks that without timeout policies via64 still runs, with UDP on netstack.
func TestNoConntrackTimeoutsKeepsUDPOnNetstack(t *testing.T) {
	tstest.RequireRoot(t)
	ns := addNetNS(t, "via64-noct")
	sh(t, "ip netns exec via64-noct sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1")
	restore := ctTimeoutSupportedFunc
	ctTimeoutSupportedFunc = func() bool { return false }
	t.Cleanup(func() { ctTimeoutSupportedFunc = restore })
	ctl := NewController(Config{
		Ingress:      "lo",
		RulePriority: 5190,
		Table:        5264,
		X4:           netip.MustParseAddr("192.0.0.6"),
		NewBackend:   func() (Backend, error) { return stubBackend{}, nil },
		Logf:         t.Logf,
	})
	t.Cleanup(func() { inNS(ns, ctl.Close) })
	ip := netip.MustParseAddr("fd7a:115c:a1e0:b1a:0:7:a01:2")
	d := Desired{Netfilter: preftype.NetfilterOn, SNAT: true, TunIPv6: true, Advertised: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7::/96")}}
	if err := inNS(ns, func() error { _, err := ctl.Update(d); return err }); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !via64.KernelHandles(ip, ipproto.TCP) || via64.KernelHandles(ip, ipproto.UDP) {
		t.Errorf("KernelHandles: TCP %v, UDP %v; want TCP in the kernel and UDP on netstack", via64.KernelHandles(ip, ipproto.TCP), via64.KernelHandles(ip, ipproto.UDP))
	}
	if out := sh(t, "ip netns exec via64-noct nft list ruleset"); strings.Contains(out, "ct timeout") || !strings.Contains(out, "meta l4proto != udp") {
		t.Errorf("ruleset still has UDP in the kernel:\n%s", out)
	}
}

// TestCleanupRemovesOnlyVia64State checks that Cleanup, which tailscaled --cleanup runs, removes what a process that died left behind, and that neither it nor Close touches another rule at via64's priority.
func TestCleanupRemovesOnlyVia64State(t *testing.T) {
	tstest.RequireRoot(t)
	ns := addNetNS(t, "via64-clean")
	sh(t, "ip netns exec via64-clean sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1")
	sh(t, "ip -n via64-clean rule add pref 5190 to 10.1.2.3 lookup 100")
	t.Cleanup(func() { via64.SetKernelHandled(nil, false) })
	d := Desired{Netfilter: preftype.NetfilterOn, SNAT: true, TunIPv6: true, Advertised: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:7::/96")}}
	install := func() *Controller {
		ctl := NewController(Config{Ingress: "lo", RulePriority: 5190, Table: 5264, X4: netip.MustParseAddr("192.0.0.6"), NewBackend: func() (Backend, error) { return stubBackend{}, nil }, Logf: t.Logf})
		if err := inNS(ns, func() error { _, err := ctl.Update(d); return err }); err != nil {
			t.Fatalf("Update: %v", err)
		}
		return ctl
	}
	check := func(when string) {
		t.Helper()
		rules := sh(t, "ip -n via64-clean rule") + sh(t, "ip -n via64-clean -6 rule")
		if strings.Contains(rules, "lookup 5264") || strings.Contains(rules, "lookup 5265") {
			t.Errorf("%s: via64 rules remain:\n%s", when, rules)
		}
		if !strings.Contains(rules, "10.1.2.3 lookup 100") {
			t.Errorf("%s: the other rule at priority 5190 was deleted:\n%s", when, rules)
		}
		if out := sh(t, "ip -n via64-clean link") + sh(t, "ip netns exec via64-clean nft list tables") + sh(t, "ip -n via64-clean route show table 5264") + sh(t, "ip -n via64-clean route show table 5265"); strings.Contains(out, PrimaryName) || strings.Contains(out, natTable) || strings.Contains(out, "192.0.0.6") {
			t.Errorf("%s: via64 state remains:\n%s", when, out)
		}
	}
	install() // and never closed, as if tailscaled had been killed
	if err := inNS(ns, func() error { return Cleanup(5264) }); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	check("after Cleanup")
	if err := inNS(ns, func() error { return Cleanup(5264) }); err != nil {
		t.Errorf("Cleanup with nothing to remove: %v", err)
	}
	ctl := install()
	if err := inNS(ns, ctl.Close); err != nil {
		t.Fatalf("Close: %v", err)
	}
	check("after Close")
}
