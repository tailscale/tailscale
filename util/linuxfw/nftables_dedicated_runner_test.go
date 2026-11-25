// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

func newTestDedicatedRunner(t *testing.T, conn *nftables.Conn, hasIPv6 bool) *nftablesDedicatedRunner {
	t.Helper()
	if !hasIPv6 {
		tstest.Replace(t, &checkIPv6ForTest, func(logger.Logf) error {
			return errors.New("test: no IPv6")
		})
	}
	return newNfTablesDedicatedRunnerWithConn(t.Logf, conn)
}

// mustGetTSChain returns the named chain from the Tailscale table.
func mustGetTSChain(t *testing.T, conn *nftables.Conn, name string) *nftables.Chain {
	t.Helper()
	chain, err := getChainFromTable(conn, tsTable, name)
	if err != nil {
		t.Fatalf("getChainFromTable(%q) failed: %v", name, err)
	}
	return chain
}

// tableNames returns the "family name" of each table in conn, sorted.
func tableNames(t *testing.T, conn *nftables.Conn) []string {
	t.Helper()
	tables, err := conn.ListTables()
	if err != nil {
		t.Fatalf("conn.ListTables() failed: %v", err)
	}
	var names []string
	for _, table := range tables {
		fam := map[nftables.TableFamily]string{
			nftables.TableFamilyIPv4: "ip",
			nftables.TableFamilyIPv6: "ip6",
			nftables.TableFamilyINet: "inet",
		}[table.Family]
		names = append(names, fmt.Sprintf("%s %s", fam, table.Name))
	}
	slices.Sort(names)
	return names
}

// chainNames returns the names of the chains in the given table, sorted.
func chainNames(t *testing.T, conn *nftables.Conn, table *nftables.Table) []string {
	t.Helper()
	chains, err := conn.ListChainsOfTableFamily(table.Family)
	if err != nil {
		t.Fatalf("conn.ListChainsOfTableFamily() failed: %v", err)
	}
	var names []string
	for _, chain := range chains {
		if chain.Table.Name == table.Name {
			names = append(names, chain.Name)
		}
	}
	slices.Sort(names)
	return names
}

// mustRule returns r, panicking on err, for builders that can't fail here.
func mustRule(r *nftables.Rule, err error) *nftables.Rule {
	if err != nil {
		panic(err)
	}
	return r
}

// checkTable checks that the Tailscale table holds exactly want, in order.
func checkTable(t *testing.T, conn *nftables.Conn, want []chainRules) {
	t.Helper()
	var wantNames []string
	for _, c := range want {
		wantNames = append(wantNames, c.chain.Name)
	}
	slices.Sort(wantNames)
	if got := chainNames(t, conn, tsTable); !slices.Equal(got, wantNames) {
		t.Fatalf("chains = %v, want %v", got, wantNames)
	}
	for _, c := range want {
		got, err := conn.GetRules(tsTable, mustGetTSChain(t, conn, c.chain.Name))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(c.rules) {
			t.Errorf("chain %s: got %d rules, want %d", c.chain.Name, len(got), len(c.rules))
			continue
		}
		for i, w := range c.rules {
			if !sameRule(got[i], w) {
				t.Errorf("chain %s rule %d:\ngot:  %#v\nwant: %#v", c.chain.Name, i, got[i].Exprs, w.Exprs)
			}
		}
	}
}

// sameRule reports whether got is want. Rules with user data are compared by
// it, as connmark rules don't read back exactly.
func sameRule(got, want *nftables.Rule) bool {
	if want.UserData != nil {
		return slices.Equal(got.UserData, want.UserData)
	}
	if len(got.Exprs) != len(want.Exprs) {
		return false
	}
	for i := range want.Exprs {
		if _, ok := want.Exprs[i].(*expr.Counter); ok {
			continue
		}
		if !reflect.DeepEqual(got.Exprs[i], want.Exprs[i]) {
			return false
		}
	}
	return true
}

func TestDedicatedRunnerChains(t *testing.T) {
	conn := newSysConn(t)
	runner := newTestDedicatedRunner(t, conn, true)
	in := tsInputChain
	fwd := tsForwardChain
	post := tsPostroutingChain

	// Nothing is installed before AddHooks, as in the nodivert mode.
	if err := runner.DelConnmarkSaveRule(); err != nil {
		t.Fatalf("DelConnmarkSaveRule() = %v", err)
	}
	if err := runner.AddChains(); err != nil {
		t.Fatalf("AddChains() failed: %v", err)
	}
	if err := runner.AddSNATRule(); err != nil {
		t.Fatalf("AddSNATRule() = %v", err)
	}
	if got := tableNames(t, conn); len(got) != 0 {
		t.Fatalf("tables before AddHooks = %v, want none", got)
	}
	if err := runner.AddHooks(); err != nil {
		t.Fatalf("AddHooks() failed: %v", err)
	}
	if got, want := tableNames(t, conn), []string{"inet tailscale"}; !slices.Equal(got, want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}
	checkTable(t, conn, []chainRules{
		{chain: in},
		{chain: fwd},
		{post, []*nftables.Rule{mustRule(createMatchSubnetRouteMarkRule(tsTable, post, Masq))}},
	})
	for _, tt := range []struct {
		name     string
		typ      nftables.ChainType
		hook     *nftables.ChainHook
		priority nftables.ChainPriority
	}{
		{tsInputChain.Name, nftables.ChainTypeFilter, nftables.ChainHookInput, -9},
		{tsForwardChain.Name, nftables.ChainTypeFilter, nftables.ChainHookForward, -9},
		{tsPostroutingChain.Name, nftables.ChainTypeNAT, nftables.ChainHookPostrouting, 91},
	} {
		chain := mustGetTSChain(t, conn, tt.name)
		if chain.Type != tt.typ || *chain.Hooknum != *tt.hook || *chain.Priority != tt.priority {
			t.Errorf("chain %s: type %v hook %v priority %v, want %v %v %v", tt.name, chain.Type, *chain.Hooknum, *chain.Priority, tt.typ, *tt.hook, tt.priority)
		}
		if chain.Policy == nil || *chain.Policy != nftables.ChainPolicyAccept {
			t.Errorf("chain %s: policy is not accept", tt.name)
		}
	}

	// DelHooks deletes the table but keeps its rules for the next AddHooks.
	if err := runner.DelHooks(t.Logf); err != nil {
		t.Fatalf("DelHooks() failed: %v", err)
	}
	if got := tableNames(t, conn); len(got) != 0 {
		t.Fatalf("tables after DelHooks = %v, want none", got)
	}
	if err := runner.AddHooks(); err != nil {
		t.Fatalf("AddHooks() failed: %v", err)
	}
	checkTable(t, conn, []chainRules{
		{chain: in},
		{chain: fwd},
		{post, []*nftables.Rule{mustRule(createMatchSubnetRouteMarkRule(tsTable, post, Masq))}},
	})

	// DelChains deletes the table and its rules.
	if err := runner.DelChains(); err != nil {
		t.Fatalf("DelChains() failed: %v", err)
	}
	if got := tableNames(t, conn); len(got) != 0 {
		t.Fatalf("tables after DelChains = %v, want none", got)
	}
	if err := runner.AddHooks(); err != nil {
		t.Fatalf("AddHooks() failed: %v", err)
	}
	checkTable(t, conn, []chainRules{{chain: in}, {chain: fwd}, {chain: post}})
}

// TestDedicatedRunnerRules checks the whole table after each change.
func TestDedicatedRunnerRules(t *testing.T) {
	const tun = "tailscale0"
	conn := newSysConn(t)
	r := newTestDedicatedRunner(t, conn, true)
	in := tsInputChain
	fwd := tsForwardChain
	post := tsPostroutingChain
	pre := tsPreroutingChain
	out := tsOutputChain
	v4, v6 := nftables.TableFamilyIPv4, nftables.TableFamilyIPv6
	addr4 := netip.MustParseAddr("100.101.102.103")
	addr6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	connmark := []chainRules{
		{pre, []*nftables.Rule{{UserData: []byte(connmarkRestoreUserData)}}},
		{out, []*nftables.Rule{{UserData: []byte(connmarkSaveUserData)}}},
	}

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.AddHooks())
	t.Cleanup(func() { r.DelChains() })

	steps := []struct {
		name string
		do   func() error
		want []chainRules
	}{
		{"base", func() error { return r.AddBase(tun) }, []chainRules{
			{in, []*nftables.Rule{createAcceptIncomingPacketRule(tsTable, in, tun)}},
			{fwd, []*nftables.Rule{
				mustRule(createSetSubnetRouteMarkRule(tsTable, fwd, tun)),
				mustRule(createMatchSubnetRouteMarkRule(tsTable, fwd, Accept)),
				mustRule(createDropOutgoingPacketFromCGNATRangeRuleWithTunname(tsTable, fwd, tun)),
				createAcceptOutgoingPacketRule(tsTable, fwd, tun),
			}},
			{chain: post},
		}},
		{"everything", func() error {
			for _, f := range []func() error{
				// In arbitrary order, some twice.
				func() error { return r.AddExternalCGNATRules(CGNATModeDrop, tun) },
				func() error { return r.AddLoopbackRule(addr6) },
				func() error { return r.AddMagicsockPortRule(41642, "udp6") },
				func() error { return r.AddLoopbackRule(addr4) },
				func() error { return r.AddLoopbackRule(addr4) },
				func() error { return r.AddMagicsockPortRule(41641, "udp4") },
				r.AddSNATRule,
				func() error { return r.AddStatefulRule(tun) },
				r.AddConnmarkSaveRule,
				r.AddConnmarkSaveRule,
			} {
				if err := f(); err != nil {
					return err
				}
			}
			return nil
		}, append([]chainRules{
			{in, []*nftables.Rule{
				mustRule(createLoopbackRule(nftables.TableFamilyIPv4, tsTable, in, addr4)),
				mustRule(createLoopbackRule(nftables.TableFamilyIPv6, tsTable, in, addr6)),
				createAcceptIncomingPacketRule(tsTable, in, tun),
				createAcceptOnPortRule(tsTable, in, v4, 41641),
				createAcceptOnPortRule(tsTable, in, v6, 41642),
				mustRule(createRangeRule(tsTable, in, tun, tsaddr.ChromeOSVMRange(), expr.VerdictReturn)),
				mustRule(createRangeRule(tsTable, in, tun, tsaddr.CGNATRange(), expr.VerdictDrop)),
			}},
			{fwd, []*nftables.Rule{
				mustRule(createSetSubnetRouteMarkRule(tsTable, fwd, tun)),
				mustRule(createMatchSubnetRouteMarkRule(tsTable, fwd, Accept)),
				mustRule(createDropOutgoingPacketFromCGNATRangeRuleWithTunname(tsTable, fwd, tun)),
				&nftables.Rule{Table: tsTable, Chain: fwd, Exprs: makeStatefulRuleExprs(tun)},
				createAcceptOutgoingPacketRule(tsTable, fwd, tun),
			}},
			{post, []*nftables.Rule{mustRule(createMatchSubnetRouteMarkRule(tsTable, post, Masq))}},
		}, connmark...)},
		{"remove-some", func() error {
			for _, f := range []func() error{
				func() error { return r.DelLoopbackRule(addr4) },
				func() error { return r.DelMagicsockPortRule(41642, "udp6") },
				func() error { return r.DelExternalCGNATRules(CGNATModeDrop, tun) },
				func() error { return r.AddExternalCGNATRules(CGNATModeReturn, tun) },
				func() error { return r.DelStatefulRule(tun) },
				r.DelSNATRule,
			} {
				if err := f(); err != nil {
					return err
				}
			}
			return nil
		}, append([]chainRules{
			{in, []*nftables.Rule{
				mustRule(createLoopbackRule(nftables.TableFamilyIPv6, tsTable, in, addr6)),
				createAcceptIncomingPacketRule(tsTable, in, tun),
				createAcceptOnPortRule(tsTable, in, v4, 41641),
				mustRule(createRangeRule(tsTable, in, tun, tsaddr.CGNATRange(), expr.VerdictReturn)),
			}},
			{fwd, []*nftables.Rule{
				mustRule(createSetSubnetRouteMarkRule(tsTable, fwd, tun)),
				mustRule(createMatchSubnetRouteMarkRule(tsTable, fwd, Accept)),
				mustRule(createDropOutgoingPacketFromCGNATRangeRuleWithTunname(tsTable, fwd, tun)),
				createAcceptOutgoingPacketRule(tsTable, fwd, tun),
			}},
			{chain: post},
		}, connmark...)},
		// DelBase keeps the connmark rules.
		{"del-base", r.DelBase, append([]chainRules{{chain: in}, {chain: fwd}, {chain: post}}, connmark...)},
		{"del-connmark", r.DelConnmarkSaveRule, []chainRules{{chain: in}, {chain: fwd}, {chain: post}}},
	}
	for _, step := range steps {
		if err := step.do(); err != nil {
			t.Fatalf("step %s: %v", step.name, err)
		}
		t.Logf("step %s", step.name)
		checkTable(t, conn, step.want)
	}
}

// TestDedicatedRunnerRecreatesTable checks that the next change recreates a
// table someone else deleted.
func TestDedicatedRunnerRecreatesTable(t *testing.T) {
	const tun = "tailscale0"
	conn := newSysConn(t)
	r := newTestDedicatedRunner(t, conn, true)
	for _, f := range []func() error{
		r.AddHooks,
		func() error { return r.AddBase(tun) },
		func() error { return r.AddMagicsockPortRule(41641, "udp4") },
		r.AddConnmarkSaveRule,
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	defer r.DelChains()

	conn.FlushRuleset()
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := tableNames(t, conn); len(got) != 0 {
		t.Fatalf("tables after flush ruleset = %v, want none", got)
	}

	if err := r.AddLoopbackRule(netip.MustParseAddr("100.101.102.103")); err != nil {
		t.Fatalf("AddLoopbackRule() after flush ruleset failed: %v", err)
	}
	want, err := r.rules(&r.state)
	if err != nil {
		t.Fatal(err)
	}
	checkTable(t, conn, want)
	in := mustGetTSChain(t, conn, tsInputChain.Name)
	checkChainRules(t, conn, in, 3) // loopback, tailscale0, port
	checkChainRules(t, conn, mustGetTSChain(t, conn, tsOutputChain.Name), 1)
}

// addDefaultRunnerRules installs the default nftables runner's rules.
func addDefaultRunnerRules(t *testing.T, conn *nftables.Conn) {
	t.Helper()
	nfr := newFakeNftablesRunnerWithConn(t, conn, true)
	for _, f := range []func() error{
		nfr.AddChains,
		nfr.AddHooks,
		func() error { return nfr.AddBase("tailscale0") },
		func() error { return nfr.AddMagicsockPortRule(41641, "udp4") },
		func() error { return nfr.AddLoopbackRule(netip.MustParseAddr("100.101.102.103")) },
		nfr.AddSNATRule,
		nfr.AddConnmarkSaveRule,
	} {
		if err := f(); err != nil {
			t.Fatalf("setting up default runner: %v", err)
		}
	}
}

// conventionalRules returns the rule count of each ip and ip6 chain.
func conventionalRules(t *testing.T, conn *nftables.Conn) map[string]int {
	t.Helper()
	got := map[string]int{}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		chains, err := conn.ListChainsOfTableFamily(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, chain := range chains {
			rules, err := conn.GetRules(chain.Table, chain)
			if err != nil {
				t.Fatal(err)
			}
			got[fmt.Sprintf("%v %s %s", fam, chain.Table.Name, chain.Name)] = len(rules)
		}
	}
	return got
}

// TestDedicatedRunnerMigration checks that the startup cleanup and AddHooks
// only remove the default runner's chains and rules.
func TestDedicatedRunnerMigration(t *testing.T) {
	const ip, ip6 = nftables.TableFamilyIPv4, nftables.TableFamilyIPv6
	key := func(fam nftables.TableFamily, table, chain string) string {
		return fmt.Sprintf("%v %s %s", fam, table, chain)
	}
	conn := newSysConn(t)
	addDefaultRunnerRules(t, conn)

	// Rules and chains of other software, which must be kept.
	filter := &nftables.Table{Family: ip, Name: "filter"}
	nat := &nftables.Table{Family: ip, Name: "nat"}
	mangle := &nftables.Table{Family: ip, Name: "mangle"}
	inetFilter := &nftables.Table{Family: nftables.TableFamilyINet, Name: "filter"}
	input, err := getChainFromTable(conn, filter, "INPUT")
	if err != nil {
		t.Fatal(err)
	}
	userRule := createAcceptOutgoingPacketRule(filter, input, "eth0")
	conn.AddRule(userRule)
	conn.AddChain(&nftables.Chain{Name: "user-chain", Table: nat})
	prerouting, err := getChainFromTable(conn, mangle, "PREROUTING")
	if err != nil {
		t.Fatal(err)
	}
	conn.AddRule(createAcceptIncomingPacketRule(mangle, prerouting, "eth0"))
	polAccept := nftables.ChainPolicyAccept
	conn.AddTable(inetFilter)
	conn.AddChain(&nftables.Chain{Name: "INPUT", Table: inetFilter, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &polAccept})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	// As at startup. NfTablesCleanUp connects in the test namespace.
	NfTablesCleanUp(t.Logf)
	runner := newTestDedicatedRunner(t, conn, true)
	if err := runner.AddHooks(); err != nil {
		t.Fatalf("AddHooks() failed: %v", err)
	}

	// Only Tailscale's chains and rules are removed.
	want := map[string]int{}
	for _, fam := range []nftables.TableFamily{ip, ip6} {
		want[key(fam, "filter", "INPUT")] = 0
		want[key(fam, "filter", "FORWARD")] = 0
		want[key(fam, "nat", "POSTROUTING")] = 0
		want[key(fam, "mangle", "PREROUTING")] = 0
		want[key(fam, "mangle", "OUTPUT")] = 0
	}
	want[key(ip, "filter", "INPUT")] = 1      // the user rule
	want[key(ip, "nat", "user-chain")] = 0    // the user's chain
	want[key(ip, "mangle", "PREROUTING")] = 1 // the user rule
	if got := conventionalRules(t, conn); !maps.Equal(got, want) {
		t.Errorf("conventional chains and rule counts =\n%v\nwant\n%v", got, want)
	}
	if r, err := findRule(conn, userRule); err != nil || r == nil {
		t.Errorf("other software's rule is gone (err %v)", err)
	}
	if got, want := chainNames(t, conn, inetFilter), []string{"INPUT"}; !slices.Equal(got, want) {
		t.Errorf("inet filter chains = %v, want %v", got, want)
	}
}

func TestNfTablesCleanUpRemovesTailscaleTable(t *testing.T) {
	conn := newSysConn(t)
	runner := newTestDedicatedRunner(t, conn, true)
	if err := runner.AddHooks(); err != nil {
		t.Fatalf("AddHooks() failed: %v", err)
	}
	if err := runner.AddConnmarkSaveRule(); err != nil {
		t.Fatalf("AddConnmarkSaveRule() failed: %v", err)
	}

	// NfTablesCleanUp connects in the test namespace.
	NfTablesCleanUp(t.Logf)

	if got := tableNames(t, conn); len(got) != 0 {
		t.Fatalf("tables after cleanup = %v, want none", got)
	}
}

func TestDetectFirewallModeNfTablesDedicated(t *testing.T) {
	envknob.SetenvForTest(t, "TS_DEBUG_FIREWALL_MODE", "")
	if got := detectFirewallMode(t.Logf, "nftables-dedicated"); got != FirewallModeNfTablesDedicated {
		t.Errorf("detectFirewallMode(nftables-dedicated) = %v, want %v", got, FirewallModeNfTablesDedicated)
	}
}
