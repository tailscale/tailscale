// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

// tsTableName is the table of the nftables-dedicated firewall mode.
const tsTableName = "tailscale"

// tsTable is the Tailscale table.
var tsTable = &nftables.Table{Family: nftables.TableFamilyINet, Name: tsTableName}

// tsPriorityOffset is added to each hook's standard priority, so that the
// Tailscale chains run before the standard ones.
const tsPriorityOffset = -9

// Base chains of the Tailscale table.
var (
	tsInputChain       = tsBaseChain("input", nftables.ChainTypeFilter, nftables.ChainHookInput, nftables.ChainPriorityFilter)
	tsForwardChain     = tsBaseChain("forward", nftables.ChainTypeFilter, nftables.ChainHookForward, nftables.ChainPriorityFilter)
	tsPostroutingChain = tsBaseChain("postrouting", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, nftables.ChainPriorityNATSource)
	tsPreroutingChain  = tsBaseChain("prerouting", nftables.ChainTypeFilter, nftables.ChainHookPrerouting, nftables.ChainPriorityMangle)
	tsOutputChain      = tsBaseChain("output", nftables.ChainTypeFilter, nftables.ChainHookOutput, nftables.ChainPriorityMangle)
)

// tsBaseChain returns a Tailscale base chain on hook, at std + tsPriorityOffset.
func tsBaseChain(name string, typ nftables.ChainType, hook *nftables.ChainHook, std *nftables.ChainPriority) *nftables.Chain {
	polAccept := nftables.ChainPolicyAccept
	return &nftables.Chain{
		Name:     name,
		Table:    tsTable,
		Type:     typ,
		Hooknum:  hook,
		Priority: nftables.ChainPriorityRef(*std + tsPriorityOffset),
		Policy:   &polAccept,
	}
}

// UserData tags of the connmark rules.
const (
	connmarkRestoreUserData = "ts-connmark-restore"
	connmarkSaveUserData    = "ts-connmark-save"
)

// nftablesDedicatedRunner is a NetfilterRunner that keeps the router's rules
// in the "inet tailscale" table, which it replaces in one transaction on every
// change. It doesn't support the service and MSS clamping rules.
type nftablesDedicatedRunner struct {
	logf        logger.Logf
	conn        *nftables.Conn
	v6Available bool // whether the host supports IPv6

	hooked bool
	state  tableState
}

func newNfTablesDedicatedRunner(logf logger.Logf) (*nftablesDedicatedRunner, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables connection: %w", err)
	}
	return newNfTablesDedicatedRunnerWithConn(logf, conn), nil
}

func newNfTablesDedicatedRunnerWithConn(logf logger.Logf, conn *nftables.Conn) *nftablesDedicatedRunner {
	v6err := CheckIPv6(logf)
	if v6err != nil {
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	}
	logf("netfilter using the dedicated nftables table %q, v6 = %v", tsTableName, v6err == nil)
	return &nftablesDedicatedRunner{logf: logf, conn: conn, v6Available: v6err == nil}
}

// tableState is the desired content of the Tailscale table.
type tableState struct {
	tunname        string
	base           bool
	loopback       set.Set[netip.Addr]
	magicsockPorts map[nftables.TableFamily]set.Set[uint16]
	cgnatMode      CGNATMode
	snat           bool
	stateful       bool
	connmark       bool
}

// clearRules removes all but the connmark rules, like nftablesRunner.DelBase.
func (s *tableState) clearRules() {
	*s = tableState{connmark: s.connmark}
}

func (s *tableState) addLoopback(addr netip.Addr) {
	if s.loopback == nil {
		s.loopback = set.Set[netip.Addr]{}
	}
	s.loopback.Add(addr)
}

func (s *tableState) addMagicsockPort(fam nftables.TableFamily, port uint16) {
	if s.magicsockPorts == nil {
		s.magicsockPorts = map[nftables.TableFamily]set.Set[uint16]{}
	}
	if s.magicsockPorts[fam] == nil {
		s.magicsockPorts[fam] = set.Set[uint16]{}
	}
	s.magicsockPorts[fam].Add(port)
}

// rules returns the chains of the table for s, each with its rules in order.
func (n *nftablesDedicatedRunner) rules(s *tableState) ([]chainRules, error) {
	t := tsTable
	input, forward, postrouting := tsInputChain, tsForwardChain, tsPostroutingChain
	var in, fwd, post []*nftables.Rule
	var err error
	check := func(r *nftables.Rule, e error) *nftables.Rule {
		if err == nil {
			err = e
		}
		return r
	}

	for _, addr := range slices.SortedFunc(maps.Keys(s.loopback), netip.Addr.Compare) {
		fam := nftables.TableFamilyIPv4
		if addr.Is6() {
			fam = nftables.TableFamilyIPv6
		}
		in = append(in, check(createLoopbackRule(fam, t, input, addr)))
	}
	if s.base {
		in = append(in, createAcceptIncomingPacketRule(t, input, s.tunname))
	}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		for _, port := range slices.Sorted(maps.Keys(s.magicsockPorts[fam])) {
			in = append(in, createAcceptOnPortRule(t, input, fam, port))
		}
	}
	switch s.cgnatMode {
	case CGNATModeDrop:
		in = append(in,
			check(createRangeRule(t, input, s.tunname, tsaddr.ChromeOSVMRange(), expr.VerdictReturn)),
			check(createRangeRule(t, input, s.tunname, tsaddr.CGNATRange(), expr.VerdictDrop)),
		)
	case CGNATModeReturn:
		in = append(in, check(createRangeRule(t, input, s.tunname, tsaddr.CGNATRange(), expr.VerdictReturn)))
	}

	if s.base {
		fwd = append(fwd,
			check(createSetSubnetRouteMarkRule(t, forward, s.tunname)),
			check(createMatchSubnetRouteMarkRule(t, forward, Accept)),
			check(createDropOutgoingPacketFromCGNATRangeRuleWithTunname(t, forward, s.tunname)),
		)
		if s.stateful {
			fwd = append(fwd, &nftables.Rule{Table: t, Chain: forward, Exprs: makeStatefulRuleExprs(s.tunname)})
		}
		fwd = append(fwd, createAcceptOutgoingPacketRule(t, forward, s.tunname))
	}

	if s.snat {
		post = append(post, check(createMatchSubnetRouteMarkRule(t, postrouting, Masq)))
	}

	if err != nil {
		return nil, err
	}

	chains := []chainRules{{input, in}, {forward, fwd}, {postrouting, post}}
	if s.connmark {
		prerouting, output := tsPreroutingChain, tsOutputChain
		chains = append(chains,
			chainRules{prerouting, []*nftables.Rule{{
				Table:    t,
				Chain:    prerouting,
				Exprs:    makeConnmarkRestoreExprs(),
				UserData: []byte(connmarkRestoreUserData),
			}}},
			chainRules{output, []*nftables.Rule{{
				Table:    t,
				Chain:    output,
				Exprs:    makeConnmarkSaveExprs(),
				UserData: []byte(connmarkSaveUserData),
			}}},
		)
	}
	return chains, nil
}

type chainRules struct {
	chain *nftables.Chain
	rules []*nftables.Rule
}

// tableExists reports whether the Tailscale table exists.
func (n *nftablesDedicatedRunner) tableExists() (bool, error) {
	_, err := n.conn.ListTableOfFamily(tsTable.Name, tsTable.Family)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

// apply replaces the Tailscale table with one built from the state, in one
// transaction. It does nothing before AddHooks.
func (n *nftablesDedicatedRunner) apply() error {
	if !n.hooked {
		return nil
	}
	chains, err := n.rules(&n.state)
	if err != nil {
		return fmt.Errorf("nftables: build %s table: %w", tsTableName, err)
	}
	exists, err := n.tableExists()
	if err != nil {
		return fmt.Errorf("nftables: get %s table: %w", tsTableName, err)
	}
	if exists {
		n.conn.DelTable(tsTable)
	}
	n.conn.AddTable(tsTable)
	for _, c := range chains {
		n.conn.AddChain(c.chain)
		for _, rule := range c.rules {
			n.conn.AddRule(rule)
		}
	}
	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: replace %s table: %w", tsTableName, err)
	}
	return nil
}

// AddChains is a no-op: AddHooks creates the chains, so the nodivert mode
// installs nothing.
func (n *nftablesDedicatedRunner) AddChains() error {
	return nil
}

// DelChains deletes the Tailscale table and forgets its rules.
func (n *nftablesDedicatedRunner) DelChains() error {
	n.state = tableState{}
	return n.DelHooks(n.logf)
}

// AddHooks creates the Tailscale table.
func (n *nftablesDedicatedRunner) AddHooks() error {
	n.hooked = true
	return n.apply()
}

// DelHooks deletes the Tailscale table, keeping its rules for the next AddHooks.
func (n *nftablesDedicatedRunner) DelHooks(logf logger.Logf) error {
	n.hooked = false
	exists, err := n.tableExists()
	if err != nil || !exists {
		return err
	}
	n.conn.DelTable(tsTable)
	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("delete table: %w", err)
	}
	return nil
}

// AddBase adds some basic processing rules.
func (n *nftablesDedicatedRunner) AddBase(tunname string) error {
	n.state.tunname, n.state.base = tunname, true
	return n.apply()
}

// DelBase removes all but the connmark rules.
func (n *nftablesDedicatedRunner) DelBase() error {
	n.state.clearRules()
	return n.apply()
}

// AddLoopbackRule accepts loopback traffic from the Tailscale address addr.
func (n *nftablesDedicatedRunner) AddLoopbackRule(addr netip.Addr) error {
	if addr.Is6() && !n.v6Available {
		return errors.New("IPv6 is not available on this host")
	}
	n.state.addLoopback(addr)
	return n.apply()
}

// DelLoopbackRule removes the rule added by AddLoopbackRule.
func (n *nftablesDedicatedRunner) DelLoopbackRule(addr netip.Addr) error {
	n.state.loopback.Delete(addr)
	return n.apply()
}

// magicsockPortFamily returns the IP family of network, "udp4" or "udp6".
func (n *nftablesDedicatedRunner) magicsockPortFamily(network string) (nftables.TableFamily, error) {
	switch network {
	case "udp4":
		return nftables.TableFamilyIPv4, nil
	case "udp6":
		if !n.v6Available {
			return 0, errors.New("IPv6 is not available on this host")
		}
		return nftables.TableFamilyIPv6, nil
	default:
		return 0, fmt.Errorf("unsupported network %s", network)
	}
}

// AddMagicsockPortRule accepts UDP traffic to port; network is udp4 or udp6.
func (n *nftablesDedicatedRunner) AddMagicsockPortRule(port uint16, network string) error {
	fam, err := n.magicsockPortFamily(network)
	if err != nil {
		return err
	}
	n.state.addMagicsockPort(fam, port)
	return n.apply()
}

// DelMagicsockPortRule removes the rule added by AddMagicsockPortRule.
func (n *nftablesDedicatedRunner) DelMagicsockPortRule(port uint16, network string) error {
	fam, err := n.magicsockPortFamily(network)
	if err != nil {
		return err
	}
	n.state.magicsockPorts[fam].Delete(port)
	return n.apply()
}

// AddExternalCGNATRules handles CGNAT traffic arriving on other interfaces.
func (n *nftablesDedicatedRunner) AddExternalCGNATRules(mode CGNATMode, tunname string) error {
	switch mode {
	case CGNATModeDrop, CGNATModeReturn:
	default:
		return fmt.Errorf("unsupported cgnat mode %q", mode)
	}
	n.state.cgnatMode, n.state.tunname = mode, tunname
	return n.apply()
}

// DelExternalCGNATRules removes the rules added by AddExternalCGNATRules.
func (n *nftablesDedicatedRunner) DelExternalCGNATRules(mode CGNATMode, tunname string) error {
	if n.state.cgnatMode != mode {
		return nil
	}
	n.state.cgnatMode = ""
	return n.apply()
}

// AddSNATRule masquerades traffic to local subnets.
func (n *nftablesDedicatedRunner) AddSNATRule() error {
	n.state.snat = true
	return n.apply()
}

// DelSNATRule removes the rule added by AddSNATRule.
func (n *nftablesDedicatedRunner) DelSNATRule() error {
	n.state.snat = false
	return n.apply()
}

// AddStatefulRule adds the stateful filtering rule. The base rules must exist.
func (n *nftablesDedicatedRunner) AddStatefulRule(tunname string) error {
	if !n.state.base {
		return errors.New("nftables: the base rules must be added before the stateful rule")
	}
	n.state.stateful, n.state.tunname = true, tunname
	return n.apply()
}

// DelStatefulRule removes the stateful filtering rule.
func (n *nftablesDedicatedRunner) DelStatefulRule(tunname string) error {
	n.state.stateful = false
	return n.apply()
}

// AddConnmarkSaveRule adds the conntrack mark save and restore rules.
func (n *nftablesDedicatedRunner) AddConnmarkSaveRule() error {
	n.state.connmark = true
	return n.apply()
}

// DelConnmarkSaveRule removes the connmark rules.
func (n *nftablesDedicatedRunner) DelConnmarkSaveRule() error {
	n.state.connmark = false
	return n.apply()
}

func (n *nftablesDedicatedRunner) HasIPV6() bool       { return n.v6Available }
func (n *nftablesDedicatedRunner) HasIPV6NAT() bool    { return n.v6Available }
func (n *nftablesDedicatedRunner) HasIPV6Filter() bool { return n.v6Available }

// errServiceRulesUnsupported is returned by the service and MSS clamping methods.
var errServiceRulesUnsupported = fmt.Errorf("%w in the nftables-dedicated firewall mode", errors.ErrUnsupported)

func (n *nftablesDedicatedRunner) AddDNATRule(origDst, dst netip.Addr) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) DNATWithLoadBalancer(origDst netip.Addr, dsts []netip.Addr) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) EnsureSNATForDst(src, dst netip.Addr) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) DNATNonTailscaleTraffic(exemptInterface string, dst netip.Addr) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) EnsurePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) DeletePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) EnsureDNATRuleForSvc(svcName string, origDst, dst netip.Addr) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) DeleteDNATRuleForSvc(svcName string, origDst, dst netip.Addr) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) DeleteSvc(svc, tun string, targetIPs []netip.Addr, pm []PortMap) error {
	return errServiceRulesUnsupported
}

func (n *nftablesDedicatedRunner) ClampMSSToPMTU(tun string, addr netip.Addr) error {
	return errServiceRulesUnsupported
}
