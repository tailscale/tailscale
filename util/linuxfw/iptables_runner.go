// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/multierr"
)

type iptablesInterface interface {
	// Adding this interface for testing purposes so we can mock out
	// the iptables library, in reality this is a wrapper to *iptables.IPTables.
	Insert(table, chain string, pos int, args ...string) error
	Append(table, chain string, args ...string) error
	Exists(table, chain string, args ...string) (bool, error)
	Delete(table, chain string, args ...string) error
	ClearChain(table, chain string) error
	NewChain(table, chain string) error
	DeleteChain(table, chain string) error
}

type iptablesRunner struct {
	ipt4 iptablesInterface
	ipt6 iptablesInterface

	v6Available    bool
	v6NATAvailable bool
}

func checkIP6TablesExists() error {
	// Some distros ship ip6tables separately from iptables.
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return fmt.Errorf("path not found: %w", err)
	}
	return nil
}

// newIPTablesRunner constructs a NetfilterRunner that programs iptables rules.
// If the underlying iptables library fails to initialize, that error is
// returned. The runner probes for IPv6 support once at initialization time and
// if not found, no IPv6 rules will be modified for the lifetime of the runner.
func newIPTablesRunner(logf logger.Logf) (*iptablesRunner, error) {
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	supportsV6, supportsV6NAT := false, false
	v6err := checkIPv6(logf)
	ip6terr := checkIP6TablesExists()
	switch {
	case v6err != nil:
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	case ip6terr != nil:
		logf("disabling tunneled IPv6 due to missing ip6tables: %v", ip6terr)
	default:
		supportsV6 = true
		supportsV6NAT = supportsV6 && checkSupportsV6NAT()
		logf("v6nat = %v", supportsV6NAT)
	}

	var ipt6 *iptables.IPTables
	if supportsV6 {
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
	}
	return &iptablesRunner{ipt4, ipt6, supportsV6, supportsV6NAT}, nil
}

// HasIPV6 reports true if the system supports IPv6.
func (i *iptablesRunner) HasIPV6() bool {
	return i.v6Available
}

// HasIPV6NAT reports true if the system supports IPv6 NAT.
func (i *iptablesRunner) HasIPV6NAT() bool {
	return i.v6NATAvailable
}

func isErrChainNotExist(err error) bool {
	return errCode(err) == 1
}

// getIPTByAddr returns the iptablesInterface with correct IP family
// that we will be using for the given address.
func (i *iptablesRunner) getIPTByAddr(addr netip.Addr) iptablesInterface {
	nf := i.ipt4
	if addr.Is6() {
		nf = i.ipt6
	}
	return nf
}

// AddLoopbackRule adds an iptables rule to permit loopback traffic to
// a local Tailscale IP.
func (i *iptablesRunner) AddLoopbackRule(addr netip.Addr) error {
	if err := i.getIPTByAddr(addr).Insert("filter", "ts-input", 1, "-i", "lo", "-s", addr.String(), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("adding loopback allow rule for %q: %w", addr, err)
	}

	return nil
}

// tsChain returns the name of the tailscale sub-chain corresponding
// to the given "parent" chain (e.g. INPUT, FORWARD, ...).
func tsChain(chain string) string {
	return "ts-" + strings.ToLower(chain)
}

// DelLoopbackRule removes the iptables rule permitting loopback
// traffic to a Tailscale IP.
func (i *iptablesRunner) DelLoopbackRule(addr netip.Addr) error {
	if err := i.getIPTByAddr(addr).Delete("filter", "ts-input", "-i", "lo", "-s", addr.String(), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("deleting loopback allow rule for %q: %w", addr, err)
	}

	return nil
}

// getTables gets the available iptablesInterface in iptables runner.
func (i *iptablesRunner) getTables() []iptablesInterface {
	if i.HasIPV6() {
		return []iptablesInterface{i.ipt4, i.ipt6}
	}
	return []iptablesInterface{i.ipt4}
}

// getNATTables gets the available iptablesInterface in iptables runner.
// If the system does not support IPv6 NAT, only the IPv4 iptablesInterface
// is returned.
func (i *iptablesRunner) getNATTables() []iptablesInterface {
	if i.HasIPV6NAT() {
		return i.getTables()
	}
	return []iptablesInterface{i.ipt4}
}

// AddHooks inserts calls to tailscale's netfilter chains in
// the relevant main netfilter chains. The tailscale chains must
// already exist. If they do not, an error is returned.
func (i *iptablesRunner) AddHooks() error {
	// divert inserts a jump to the tailscale chain in the given table/chain.
	// If the jump already exists, it is a no-op.
	divert := func(ipt iptablesInterface, table, chain string) error {
		tsChain := tsChain(chain)

		args := []string{"-j", tsChain}
		exists, err := ipt.Exists(table, chain, args...)
		if err != nil {
			return fmt.Errorf("checking for %v in %s/%s: %w", args, table, chain, err)
		}
		if exists {
			return nil
		}
		if err := ipt.Insert(table, chain, 1, args...); err != nil {
			return fmt.Errorf("adding %v in %s/%s: %w", args, table, chain, err)
		}
		return nil
	}

	for _, ipt := range i.getTables() {
		if err := divert(ipt, "filter", "INPUT"); err != nil {
			return err
		}
		if err := divert(ipt, "filter", "FORWARD"); err != nil {
			return err
		}
	}

	for _, ipt := range i.getNATTables() {
		if err := divert(ipt, "nat", "POSTROUTING"); err != nil {
			return err
		}
	}
	return nil
}

// AddChains creates custom Tailscale chains in netfilter via iptables
// if the ts-chain doesn't already exist.
func (i *iptablesRunner) AddChains() error {
	// create creates a chain in the given table if it doesn't already exist.
	// If the chain already exists, it is a no-op.
	create := func(ipt iptablesInterface, table, chain string) error {
		err := ipt.ClearChain(table, chain)
		if isErrChainNotExist(err) {
			// nonexistent chain. let's create it!
			return ipt.NewChain(table, chain)
		}
		if err != nil {
			return fmt.Errorf("setting up %s/%s: %w", table, chain, err)
		}
		return nil
	}

	for _, ipt := range i.getTables() {
		if err := create(ipt, "filter", "ts-input"); err != nil {
			return err
		}
		if err := create(ipt, "filter", "ts-forward"); err != nil {
			return err
		}
	}

	for _, ipt := range i.getNATTables() {
		if err := create(ipt, "nat", "ts-postrouting"); err != nil {
			return err
		}
	}

	return nil
}

// AddBase adds some basic processing rules to be supplemented by
// later calls to other helpers.
func (i *iptablesRunner) AddBase(tunname string) error {
	if err := i.addBase4(tunname); err != nil {
		return err
	}
	if i.HasIPV6() {
		if err := i.addBase6(tunname); err != nil {
			return err
		}
	}
	return nil
}

// addBase4 adds some basic IPv4 processing rules to be
// supplemented by later calls to other helpers.
func (i *iptablesRunner) addBase4(tunname string) error {
	// Only allow CGNAT range traffic to come from tailscale0. There
	// is an exception carved out for ranges used by ChromeOS, for
	// which we fall out of the Tailscale chain.
	//
	// Note, this will definitely break nodes that end up using the
	// CGNAT range for other purposes :(.
	args := []string{"!", "-i", tunname, "-s", tsaddr.ChromeOSVMRange().String(), "-j", "RETURN"}
	if err := i.ipt4.Append("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-input: %w", args, err)
	}
	args = []string{"!", "-i", tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"}
	if err := i.ipt4.Append("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-input: %w", args, err)
	}

	// Explicitly allow all other inbound traffic to the tun interface
	args = []string{"-i", tunname, "-j", "ACCEPT"}
	if err := i.ipt4.Append("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-input: %w", args, err)
	}

	// Forward all traffic from the Tailscale interface, and drop
	// traffic to the tailscale interface by default. We use packet
	// marks here so both filter/FORWARD and nat/POSTROUTING can match
	// on these packets of interest.
	//
	// In particular, we only want to apply SNAT rules in
	// nat/POSTROUTING to packets that originated from the Tailscale
	// interface, but we can't match on the inbound interface in
	// POSTROUTING. So instead, we match on the inbound interface in
	// filter/FORWARD, and set a packet mark that nat/POSTROUTING can
	// use to effectively run that same test again.
	args = []string{"-i", tunname, "-j", "MARK", "--set-mark", TailscaleSubnetRouteMark + "/" + TailscaleFwmarkMask}
	if err := i.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}
	args = []string{"-m", "mark", "--mark", TailscaleSubnetRouteMark + "/" + TailscaleFwmarkMask, "-j", "ACCEPT"}
	if err := i.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}
	args = []string{"-o", tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"}
	if err := i.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}
	args = []string{"-o", tunname, "-j", "ACCEPT"}
	if err := i.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}

	return nil
}

func (i *iptablesRunner) AddDNATRule(origDst, dst netip.Addr) error {
	table := i.getIPTByAddr(dst)
	return table.Insert("nat", "PREROUTING", 1, "--destination", origDst.String(), "-j", "DNAT", "--to-destination", dst.String())
}

func (i *iptablesRunner) AddSNATRuleForDst(src, dst netip.Addr) error {
	table := i.getIPTByAddr(dst)
	return table.Insert("nat", "POSTROUTING", 1, "--destination", dst.String(), "-j", "SNAT", "--to-source", src.String())
}

func (i *iptablesRunner) DNATNonTailscaleTraffic(tun string, dst netip.Addr) error {
	table := i.getIPTByAddr(dst)
	return table.Insert("nat", "PREROUTING", 1, "!", "-i", tun, "-j", "DNAT", "--to-destination", dst.String())
}

func (i *iptablesRunner) ClampMSSToPMTU(tun string, addr netip.Addr) error {
	table := i.getIPTByAddr(addr)
	return table.Append("mangle", "FORWARD", "-o", tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu")
}

// addBase6 adds some basic IPv6 processing rules to be
// supplemented by later calls to other helpers.
func (i *iptablesRunner) addBase6(tunname string) error {
	// TODO: only allow traffic from Tailscale's ULA range to come
	// from tailscale0.

	// Explicitly allow all other inbound traffic to the tun interface
	args := []string{"-i", tunname, "-j", "ACCEPT"}
	if err := i.ipt6.Append("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("adding %v in v6/filter/ts-input: %w", args, err)
	}

	args = []string{"-i", tunname, "-j", "MARK", "--set-mark", TailscaleSubnetRouteMark + "/" + TailscaleFwmarkMask}
	if err := i.ipt6.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v6/filter/ts-forward: %w", args, err)
	}
	args = []string{"-m", "mark", "--mark", TailscaleSubnetRouteMark + "/" + TailscaleFwmarkMask, "-j", "ACCEPT"}
	if err := i.ipt6.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v6/filter/ts-forward: %w", args, err)
	}
	// TODO: drop forwarded traffic to tailscale0 from tailscale's ULA
	// (see corresponding IPv4 CGNAT rule).
	args = []string{"-o", tunname, "-j", "ACCEPT"}
	if err := i.ipt6.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v6/filter/ts-forward: %w", args, err)
	}

	return nil
}

// DelChains removes the custom Tailscale chains from netfilter via iptables.
func (i *iptablesRunner) DelChains() error {
	for _, ipt := range i.getTables() {
		if err := delChain(ipt, "filter", "ts-input"); err != nil {
			return err
		}
		if err := delChain(ipt, "filter", "ts-forward"); err != nil {
			return err
		}
	}

	for _, ipt := range i.getNATTables() {
		if err := delChain(ipt, "nat", "ts-postrouting"); err != nil {
			return err
		}
	}

	return nil
}

// DelBase empties but does not remove custom Tailscale chains from
// netfilter via iptables.
func (i *iptablesRunner) DelBase() error {
	del := func(ipt iptablesInterface, table, chain string) error {
		if err := ipt.ClearChain(table, chain); err != nil {
			if isErrChainNotExist(err) {
				// nonexistent chain. That's fine, since it's
				// the desired state anyway.
				return nil
			}
			return fmt.Errorf("flushing %s/%s: %w", table, chain, err)
		}
		return nil
	}

	for _, ipt := range i.getTables() {
		if err := del(ipt, "filter", "ts-input"); err != nil {
			return err
		}
		if err := del(ipt, "filter", "ts-forward"); err != nil {
			return err
		}
	}
	for _, ipt := range i.getNATTables() {
		if err := del(ipt, "nat", "ts-postrouting"); err != nil {
			return err
		}
	}

	return nil
}

// DelHooks deletes the calls to tailscale's netfilter chains
// in the relevant main netfilter chains.
func (i *iptablesRunner) DelHooks(logf logger.Logf) error {
	for _, ipt := range i.getTables() {
		if err := delTSHook(ipt, "filter", "INPUT", logf); err != nil {
			return err
		}
		if err := delTSHook(ipt, "filter", "FORWARD", logf); err != nil {
			return err
		}
	}
	for _, ipt := range i.getNATTables() {
		if err := delTSHook(ipt, "nat", "POSTROUTING", logf); err != nil {
			return err
		}
	}

	return nil
}

// AddSNATRule adds a netfilter rule to SNAT traffic destined for
// local subnets.
func (i *iptablesRunner) AddSNATRule() error {
	args := []string{"-m", "mark", "--mark", TailscaleSubnetRouteMark + "/" + TailscaleFwmarkMask, "-j", "MASQUERADE"}
	for _, ipt := range i.getNATTables() {
		if err := ipt.Append("nat", "ts-postrouting", args...); err != nil {
			return fmt.Errorf("adding %v in nat/ts-postrouting: %w", args, err)
		}
	}
	return nil
}

// DelSNATRule removes the netfilter rule to SNAT traffic destined for
// local subnets. An error is returned if the rule does not exist.
func (i *iptablesRunner) DelSNATRule() error {
	args := []string{"-m", "mark", "--mark", TailscaleSubnetRouteMark + "/" + TailscaleFwmarkMask, "-j", "MASQUERADE"}
	for _, ipt := range i.getNATTables() {
		if err := ipt.Delete("nat", "ts-postrouting", args...); err != nil {
			return fmt.Errorf("deleting %v in nat/ts-postrouting: %w", args, err)
		}
	}
	return nil
}

// buildMagicsockPortRule generates the string slice containing the arguments
// to describe a rule accepting traffic on a particular port to iptables. It is
// separated out here to avoid repetition in AddMagicsockPortRule and
// RemoveMagicsockPortRule, since it is important that the same rule is passed
// to Append() and Delete().
func buildMagicsockPortRule(port uint16) []string {
	return []string{"-p", "udp", "--dport", strconv.FormatUint(uint64(port), 10), "-j", "ACCEPT"}
}

// AddMagicsockPortRule adds a rule to iptables to allow incoming traffic on
// the specified UDP port, so magicsock can accept incoming connections.
// network must be either "udp4" or "udp6" - this determines whether the rule
// is added for IPv4 or IPv6.
func (i *iptablesRunner) AddMagicsockPortRule(port uint16, network string) error {
	var ipt iptablesInterface
	switch network {
	case "udp4":
		ipt = i.ipt4
	case "udp6":
		ipt = i.ipt6
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	args := buildMagicsockPortRule(port)

	if err := ipt.Append("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("adding %v in filter/ts-input: %w", args, err)
	}

	return nil
}

// DelMagicsockPortRule removes a rule added by AddMagicsockPortRule to accept
// incoming traffic on a particular UDP port.
// network must be either "udp4" or "udp6" - this determines whether the rule
// is removed for IPv4 or IPv6.
func (i *iptablesRunner) DelMagicsockPortRule(port uint16, network string) error {
	var ipt iptablesInterface
	switch network {
	case "udp4":
		ipt = i.ipt4
	case "udp6":
		ipt = i.ipt6
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	args := buildMagicsockPortRule(port)

	if err := ipt.Delete("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("removing %v in filter/ts-input: %w", args, err)
	}

	return nil
}

// IPTablesCleanup removes all Tailscale added iptables rules.
// Any errors that occur are logged to the provided logf.
func IPTablesCleanup(logf logger.Logf) {
	err := clearRules(iptables.ProtocolIPv4, logf)
	if err != nil {
		logf("linuxfw: clear iptables: %v", err)
	}

	err = clearRules(iptables.ProtocolIPv6, logf)
	if err != nil {
		logf("linuxfw: clear ip6tables: %v", err)
	}
}

// delTSHook deletes hook in a chain that jumps to a ts-chain. If the hook does not
// exist, it's a no-op since the desired state is already achieved but we log the
// error because error code from the iptables module resists unwrapping.
func delTSHook(ipt iptablesInterface, table, chain string, logf logger.Logf) error {
	tsChain := tsChain(chain)
	args := []string{"-j", tsChain}
	if err := ipt.Delete(table, chain, args...); err != nil {
		// TODO(apenwarr): check for errCode(1) here.
		// Unfortunately the error code from the iptables
		// module resists unwrapping, unlike with other
		// calls. So we have to assume if Delete fails,
		// it's because there is no such rule.
		logf("deleting %v in %s/%s: %v", args, table, chain, err)
		return nil
	}
	return nil
}

// delChain flushs and deletes a chain. If the chain does not exist, it's a no-op
// since the desired state is already achieved. otherwise, it returns an error.
func delChain(ipt iptablesInterface, table, chain string) error {
	if err := ipt.ClearChain(table, chain); err != nil {
		if isErrChainNotExist(err) {
			// nonexistent chain. nothing to do.
			return nil
		}
		return fmt.Errorf("flushing %s/%s: %w", table, chain, err)
	}
	if err := ipt.DeleteChain(table, chain); err != nil {
		return fmt.Errorf("deleting %s/%s: %w", table, chain, err)
	}
	return nil
}

// clearRules clears all the iptables rules created by Tailscale
// for the given protocol. If error occurs, it's logged but not returned.
func clearRules(proto iptables.Protocol, logf logger.Logf) error {
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return err
	}

	var errs []error

	if err := delTSHook(ipt, "filter", "INPUT", logf); err != nil {
		errs = append(errs, err)
	}
	if err := delTSHook(ipt, "filter", "FORWARD", logf); err != nil {
		errs = append(errs, err)
	}
	if err := delTSHook(ipt, "nat", "POSTROUTING", logf); err != nil {
		errs = append(errs, err)
	}

	if err := delChain(ipt, "filter", "ts-input"); err != nil {
		errs = append(errs, err)
	}
	if err := delChain(ipt, "filter", "ts-forward"); err != nil {
		errs = append(errs, err)
	}

	if err := delChain(ipt, "nat", "ts-postrouting"); err != nil {
		errs = append(errs, err)
	}

	return multierr.New(errs...)
}
