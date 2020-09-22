// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/go-multierror/multierror"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine/router/dns"
)

// The following bits are added to packet marks for Tailscale use.
//
// We tried to pick bits sufficiently out of the way that it's
// unlikely to collide with existing uses. We have 4 bytes of mark
// bits to play with. We leave the lower byte alone on the assumption
// that sysadmins would use those. Kubernetes uses a few bits in the
// second byte, so we steer clear of that too.
//
// Empirically, most of the documentation on packet marks on the
// internet gives the impression that the marks are 16 bits
// wide. Based on this, we theorize that the upper two bytes are
// relatively unused in the wild, and so we consume bits starting at
// the 17th.
//
// The constants are in the iptables/iproute2 string format for
// matching and setting the bits, so they can be directly embedded in
// commands.
const (
	// Packet is from Tailscale and to a subnet route destination, so
	// is allowed to be routed through this machine.
	tailscaleSubnetRouteMark = "0x40000"
	// Packet was originated by tailscaled itself, and must not be
	// routed over the Tailscale network.
	//
	// Keep this in sync with tailscaleBypassMark in
	// net/netns/netns_linux.go.
	tailscaleBypassMark = "0x80000"
)

// tailscaleRouteTable is the routing table number for Tailscale
// network routes. See addIPRules for the detailed policy routing
// logic that ends up doing lookups within that table.
//
// NOTE(danderson): We chose 52 because those are the digits above the
// letters "TS" on a qwerty keyboard, and 52 is sufficiently unlikely
// to be picked by other software.
//
// NOTE(danderson): You might wonder why we didn't pick some high
// table number like 5252, to further avoid the potential for
// collisions with other software. Unfortunately, Busybox's `ip`
// implementation believes that table numbers are 8-bit integers, so
// for maximum compatibility we have to stay in the 0-255 range even
// though linux itself supports larger numbers.
const tailscaleRouteTable = "52"

// netfilterRunner abstracts helpers to run netfilter commands. It
// exists purely to swap out go-iptables for a fake implementation in
// tests.
type netfilterRunner interface {
	Insert(table, chain string, pos int, args ...string) error
	Append(table, chain string, args ...string) error
	Exists(table, chain string, args ...string) (bool, error)
	Delete(table, chain string, args ...string) error
	ClearChain(table, chain string) error
	NewChain(table, chain string) error
	DeleteChain(table, chain string) error
}

type linuxRouter struct {
	logf             func(fmt string, args ...interface{})
	tunname          string
	addrs            map[netaddr.IPPrefix]bool
	routes           map[netaddr.IPPrefix]bool
	snatSubnetRoutes bool
	netfilterMode    NetfilterMode

	// Various feature checks for the network stack.
	ipRuleAvailable bool
	v6Available     bool
	v6NATAvailable  bool

	dns *dns.Manager

	ipt4 netfilterRunner
	ipt6 netfilterRunner
	cmd  commandRunner
}

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tunDev tun.Device) (Router, error) {
	tunname, err := tunDev.Name()
	if err != nil {
		return nil, err
	}

	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	var ipt6 netfilterRunner
	if supportsV6() {
		// The iptables package probes for `ip6tables` and errors out
		// if unavailable. We want that to be a non-fatal error.
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
	}

	return newUserspaceRouterAdvanced(logf, tunname, ipt4, ipt6, osCommandRunner{})
}

func newUserspaceRouterAdvanced(logf logger.Logf, tunname string, netfilter4, netfilter6 netfilterRunner, cmd commandRunner) (Router, error) {
	ipRuleAvailable := (cmd.run("ip", "rule") == nil)

	mconfig := dns.ManagerConfig{
		Logf:          logf,
		InterfaceName: tunname,
	}

	supportsV6 := supportsV6()

	return &linuxRouter{
		logf:          logf,
		tunname:       tunname,
		netfilterMode: NetfilterOff,

		ipRuleAvailable: ipRuleAvailable,
		v6Available:     supportsV6,
		v6NATAvailable:  supportsV6 && supportsV6NAT(),

		ipt4: netfilter4,
		ipt6: netfilter6,
		cmd:  cmd,
		dns:  dns.NewManager(mconfig),
	}, nil
}

func (r *linuxRouter) Up() error {
	if err := r.delLegacyNetfilter(); err != nil {
		return err
	}
	if err := r.addIPRules(); err != nil {
		return err
	}
	if err := r.setNetfilterMode(NetfilterOff); err != nil {
		return err
	}
	if err := r.upInterface(); err != nil {
		return err
	}

	return nil
}

func (r *linuxRouter) Close() error {
	if err := r.dns.Down(); err != nil {
		return fmt.Errorf("dns down: %w", err)
	}
	if err := r.downInterface(); err != nil {
		return err
	}
	if err := r.delIPRules(); err != nil {
		return err
	}
	if err := r.setNetfilterMode(NetfilterOff); err != nil {
		return err
	}

	r.addrs = nil
	r.routes = nil

	return nil
}

// Set implements the Router interface.
func (r *linuxRouter) Set(cfg *Config) error {
	var errs []error
	if cfg == nil {
		cfg = &shutdownConfig
	}

	if err := r.dns.Set(cfg.DNS); err != nil {
		errs = append(errs, fmt.Errorf("dns set: %w", err))
	}

	if err := r.setNetfilterMode(cfg.NetfilterMode); err != nil {
		errs = append(errs, err)
	}

	newRoutes, err := cidrDiff("route", r.routes, cfg.Routes, r.addRoute, r.delRoute, r.logf)
	if err != nil {
		errs = append(errs, err)
	}
	r.routes = newRoutes

	newAddrs, err := cidrDiff("addr", r.addrs, cfg.LocalAddrs, r.addAddress, r.delAddress, r.logf)
	if err != nil {
		errs = append(errs, err)
	}
	r.addrs = newAddrs

	switch {
	case cfg.SNATSubnetRoutes == r.snatSubnetRoutes:
		// state already correct, nothing to do.
	case cfg.SNATSubnetRoutes:
		if err := r.addSNATRule(); err != nil {
			errs = append(errs, err)
		}
	default:
		if err := r.delSNATRule(); err != nil {
			errs = append(errs, err)
		}
	}
	r.snatSubnetRoutes = cfg.SNATSubnetRoutes

	return multierror.New(errs)
}

// setNetfilterMode switches the router to the given netfilter
// mode. Netfilter state is created or deleted appropriately to
// reflect the new mode, and r.snatSubnetRoutes is updated to reflect
// the current state of subnet SNATing.
func (r *linuxRouter) setNetfilterMode(mode NetfilterMode) error {
	if distro.Get() == distro.Synology {
		mode = NetfilterOff
	}
	if r.netfilterMode == mode {
		return nil
	}

	// Depending on the netfilter mode we switch from and to, we may
	// have created the Tailscale netfilter chains. If so, we have to
	// go back through existing router state, and add the netfilter
	// rules for that state.
	//
	// This bool keeps track of whether the current state transition
	// is one that requires adding rules of existing state.
	reprocess := false

	switch mode {
	case NetfilterOff:
		switch r.netfilterMode {
		case NetfilterNoDivert:
			if err := r.delNetfilterBase(); err != nil {
				return err
			}
			if err := r.delNetfilterChains(); err != nil {
				r.logf("note: %v", err)
				// harmless, continue.
				// This can happen if someone left a ref to
				// this table somewhere else.
			}
		case NetfilterOn:
			if err := r.delNetfilterHooks(); err != nil {
				return err
			}
			if err := r.delNetfilterBase(); err != nil {
				return err
			}
			if err := r.delNetfilterChains(); err != nil {
				r.logf("note: %v", err)
				// harmless, continue.
				// This can happen if someone left a ref to
				// this table somewhere else.
			}
		}
		r.snatSubnetRoutes = false
	case NetfilterNoDivert:
		switch r.netfilterMode {
		case NetfilterOff:
			reprocess = true
			if err := r.addNetfilterChains(); err != nil {
				return err
			}
			if err := r.addNetfilterBase(); err != nil {
				return err
			}
			r.snatSubnetRoutes = false
		case NetfilterOn:
			if err := r.delNetfilterHooks(); err != nil {
				return err
			}
		}
	case NetfilterOn:
		// Because of bugs in old version of iptables-compat,
		// we can't add a "-j ts-forward" rule to FORWARD
		// while ts-forward contains an "-m mark" rule. But
		// we can add the row *before* populating ts-forward.
		// So we have to delNetFilterBase, then add the hooks,
		// then re-addNetFilterBase, just in case.
		switch r.netfilterMode {
		case NetfilterOff:
			reprocess = true
			if err := r.addNetfilterChains(); err != nil {
				return err
			}
			if err := r.delNetfilterBase(); err != nil {
				return err
			}
			if err := r.addNetfilterHooks(); err != nil {
				return err
			}
			if err := r.addNetfilterBase(); err != nil {
				return err
			}
			r.snatSubnetRoutes = false
		case NetfilterNoDivert:
			reprocess = true
			if err := r.delNetfilterBase(); err != nil {
				return err
			}
			if err := r.addNetfilterHooks(); err != nil {
				return err
			}
			if err := r.addNetfilterBase(); err != nil {
				return err
			}
			r.snatSubnetRoutes = false
		}
	default:
		panic("unhandled netfilter mode")
	}

	r.netfilterMode = mode

	if !reprocess {
		return nil
	}

	for cidr := range r.addrs {
		if err := r.addLoopbackRule(cidr.IP); err != nil {
			return err
		}
	}

	return nil
}

// addAddress adds an IP/mask to the tunnel interface. Fails if the
// address is already assigned to the interface, or if the addition
// fails.
func (r *linuxRouter) addAddress(addr netaddr.IPPrefix) error {
	if err := r.cmd.run("ip", "addr", "add", addr.String(), "dev", r.tunname); err != nil {
		return fmt.Errorf("adding address %q to tunnel interface: %w", addr, err)
	}
	if err := r.addLoopbackRule(addr.IP); err != nil {
		return err
	}
	return nil
}

// delAddress removes an IP/mask from the tunnel interface. Fails if
// the address is not assigned to the interface, or if the removal
// fails.
func (r *linuxRouter) delAddress(addr netaddr.IPPrefix) error {
	if err := r.delLoopbackRule(addr.IP); err != nil {
		return err
	}
	if err := r.cmd.run("ip", "addr", "del", addr.String(), "dev", r.tunname); err != nil {
		return fmt.Errorf("deleting address %q from tunnel interface: %w", addr, err)
	}
	return nil
}

// addLoopbackRule adds a firewall rule to permit loopback traffic to
// a local Tailscale IP.
func (r *linuxRouter) addLoopbackRule(addr netaddr.IP) error {
	if r.netfilterMode == NetfilterOff {
		return nil
	}
	if err := r.ipt4.Insert("filter", "ts-input", 1, "-i", "lo", "-s", addr.String(), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("adding loopback allow rule for %q: %w", addr, err)
	}
	return nil
}

// delLoopbackRule removes the firewall rule permitting loopback
// traffic to a Tailscale IP.
func (r *linuxRouter) delLoopbackRule(addr netaddr.IP) error {
	if r.netfilterMode == NetfilterOff {
		return nil
	}
	if err := r.ipt4.Delete("filter", "ts-input", "-i", "lo", "-s", addr.String(), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("deleting loopback allow rule for %q: %w", addr, err)
	}
	return nil
}

// addRoute adds a route for cidr, pointing to the tunnel
// interface. Fails if the route already exists, or if adding the
// route fails.
func (r *linuxRouter) addRoute(cidr netaddr.IPPrefix) error {
	args := []string{
		"ip", "route", "add",
		normalizeCIDR(cidr),
		"dev", r.tunname,
	}
	if r.ipRuleAvailable {
		args = append(args, "table", tailscaleRouteTable)
	}
	return r.cmd.run(args...)
}

// delRoute removes the route for cidr pointing to the tunnel
// interface. Fails if the route doesn't exist, or if removing the
// route fails.
func (r *linuxRouter) delRoute(cidr netaddr.IPPrefix) error {
	args := []string{
		"ip", "route", "del",
		normalizeCIDR(cidr),
		"dev", r.tunname,
	}
	if r.ipRuleAvailable {
		args = append(args, "table", tailscaleRouteTable)
	}
	return r.cmd.run(args...)
}

// upInterface brings up the tunnel interface.
func (r *linuxRouter) upInterface() error {
	return r.cmd.run("ip", "link", "set", "dev", r.tunname, "up")
}

// downInterface sets the tunnel interface administratively down.
func (r *linuxRouter) downInterface() error {
	return r.cmd.run("ip", "link", "set", "dev", r.tunname, "down")
}

func (r *linuxRouter) iprouteFamilies() []string {
	if r.v6Available {
		return []string{"-4", "-6"}
	}
	return []string{"-4"}
}

// addIPRules adds the policy routing rule that avoids tailscaled
// routing loops. If the rule exists and appears to be a
// tailscale-managed rule, it is gracefully replaced.
func (r *linuxRouter) addIPRules() error {
	if !r.ipRuleAvailable {
		return nil
	}

	// Clear out old rules. After that, any error adding a rule is fatal,
	// because there should be no reason we add a duplicate.
	if err := r.delIPRules(); err != nil {
		return err
	}

	rg := newRunGroup(nil, r.cmd)

	for _, family := range r.iprouteFamilies() {
		// NOTE(apenwarr): We leave spaces between each pref number.
		// This is so the sysadmin can override by inserting rules in
		// between if they want.

		// NOTE(apenwarr): This sequence seems complicated, right?
		// If we could simply have a rule that said "match packets that
		// *don't* have this fwmark", then we would only need to add one
		// link to table 52 and we'd be done. Unfortunately, older kernels
		// and 'ip rule' implementations (including busybox), don't support
		// checking for the lack of a fwmark, only the presence. The technique
		// below works even on very old kernels.

		// Packets from us, tagged with our fwmark, first try the kernel's
		// main routing table.
		rg.Run(
			"ip", family, "rule", "add",
			"pref", tailscaleRouteTable+"10",
			"fwmark", tailscaleBypassMark,
			"table", "main",
		)
		// ...and then we try the 'default' table, for correctness,
		// even though it's been empty on every Linux system I've ever seen.
		rg.Run(
			"ip", family, "rule", "add",
			"pref", tailscaleRouteTable+"30",
			"fwmark", tailscaleBypassMark,
			"table", "default",
		)
		// If neither of those matched (no default route on this system?)
		// then packets from us should be aborted rather than falling through
		// to the tailscale routes, because that would create routing loops.
		rg.Run(
			"ip", family, "rule", "add",
			"pref", tailscaleRouteTable+"50",
			"fwmark", tailscaleBypassMark,
			"type", "unreachable",
		)
		// If we get to this point, capture all packets and send them
		// through to the tailscale route table. For apps other than us
		// (ie. with no fwmark set), this is the first routing table, so
		// it takes precedence over all the others, ie. VPN routes always
		// beat non-VPN routes.
		//
		// NOTE(apenwarr): tables >255 are not supported in busybox, so we
		// can't use a table number that aligns with the rule preferences.
		rg.Run(
			"ip", family, "rule", "add",
			"pref", tailscaleRouteTable+"70",
			"table", tailscaleRouteTable,
		)
		// If that didn't match, then non-fwmark packets fall through to the
		// usual rules (pref 32766 and 32767, ie. main and default).
	}

	return rg.ErrAcc
}

// delBypassrule removes the policy routing rules that avoid
// tailscaled routing loops, if it exists.
func (r *linuxRouter) delIPRules() error {
	if !r.ipRuleAvailable {
		return nil
	}

	// Error codes: 'ip rule' returns error code 2 if the rule is a
	// duplicate (add) or not found (del). It returns a different code
	// for syntax errors. This is also true of busybox.
	//
	// Some older versions of iproute2 also return error code 254 for
	// unknown rules during deletion.
	rg := newRunGroup([]int{2, 254}, r.cmd)

	for _, family := range r.iprouteFamilies() {
		// When deleting rules, we want to be a bit specific (mention which
		// table we were routing to) but not *too* specific (fwmarks, etc).
		// That leaves us some flexibility to change these values in later
		// versions without having ongoing hacks for every possible
		// combination.

		// Delete old-style tailscale rules
		// (never released in a stable version, so we can drop this
		// support eventually).
		rg.Run(
			"ip", family, "rule", "del",
			"pref", "10000",
			"table", "main",
		)

		// Delete new-style tailscale rules.
		rg.Run(
			"ip", family, "rule", "del",
			"pref", tailscaleRouteTable+"10",
			"table", "main",
		)
		rg.Run(
			"ip", family, "rule", "del",
			"pref", tailscaleRouteTable+"30",
			"table", "default",
		)
		rg.Run(
			"ip", family, "rule", "del",
			"pref", tailscaleRouteTable+"50",
			"type", "unreachable",
		)
		rg.Run(
			"ip", family, "rule", "del",
			"pref", tailscaleRouteTable+"70",
			"table", tailscaleRouteTable,
		)
	}

	return rg.ErrAcc
}

func (r *linuxRouter) netfilterFamilies() []netfilterRunner {
	if r.v6Available {
		return []netfilterRunner{r.ipt4, r.ipt6}
	}
	return []netfilterRunner{r.ipt4}
}

// addNetfilterChains creates custom Tailscale chains in netfilter.
func (r *linuxRouter) addNetfilterChains() error {
	create := func(ipt netfilterRunner, table, chain string) error {
		err := ipt.ClearChain(table, chain)
		if errCode(err) == 1 {
			// nonexistent chain. let's create it!
			return ipt.NewChain(table, chain)
		}
		if err != nil {
			return fmt.Errorf("setting up %s/%s: %w", table, chain, err)
		}
		return nil
	}

	for _, ipt := range r.netfilterFamilies() {
		if err := create(ipt, "filter", "ts-input"); err != nil {
			return err
		}
		if err := create(ipt, "filter", "ts-forward"); err != nil {
			return err
		}
	}
	if err := create(r.ipt4, "nat", "ts-postrouting"); err != nil {
		return err
	}
	if r.v6NATAvailable {
		if err := create(r.ipt6, "nat", "ts-postrouting"); err != nil {
			return err
		}
	}
	return nil
}

// addNetfilterBase adds some basic processing rules to be
// supplemented by later calls to other helpers.
func (r *linuxRouter) addNetfilterBase() error {
	if err := r.addNetfilterBase4(); err != nil {
		return err
	}
	if r.v6Available {
		if err := r.addNetfilterBase6(); err != nil {
			return err
		}
	}
	return nil
}

// addNetfilterBase4 adds some basic IPv4 processing rules to be
// supplemented by later calls to other helpers.
func (r *linuxRouter) addNetfilterBase4() error {
	// Only allow CGNAT range traffic to come from tailscale0. There
	// is an exception carved out for ranges used by ChromeOS, for
	// which we fall out of the Tailscale chain.
	//
	// Note, this will definitely break nodes that end up using the
	// CGNAT range for other purposes :(.
	args := []string{"!", "-i", r.tunname, "-s", tsaddr.ChromeOSVMRange().String(), "-j", "RETURN"}
	if err := r.ipt4.Append("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-input: %w", args, err)
	}
	args = []string{"!", "-i", r.tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"}
	if err := r.ipt4.Append("filter", "ts-input", args...); err != nil {
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
	args = []string{"-i", r.tunname, "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark}
	if err := r.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}
	args = []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "ACCEPT"}
	if err := r.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}
	args = []string{"-o", r.tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"}
	if err := r.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}
	args = []string{"-o", r.tunname, "-j", "ACCEPT"}
	if err := r.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}

	return nil
}

// addNetfilterBase4 adds some basic IPv6 processing rules to be
// supplemented by later calls to other helpers.
func (r *linuxRouter) addNetfilterBase6() error {
	// TODO: only allow traffic from Tailscale's ULA range to come
	// from tailscale0.

	args := []string{"-i", r.tunname, "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark}
	if err := r.ipt6.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v6/filter/ts-forward: %w", args, err)
	}
	args = []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "ACCEPT"}
	if err := r.ipt6.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v6/filter/ts-forward: %w", args, err)
	}
	// TODO: drop forwarded traffic to tailscale0 from tailscale's ULA
	// (see corresponding IPv4 CGNAT rule).
	args = []string{"-o", r.tunname, "-j", "ACCEPT"}
	if err := r.ipt6.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v6/filter/ts-forward: %w", args, err)
	}

	return nil
}

// delNetfilterChains removes the custom Tailscale chains from netfilter.
func (r *linuxRouter) delNetfilterChains() error {
	del := func(ipt netfilterRunner, table, chain string) error {
		if err := ipt.ClearChain(table, chain); err != nil {
			if errCode(err) == 1 {
				// nonexistent chain. That's fine, since it's
				// the desired state anyway.
				return nil
			}
			return fmt.Errorf("flushing %s/%s: %w", table, chain, err)
		}
		if err := ipt.DeleteChain(table, chain); err != nil {
			// this shouldn't fail, because if the chain didn't
			// exist, we would have returned after ClearChain.
			return fmt.Errorf("deleting %s/%s: %v", table, chain, err)
		}
		return nil
	}

	for _, ipt := range r.netfilterFamilies() {
		if err := del(ipt, "filter", "ts-input"); err != nil {
			return err
		}
		if err := del(ipt, "filter", "ts-forward"); err != nil {
			return err
		}
	}
	if err := del(r.ipt4, "nat", "ts-postrouting"); err != nil {
		return err
	}
	if r.v6NATAvailable {
		if err := del(r.ipt6, "nat", "ts-postrouting"); err != nil {
			return err
		}
	}

	return nil
}

// delNetfilterBase empties but does not remove custom Tailscale chains from
// netfilter.
func (r *linuxRouter) delNetfilterBase() error {
	del := func(ipt netfilterRunner, table, chain string) error {
		if err := ipt.ClearChain(table, chain); err != nil {
			if errCode(err) == 1 {
				// nonexistent chain. That's fine, since it's
				// the desired state anyway.
				return nil
			}
			return fmt.Errorf("flushing %s/%s: %w", table, chain, err)
		}
		return nil
	}

	for _, ipt := range r.netfilterFamilies() {
		if err := del(ipt, "filter", "ts-input"); err != nil {
			return err
		}
		if err := del(ipt, "filter", "ts-forward"); err != nil {
			return err
		}
	}
	if err := del(r.ipt4, "nat", "ts-postrouting"); err != nil {
		return err
	}
	if r.v6NATAvailable {
		if err := del(r.ipt6, "nat", "ts-postrouting"); err != nil {
			return err
		}
	}

	return nil
}

// addNetfilterHooks inserts calls to tailscale's netfilter chains in
// the relevant main netfilter chains. The tailscale chains must
// already exist.
func (r *linuxRouter) addNetfilterHooks() error {
	divert := func(ipt netfilterRunner, table, chain string) error {
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

	for _, ipt := range r.netfilterFamilies() {
		if err := divert(ipt, "filter", "INPUT"); err != nil {
			return err
		}
		if err := divert(ipt, "filter", "FORWARD"); err != nil {
			return err
		}
	}
	if err := divert(r.ipt4, "nat", "POSTROUTING"); err != nil {
		return err
	}
	if r.v6NATAvailable {
		if err := divert(r.ipt6, "nat", "POSTROUTING"); err != nil {
			return err
		}
	}
	return nil
}

// delNetfilterHooks deletes the calls to tailscale's netfilter chains
// in the relevant main netfilter chains.
func (r *linuxRouter) delNetfilterHooks() error {
	del := func(ipt netfilterRunner, table, chain string) error {
		tsChain := tsChain(chain)
		args := []string{"-j", tsChain}
		if err := ipt.Delete(table, chain, args...); err != nil {
			// TODO(apenwarr): check for errCode(1) here.
			// Unfortunately the error code from the iptables
			// module resists unwrapping, unlike with other
			// calls. So we have to assume if Delete fails,
			// it's because there is no such rule.
			r.logf("note: deleting %v in %s/%s: %w", args, table, chain, err)
			return nil
		}
		return nil
	}

	for _, ipt := range r.netfilterFamilies() {
		if err := del(ipt, "filter", "INPUT"); err != nil {
			return err
		}
		if err := del(ipt, "filter", "FORWARD"); err != nil {
			return err
		}
	}
	if err := del(r.ipt4, "nat", "POSTROUTING"); err != nil {
		return err
	}
	if r.v6NATAvailable {
		if err := del(r.ipt6, "nat", "POSTROUTING"); err != nil {
			return err
		}
	}
	return nil
}

// addSNATRule adds a netfilter rule to SNAT traffic destined for
// local subnets.
func (r *linuxRouter) addSNATRule() error {
	if r.netfilterMode == NetfilterOff {
		return nil
	}

	args := []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "MASQUERADE"}
	if err := r.ipt4.Append("nat", "ts-postrouting", args...); err != nil {
		return fmt.Errorf("adding %v in v4/nat/ts-postrouting: %w", args, err)
	}
	if r.v6NATAvailable {
		if err := r.ipt6.Append("nat", "ts-postrouting", args...); err != nil {
			return fmt.Errorf("adding %v in v6/nat/ts-postrouting: %w", args, err)
		}
	}
	return nil
}

// delSNATRule removes the netfilter rule to SNAT traffic destined for
// local subnets. Fails if the rule does not exist.
func (r *linuxRouter) delSNATRule() error {
	if r.netfilterMode == NetfilterOff {
		return nil
	}

	args := []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "MASQUERADE"}
	if err := r.ipt4.Delete("nat", "ts-postrouting", args...); err != nil {
		return fmt.Errorf("deleting %v in v4/nat/ts-postrouting: %w", args, err)
	}
	if r.v6NATAvailable {
		if err := r.ipt6.Delete("nat", "ts-postrouting", args...); err != nil {
			return fmt.Errorf("deleting %v in v6/nat/ts-postrouting: %w", args, err)
		}
	}
	return nil
}

func (r *linuxRouter) delLegacyNetfilter() error {
	del := func(table, chain string, args ...string) error {
		exists, err := r.ipt4.Exists(table, chain, args...)
		if err != nil {
			return fmt.Errorf("checking for %v in %s/%s: %w", args, table, chain, err)
		}
		if exists {
			if err := r.ipt4.Delete(table, chain, args...); err != nil {
				return fmt.Errorf("deleting %v in %s/%s: %w", args, table, chain, err)
			}
		}
		return nil
	}

	if err := del("filter", "FORWARD", "-m", "comment", "--comment", "tailscale", "-i", r.tunname, "-j", "ACCEPT"); err != nil {
		r.logf("failed to delete legacy rule, continuing anyway: %v", err)
	}
	if err := del("nat", "POSTROUTING", "-m", "comment", "--comment", "tailscale", "-o", "eth0", "-j", "MASQUERADE"); err != nil {
		r.logf("failed to delete legacy rule, continuing anyway: %v", err)
	}

	return nil
}

// cidrDiff calls add and del as needed to make the set of prefixes in
// old and new match. Returns a map reflecting the actual new state
// (which may be somewhere in between old and new if some commands
// failed), and any error encountered while reconfiguring.
func cidrDiff(kind string, old map[netaddr.IPPrefix]bool, new []netaddr.IPPrefix, add, del func(netaddr.IPPrefix) error, logf logger.Logf) (map[netaddr.IPPrefix]bool, error) {
	newMap := make(map[netaddr.IPPrefix]bool, len(new))
	for _, cidr := range new {
		newMap[cidr] = true
	}

	// ret starts out as a copy of old, and updates as we
	// add/delete. That way we can always return it and have it be the
	// true state of what we've done so far.
	ret := make(map[netaddr.IPPrefix]bool, len(old))
	for cidr := range old {
		ret[cidr] = true
	}

	for cidr := range old {
		if newMap[cidr] {
			continue
		}
		if err := del(cidr); err != nil {
			logf("%s del failed: %v", kind, err)
			return ret, err
		}
		delete(ret, cidr)
	}
	for cidr := range newMap {
		if old[cidr] {
			continue
		}
		if err := add(cidr); err != nil {
			logf("%s add failed: %v", kind, err)
			return ret, err
		}
		ret[cidr] = true
	}

	return ret, nil
}

// tsChain returns the name of the tailscale sub-chain corresponding
// to the given "parent" chain (e.g. INPUT, FORWARD, ...).
func tsChain(chain string) string {
	return "ts-" + strings.ToLower(chain)
}

// normalizeCIDR returns cidr as an ip/mask string, with the host bits
// of the IP address zeroed out.
func normalizeCIDR(cidr netaddr.IPPrefix) string {
	ncidr := cidr.IPNet()
	nip := ncidr.IP.Mask(ncidr.Mask)
	return fmt.Sprintf("%s/%d", nip, cidr.Bits)
}

func cleanup(logf logger.Logf, interfaceName string) {
	// TODO(dmytro): clean up iptables.
}

// supportsV6 returns whether the system appears to have a working
// IPv6 network stack.
func supportsV6() bool {
	_, err := os.Stat("/proc/sys/net/ipv6")
	if os.IsNotExist(err) {
		return false
	}
	bs, err := ioutil.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if err != nil {
		// Be conservative if we can't find the ipv6 configuration knob.
		return false
	}
	disabled, err := strconv.ParseBool(strings.TrimSpace(string(bs)))
	if err != nil {
		return false
	}
	if disabled {
		return false
	}

	// Some distros ship ip6tables separately from iptables.
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return false
	}

	return true
}

// supportsV6NAT returns whether the system has a "nat" table in the
// IPv6 netfilter stack.
//
// The nat table was added after the initial release of ipv6
// netfilter, so some older distros ship a kernel that can't NAT IPv6
// traffic.
func supportsV6NAT() bool {
	bs, err := ioutil.ReadFile("/proc/net/ip6_tables_names")
	if err != nil {
		// Can't read the file. Assume SNAT works.
		return true
	}

	return bytes.Contains(bs, []byte("nat\n"))
}
