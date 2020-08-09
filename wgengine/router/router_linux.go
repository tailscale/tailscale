// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"fmt"
	"regexp"
	"strconv"
	"os/exec"

	"github.com/coreos/go-iptables/iptables"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router/dns"
)



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
	ipRuleAvailable  bool
	tunname          string
	rtable           int16
	subnetRouteMark  int32
	bypassMark		 int32
	multiTS			 bool
	addrs            map[netaddr.IPPrefix]bool
	routes           map[netaddr.IPPrefix]bool
	snatSubnetRoutes bool
	netfilterMode    NetfilterMode

	dns *dns.Manager

	ipt4 netfilterRunner
	cmd  commandRunner
}

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
var stripLastDigits = regexp.MustCompile("([0-9]+)$")
func (r *linuxRouter) tailscaleRouteTableNr() int16 {
	if r.rtable == 0 {
		lastDigits := stripLastDigits.FindStringSubmatch(r.tunname)
		if len(lastDigits) != 2 {
			panic(fmt.Sprintf("to calculate the right routing table nr its required to set the tun atleast with a number:%s", r.tunname))
		}
		base, err := strconv.Atoi(lastDigits[1])
		if err != nil {
			panic(fmt.Sprintf("can convert to number:%s", lastDigits[1]))
		}
		return 52 + int16(base)
	} else {
		return r.rtable
	}
}
func (r *linuxRouter) tailscaleRouteTable() string {
	return fmt.Sprintf("%d", r.tailscaleRouteTableNr())
}

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

// Packet is from Tailscale and to a subnet route destination, so
// is allowed to be routed through this machine.
func (r *linuxRouter) tailscaleSubnetRouteMark() string {
	if r.subnetRouteMark == 0 {
		rtId := r.tailscaleRouteTableNr()
		return fmt.Sprintf("0x%x", 0x40000 + int32(rtId))
	} else {
		return fmt.Sprintf("0x%x", r.subnetRouteMark)
	}
}

// Packet was originated by tailscaled itself, and must not be
// routed over the Tailscale network.
//
// Keep this in sync with tailscaleBypassMark in
// net/netns/netns_linux.go.
func (r *linuxRouter) tailscaleBypassMark() string {
	if r.bypassMark == 0 {
		rtId := r.tailscaleRouteTableNr()
		return fmt.Sprintf("0x%x", 0x80000 + int(rtId))
	} else {
		return fmt.Sprintf("0x%x", r.bypassMark)
	}
}



func (r *linuxRouter) inputRule() string {
	return fmt.Sprintf("%s-inp", r.tunname)
}

func (r *linuxRouter) forwardRule() string {
	return fmt.Sprintf("%s-fwd", r.tunname)
}

func (r *linuxRouter) postroutingRule() string {
	return fmt.Sprintf("%s-prt", r.tunname)
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

	return newUserspaceRouterAdvanced(logf, tunname, ipt4, osCommandRunner{}, 0)
}

func newUserspaceRouterAdvanced(logf logger.Logf, tunname string, netfilter netfilterRunner, cmd commandRunner, rtable int16) (Router, error) {
	_, err := exec.Command("ip", "rule").Output()
	ipRuleAvailable := (err == nil)

	mconfig := dns.ManagerConfig{
		Logf:          logf,
		InterfaceName: tunname,
	}

	return &linuxRouter{
		logf:            logf,
		ipRuleAvailable: ipRuleAvailable,
		tunname:         tunname,

		rtable:          rtable,
		subnetRouteMark: 0,
		bypassMark:      0,
		multiTS:		 false,

		netfilterMode:   NetfilterOff,
		ipt4:            netfilter,
		cmd:             cmd,
		dns:             dns.NewManager(mconfig),
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
		return fmt.Errorf("dns down: %v", err)
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
	if cfg == nil {
		cfg = &shutdownConfig
	}

	if err := r.setNetfilterMode(cfg.NetfilterMode); err != nil {
		return err
	}

	newAddrs, err := cidrDiff("addr", r.addrs, cfg.LocalAddrs, r.addAddress, r.delAddress, r.logf)
	if err != nil {
		return err
	}
	r.addrs = newAddrs

	newRoutes, err := cidrDiff("route", r.routes, cfg.Routes, r.addRoute, r.delRoute, r.logf)
	if err != nil {
		return err
	}
	r.routes = newRoutes

	switch {
	case cfg.SNATSubnetRoutes == r.snatSubnetRoutes:
		// state already correct, nothing to do.
	case cfg.SNATSubnetRoutes:
		if err := r.addSNATRule(); err != nil {
			return err
		}
	default:
		if err := r.delSNATRule(); err != nil {
			return err
		}
	}
	r.snatSubnetRoutes = cfg.SNATSubnetRoutes

	if err := r.dns.Set(cfg.DNS); err != nil {
		return fmt.Errorf("dns set: %v", err)
	}

	return nil
}

// setNetfilterMode switches the router to the given netfilter
// mode. Netfilter state is created or deleted appropriately to
// reflect the new mode, and r.snatSubnetRoutes is updated to reflect
// the current state of subnet SNATing.
func (r *linuxRouter) setNetfilterMode(mode NetfilterMode) error {
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
	if err := r.ipt4.Insert("filter", r.inputRule(), 1, "-i", "lo", "-s", addr.String(), "-j", "ACCEPT"); err != nil {
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
	if err := r.ipt4.Delete("filter", r.inputRule(), "-i", "lo", "-s", addr.String(), "-j", "ACCEPT"); err != nil {
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
		args = append(args, "table", r.tailscaleRouteTable())
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
		args = append(args, "table", r.tailscaleRouteTable())
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
		"ip", "rule", "add",
		"pref", r.tailscaleRouteTable()+"10",
		"fwmark", r.tailscaleBypassMark(),
		"table", "main",
	)
	// ...and then we try the 'default' table, for correctness,
	// even though it's been empty on every Linux system I've ever seen.
	rg.Run(
		"ip", "rule", "add",
		"pref", r.tailscaleRouteTable()+"30",
		"fwmark", r.tailscaleBypassMark(),
		"table", "default",
	)
	// If neither of those matched (no default route on this system?)
	// then packets from us should be aborted rather than falling through
	// to the tailscale routes, because that would create routing loops.
	rg.Run(
		"ip", "rule", "add",
		"pref", r.tailscaleRouteTable()+"50",
		"fwmark", r.tailscaleBypassMark(),
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
		"ip", "rule", "add",
		"pref", r.tailscaleRouteTable()+"70",
		"table", r.tailscaleRouteTable(),
	)
	// If that didn't match, then non-fwmark packets fall through to the
	// usual rules (pref 32766 and 32767, ie. main and default).

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

	// When deleting rules, we want to be a bit specific (mention which
	// table we were routing to) but not *too* specific (fwmarks, etc).
	// That leaves us some flexibility to change these values in later
	// versions without having ongoing hacks for every possible
	// combination.

	// Delete old-style tailscale rules
	// (never released in a stable version, so we can drop this
	// support eventually).
	rg.Run(
		"ip", "rule", "del",
		"pref", "10000",
		"table", "main",
	)

	// Delete new-style tailscale rules.
	rg.Run(
		"ip", "rule", "del",
		"pref", r.tailscaleRouteTable()+"10",
		"table", "main",
	)
	rg.Run(
		"ip", "rule", "del",
		"pref", r.tailscaleRouteTable()+"30",
		"table", "default",
	)
	rg.Run(
		"ip", "rule", "del",
		"pref", r.tailscaleRouteTable()+"50",
		"type", "unreachable",
	)
	rg.Run(
		"ip", "rule", "del",
		"pref", r.tailscaleRouteTable()+"70",
		"table", r.tailscaleRouteTable(),
	)
	return rg.ErrAcc
}

// addNetfilterChains creates custom Tailscale chains in netfilter.
func (r *linuxRouter) addNetfilterChains() error {
	create := func(table, chain string) error {
		err := r.ipt4.ClearChain(table, chain)
		if errCode(err) == 1 {
			// nonexistent chain. let's create it!
			return r.ipt4.NewChain(table, chain)
		}
		if err != nil {
			return fmt.Errorf("setting up %s/%s: %w", table, chain, err)
		}
		return nil
	}
	if err := create("filter", r.inputRule()); err != nil {
		return err
	}
	if err := create("filter", r.forwardRule()); err != nil {
		return err
	}
	if err := create("nat", r.postroutingRule()); err != nil {
		return err
	}
	return nil
}

// addNetfilterBase adds with some basic processing rules to be supplemented
// by later calls to other helpers.
func (r *linuxRouter) addNetfilterBase() error {
	// Only allow CGNAT range traffic to come from tailscale0. There
	// is an exception carved out for ranges used by ChromeOS, for
	// which we fall out of the Tailscale chain.
	//
	// Note, this will definitely break nodes that end up using the
	// CGNAT range for other purposes :(.
	args := []string{"!", "-i", r.tunname, "-s", tsaddr.ChromeOSVMRange().String(), "-j", "RETURN"}
	if err := r.ipt4.Append("filter", r.inputRule(), args...); err != nil {
		return fmt.Errorf("adding %v in filter/%s: %w", args, r.inputRule(), err)
	}
	if !r.multiTS {
		args = []string{"!", "-i", r.tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"}
		if err := r.ipt4.Append("filter", r.inputRule(), args...); err != nil {
			return fmt.Errorf("adding %v in filter/%s: %w", args, r.inputRule(), err)
		}
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
	args = []string{"-i", r.tunname, "-j", "MARK", "--set-mark", r.tailscaleSubnetRouteMark()}
	if err := r.ipt4.Append("filter", r.forwardRule(), args...); err != nil {
		return fmt.Errorf("adding %v in filter/%s: %w", args, r.forwardRule(), err)
	}
	args = []string{"-m", "mark", "--mark", r.tailscaleSubnetRouteMark(), "-j", "ACCEPT"}
	if err := r.ipt4.Append("filter", r.forwardRule(), args...); err != nil {
		return fmt.Errorf("adding %v in filter/%s: %w", args, r.forwardRule(), err)
	}
	if !r.multiTS {
		args = []string{"-o", r.tunname, "-s", tsaddr.CGNATRange().String(), "-j", "DROP"}
		if err := r.ipt4.Append("filter", r.forwardRule(), args...); err != nil {
			return fmt.Errorf("adding %v in filter/%s: %w", args, r.forwardRule(), err)
		}
	}
	args = []string{"-o", r.tunname, "-j", "ACCEPT"}
	if err := r.ipt4.Append("filter", r.forwardRule(), args...); err != nil {
		return fmt.Errorf("adding %v in filter/%s: %w", args, r.forwardRule(), err)
	}

	return nil
}

// delNetfilterChains removes the custom Tailscale chains from netfilter.
func (r *linuxRouter) delNetfilterChains() error {
	del := func(table, chain string) error {
		if err := r.ipt4.ClearChain(table, chain); err != nil {
			if errCode(err) == 1 {
				// nonexistent chain. That's fine, since it's
				// the desired state anyway.
				return nil
			}
			return fmt.Errorf("flushing %s/%s: %w", table, chain, err)
		}
		if err := r.ipt4.DeleteChain(table, chain); err != nil {
			// this shouldn't fail, because if the chain didn't
			// exist, we would have returned after ClearChain.
			return fmt.Errorf("deleting %s/%s: %v", table, chain, err)
		}
		return nil
	}

	if err := del("filter", r.inputRule()); err != nil {
		return err
	}
	if err := del("filter", r.forwardRule()); err != nil {
		return err
	}
	if err := del("nat", r.postroutingRule()); err != nil {
		return err
	}

	return nil
}

// delNetfilterBase empties but does not remove custom Tailscale chains from
// netfilter.
func (r *linuxRouter) delNetfilterBase() error {
	del := func(table, chain string) error {
		if err := r.ipt4.ClearChain(table, chain); err != nil {
			if errCode(err) == 1 {
				// nonexistent chain. That's fine, since it's
				// the desired state anyway.
				return nil
			}
			return fmt.Errorf("flushing %s/%s: %w", table, chain, err)
		}
		return nil
	}

	if err := del("filter", r.inputRule()); err != nil {
		return err
	}
	if err := del("filter", r.forwardRule()); err != nil {
		return err
	}
	if err := del("nat", r.postroutingRule()); err != nil {
		return err
	}

	return nil
}

// addNetfilterHooks inserts calls to tailscale's netfilter chains in
// the relevant main netfilter chains. The tailscale chains must
// already exist.
func (r *linuxRouter) addNetfilterHooks() error {
	divert := func(table, ichain string, ochain string) error {
		args := []string{"-j", ochain}
		exists, err := r.ipt4.Exists(table, ichain, args...)
		if err != nil {
			return fmt.Errorf("checking for %v in %s/%s:%s %w", args, table, ichain, ochain, err)
		}
		if exists {
			return nil
		}
		if err := r.ipt4.Insert(table, ichain, 1, args...); err != nil {
			return fmt.Errorf("adding %v in %s/%s:%s %w", args, table, ichain, ochain, err)
		}
		return nil
	}

	if err := divert("filter", "INPUT", r.inputRule()); err != nil {
		return err
	}
	if err := divert("filter", "FORWARD", r.forwardRule()); err != nil {
		return err
	}
	if err := divert("nat", "POSTROUTING", r.postroutingRule()); err != nil {
		return err
	}
	return nil
}

// delNetfilterHooks deletes the calls to tailscale's netfilter chains
// in the relevant main netfilter chains.
func (r *linuxRouter) delNetfilterHooks() error {
	del := func(table, ichain string, ochain string) error {
		args := []string{"-j", ochain}
		if err := r.ipt4.Delete(table, ichain, args...); err != nil {
			// TODO(apenwarr): check for errCode(1) here.
			// Unfortunately the error code from the iptables
			// module resists unwrapping, unlike with other
			// calls. So we have to assume if Delete fails,
			// it's because there is no such rule.
			r.logf("note: deleting %v in %s/%s:%s %w", args, table, ichain, ochain, err)
			return nil
		}
		return nil
	}

	if err := del("filter", "INPUT", r.inputRule()); err != nil {
		return err
	}
	if err := del("filter", "FORWARD", r.forwardRule()); err != nil {
		return err
	}
	if err := del("nat", "POSTROUTING", r.postroutingRule()); err != nil {
		return err
	}
	return nil
}

// addSNATRule adds a netfilter rule to SNAT traffic destined for
// local subnets.
func (r *linuxRouter) addSNATRule() error {
	if r.netfilterMode == NetfilterOff {
		return nil
	}

	args := []string{"-m", "mark", "--mark", r.tailscaleSubnetRouteMark(), "-j", "MASQUERADE"}
	if err := r.ipt4.Append("nat", r.postroutingRule(), args...); err != nil {
		return fmt.Errorf("adding %v in nat/%s: %w", args, r.postroutingRule(), err)
	}
	return nil
}

// delSNATRule removes the netfilter rule to SNAT traffic destined for
// local subnets. Fails if the rule does not exist.
func (r *linuxRouter) delSNATRule() error {
	if r.netfilterMode == NetfilterOff {
		return nil
	}

	args := []string{"-m", "mark", "--mark", r.tailscaleSubnetRouteMark(), "-j", "MASQUERADE"}
	if err := r.ipt4.Delete("nat", r.postroutingRule(), args...); err != nil {
		return fmt.Errorf("deleting %v in nat/%s: %w", args, r.postroutingRule(), err)
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
