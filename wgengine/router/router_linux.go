// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"
	"tailscale.com/atomicfile"
	"tailscale.com/types/logger"
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
	tailscaleSubnetRouteMark = "0x10000/0x10000"
	// Packet was originated by tailscaled itself, and must not be
	// routed over the Tailscale network.
	tailscaleBypassMark = "0x20000/0x20000"
)

// chromeOSVMRange is the subset of the CGNAT IPv4 range used by
// ChromeOS to interconnect the host OS to containers and VMs. We
// avoid allocating Tailscale IPs from it, to avoid conflicts.
const chromeOSVMRange = "100.115.92.0/23"

// netfilterRunner abstracts helpers to run netfilter commands. It
// exists purely to swap out go-iptables for a fake implementation in
// tests.
type netfilterRunner interface {
	Insert(table, chain string, pos int, args ...string) error
	Append(table, chain string, args ...string) error
	Exists(table, chain string, args ...string) (bool, error)
	Delete(table, chain string, args ...string) error
	ListChains(table string) ([]string, error)
	ClearChain(table, chain string) error
	NewChain(table, chain string) error
	DeleteChain(table, chain string) error
}

// commandRunner abstracts helpers to run OS commands. It exists
// purely to swap out osCommandRunner (below) with a fake runner in
// tests.
type commandRunner interface {
	run(...string) error
	output(...string) ([]byte, error)
}

type linuxRouter struct {
	logf             func(fmt string, args ...interface{})
	tunname          string
	addrs            map[netaddr.IPPrefix]bool
	routes           map[netaddr.IPPrefix]bool
	subnetRoutes     map[netaddr.IPPrefix]bool
	snatSubnetRoutes bool
	netfilterMode    NetfilterMode

	ipt4 netfilterRunner
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

	return newUserspaceRouterAdvanced(logf, tunname, ipt4, osCommandRunner{})
}

func newUserspaceRouterAdvanced(logf logger.Logf, tunname string, netfilter netfilterRunner, cmd commandRunner) (Router, error) {
	return &linuxRouter{
		logf:          logf,
		tunname:       tunname,
		netfilterMode: NetfilterOff,
		ipt4:          netfilter,
		cmd:           cmd,
	}, nil
}

type osCommandRunner struct{}

func (o osCommandRunner) run(args ...string) error {
	_, err := o.output(args...)
	return err
}

func (o osCommandRunner) output(args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("cmd: no argv[0]")
	}

	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("running %q failed: %v\n%s", strings.Join(args, " "), err, out)
	}

	return out, nil
}

func (r *linuxRouter) Up() error {
	if err := r.delLegacyNetfilter(); err != nil {
		return err
	}
	if err := r.delNetfilterHooks(); err != nil {
		return err
	}
	if err := r.delNetfilterBase(); err != nil {
		return err
	}

	if err := r.addBypassRule(); err != nil {
		return err
	}
	if err := r.upInterface(); err != nil {
		return err
	}

	return nil
}

func (r *linuxRouter) down() error {
	if err := r.downInterface(); err != nil {
		return err
	}
	if err := r.delBypassRule(); err != nil {
		return err
	}
	if err := r.delNetfilterHooks(); err != nil {
		return err
	}
	if err := r.delNetfilterBase(); err != nil {
		return err
	}

	r.addrs = nil
	r.routes = nil
	r.subnetRoutes = nil

	return nil
}

func (r *linuxRouter) Close() error {
	var ret error
	if ret = r.restoreResolvConf(); ret != nil {
		r.logf("failed to restore system resolv.conf: %v", ret)
	}
	if err := r.down(); err != nil {
		if ret == nil {
			ret = err
		}
	}

	return ret
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

	newSubnetRoutes, err := cidrDiff("subnet rule", r.subnetRoutes, cfg.SubnetRoutes, r.addSubnetRule, r.delSubnetRule, r.logf)
	if err != nil {
		return err
	}
	r.subnetRoutes = newSubnetRoutes

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

	// TODO: this:
	if false {
		if err := r.replaceResolvConf(cfg.DNS, cfg.DNSDomains); err != nil {
			return fmt.Errorf("replacing resolv.conf failed: %v", err)
		}
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
		if err := r.delNetfilterHooks(); err != nil {
			return err
		}
		if err := r.delNetfilterBase(); err != nil {
			return err
		}
		r.snatSubnetRoutes = false
	case NetfilterNoDivert:
		switch r.netfilterMode {
		case NetfilterOff:
			reprocess = true
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
		switch r.netfilterMode {
		case NetfilterOff:
			reprocess = true
			if err := r.addNetfilterBase(); err != nil {
				return err
			}
			if err := r.addNetfilterHooks(); err != nil {
				return err
			}
			r.snatSubnetRoutes = false
		case NetfilterNoDivert:
			if err := r.addNetfilterHooks(); err != nil {
				return err
			}
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
	for cidr := range r.subnetRoutes {
		if err := r.addSubnetRule(cidr); err != nil {
			return err
		}
	}

	return nil
}

const (
	tsConf     = "/etc/resolv.tailscale.conf"
	backupConf = "/etc/resolv.pre-tailscale-backup.conf"
	resolvConf = "/etc/resolv.conf"
)

func (r *linuxRouter) replaceResolvConf(servers []netaddr.IP, domains []string) error {
	if len(servers) == 0 {
		return r.restoreResolvConf()
	}

	// First write the tsConf file.
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "# resolv.conf(5) file generated by tailscale\n")
	fmt.Fprintf(buf, "#     DO NOT EDIT THIS FILE BY HAND -- CHANGES WILL BE OVERWRITTEN\n\n")
	for _, ns := range servers {
		fmt.Fprintf(buf, "nameserver %s\n", ns)
	}
	if len(domains) > 0 {
		fmt.Fprintf(buf, "search "+strings.Join(domains, " ")+"\n")
	}
	f, err := ioutil.TempFile(filepath.Dir(tsConf), filepath.Base(tsConf)+".*")
	if err != nil {
		return err
	}
	f.Close()
	if err := atomicfile.WriteFile(f.Name(), buf.Bytes(), 0644); err != nil {
		return err
	}
	os.Chmod(f.Name(), 0644) // ioutil.TempFile creates the file with 0600
	if err := os.Rename(f.Name(), tsConf); err != nil {
		return err
	}

	if linkPath, err := os.Readlink(resolvConf); err != nil {
		// Remove any old backup that may exist.
		os.Remove(backupConf)

		// Backup the existing /etc/resolv.conf file.
		contents, err := ioutil.ReadFile(resolvConf)
		if os.IsNotExist(err) {
			// No existing /etc/resolv.conf file to backup.
			// Nothing to do.
			return nil
		} else if err != nil {
			return err
		}
		if err := atomicfile.WriteFile(backupConf, contents, 0644); err != nil {
			return err
		}
	} else if linkPath != tsConf {
		// Backup the existing symlink.
		os.Remove(backupConf)
		if err := os.Symlink(linkPath, backupConf); err != nil {
			return err
		}
	} else {
		// Nothing to do, resolvConf already points to tsConf.
		return nil
	}

	os.Remove(resolvConf)
	if err := os.Symlink(tsConf, resolvConf); err != nil {
		return nil
	}

	out, _ := exec.Command("service", "systemd-resolved", "restart").CombinedOutput()
	if len(out) > 0 {
		r.logf("service systemd-resolved restart: %s", out)
	}
	return nil
}

func (r *linuxRouter) restoreResolvConf() error {
	if _, err := os.Stat(backupConf); err != nil {
		if os.IsNotExist(err) {
			return nil // no backup resolv.conf to restore
		}
		return err
	}
	if ln, err := os.Readlink(resolvConf); err != nil {
		return err
	} else if ln != tsConf {
		return fmt.Errorf("resolv.conf is not a symlink to %s", tsConf)
	}
	if err := os.Rename(backupConf, resolvConf); err != nil {
		return err
	}
	os.Remove(tsConf) // best effort removal of tsConf file
	out, _ := exec.Command("service", "systemd-resolved", "restart").CombinedOutput()
	if len(out) > 0 {
		r.logf("service systemd-resolved restart: %s", out)
	}
	return nil
}

// addAddress adds an IP/mask to the tunnel interface. Fails if the
// address is already assigned to the interface, or if the addition
// fails.
func (r *linuxRouter) addAddress(addr netaddr.IPPrefix) error {
	if err := r.cmd.run("ip", "addr", "add", addr.String(), "dev", r.tunname); err != nil {
		return fmt.Errorf("adding address %q to tunnel interface: %v", addr, err)
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
		return fmt.Errorf("deleting address %q from tunnel interface: %v", addr, err)
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
		return fmt.Errorf("adding loopback allow rule for %q: %v", addr, err)
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
		return fmt.Errorf("deleting loopback allow rule for %q: %v", addr, err)
	}
	return nil
}

// addRoute adds a route for cidr, pointing to the tunnel
// interface. Fails if the route already exists, or if adding the
// route fails.
func (r *linuxRouter) addRoute(cidr netaddr.IPPrefix) error {
	return r.cmd.run("ip", "route", "add", normalizeCIDR(cidr), "dev", r.tunname, "scope", "global")
}

// delRoute removes the route for cidr pointing to the tunnel
// interface. Fails if the route doesn't exist, or if removing the
// route fails.
func (r *linuxRouter) delRoute(cidr netaddr.IPPrefix) error {
	return r.cmd.run("ip", "route", "del", normalizeCIDR(cidr), "dev", r.tunname, "scope", "global")
}

// addSubnetRule adds a netfilter rule that allows traffic to flow
// from Tailscale to cidr.
func (r *linuxRouter) addSubnetRule(cidr netaddr.IPPrefix) error {
	if r.netfilterMode == NetfilterOff {
		return nil
	}

	if err := r.ipt4.Insert("filter", "ts-forward", 1, "-i", r.tunname, "-d", normalizeCIDR(cidr), "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark); err != nil {
		return fmt.Errorf("adding subnet mark rule for %q: %v", cidr, err)
	}
	if err := r.ipt4.Insert("filter", "ts-forward", 1, "-o", r.tunname, "-s", normalizeCIDR(cidr), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("adding subnet forward rule for %q: %v", cidr, err)
	}
	return nil
}

// delSubnetRule deletes the netfilter subnet forwarding rule for
// cidr. Fails if the rule doesn't exist, or if removing the route
// fails.
func (r *linuxRouter) delSubnetRule(cidr netaddr.IPPrefix) error {
	if r.netfilterMode == NetfilterOff {
		return nil
	}

	if err := r.ipt4.Delete("filter", "ts-forward", "-i", r.tunname, "-d", normalizeCIDR(cidr), "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark); err != nil {
		return fmt.Errorf("deleting subnet mark rule for %q: %v", cidr, err)
	}
	if err := r.ipt4.Delete("filter", "ts-forward", "-o", r.tunname, "-s", normalizeCIDR(cidr), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("deleting subnet forward rule for %q: %v", cidr, err)
	}
	return nil
}

// upInterface brings up the tunnel interface and adds it to the
// Tailscale interface group.
func (r *linuxRouter) upInterface() error {
	return r.cmd.run("ip", "link", "set", "dev", r.tunname, "group", "10000", "up")
}

// downInterface sets the tunnel interface administratively down, and
// returns it to the default interface group.
func (r *linuxRouter) downInterface() error {
	return r.cmd.run("ip", "link", "set", "dev", r.tunname, "group", "0", "down")
}

// addBypassRule adds the policy routing rule that avoids tailscaled
// routing loops. If the rule exists and appears to be a
// tailscale-managed rule, it is gracefully replaced.
func (r *linuxRouter) addBypassRule() error {
	if err := r.delBypassRule(); err != nil {
		return err
	}
	return r.cmd.run("ip", "rule", "add", "fwmark", tailscaleBypassMark, "priority", "10000", "table", "main", "suppress_ifgroup", "10000")
}

// delBypassrule removes the policy routing rule that avoids
// tailscaled routing loops, if it exists.
func (r *linuxRouter) delBypassRule() error {
	out, err := r.cmd.output("ip", "rule", "list", "priority", "10000")
	if err != nil {
		// Busybox ships an `ip` binary that doesn't understand
		// uncommon rules. Try to detect this explicitly, and steer
		// the user towards the correct fix. See
		// https://github.com/tailscale/tailscale/issues/368 for an
		// example of this issue.
		if bytes.Contains(out, []byte("ip: ignoring all arguments")) {
			return errors.New("cannot list ip rules, `ip` appears to be the busybox implementation. Please install iproute2")
		}
		return fmt.Errorf("listing ip rules: %v\n%s", err, out)
	}
	if len(out) == 0 {
		// No rule exists.
		return nil
	}
	// Approximate sanity check that the rule we're about to delete
	// looks like one that handles Tailscale's fwmark.
	if !bytes.Contains(out, []byte(" fwmark "+tailscaleBypassMark)) {
		return fmt.Errorf("ip rule 10000 doesn't look like a Tailscale policy rule: %q", string(out))
	}
	return r.cmd.run("ip", "rule", "del", "priority", "10000")
}

// addNetfilterBase adds custom Tailscale chains to netfilter, along
// with some basic processing rules to be supplemented by later calls
// to other helpers.
func (r *linuxRouter) addNetfilterBase() error {
	create := func(table, chain string) error {
		chains, err := r.ipt4.ListChains(table)
		if err != nil {
			return fmt.Errorf("listing iptables chains: %v", err)
		}
		found := false
		for _, ch := range chains {
			if ch == chain {
				found = true
				break
			}
		}
		if found {
			err = r.ipt4.ClearChain(table, chain)
		} else {
			err = r.ipt4.NewChain(table, chain)
		}
		if err != nil {
			return fmt.Errorf("setting up %s/%s: %v", table, chain, err)
		}
		return nil
	}
	if err := create("filter", "ts-input"); err != nil {
		return err
	}
	if err := create("filter", "ts-forward"); err != nil {
		return err
	}
	if err := create("nat", "ts-postrouting"); err != nil {
		return err
	}

	// Only allow CGNAT range traffic to come from tailscale0. There
	// is an exception carved out for ranges used by ChromeOS, for
	// which we fall out of the Tailscale chain.
	//
	// Note, this will definitely break nodes that end up using the
	// CGNAT range for other purposes :(.
	args := []string{"!", "-i", r.tunname, "-s", chromeOSVMRange, "-j", "RETURN"}
	if err := r.ipt4.Append("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("adding %v in filter/ts-input: %v", args, err)
	}
	args = []string{"!", "-i", r.tunname, "-s", "100.64.0.0/10", "-j", "DROP"}
	if err := r.ipt4.Append("filter", "ts-input", args...); err != nil {
		return fmt.Errorf("adding %v in filter/ts-input: %v", args, err)
	}

	// Forward and mark packets that have the Tailscale subnet route
	// bit set. The bit gets set by rules inserted into filter/FORWARD
	// later on. We use packet marks here so both filter/FORWARD and
	// nat/POSTROUTING can match on these packets of interest.
	//
	// In particular, we only want to apply SNAT rules in
	// nat/POSTROUTING to packets that originated from the Tailscale
	// interface, but we can't match on the inbound interface in
	// POSTROUTING. So instead, we match on the inbound interface and
	// destination IP in filter/FORWARD, and set a packet mark that
	// nat/POSTROUTING can use to effectively run that same test
	// again.
	args = []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "ACCEPT"}
	if err := r.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in filter/ts-forward: %v", args, err)
	}
	args = []string{"-i", r.tunname, "-j", "DROP"}
	if err := r.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in filter/ts-forward: %v", args, err)
	}

	return nil
}

// delNetfilterBase removes custom Tailscale chains from netfilter.
func (r *linuxRouter) delNetfilterBase() error {
	del := func(table, chain string) error {
		chains, err := r.ipt4.ListChains(table)
		if err != nil {
			return fmt.Errorf("listing iptables chains: %v", err)
		}
		for _, ch := range chains {
			if ch == chain {
				if err := r.ipt4.ClearChain(table, chain); err != nil {
					return fmt.Errorf("flushing %s/%s: %v", table, chain, err)
				}
				if err := r.ipt4.DeleteChain(table, chain); err != nil {
					return fmt.Errorf("deleting %s/%s: %v", table, chain, err)
				}
				return nil
			}
		}
		return nil
	}

	if err := del("filter", "ts-input"); err != nil {
		return err
	}
	if err := del("filter", "ts-forward"); err != nil {
		return err
	}
	if err := del("nat", "ts-postrouting"); err != nil {
		return err
	}

	return nil
}

// addNetfilterHooks inserts calls to tailscale's netfilter chains in
// the relevant main netfilter chains. The tailscale chains must
// already exist.
func (r *linuxRouter) addNetfilterHooks() error {
	divert := func(table, chain string) error {
		tsChain := tsChain(chain)

		chains, err := r.ipt4.ListChains(table)
		if err != nil {
			return fmt.Errorf("listing iptables chains: %v", err)
		}
		found := false
		for _, chain := range chains {
			if chain == tsChain {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("chain %q does not exist, cannot divert to it", tsChain)
		}

		args := []string{"-j", tsChain}
		exists, err := r.ipt4.Exists(table, chain, args...)
		if err != nil {
			return fmt.Errorf("checking for %v in %s/%s: %v", args, table, chain, err)
		}
		if exists {
			return nil
		}
		if err := r.ipt4.Insert(table, chain, 1, args...); err != nil {
			return fmt.Errorf("adding %v in %s/%s: %v", args, table, chain, err)
		}
		return nil
	}

	if err := divert("filter", "INPUT"); err != nil {
		return err
	}
	if err := divert("filter", "FORWARD"); err != nil {
		return err
	}
	if err := divert("nat", "POSTROUTING"); err != nil {
		return err
	}
	return nil
}

// delNetfilterHooks deletes the calls to tailscale's netfilter chains
// in the relevant main netfilter chains.
func (r *linuxRouter) delNetfilterHooks() error {
	del := func(table, chain string) error {
		tsChain := tsChain(chain)

		chains, err := r.ipt4.ListChains(table)
		if err != nil {
			return fmt.Errorf("listing iptables chains: %v", err)
		}
		found := false
		for _, chain := range chains {
			if chain == tsChain {
				found = true
				break
			}
		}
		if !found {
			// The divert rule can't exist if the chain doesn't exist,
			// and querying for a jump to a non-existent chain errors
			// out.
			return nil
		}

		args := []string{"-j", tsChain}
		exists, err := r.ipt4.Exists(table, chain, args...)
		if err != nil {
			return fmt.Errorf("checking for %v in %s/%s: %v", args, table, chain, err)
		}
		if !exists {
			return nil
		}
		if err := r.ipt4.Delete(table, chain, args...); err != nil {
			return fmt.Errorf("deleting %v in %s/%s: %v", args, table, chain, err)
		}
		return nil
	}

	if err := del("filter", "INPUT"); err != nil {
		return err
	}
	if err := del("filter", "FORWARD"); err != nil {
		return err
	}
	if err := del("nat", "POSTROUTING"); err != nil {
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

	args := []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "MASQUERADE"}
	if err := r.ipt4.Append("nat", "ts-postrouting", args...); err != nil {
		return fmt.Errorf("adding %v in nat/ts-postrouting: %v", args, err)
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
		return fmt.Errorf("deleting %v in nat/ts-postrouting: %v", args, err)
	}
	return nil
}

func (r *linuxRouter) delLegacyNetfilter() error {
	del := func(table, chain string, args ...string) error {
		exists, err := r.ipt4.Exists(table, chain, args...)
		if err != nil {
			return fmt.Errorf("checking for %v in %s/%s: %v", args, table, chain, err)
		}
		if exists {
			if err := r.ipt4.Delete(table, chain, args...); err != nil {
				return fmt.Errorf("deleting %v in %s/%s: %v", args, table, chain, err)
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
