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

type linuxRouter struct {
	logf         func(fmt string, args ...interface{})
	tunname      string
	addrs        map[netaddr.IPPrefix]bool
	routes       map[netaddr.IPPrefix]bool
	subnetRoutes map[netaddr.IPPrefix]bool
	noSNAT       bool

	ipt4 *iptables.IPTables
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

	return &linuxRouter{
		logf:    logf,
		tunname: tunname,
		noSNAT:  true,
		ipt4:    ipt4,
	}, nil
}

func cmd(args ...string) error {
	if len(args) == 0 {
		return errors.New("cmd: no argv[0]")
	}

	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %q failed: %v\n%s", strings.Join(args, " "), err, out)
	}

	return nil
}

func (r *linuxRouter) Up() error {
	if err := r.deleteLegacyNetfilter(); err != nil {
		return err
	}
	if err := r.addBaseNetfilter4(); err != nil {
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
	if err := r.delNetfilter4(); err != nil {
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

	// cidrDiff calls add and del as needed to make the set of prefixes in
	// old and new match. Returns a map version of new, and the first
	// error encountered while reconfiguring, if any.
	cidrDiff := func(kind string, old map[netaddr.IPPrefix]bool, new []netaddr.IPPrefix, add, del func(netaddr.IPPrefix) error) (map[netaddr.IPPrefix]bool, error) {
		var (
			ret  = make(map[netaddr.IPPrefix]bool, len(new))
			errq error
		)

		for _, cidr := range new {
			ret[cidr] = true
		}
		for cidr := range old {
			if ret[cidr] {
				continue
			}
			if err := del(cidr); err != nil {
				r.logf("%s del failed: %v", kind, err)
				if errq == nil {
					errq = err
				}
			}
		}
		for cidr := range ret {
			if old[cidr] {
				continue
			}
			if err := add(cidr); err != nil {
				r.logf("%s add failed: %v", kind, err)
				if errq == nil {
					errq = err
				}
			}
		}

		return ret, errq
	}

	var errq error

	newAddrs, err := cidrDiff("addr", r.addrs, cfg.LocalAddrs, r.addAddress, r.delAddress)
	if err != nil && errq == nil {
		errq = err
	}
	newRoutes, err := cidrDiff("route", r.routes, cfg.Routes, r.addRoute, r.delRoute)
	if err != nil && errq == nil {
		errq = err
	}
	newSubnetRoutes, err := cidrDiff("subnet rule", r.subnetRoutes, cfg.SubnetRoutes, r.addSubnetRule, r.delSubnetRule)
	if err != nil && errq == nil {
		errq = err
	}

	switch {
	case cfg.NoSNAT == r.noSNAT:
		// state already correct, nothing to do.
	case cfg.NoSNAT:
		if err := r.delSNATRule(); err != nil && errq == nil {
			errq = err
		}
	default:
		if err := r.addSNATRule(); err != nil && errq == nil {
			errq = err
		}
	}

	r.addrs = newAddrs
	r.routes = newRoutes
	r.subnetRoutes = newSubnetRoutes
	r.noSNAT = cfg.NoSNAT

	// TODO: this:
	if false {
		if err := r.replaceResolvConf(cfg.DNS, cfg.DNSDomains); err != nil {
			errq = fmt.Errorf("replacing resolv.conf failed: %v", err)
		}
	}
	return errq
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

// addAddress adds an IP/mask to the tunnel interface, and firewall
// rules to permit loopback traffic. Fails if the address is already
// assigned to the interface, or if the addition fails.
func (r *linuxRouter) addAddress(addr netaddr.IPPrefix) error {
	if err := cmd("ip", "addr", "add", addr.String(), "dev", r.tunname); err != nil {
		return err
	}
	if err := r.ipt4.Insert("filter", "ts-input", 1, "-i", "lo", "-s", addr.IP.String(), "-j", "ACCEPT"); err != nil {
		return err
	}
	return nil
}

// delAddress removes an IP/mask from the tunnel interface, and
// firewall rules permitting loopback traffic. Fails if the address is
// not assigned to the interface, or if the removal fails.
func (r *linuxRouter) delAddress(addr netaddr.IPPrefix) error {
	if err := r.ipt4.Delete("filter", "ts-input", "-i", "lo", "-s", addr.IP.String(), "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := cmd("ip", "addr", "del", addr.String(), "dev", r.tunname); err != nil {
		return err
	}
	return nil
}

// normalizeCIDR returns cidr as an ip/mask string, with the host bits
// of the IP address zeroed out.
func normalizeCIDR(cidr netaddr.IPPrefix) string {
	ncidr := cidr.IPNet()
	nip := ncidr.IP.Mask(ncidr.Mask)
	return fmt.Sprintf("%s/%d", nip, cidr.Bits)
}

// addRoute adds a route for cidr, pointing to the tunnel
// interface. Fails if the route already exists, or if adding the
// route fails.
func (r *linuxRouter) addRoute(cidr netaddr.IPPrefix) error {
	return cmd("ip", "route", "add", normalizeCIDR(cidr), "dev", r.tunname, "scope", "global")
}

// delRoute removes the route for cidr pointing to the tunnel
// interface. Fails if the route doesn't exist, or if removing the
// route fails.
func (r *linuxRouter) delRoute(cidr netaddr.IPPrefix) error {
	return cmd("ip", "route", "del", normalizeCIDR(cidr), "dev", r.tunname, "scope", "global")
}

// addSubnetRule adds a netfilter rule that allows traffic to flow
// from Tailscale to cidr. Fails if the rule already exists, or if
// adding the route fails.
func (r *linuxRouter) addSubnetRule(cidr netaddr.IPPrefix) error {
	if err := r.ipt4.Insert("filter", "ts-forward", 1, "-i", r.tunname, "-d", normalizeCIDR(cidr), "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark); err != nil {
		return fmt.Errorf("adding subnet mark rule for %q: %v", cidr, err)
	}
	if err := r.ipt4.Insert("filter", "ts-forward", 1, "-o", r.tunname, "-s", normalizeCIDR(cidr), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("adding subnet forward rule for %q: %v", cidr, err)
	}
	return nil
}

// delSubnetRule deletes the netfilter subnet forwarding rule for
// cidr. Fails if the rule doesn't exist, or if removing the rule
// fails.
func (r *linuxRouter) delSubnetRule(cidr netaddr.IPPrefix) error {
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
	return cmd("ip", "link", "set", "dev", r.tunname, "group", "10000", "up")
}

// downInterface sets the tunnel interface administratively down, and
// returns it to the default interface group.
func (r *linuxRouter) downInterface() error {
	return cmd("ip", "link", "set", "dev", r.tunname, "group", "0", "down")
}

// addBypassRule adds the policy routing rule that avoids tailscaled
// routing loops. If the rule exists and appears to be a
// tailscale-managed rule, it is gracefully replaced.
func (r *linuxRouter) addBypassRule() error {
	if err := r.delBypassRule(); err != nil {
		return err
	}
	return cmd("ip", "rule", "add", "fwmark", tailscaleBypassMark, "priority", "10000", "table", "main", "suppress_ifgroup", "10000")
}

// delBypassrule removes the policy routing rule that avoids
// tailscaled routing loops, if it exists.
func (r *linuxRouter) delBypassRule() error {
	out, err := exec.Command("ip", "rule", "list", "priority", "10000").CombinedOutput()
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
	return cmd("ip", "rule", "del", "priority", "10000")
}

// deleteLegacyNetfilter removes the netfilter rules installed by
// older versions of Tailscale, if they exist.
func (r *linuxRouter) deleteLegacyNetfilter() error {
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
		return err
	}
	if err := del("nat", "POSTROUTING", "-m", "comment", "--comment", "tailscale", "-o", "eth0", "-j", "MASQUERADE"); err != nil {
		return err
	}

	return nil
}

// deleteNetfilter4 removes custom Tailscale chains and processing
// hooks from netfilter.
func (r *linuxRouter) delNetfilter4() error {
	del := func(table, chain string) error {
		tsChain := "ts-" + strings.ToLower(chain)

		args := []string{"-j", tsChain}
		exists, err := r.ipt4.Exists(table, chain, args...)
		if err != nil {
			return fmt.Errorf("checking for %v in %s/%s: %v", args, table, chain, err)
		}
		if exists {
			if err := r.ipt4.Delete(table, chain, "-j", tsChain); err != nil {
				return fmt.Errorf("deleting %v in %s/%s: %v", args, table, chain, err)
			}
		}

		chains, err := r.ipt4.ListChains(table)
		if err != nil {
			return fmt.Errorf("listing iptables chains: %v", err)
		}
		for _, chain := range chains {
			if chain == tsChain {
				if err := r.ipt4.DeleteChain(table, tsChain); err != nil {
					return fmt.Errorf("deleting %s/%s: %v", table, tsChain, err)
				}
				break
			}
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

// chromeOSVMRange is the subset of the CGNAT IPv4 range used by
// ChromeOS to interconnect the host OS to containers and VMs. We
// avoid allocating Tailscale IPs from it, to avoid conflicts.
const chromeOSVMRange = "100.115.92.0/23"

// addBaseNetfilter4 installs the basic IPv4 netfilter framework for
// Tailscale, in preparation for inserting more rules later.
func (r *linuxRouter) addBaseNetfilter4() error {
	// Create our own filtering chains, and hook them into the head of
	// various main tables. If the hooks already exist, we don't try
	// to fight for first place, because other software does the
	// same. We're happy with "someplace up before most other stuff".
	divert := func(table, chain string) error {
		tsChain := "ts-" + strings.ToLower(chain)

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
		if found {
			err = r.ipt4.ClearChain(table, tsChain)
		} else {
			err = r.ipt4.NewChain(table, tsChain)
		}
		if err != nil {
			return fmt.Errorf("setting up %s/%s: %v", table, tsChain, err)
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

	// Only allow CGNAT range traffic to come from tailscale0. There
	// is an exception carved out for ranges used by ChromeOS, for
	// which we fall out of the Tailscale chain.
	//
	// Note, this will definitely break nodes that end up using the
	// CGNAT range for other purposes :(.
	args := []string{"!", "-i", r.tunname, "-s", chromeOSVMRange, "-m", "comment", "--comment", "ChromeOS VM connectivity", "-j", "RETURN"}
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

// addSNATRule adds a netfilter rule to SNAT traffic destined for
// local subnets.
func (r *linuxRouter) addSNATRule() error {
	args := []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "MASQUERADE"}
	if err := r.ipt4.Append("nat", "ts-postrouting", args...); err != nil {
		return fmt.Errorf("adding %v in nat/ts-postrouting: %v", args, err)
	}
	return nil
}

// delSNATRule removes the netfilter rule to SNAT traffic destined for
// local subnets. Fails if the rule does not exist.
func (r *linuxRouter) delSNATRule() error {
	args := []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "MASQUERADE"}
	if err := r.ipt4.Delete("nat", "ts-postrouting", args...); err != nil {
		return fmt.Errorf("deleting %v in nat/ts-postrouting: %v", args, err)
	}
	return nil
}
