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
	"github.com/tailscale/wireguard-go/wgcfg"
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
	local        wgcfg.CIDR
	routes       map[wgcfg.CIDR]bool
	subnetRoutes map[wgcfg.CIDR]bool

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

	r.routes = map[wgcfg.CIDR]bool{}
	r.local = wgcfg.CIDR{}

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

func (r *linuxRouter) SetRoutes(rs RouteSettings) error {
	var errq error

	if rs.LocalAddr != r.local {
		if r.local != (wgcfg.CIDR{}) {
			if err := r.delAddress(r.local); err != nil {
				r.logf("addr del failed: %v", err)
				if errq == nil {
					errq = err
				}
			}
		}
		if err := r.addAddress(rs.LocalAddr); err != nil {
			r.logf("addr add failed: %v", err)
			if errq == nil {
				errq = err
			}
		}
	}

	newRoutes := make(map[wgcfg.CIDR]bool)
	for _, peer := range rs.Cfg.Peers {
		for _, route := range peer.AllowedIPs {
			newRoutes[route] = true
		}
	}
	for route := range r.routes {
		if newRoutes[route] {
			continue
		}
		if err := r.delRoute(route, r.local.IP); err != nil {
			r.logf("route del failed: %v", err)
			if errq == nil {
				errq = err
			}
		}
	}
	for route := range newRoutes {
		if r.routes[route] {
			continue
		}
		if err := r.addRoute(route, rs.LocalAddr.IP); err != nil {
			r.logf("route add failed: %v", err)
			if errq == nil {
				errq = err
			}
		}
	}

	newSubnetRoutes := map[wgcfg.CIDR]bool{}
	for _, route := range rs.SubnetRoutes {
		newSubnetRoutes[route] = true
	}
	for route := range r.subnetRoutes {
		if newSubnetRoutes[route] {
			continue
		}
		if err := r.delSubnetRule(route); err != nil {
			r.logf("subnet rule del failed: %v", err)
			if errq == nil {
				errq = err
			}
		}
	}
	for route := range newSubnetRoutes {
		if r.subnetRoutes[route] {
			continue
		}
		if err := r.addSubnetRule(route); err != nil {
			r.logf("subnet rule add failed: %v", err)
			if errq == nil {
				errq = err
			}
		}
	}

	r.local = rs.LocalAddr
	r.routes = newRoutes
	r.subnetRoutes = newSubnetRoutes

	// TODO: this:
	if false {
		if err := r.replaceResolvConf(rs.DNS, rs.DNSDomains); err != nil {
			errq = fmt.Errorf("replacing resolv.conf failed: %v", err)
		}
	}
	return errq
}

var tailscaleCGNATRange = wgcfg.CIDR{
	IP:   wgcfg.IPv4(100, 64, 0, 0),
	Mask: 10,
}

const (
	tsConf     = "/etc/resolv.tailscale.conf"
	backupConf = "/etc/resolv.pre-tailscale-backup.conf"
	resolvConf = "/etc/resolv.conf"
)

func (r *linuxRouter) replaceResolvConf(servers []wgcfg.IP, domains []string) error {
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
func (r *linuxRouter) addAddress(addr wgcfg.CIDR) error {
	return cmd("ip", "addr", "add", addr.String(), "dev", r.tunname)
}

// delAddress removes an IP/mask from the tunnel interface. Fails if
// the address is not assigned to the interface, or if the removal
// fails.
func (r *linuxRouter) delAddress(addr wgcfg.CIDR) error {
	return cmd("ip", "addr", "del", addr.String(), "dev", r.tunname)
}

// normalizeCIDR returns cidr as an ip/mask string, with the host bits
// of the IP address zeroed out.
func normalizeCIDR(cidr wgcfg.CIDR) string {
	ncidr := cidr.IPNet()
	nip := ncidr.IP.Mask(ncidr.Mask)
	return fmt.Sprintf("%s/%d", nip, cidr.Mask)
}

// addRoute adds a route for cidr, pointing to the tunnel interface by
// way of via. Fails if the route already exists, or if adding the
// route fails.
func (r *linuxRouter) addRoute(cidr wgcfg.CIDR, via wgcfg.IP) error {
	// TODO(danderson): I don't think we need `via` here? Should work
	// with just a direct interface pointer.
	return cmd("ip", "route", "add", normalizeCIDR(cidr), "via", via.String(), "dev", r.tunname)
}

// delRoute removes the route for cidr, pointing to the tunnel
// interface by way of via. Fails if the route doesn't exist, or if
// removing the route fails.
func (r *linuxRouter) delRoute(cidr wgcfg.CIDR, via wgcfg.IP) error {
	return cmd("ip", "route", "del", normalizeCIDR(cidr), "via", via.String(), "dev", r.tunname)
}

// addSubnetRule adds a netfilter rule that allows traffic to flow
// from Tailscale to cidr. Fails if the rule already exists, or if
// adding the route fails.
func (r *linuxRouter) addSubnetRule(cidr wgcfg.CIDR) error {
	if err := r.ipt4.Insert("filter", "ts-forward", 1, "-i", r.tunname, "-d", normalizeCIDR(cidr), "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark); err != nil {
		return err
	}
	if err := r.ipt4.Insert("filter", "ts-forward", 1, "-o", r.tunname, "-s", normalizeCIDR(cidr), "-j", "ACCEPT"); err != nil {
		return err
	}
	return nil
}

// delSubnetRule deletes the netfilter subnet forwarding rule for
// cidr. Fails if the rule doesn't exist, or if removing the rule
// fails.
func (r *linuxRouter) delSubnetRule(cidr wgcfg.CIDR) error {
	if err := r.ipt4.Delete("filter", "ts-forward", "-i", r.tunname, "-d", normalizeCIDR(cidr), "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark); err != nil {
		return err
	}
	if err := r.ipt4.Delete("filter", "ts-forward", "-o", r.tunname, "-s", normalizeCIDR(cidr), "-j", "ACCEPT"); err != nil {
		return err
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
		return err
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
			return err
		}
		if exists {
			if err := r.ipt4.Delete(table, chain, args...); err != nil {
				return err
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

		exists, err := r.ipt4.Exists(table, chain, "-j", tsChain)
		if err != nil {
			return err
		}
		if exists {
			if err := r.ipt4.Delete(table, chain, "-j", tsChain); err != nil {
				return err
			}
		}

		chains, err := r.ipt4.ListChains(table)
		if err != nil {
			return err
		}
		for _, chain := range chains {
			if chain == tsChain {
				if err := r.ipt4.DeleteChain(table, tsChain); err != nil {
					return err
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
			return err
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
			return err
		}

		args := []string{"-j", tsChain}
		exists, err := r.ipt4.Exists(table, chain, args...)
		if err != nil {
			return err
		}
		if !exists {
			return r.ipt4.Insert(table, chain, 1, args...)
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
	if err := r.ipt4.Append("filter", "ts-input", "!", "-i", r.tunname, "-s", "100.115.92.0/23", "-m", "comment", "--comment", "ChromeOS special ranges", "-j", "RETURN"); err != nil {
		return err
	}
	if err := r.ipt4.Append("filter", "ts-input", "!", "-i", r.tunname, "-s", "100.64.0.0/10", "-j", "DROP"); err != nil {
		return err
	}

	// Forward and masquerade packets that have the Tailscale subnet
	// route bit set. The bit gets set by rules inserted into
	// filter/FORWARD later on. We use packet marks here so both
	// filter/FORWARD and nat/POSTROUTING can match on these packets
	// of interest.
	if err := r.ipt4.Append("filter", "ts-forward", "-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := r.ipt4.Append("filter", "ts-forward", "-i", r.tunname, "-j", "DROP"); err != nil {
		return err
	}
	// TODO(danderson): this should be optional.
	if err := r.ipt4.Append("nat", "ts-postrouting", "-m", "mark", "--mark", tailscaleSubnetRouteMark, "-j", "MASQUERADE"); err != nil {
		return err
	}

	return nil
}
