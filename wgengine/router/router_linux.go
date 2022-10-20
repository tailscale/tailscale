// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/tailscale/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/types/preftype"
	"tailscale.com/util/multierr"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine/monitor"
)

const (
	netfilterOff      = preftype.NetfilterOff
	netfilterNoDivert = preftype.NetfilterNoDivert
	netfilterOn       = preftype.NetfilterOn
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
// relatively unused in the wild, and so we consume bits 16:23 (the
// third byte).
//
// The constants are in the iptables/iproute2 string format for
// matching and setting the bits, so they can be directly embedded in
// commands.
const (
	// The mask for reading/writing the 'firewall mask' bits on a packet.
	// See the comment on the const block on why we only use the third byte.
	//
	// We claim bits 16:23 entirely. For now we only use the lower four
	// bits, leaving the higher 4 bits for future use.
	tailscaleFwmarkMask    = "0xff0000"
	tailscaleFwmarkMaskNum = 0xff0000

	// Packet is from Tailscale and to a subnet route destination, so
	// is allowed to be routed through this machine.
	tailscaleSubnetRouteMark = "0x40000"

	// Packet was originated by tailscaled itself, and must not be
	// routed over the Tailscale network.
	//
	// Keep this in sync with tailscaleBypassMark in
	// net/netns/netns_linux.go.
	tailscaleBypassMark    = "0x80000"
	tailscaleBypassMarkNum = 0x80000
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
	closed           atomic.Bool
	logf             func(fmt string, args ...any)
	tunname          string
	linkMon          *monitor.Mon
	unregLinkMon     func()
	addrs            map[netip.Prefix]bool
	routes           map[netip.Prefix]bool
	localRoutes      map[netip.Prefix]bool
	snatSubnetRoutes bool
	netfilterMode    preftype.NetfilterMode

	// ruleRestorePending is whether a timer has been started to
	// restore deleted ip rules.
	ruleRestorePending atomic.Bool
	ipRuleFixLimiter   *rate.Limiter

	// Various feature checks for the network stack.
	ipRuleAvailable bool // whether kernel was built with IP_MULTIPLE_TABLES
	v6Available     bool
	v6NATAvailable  bool
	fwmaskWorks     bool // whether we can use 'ip rule...fwmark <mark>/<mask>'

	// ipPolicyPrefBase is the base priority at which ip rules are installed.
	ipPolicyPrefBase int

	ipt4 netfilterRunner
	ipt6 netfilterRunner
	cmd  commandRunner
}

func newUserspaceRouter(logf logger.Logf, tunDev tun.Device, linkMon *monitor.Mon) (Router, error) {
	tunname, err := tunDev.Name()
	if err != nil {
		return nil, err
	}

	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	v6err := checkIPv6(logf)
	if v6err != nil {
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	}
	supportsV6 := v6err == nil
	supportsV6NAT := supportsV6 && supportsV6NAT()
	if supportsV6 {
		logf("v6nat = %v", supportsV6NAT)
	}

	var ipt6 netfilterRunner
	if supportsV6 {
		// The iptables package probes for `ip6tables` and errors out
		// if unavailable. We want that to be a non-fatal error.
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, err
		}
	}

	cmd := osCommandRunner{
		ambientCapNetAdmin: useAmbientCaps(),
	}

	return newUserspaceRouterAdvanced(logf, tunname, linkMon, ipt4, ipt6, cmd, supportsV6, supportsV6NAT)
}

func newUserspaceRouterAdvanced(logf logger.Logf, tunname string, linkMon *monitor.Mon, netfilter4, netfilter6 netfilterRunner, cmd commandRunner, supportsV6, supportsV6NAT bool) (Router, error) {
	r := &linuxRouter{
		logf:          logf,
		tunname:       tunname,
		netfilterMode: netfilterOff,
		linkMon:       linkMon,

		v6Available:    supportsV6,
		v6NATAvailable: supportsV6NAT,

		ipt4: netfilter4,
		ipt6: netfilter6,
		cmd:  cmd,

		ipRuleFixLimiter: rate.NewLimiter(rate.Every(5*time.Second), 10),
		ipPolicyPrefBase: 5200,
	}
	if r.useIPCommand() {
		r.ipRuleAvailable = (cmd.run("ip", "rule") == nil)
	} else {
		if rules, err := netlink.RuleList(netlink.FAMILY_V4); err != nil {
			r.logf("error querying IP rules (does kernel have IP_MULTIPLE_TABLES?): %v", err)
			r.logf("warning: running without policy routing")
		} else {
			r.logf("[v1] policy routing available; found %d rules", len(rules))
			r.ipRuleAvailable = true
		}
	}

	// To be a good denizen of the 4-byte 'fwmark' bitspace on every packet, we try to
	// only use the third byte. However, support for masking to part of the fwmark bitspace
	// was only added to busybox in 1.33.0. As such, we want to detect older versions and
	// not issue such a stanza.
	var err error
	if r.fwmaskWorks, err = ipCmdSupportsFwmask(); err != nil {
		r.logf("failed to determine ip command fwmask support: %v", err)
	}
	if r.fwmaskWorks {
		r.logf("[v1] ip command supports fwmark masks")
	} else {
		r.logf("[v1] ip command does NOT support fwmark masks")
	}

	// A common installation of OpenWRT involves use of the 'mwan3' package.
	// This package installs ip-tables rules like:
	//  -A mwan3_fallback_policy -m mark --mark 0x0/0x3f00 -j MARK --set-xmark 0x100/0x3f00
	//
	// which coupled with an ip rule:
	//  2001: from all fwmark 0x100/0x3f00 lookup 1
	//
	// has the effect of gobbling tailscale packets, because tailscale by default installs
	// its policy routing rules at priority 52xx.
	//
	// As such, if we are running on openWRT, detect a mwan3 config, AND detect a rule
	// with a preference 2001 (corresponding to the first interface wman3 manages), we
	// shift the priority of our policies to 13xx. This effectively puts us between mwan3's
	// permit-by-src-ip rules and mwan3 lookup of its own routing table which would drop
	// the packet.
	isMWAN3, err := checkOpenWRTUsingMWAN3()
	if err != nil {
		r.logf("error checking mwan3 installation: %v", err)
	} else if isMWAN3 {
		r.ipPolicyPrefBase = 1300
		r.logf("mwan3 on openWRT detected, switching policy base priority to 1300")
	}

	return r, nil
}

// ipCmdSupportsFwmask returns true if the system 'ip' binary supports using a
// fwmark stanza with a mask specified. To our knowledge, everything except busybox
// pre-1.33 supports this.
func ipCmdSupportsFwmask() (bool, error) {
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		return false, fmt.Errorf("lookpath: %v", err)
	}
	stat, err := os.Lstat(ipPath)
	if err != nil {
		return false, fmt.Errorf("lstat: %v", err)
	}
	if stat.Mode()&os.ModeSymlink == 0 {
		// Not a symlink, so can't be busybox. Must be regular ip utility.
		return true, nil
	}

	linkDest, err := os.Readlink(ipPath)
	if err != nil {
		return false, err
	}
	if !strings.Contains(strings.ToLower(linkDest), "busybox") {
		// Not busybox, presumably supports fwmark masks.
		return true, nil
	}

	// If we got this far, the ip utility is a busybox version with an
	// unknown version.
	// We run `ip --version` and look for the busybox banner (which
	// is a stable 'BusyBox vX.Y.Z (<builddate>)' string) to determine
	// the version.
	out, err := exec.Command("ip", "--version").CombinedOutput()
	if err != nil {
		return false, err
	}
	major, minor, _, err := busyboxParseVersion(string(out))
	if err != nil {
		return false, nil
	}

	// Support for masks added in 1.33.0.
	switch {
	case major > 1:
		return true, nil
	case major == 1 && minor >= 33:
		return true, nil
	default:
		return false, nil
	}
}

func busyboxParseVersion(output string) (major, minor, patch int, err error) {
	bannerStart := strings.Index(output, "BusyBox v")
	if bannerStart < 0 {
		return 0, 0, 0, errors.New("missing BusyBox banner")
	}
	bannerEnd := bannerStart + len("BusyBox v")

	end := strings.Index(output[bannerEnd:], " ")
	if end < 0 {
		return 0, 0, 0, errors.New("missing end delimiter")
	}

	elements := strings.Split(output[bannerEnd:bannerEnd+end], ".")
	if len(elements) < 3 {
		return 0, 0, 0, fmt.Errorf("expected 3 version elements, got %d", len(elements))
	}

	if major, err = strconv.Atoi(elements[0]); err != nil {
		return 0, 0, 0, fmt.Errorf("parsing major: %v", err)
	}
	if minor, err = strconv.Atoi(elements[1]); err != nil {
		return 0, 0, 0, fmt.Errorf("parsing minor: %v", err)
	}
	if patch, err = strconv.Atoi(elements[2]); err != nil {
		return 0, 0, 0, fmt.Errorf("parsing patch: %v", err)
	}
	return major, minor, patch, nil
}

func useAmbientCaps() bool {
	if distro.Get() != distro.Synology {
		return false
	}
	return distro.DSMVersion() >= 7
}

var forceIPCommand = envknob.RegisterBool("TS_DEBUG_USE_IP_COMMAND")

// useIPCommand reports whether r should use the "ip" command (or its
// fake commandRunner for tests) instead of netlink.
func (r *linuxRouter) useIPCommand() bool {
	if r.cmd == nil {
		panic("invalid init")
	}
	if forceIPCommand() {
		return true
	}
	// In the future we might need to fall back to using the "ip"
	// command if, say, netlink is blocked somewhere but the ip
	// command is allowed to use netlink. For now we only use the ip
	// command runner in tests.
	_, ok := r.cmd.(osCommandRunner)
	return !ok
}

// onIPRuleDeleted is the callback from the link monitor for when an IP policy
// rule is deleted. See Issue 1591.
//
// If an ip rule is deleted (with pref number 52xx, as Tailscale sets), then
// set a timer to restore our rules, in case they were deleted. The timer lets
// us do one fixup in response to a batch of rule deletes. It also lets us
// delay arbitrarily to prevent a high-speed fight over the rule between
// competing processes. (Although empirically, systemd doesn't fight us
// like that... yet.)
//
// Note that we don't care about the table number. We don't strictly even care
// about the priority number. We could just do this in response to any netlink
// change. Filtering by known priority ranges cuts back on some logspam.
func (r *linuxRouter) onIPRuleDeleted(table uint8, priority uint32) {
	if int(priority) < r.ipPolicyPrefBase || int(priority) >= (r.ipPolicyPrefBase+100) {
		// Not our rule.
		return
	}
	if !r.ruleRestorePending.Swap(true) {
		// Another timer is already pending.
		return
	}
	rr := r.ipRuleFixLimiter.Reserve()
	if !rr.OK() {
		r.ruleRestorePending.Swap(false)
		return
	}
	time.AfterFunc(rr.Delay()+250*time.Millisecond, func() {
		if r.ruleRestorePending.Swap(false) && !r.closed.Load() {
			r.logf("somebody (likely systemd-networkd) deleted ip rules; restoring Tailscale's")
			r.justAddIPRules()
		}
	})
}

func (r *linuxRouter) Up() error {
	if r.unregLinkMon == nil && r.linkMon != nil {
		r.unregLinkMon = r.linkMon.RegisterRuleDeleteCallback(r.onIPRuleDeleted)
	}
	if err := r.addIPRules(); err != nil {
		return fmt.Errorf("adding IP rules: %w", err)
	}
	if err := r.setNetfilterMode(netfilterOff); err != nil {
		return fmt.Errorf("setting netfilter mode: %w", err)
	}
	if err := r.upInterface(); err != nil {
		return fmt.Errorf("bringing interface up: %w", err)
	}

	return nil
}

func (r *linuxRouter) Close() error {
	r.closed.Store(true)
	if r.unregLinkMon != nil {
		r.unregLinkMon()
	}
	if err := r.downInterface(); err != nil {
		return err
	}
	if err := r.delIPRules(); err != nil {
		return err
	}
	if err := r.setNetfilterMode(netfilterOff); err != nil {
		return err
	}
	if err := r.delRoutes(); err != nil {
		return err
	}

	r.addrs = nil
	r.routes = nil
	r.localRoutes = nil

	return nil
}

// Set implements the Router interface.
func (r *linuxRouter) Set(cfg *Config) error {
	var errs []error
	if cfg == nil {
		cfg = &shutdownConfig
	}

	if err := r.setNetfilterMode(cfg.NetfilterMode); err != nil {
		errs = append(errs, err)
	}

	newLocalRoutes, err := cidrDiff("localRoute", r.localRoutes, cfg.LocalRoutes, r.addThrowRoute, r.delThrowRoute, r.logf)
	if err != nil {
		errs = append(errs, err)
	}
	r.localRoutes = newLocalRoutes

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

	return multierr.New(errs...)
}

// setNetfilterMode switches the router to the given netfilter
// mode. Netfilter state is created or deleted appropriately to
// reflect the new mode, and r.snatSubnetRoutes is updated to reflect
// the current state of subnet SNATing.
func (r *linuxRouter) setNetfilterMode(mode preftype.NetfilterMode) error {
	if distro.Get() == distro.Synology {
		mode = netfilterOff
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
	case netfilterOff:
		switch r.netfilterMode {
		case netfilterNoDivert:
			if err := r.delNetfilterBase(); err != nil {
				return err
			}
			if err := r.delNetfilterChains(); err != nil {
				r.logf("note: %v", err)
				// harmless, continue.
				// This can happen if someone left a ref to
				// this table somewhere else.
			}
		case netfilterOn:
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
	case netfilterNoDivert:
		switch r.netfilterMode {
		case netfilterOff:
			reprocess = true
			if err := r.addNetfilterChains(); err != nil {
				return err
			}
			if err := r.addNetfilterBase(); err != nil {
				return err
			}
			r.snatSubnetRoutes = false
		case netfilterOn:
			if err := r.delNetfilterHooks(); err != nil {
				return err
			}
		}
	case netfilterOn:
		// Because of bugs in old version of iptables-compat,
		// we can't add a "-j ts-forward" rule to FORWARD
		// while ts-forward contains an "-m mark" rule. But
		// we can add the row *before* populating ts-forward.
		// So we have to delNetFilterBase, then add the hooks,
		// then re-addNetFilterBase, just in case.
		switch r.netfilterMode {
		case netfilterOff:
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
		case netfilterNoDivert:
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
		if err := r.addLoopbackRule(cidr.Addr()); err != nil {
			return err
		}
	}

	return nil
}

// addAddress adds an IP/mask to the tunnel interface. Fails if the
// address is already assigned to the interface, or if the addition
// fails.
func (r *linuxRouter) addAddress(addr netip.Prefix) error {
	if !r.v6Available && addr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		if err := r.cmd.run("ip", "addr", "add", addr.String(), "dev", r.tunname); err != nil {
			return fmt.Errorf("adding address %q to tunnel interface: %w", addr, err)
		}
	} else {
		link, err := r.link()
		if err != nil {
			return fmt.Errorf("adding address %v, %w", addr, err)
		}
		if err := netlink.AddrReplace(link, nlAddrOfPrefix(addr)); err != nil {
			return fmt.Errorf("adding address %v from tunnel interface: %w", addr, err)
		}
	}
	if err := r.addLoopbackRule(addr.Addr()); err != nil {
		return err
	}
	return nil
}

// delAddress removes an IP/mask from the tunnel interface. Fails if
// the address is not assigned to the interface, or if the removal
// fails.
func (r *linuxRouter) delAddress(addr netip.Prefix) error {
	if !r.v6Available && addr.Addr().Is6() {
		return nil
	}
	if err := r.delLoopbackRule(addr.Addr()); err != nil {
		return err
	}
	if r.useIPCommand() {
		if err := r.cmd.run("ip", "addr", "del", addr.String(), "dev", r.tunname); err != nil {
			return fmt.Errorf("deleting address %q from tunnel interface: %w", addr, err)
		}
	} else {
		link, err := r.link()
		if err != nil {
			return fmt.Errorf("deleting address %v, %w", addr, err)
		}
		if err := netlink.AddrDel(link, nlAddrOfPrefix(addr)); err != nil {
			return fmt.Errorf("deleting address %v from tunnel interface: %w", addr, err)
		}
	}
	return nil
}

// addLoopbackRule adds a firewall rule to permit loopback traffic to
// a local Tailscale IP.
func (r *linuxRouter) addLoopbackRule(addr netip.Addr) error {
	if r.netfilterMode == netfilterOff {
		return nil
	}

	nf := r.ipt4
	if addr.Is6() {
		if !r.v6Available {
			// IPv6 not available, ignore.
			return nil
		}
		nf = r.ipt6
	}

	if err := nf.Insert("filter", "ts-input", 1, "-i", "lo", "-s", addr.String(), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("adding loopback allow rule for %q: %w", addr, err)
	}
	return nil
}

// delLoopbackRule removes the firewall rule permitting loopback
// traffic to a Tailscale IP.
func (r *linuxRouter) delLoopbackRule(addr netip.Addr) error {
	if r.netfilterMode == netfilterOff {
		return nil
	}

	nf := r.ipt4
	if addr.Is6() {
		if !r.v6Available {
			// IPv6 not available, ignore.
			return nil
		}
		nf = r.ipt6
	}

	if err := nf.Delete("filter", "ts-input", "-i", "lo", "-s", addr.String(), "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("deleting loopback allow rule for %q: %w", addr, err)
	}
	return nil
}

// addRoute adds a route for cidr, pointing to the tunnel
// interface. Fails if the route already exists, or if adding the
// route fails.
func (r *linuxRouter) addRoute(cidr netip.Prefix) error {
	if !r.v6Available && cidr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		return r.addRouteDef([]string{normalizeCIDR(cidr), "dev", r.tunname}, cidr)
	}
	linkIndex, err := r.linkIndex()
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: linkIndex,
		Dst:       netipx.PrefixIPNet(cidr.Masked()),
		Table:     r.routeTable(),
	})
}

// addThrowRoute adds a throw route for the provided cidr.
// This has the effect that lookup in the routing table is terminated
// pretending that no route was found. Fails if the route already exists,
// or if adding the route fails.
func (r *linuxRouter) addThrowRoute(cidr netip.Prefix) error {
	if !r.ipRuleAvailable {
		return nil
	}
	if !r.v6Available && cidr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		return r.addRouteDef([]string{"throw", normalizeCIDR(cidr)}, cidr)
	}
	err := netlink.RouteReplace(&netlink.Route{
		Dst:   netipx.PrefixIPNet(cidr.Masked()),
		Table: tailscaleRouteTable.num,
		Type:  unix.RTN_THROW,
	})
	if err != nil {
		r.logf("THROW ERROR adding %v: %#v", cidr, err)
	}
	return err
}

func (r *linuxRouter) addRouteDef(routeDef []string, cidr netip.Prefix) error {
	if !r.v6Available && cidr.Addr().Is6() {
		return nil
	}
	args := append([]string{"ip", "route", "add"}, routeDef...)
	if r.ipRuleAvailable {
		args = append(args, "table", tailscaleRouteTable.ipCmdArg())
	}
	err := r.cmd.run(args...)
	if err == nil {
		return nil
	}

	// This is an ugly hack to detect failure to add a route that
	// already exists (as happens in when we're racing to add
	// kernel-maintained routes when enabling exit nodes w/o Local
	// LAN access, Issue 3060). Fortunately in the common case we
	// use netlink directly instead and don't exercise this code.
	if errCode(err) == 2 && strings.Contains(err.Error(), "RTNETLINK answers: File exists") {
		r.logf("ignoring route add of %v; already exists", cidr)
		return nil
	}
	return err
}

var (
	errESRCH  error = syscall.ESRCH
	errENOENT error = syscall.ENOENT
	errEEXIST error = syscall.EEXIST
)

// delRoute removes the route for cidr pointing to the tunnel
// interface. Fails if the route doesn't exist, or if removing the
// route fails.
func (r *linuxRouter) delRoute(cidr netip.Prefix) error {
	if !r.v6Available && cidr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		return r.delRouteDef([]string{normalizeCIDR(cidr), "dev", r.tunname}, cidr)
	}
	linkIndex, err := r.linkIndex()
	if err != nil {
		return err
	}
	err = netlink.RouteDel(&netlink.Route{
		LinkIndex: linkIndex,
		Dst:       netipx.PrefixIPNet(cidr.Masked()),
		Table:     r.routeTable(),
	})
	if errors.Is(err, errESRCH) {
		// Didn't exist to begin with.
		return nil
	}
	return err
}

// delThrowRoute removes the throw route for the cidr. Fails if the route
// doesn't exist, or if removing the route fails.
func (r *linuxRouter) delThrowRoute(cidr netip.Prefix) error {
	if !r.ipRuleAvailable {
		return nil
	}
	if !r.v6Available && cidr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		return r.delRouteDef([]string{"throw", normalizeCIDR(cidr)}, cidr)
	}
	err := netlink.RouteDel(&netlink.Route{
		Dst:   netipx.PrefixIPNet(cidr.Masked()),
		Table: r.routeTable(),
		Type:  unix.RTN_THROW,
	})
	if errors.Is(err, errESRCH) {
		// Didn't exist to begin with.
		return nil
	}
	return err
}

func (r *linuxRouter) delRouteDef(routeDef []string, cidr netip.Prefix) error {
	if !r.v6Available && cidr.Addr().Is6() {
		return nil
	}
	args := append([]string{"ip", "route", "del"}, routeDef...)
	if r.ipRuleAvailable {
		args = append(args, "table", tailscaleRouteTable.ipCmdArg())
	}
	err := r.cmd.run(args...)
	if err != nil {
		ok, err := r.hasRoute(routeDef, cidr)
		if err != nil {
			r.logf("warning: error checking whether %v even exists after error deleting it: %v", err)
		} else {
			if !ok {
				r.logf("warning: tried to delete route %v but it was already gone; ignoring error", cidr)
				return nil
			}
		}
	}
	return err
}

func dashFam(ip netip.Addr) string {
	if ip.Is6() {
		return "-6"
	}
	return "-4"
}

func (r *linuxRouter) hasRoute(routeDef []string, cidr netip.Prefix) (bool, error) {
	args := append([]string{"ip", dashFam(cidr.Addr()), "route", "show"}, routeDef...)
	if r.ipRuleAvailable {
		args = append(args, "table", tailscaleRouteTable.ipCmdArg())
	}
	out, err := r.cmd.output(args...)
	if err != nil {
		return false, err
	}
	return len(out) > 0, nil
}

func (r *linuxRouter) link() (netlink.Link, error) {
	link, err := netlink.LinkByName(r.tunname)
	if err != nil {
		return nil, fmt.Errorf("failed to look up link %q: %w", r.tunname, err)
	}
	return link, nil
}

func (r *linuxRouter) linkIndex() (int, error) {
	// TODO(bradfitz): cache this? It doesn't change often, and on start-up
	// hundreds of addRoute calls to add /32s can happen quickly.
	link, err := r.link()
	if err != nil {
		return 0, err
	}
	return link.Attrs().Index, nil
}

// routeTable returns the route table to use.
func (r *linuxRouter) routeTable() int {
	if r.ipRuleAvailable {
		return tailscaleRouteTable.num
	}
	return 0
}

// upInterface brings up the tunnel interface.
func (r *linuxRouter) upInterface() error {
	if r.useIPCommand() {
		return r.cmd.run("ip", "link", "set", "dev", r.tunname, "up")
	}
	link, err := r.link()
	if err != nil {
		return fmt.Errorf("bringing interface up, %w", err)
	}
	return netlink.LinkSetUp(link)
}

// downInterface sets the tunnel interface administratively down.
func (r *linuxRouter) downInterface() error {
	if r.useIPCommand() {
		return r.cmd.run("ip", "link", "set", "dev", r.tunname, "down")
	}
	link, err := r.link()
	if err != nil {
		return fmt.Errorf("bringing interface down, %w", err)
	}
	return netlink.LinkSetDown(link)
}

// addrFamily is an address family: IPv4 or IPv6.
type addrFamily byte

const (
	v4 = addrFamily(4)
	v6 = addrFamily(6)
)

func (f addrFamily) dashArg() string {
	switch f {
	case 4:
		return "-4"
	case 6:
		return "-6"
	}
	panic("illegal")
}

func (f addrFamily) netlinkInt() int {
	switch f {
	case 4:
		return netlink.FAMILY_V4
	case 6:
		return netlink.FAMILY_V6
	}
	panic("illegal")
}

func (r *linuxRouter) addrFamilies() []addrFamily {
	if r.v6Available {
		return []addrFamily{v4, v6}
	}
	return []addrFamily{v4}
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

	return r.justAddIPRules()
}

// routeTable is a Linux routing table: both its name and number.
// See /etc/iproute2/rt_tables.
type routeTable struct {
	name string
	num  int
}

// ipCmdArg returns the string form of the table to pass to the "ip" command.
func (rt routeTable) ipCmdArg() string {
	if rt.num >= 253 {
		return rt.name
	}
	return strconv.Itoa(rt.num)
}

var routeTableByNumber = map[int]routeTable{}

func newRouteTable(name string, num int) routeTable {
	rt := routeTable{name, num}
	routeTableByNumber[num] = rt
	return rt
}

func mustRouteTable(num int) routeTable {
	rt, ok := routeTableByNumber[num]
	if !ok {
		panic(fmt.Sprintf("unknown route table %v", num))
	}
	return rt
}

var (
	mainRouteTable    = newRouteTable("main", 254)
	defaultRouteTable = newRouteTable("default", 253)

	// tailscaleRouteTable is the routing table number for Tailscale
	// network routes. See addIPRules for the detailed policy routing
	// logic that ends up doing lookups within that table.
	//
	// NOTE(danderson): We chose 52 because those are the digits above the
	// letters "TS" on a qwerty keyboard, and 52 is sufficiently unlikely
	// to be picked by other software.
	//
	// NOTE(danderson): You might wonder why we didn't pick some
	// high table number like 5252, to further avoid the potential
	// for collisions with other software. Unfortunately,
	// Busybox's `ip` implementation believes that table numbers
	// are 8-bit integers, so for maximum compatibility we had to
	// stay in the 0-255 range even though linux itself supports
	// larger numbers. (but nowadays we use netlink directly and
	// aren't affected by the busybox binary's limitations)
	tailscaleRouteTable = newRouteTable("tailscale", 52)
)

// ipRules are the policy routing rules that Tailscale uses.
// The priority is the value represented here added to r.ipPolicyPrefBase,
// which is usually 5200.
//
// NOTE(apenwarr): We leave spaces between each pref number.
// This is so the sysadmin can override by inserting rules in
// between if they want.
//
// NOTE(apenwarr): This sequence seems complicated, right?
// If we could simply have a rule that said "match packets that
// *don't* have this fwmark", then we would only need to add one
// link to table 52 and we'd be done. Unfortunately, older kernels
// and 'ip rule' implementations (including busybox), don't support
// checking for the lack of a fwmark, only the presence. The technique
// below works even on very old kernels.
var ipRules = []netlink.Rule{
	// Packets from us, tagged with our fwmark, first try the kernel's
	// main routing table.
	{
		Priority: 10,
		Mark:     tailscaleBypassMarkNum,
		Table:    mainRouteTable.num,
	},
	// ...and then we try the 'default' table, for correctness,
	// even though it's been empty on every Linux system I've ever seen.
	{
		Priority: 30,
		Mark:     tailscaleBypassMarkNum,
		Table:    defaultRouteTable.num,
	},
	// If neither of those matched (no default route on this system?)
	// then packets from us should be aborted rather than falling through
	// to the tailscale routes, because that would create routing loops.
	{
		Priority: 50,
		Mark:     tailscaleBypassMarkNum,
		Type:     unix.RTN_UNREACHABLE,
	},
	// If we get to this point, capture all packets and send them
	// through to the tailscale route table. For apps other than us
	// (ie. with no fwmark set), this is the first routing table, so
	// it takes precedence over all the others, ie. VPN routes always
	// beat non-VPN routes.
	{
		Priority: 70,
		Table:    tailscaleRouteTable.num,
	},
	// If that didn't match, then non-fwmark packets fall through to the
	// usual rules (pref 32766 and 32767, ie. main and default).
}

// justAddIPRules adds policy routing rule without deleting any first.
func (r *linuxRouter) justAddIPRules() error {
	if !r.ipRuleAvailable {
		return nil
	}
	if r.useIPCommand() {
		return r.addIPRulesWithIPCommand()
	}
	var errAcc error
	for _, family := range r.addrFamilies() {

		for _, ru := range ipRules {
			// Note: r is a value type here; safe to mutate it.
			ru.Family = family.netlinkInt()
			if ru.Mark != 0 {
				ru.Mask = tailscaleFwmarkMaskNum
			}
			ru.Goto = -1
			ru.SuppressIfgroup = -1
			ru.SuppressPrefixlen = -1
			ru.Flow = -1
			ru.Priority += r.ipPolicyPrefBase

			err := netlink.RuleAdd(&ru)
			if errors.Is(err, errEEXIST) {
				// Ignore dups.
				continue
			}
			if err != nil && errAcc == nil {
				errAcc = err
			}
		}
	}
	return errAcc
}

func (r *linuxRouter) addIPRulesWithIPCommand() error {
	rg := newRunGroup(nil, r.cmd)

	for _, family := range r.addrFamilies() {
		for _, rule := range ipRules {
			args := []string{
				"ip", family.dashArg(),
				"rule", "add",
				"pref", strconv.Itoa(rule.Priority + r.ipPolicyPrefBase),
			}
			if rule.Mark != 0 {
				if r.fwmaskWorks {
					args = append(args, "fwmark", fmt.Sprintf("0x%x/%s", rule.Mark, tailscaleFwmarkMask))
				} else {
					args = append(args, "fwmark", fmt.Sprintf("0x%x", rule.Mark))
				}
			}
			if rule.Table != 0 {
				args = append(args, "table", mustRouteTable(rule.Table).ipCmdArg())
			}
			if rule.Type == unix.RTN_UNREACHABLE {
				args = append(args, "type", "unreachable")
			}
			rg.Run(args...)
		}
	}

	return rg.ErrAcc
}

// delRoutes removes any local routes that we added that would not be
// cleaned up on interface down.
func (r *linuxRouter) delRoutes() error {
	for rt := range r.localRoutes {
		if err := r.delThrowRoute(rt); err != nil {
			r.logf("failed to delete throw route(%q): %v", rt, err)
		}
	}
	return nil
}

// delIPRules removes the policy routing rules that avoid
// tailscaled routing loops, if it exists.
func (r *linuxRouter) delIPRules() error {
	if !r.ipRuleAvailable {
		return nil
	}
	if r.useIPCommand() {
		return r.delIPRulesWithIPCommand()
	}
	var errAcc error
	for _, family := range r.addrFamilies() {
		for _, ru := range ipRules {
			// Note: r is a value type here; safe to mutate it.
			// When deleting rules, we want to be a bit specific (mention which
			// table we were routing to) but not *too* specific (fwmarks, etc).
			// That leaves us some flexibility to change these values in later
			// versions without having ongoing hacks for every possible
			// combination.
			ru.Family = family.netlinkInt()
			ru.Mark = -1
			ru.Mask = -1
			ru.Goto = -1
			ru.SuppressIfgroup = -1
			ru.SuppressPrefixlen = -1
			ru.Priority += r.ipPolicyPrefBase

			err := netlink.RuleDel(&ru)
			if errors.Is(err, errENOENT) {
				// Didn't exist to begin with.
				continue
			}
			if err != nil && errAcc == nil {
				errAcc = err
			}
		}
	}
	return errAcc
}

func (r *linuxRouter) delIPRulesWithIPCommand() error {
	// Error codes: 'ip rule' returns error code 2 if the rule is a
	// duplicate (add) or not found (del). It returns a different code
	// for syntax errors. This is also true of busybox.
	//
	// Some older versions of iproute2 also return error code 254 for
	// unknown rules during deletion.
	rg := newRunGroup([]int{2, 254}, r.cmd)

	for _, family := range r.addrFamilies() {
		// When deleting rules, we want to be a bit specific (mention which
		// table we were routing to) but not *too* specific (fwmarks, etc).
		// That leaves us some flexibility to change these values in later
		// versions without having ongoing hacks for every possible
		// combination.
		for _, rule := range ipRules {
			args := []string{
				"ip", family.dashArg(),
				"rule", "del",
				"pref", strconv.Itoa(rule.Priority + r.ipPolicyPrefBase),
			}
			if rule.Table != 0 {
				args = append(args, "table", mustRouteTable(rule.Table).ipCmdArg())
			} else {
				args = append(args, "type", "unreachable")
			}
			rg.Run(args...)
		}
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
	args = []string{"-i", r.tunname, "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark + "/" + tailscaleFwmarkMask}
	if err := r.ipt4.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v4/filter/ts-forward: %w", args, err)
	}
	args = []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark + "/" + tailscaleFwmarkMask, "-j", "ACCEPT"}
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

	args := []string{"-i", r.tunname, "-j", "MARK", "--set-mark", tailscaleSubnetRouteMark + "/" + tailscaleFwmarkMask}
	if err := r.ipt6.Append("filter", "ts-forward", args...); err != nil {
		return fmt.Errorf("adding %v in v6/filter/ts-forward: %w", args, err)
	}
	args = []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark + "/" + tailscaleFwmarkMask, "-j", "ACCEPT"}
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
	if r.netfilterMode == netfilterOff {
		return nil
	}

	args := []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark + "/" + tailscaleFwmarkMask, "-j", "MASQUERADE"}
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
	if r.netfilterMode == netfilterOff {
		return nil
	}

	args := []string{"-m", "mark", "--mark", tailscaleSubnetRouteMark + "/" + tailscaleFwmarkMask, "-j", "MASQUERADE"}
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

// cidrDiff calls add and del as needed to make the set of prefixes in
// old and new match. Returns a map reflecting the actual new state
// (which may be somewhere in between old and new if some commands
// failed), and any error encountered while reconfiguring.
func cidrDiff(kind string, old map[netip.Prefix]bool, new []netip.Prefix, add, del func(netip.Prefix) error, logf logger.Logf) (map[netip.Prefix]bool, error) {
	newMap := make(map[netip.Prefix]bool, len(new))
	for _, cidr := range new {
		newMap[cidr] = true
	}

	// ret starts out as a copy of old, and updates as we
	// add/delete. That way we can always return it and have it be the
	// true state of what we've done so far.
	ret := make(map[netip.Prefix]bool, len(old))
	for cidr := range old {
		ret[cidr] = true
	}

	// We want to add before we delete, so that if there is no overlap, we don't
	// end up in a state where we have no addresses on an interface as that
	// results in other kernel entities (like routes) pointing to that interface
	// to also be deleted.
	var addFail []error
	for cidr := range newMap {
		if old[cidr] {
			continue
		}
		if err := add(cidr); err != nil {
			logf("%s add failed: %v", kind, err)
			addFail = append(addFail, err)
		} else {
			ret[cidr] = true
		}
	}

	if len(addFail) == 1 {
		return ret, addFail[0]
	}
	if len(addFail) > 0 {
		return ret, fmt.Errorf("%d add %s failures; first was: %w", len(addFail), kind, addFail[0])
	}

	var delFail []error
	for cidr := range old {
		if newMap[cidr] {
			continue
		}
		if err := del(cidr); err != nil {
			logf("%s del failed: %v", kind, err)
			delFail = append(delFail, err)
		} else {
			delete(ret, cidr)
		}
	}
	if len(delFail) == 1 {
		return ret, delFail[0]
	}
	if len(delFail) > 0 {
		return ret, fmt.Errorf("%d delete %s failures; first was: %w", len(delFail), kind, delFail[0])
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
func normalizeCIDR(cidr netip.Prefix) string {
	return cidr.Masked().String()
}

func cleanup(logf logger.Logf, interfaceName string) {
	// TODO(dmytro): clean up iptables.
}

// checkIPv6 checks whether the system appears to have a working IPv6
// network stack. It returns an error explaining what looks wrong or
// missing.  It does not check that IPv6 is currently functional or
// that there's a global address, just that the system would support
// IPv6 if it were on an IPv6 network.
func checkIPv6(logf logger.Logf) error {
	_, err := os.Stat("/proc/sys/net/ipv6")
	if os.IsNotExist(err) {
		return err
	}
	bs, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if err != nil {
		// Be conservative if we can't find the ipv6 configuration knob.
		return err
	}
	disabled, err := strconv.ParseBool(strings.TrimSpace(string(bs)))
	if err != nil {
		return errors.New("disable_ipv6 has invalid bool")
	}
	if disabled {
		return errors.New("disable_ipv6 is set")
	}

	// Older kernels don't support IPv6 policy routing. Some kernels
	// support policy routing but don't have this knob, so absence of
	// the knob is not fatal.
	bs, err = os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_policy")
	if err == nil {
		disabled, err = strconv.ParseBool(strings.TrimSpace(string(bs)))
		if err != nil {
			return errors.New("disable_policy has invalid bool")
		}
		if disabled {
			return errors.New("disable_policy is set")
		}
	}

	if err := checkIPRuleSupportsV6(logf); err != nil {
		return fmt.Errorf("kernel doesn't support IPv6 policy routing: %w", err)
	}

	// Some distros ship ip6tables separately from iptables.
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return err
	}

	return nil
}

// supportsV6NAT returns whether the system has a "nat" table in the
// IPv6 netfilter stack.
//
// The nat table was added after the initial release of ipv6
// netfilter, so some older distros ship a kernel that can't NAT IPv6
// traffic.
func supportsV6NAT() bool {
	bs, err := os.ReadFile("/proc/net/ip6_tables_names")
	if err != nil {
		// Can't read the file. Assume SNAT works.
		return true
	}
	if bytes.Contains(bs, []byte("nat\n")) {
		return true
	}
	// In nftables mode, that proc file will be empty. Try another thing:
	if exec.Command("modprobe", "ip6table_nat").Run() == nil {
		return true
	}
	return false
}

func checkIPRuleSupportsV6(logf logger.Logf) error {
	// First try just a read-only operation to ideally avoid
	// having to modify any state.
	if rules, err := netlink.RuleList(netlink.FAMILY_V6); err != nil {
		return fmt.Errorf("querying IPv6 policy routing rules: %w", err)
	} else {
		if len(rules) > 0 {
			logf("[v1] kernel supports IPv6 policy routing (found %d rules)", len(rules))
			return nil
		}
	}

	// Try to actually create & delete one as a test.
	rule := netlink.NewRule()
	rule.Priority = 1234
	rule.Mark = tailscaleBypassMarkNum
	rule.Table = tailscaleRouteTable.num
	rule.Family = netlink.FAMILY_V6
	// First delete the rule unconditionally, and don't check for
	// errors. This is just cleaning up anything that might be already
	// there.
	netlink.RuleDel(rule)
	// And clean up on exit.
	defer netlink.RuleDel(rule)
	return netlink.RuleAdd(rule)
}

// Checks if the running openWRT system is using mwan3, based on the heuristic
// of the config file being present as well as a policy rule with a specific
// priority (2000 + 1 - first interface mwan3 manages) and non-zero mark.
func checkOpenWRTUsingMWAN3() (bool, error) {
	if distro.Get() != distro.OpenWrt {
		return false, nil
	}

	if _, err := os.Stat("/etc/config/mwan3"); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		// We want to match on a rule like this:
		//    2001:	from all fwmark 0x100/0x3f00 lookup 1
		//
		// We dont match on the mask because it can vary, or the
		// table because I'm not sure if it can vary.
		if r.Priority >= 2001 && r.Priority <= 2004 && r.Mark != 0 {
			return true, nil
		}
	}

	return false, nil
}

func nlAddrOfPrefix(p netip.Prefix) *netlink.Addr {
	return &netlink.Addr{
		IPNet: netipx.PrefixIPNet(p),
	}
}
