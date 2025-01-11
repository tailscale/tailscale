// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
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

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/time/rate"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/types/preftype"
	"tailscale.com/util/linuxfw"
	"tailscale.com/util/multierr"
	"tailscale.com/version/distro"
)

var getDistroFunc = distro.Get

const (
	netfilterOff      = preftype.NetfilterOff
	netfilterNoDivert = preftype.NetfilterNoDivert
	netfilterOn       = preftype.NetfilterOn
)

type linuxRouter struct {
	closed            atomic.Bool
	logf              func(fmt string, args ...any)
	tunname           string
	netMon            *netmon.Monitor
	health            *health.Tracker
	unregNetMon       func()
	addrs             map[netip.Prefix]bool
	routes            map[netip.Prefix]bool
	localRoutes       map[netip.Prefix]bool
	snatSubnetRoutes  bool
	statefulFiltering bool
	netfilterMode     preftype.NetfilterMode
	netfilterKind     string

	// ruleRestorePending is whether a timer has been started to
	// restore deleted ip rules.
	ruleRestorePending atomic.Bool
	ipRuleFixLimiter   *rate.Limiter

	// Various feature checks for the network stack.
	ipRuleAvailable bool     // whether kernel was built with IP_MULTIPLE_TABLES
	v6Available     bool     // whether the kernel supports IPv6
	fwmaskWorksLazy opt.Bool // whether we can use 'ip rule...fwmark <mark>/<mask>'; set lazily

	// ipPolicyPrefBase is the base priority at which ip rules are installed.
	ipPolicyPrefBase int

	cmd commandRunner
	nfr linuxfw.NetfilterRunner

	magicsockPortV4 uint16
	magicsockPortV6 uint16
}

func newUserspaceRouter(logf logger.Logf, tunDev tun.Device, netMon *netmon.Monitor, health *health.Tracker) (Router, error) {
	tunname, err := tunDev.Name()
	if err != nil {
		return nil, err
	}

	cmd := osCommandRunner{
		ambientCapNetAdmin: useAmbientCaps(),
	}

	return newUserspaceRouterAdvanced(logf, tunname, netMon, cmd, health)
}

func newUserspaceRouterAdvanced(logf logger.Logf, tunname string, netMon *netmon.Monitor, cmd commandRunner, health *health.Tracker) (Router, error) {
	r := &linuxRouter{
		logf:          logf,
		tunname:       tunname,
		netfilterMode: netfilterOff,
		netMon:        netMon,
		health:        health,

		cmd: cmd,

		ipRuleFixLimiter: rate.NewLimiter(rate.Every(5*time.Second), 10),
		ipPolicyPrefBase: 5200,
	}
	if r.useIPCommand() {
		r.ipRuleAvailable = (cmd.run("ip", "rule") == nil)
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

	r.v6Available = linuxfw.CheckIPv6(r.logf) == nil

	r.fixupWSLMTU()

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
	if getDistroFunc() != distro.Synology {
		return false
	}
	return distro.DSMVersion() >= 7
}

var forceIPCommand = envknob.RegisterBool("TS_DEBUG_USE_IP_COMMAND")

// useIPCommand reports whether r should use the "ip" command (or its
// fake commandRunner for tests) instead of netlink.
func (r *linuxRouter) useIPCommand() bool {
	return true
}

// fwmaskWorks reports whether we can use 'ip rule...fwmark <mark>/<mask>'.
// This is computed lazily on first use. By default, we don't run the "ip"
// command, so never actually runs this. But the "ip" command is used in tests
// and can be forced. (see useIPCommand)
func (r *linuxRouter) fwmaskWorks() bool {
	if v, ok := r.fwmaskWorksLazy.Get(); ok {
		return v
	}
	// To be a good denizen of the 4-byte 'fwmark' bitspace on every packet, we try to
	// only use the third byte. However, support for masking to part of the fwmark bitspace
	// was only added to busybox in 1.33.0. As such, we want to detect older versions and
	// not issue such a stanza.
	v, err := ipCmdSupportsFwmask()
	if err != nil {
		r.logf("failed to determine ip command fwmask support: %v", err)
	}
	r.fwmaskWorksLazy.Set(v)
	if v {
		r.logf("[v1] ip command supports fwmark masks")
	} else {
		r.logf("[v1] ip command does NOT support fwmark masks")
	}
	return v
}

// onIPRuleDeleted is the callback from the network monitor for when an IP
// policy rule is deleted. See Issue 1591.
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
	if r.ruleRestorePending.Swap(true) {
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
	if r.unregNetMon == nil && r.netMon != nil {
		r.unregNetMon = r.netMon.RegisterRuleDeleteCallback(r.onIPRuleDeleted)
	}
	if err := r.setNetfilterMode(netfilterOff); err != nil {
		return fmt.Errorf("setting netfilter mode: %w", err)
	}
	if err := r.addIPRules(); err != nil {
		return fmt.Errorf("adding IP rules: %w", err)
	}
	if err := r.upInterface(); err != nil {
		return fmt.Errorf("bringing interface up: %w", err)
	}

	return nil
}

func (r *linuxRouter) Close() error {
	r.closed.Store(true)
	if r.unregNetMon != nil {
		r.unregNetMon()
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

// setupNetfilter initializes the NetfilterRunner in r.nfr. It expects r.nfr
// to be nil, or the current netfilter to be set to netfilterOff.
// kind should be either a linuxfw.FirewallMode, or the empty string for auto.
func (r *linuxRouter) setupNetfilter(kind string) error {
	r.netfilterKind = kind

	var err error
	r.nfr, err = linuxfw.New(r.logf, r.netfilterKind)
	if err != nil {
		return fmt.Errorf("could not create new netfilter: %w", err)
	}

	return nil
}

// Set implements the Router interface.
func (r *linuxRouter) Set(cfg *Config) error {
	var errs []error
	if cfg == nil {
		cfg = &shutdownConfig
	}

	if cfg.NetfilterKind != r.netfilterKind {
		if err := r.setNetfilterMode(netfilterOff); err != nil {
			err = fmt.Errorf("could not disable existing netfilter: %w", err)
			errs = append(errs, err)
		} else {
			r.nfr = nil
			if err := r.setupNetfilter(cfg.NetfilterKind); err != nil {
				errs = append(errs, err)
			}
		}
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

	// Ensure that the SNAT rule is added or removed as needed.
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

	// As above, for stateful filtering
	switch {
	case cfg.StatefulFiltering == r.statefulFiltering:
		// state already correct, nothing to do.
	case cfg.StatefulFiltering:
		if err := r.addStatefulRule(); err != nil {
			errs = append(errs, err)
		}
	default:
		if err := r.delStatefulRule(); err != nil {
			errs = append(errs, err)
		}
	}
	r.statefulFiltering = cfg.StatefulFiltering
	r.updateStatefulFilteringWithDockerWarning(cfg)

	// Issue 11405: enable IP forwarding on gokrazy.
	advertisingRoutes := len(cfg.SubnetRoutes) > 0
	if getDistroFunc() == distro.Gokrazy && advertisingRoutes {
		r.enableIPForwarding()
	}

	return multierr.New(errs...)
}

var dockerStatefulFilteringWarnable = health.Register(&health.Warnable{
	Code:     "docker-stateful-filtering",
	Title:    "Docker with stateful filtering",
	Severity: health.SeverityMedium,
	Text:     health.StaticMessage("Stateful filtering is enabled and Docker was detected; this may prevent Docker containers on this host from resolving DNS and connecting to Tailscale nodes. See https://tailscale.com/s/stateful-docker"),
})

func (r *linuxRouter) updateStatefulFilteringWithDockerWarning(cfg *Config) {
	// If stateful filtering is disabled, clear the warning.
	if !r.statefulFiltering {
		r.health.SetHealthy(dockerStatefulFilteringWarnable)
		return
	}

	advertisingRoutes := len(cfg.SubnetRoutes) > 0

	// TODO(andrew-d,maisem): we might want to check if we're running in a
	// container, since, if so, stateful filtering might prevent other
	// containers from connecting through the Tailscale in this container.
	//
	// For now, just check for the case where we're running Tailscale on
	// the host and Docker is also running.

	// If this node isn't a subnet router or exit node, then we would never
	// have allowed traffic from a Docker container in to Tailscale, since
	// there wouldn't be an AllowedIP for the container's source IP. So we
	// don't need to warn in this case.
	//
	// cfg.SubnetRoutes contains all subnet routes for the node, including
	// the default route (0.0.0.0/0 or ::/0) if this node is an exit node.
	if advertisingRoutes {
		// Check for the presence of a Docker interface and warn if it's found
		// on the system.
		//
		// TODO(andrew-d): do a better job at detecting Docker, e.g. by looking
		// for it in the $PATH or by checking for the presence of the Docker
		// socket/daemon/etc.
		ifstate := r.netMon.InterfaceState()
		if _, found := ifstate.Interface["docker0"]; found {
			r.health.SetUnhealthy(dockerStatefulFilteringWarnable, nil)
			return
		}
	}

	// If we get here, then we have no warnings; clear anything existing.
	r.health.SetHealthy(dockerStatefulFilteringWarnable)
}

// UpdateMagicsockPort implements the Router interface.
func (r *linuxRouter) UpdateMagicsockPort(port uint16, network string) error {
	if r.nfr == nil {
		if err := r.setupNetfilter(r.netfilterKind); err != nil {
			return fmt.Errorf("could not setup netfilter: %w", err)
		}
	}

	var magicsockPort *uint16
	switch network {
	case "udp4":
		magicsockPort = &r.magicsockPortV4
	case "udp6":
		// Skip setting up MagicSock port if the host does not support
		// IPv6. MagicSock IPv6 port needs a filter rule to function. In
		// some cases (hosts with partial iptables support) filter
		// tables are not supported, so skip setting up the port for
		// those hosts too.
		if !r.getV6FilteringAvailable() {
			return nil
		}
		magicsockPort = &r.magicsockPortV6
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	// set the port, we'll make the firewall rule when netfilter turns back on
	if r.netfilterMode == netfilterOff {
		*magicsockPort = port
		return nil
	}

	if *magicsockPort == port {
		return nil
	}

	if *magicsockPort != 0 {
		if err := r.nfr.DelMagicsockPortRule(*magicsockPort, network); err != nil {
			return fmt.Errorf("del magicsock port rule: %w", err)
		}
	}

	if port != 0 {
		if err := r.nfr.AddMagicsockPortRule(*magicsockPort, network); err != nil {
			return fmt.Errorf("add magicsock port rule: %w", err)
		}
	}

	*magicsockPort = port
	return nil
}

// setNetfilterMode switches the router to the given netfilter
// mode. Netfilter state is created or deleted appropriately to
// reflect the new mode, and r.snatSubnetRoutes is updated to reflect
// the current state of subnet SNATing.
func (r *linuxRouter) setNetfilterMode(mode preftype.NetfilterMode) error {
	if !platformCanNetfilter() {
		mode = netfilterOff
	}

	if r.nfr == nil {
		var err error
		r.nfr, err = linuxfw.New(r.logf, r.netfilterKind)
		if err != nil {
			return err
		}
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
			if err := r.nfr.DelBase(); err != nil {
				return err
			}
			if err := r.nfr.DelChains(); err != nil {
				r.logf("note: %v", err)
				// harmless, continue.
				// This can happen if someone left a ref to
				// this table somewhere else.
			}
		case netfilterOn:
			if err := r.nfr.DelHooks(r.logf); err != nil {
				return err
			}
			if err := r.nfr.DelBase(); err != nil {
				return err
			}
			if err := r.nfr.DelChains(); err != nil {
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
			if err := r.nfr.AddChains(); err != nil {
				return err
			}
			if err := r.nfr.AddBase(r.tunname); err != nil {
				return err
			}
			if r.magicsockPortV4 != 0 {
				if err := r.nfr.AddMagicsockPortRule(r.magicsockPortV4, "udp4"); err != nil {
					return fmt.Errorf("could not add magicsock port rule v4: %w", err)
				}
			}
			if r.magicsockPortV6 != 0 && r.getV6FilteringAvailable() {
				if err := r.nfr.AddMagicsockPortRule(r.magicsockPortV6, "udp6"); err != nil {
					return fmt.Errorf("could not add magicsock port rule v6: %w", err)
				}
			}
			r.snatSubnetRoutes = false
		case netfilterOn:
			if err := r.nfr.DelHooks(r.logf); err != nil {
				return err
			}
		}
	case netfilterOn:
		// Because of bugs in old version of iptables-compat,
		// we can't add a "-j ts-forward" rule to FORWARD
		// while ts-forward contains an "-m mark" rule. But
		// we can add the row *before* populating ts-forward.
		// So we have to delBase, then add the hooks,
		// then re-addBase, just in case.
		switch r.netfilterMode {
		case netfilterOff:
			reprocess = true
			if err := r.nfr.AddChains(); err != nil {
				return err
			}
			if err := r.nfr.DelBase(); err != nil {
				return err
			}
			// AddHooks adds the ts loopback rule.
			if err := r.nfr.AddHooks(); err != nil {
				return err
			}
			// AddBase adds base ts rules
			if err := r.nfr.AddBase(r.tunname); err != nil {
				return err
			}
			if r.magicsockPortV4 != 0 {
				if err := r.nfr.AddMagicsockPortRule(r.magicsockPortV4, "udp4"); err != nil {
					return fmt.Errorf("could not add magicsock port rule v4: %w", err)
				}
			}
			if r.magicsockPortV6 != 0 && r.getV6FilteringAvailable() {
				if err := r.nfr.AddMagicsockPortRule(r.magicsockPortV6, "udp6"); err != nil {
					return fmt.Errorf("could not add magicsock port rule v6: %w", err)
				}
			}
			r.snatSubnetRoutes = false
		case netfilterNoDivert:
			reprocess = true
			if err := r.nfr.DelBase(); err != nil {
				return err
			}
			if err := r.nfr.AddHooks(); err != nil {
				return err
			}
			if err := r.nfr.AddBase(r.tunname); err != nil {
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
			return fmt.Errorf("error adding loopback rule: %w", err)
		}
	}

	return nil
}

// getV6FilteringAvailable returns true if the router is able to setup the
// required tailscale filter rules for IPv6.
func (r *linuxRouter) getV6FilteringAvailable() bool {
	return r.nfr.HasIPV6() && r.nfr.HasIPV6Filter()
}

// getV6Available returns true if the host supports IPv6.
func (r *linuxRouter) getV6Available() bool {
	return r.nfr.HasIPV6()
}

// addAddress adds an IP/mask to the tunnel interface. Fails if the
// address is already assigned to the interface, or if the addition
// fails.
func (r *linuxRouter) addAddress(addr netip.Prefix) error {
	if !r.getV6Available() && addr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		if err := r.cmd.run("ip", "addr", "add", addr.String(), "dev", r.tunname); err != nil {
			return fmt.Errorf("adding address %q to tunnel interface: %w", addr, err)
		}
	} else {
		panic("lanscaping")
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
	if !r.getV6Available() && addr.Addr().Is6() {
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
		panic("lanscaping")
	}
	return nil
}

// addLoopbackRule adds a firewall rule to permit loopback traffic to
// a local Tailscale IP.
func (r *linuxRouter) addLoopbackRule(addr netip.Addr) error {
	if r.netfilterMode == netfilterOff {
		return nil
	}
	if addr.Is6() && !r.nfr.HasIPV6Filter() {
		return nil
	}

	if err := r.nfr.AddLoopbackRule(addr); err != nil {
		return err
	}
	return nil
}

// delLoopbackRule removes the firewall rule permitting loopback
// traffic to a Tailscale IP.
func (r *linuxRouter) delLoopbackRule(addr netip.Addr) error {
	if r.netfilterMode == netfilterOff {
		return nil
	}
	if addr.Is6() && !r.nfr.HasIPV6Filter() {
		return nil
	}

	if err := r.nfr.DelLoopbackRule(addr); err != nil {
		return err
	}
	return nil
}

// addRoute adds a route for cidr, pointing to the tunnel
// interface. Fails if the route already exists, or if adding the
// route fails.
func (r *linuxRouter) addRoute(cidr netip.Prefix) error {
	if !r.getV6Available() && cidr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		return r.addRouteDef([]string{normalizeCIDR(cidr), "dev", r.tunname}, cidr)
	}
	panic("lanscaping")
}

// addThrowRoute adds a throw route for the provided cidr.
// This has the effect that lookup in the routing table is terminated
// pretending that no route was found. Fails if the route already exists,
// or if adding the route fails.
func (r *linuxRouter) addThrowRoute(cidr netip.Prefix) error {
	if !r.ipRuleAvailable {
		return nil
	}
	if !r.getV6Available() && cidr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		return r.addRouteDef([]string{"throw", normalizeCIDR(cidr)}, cidr)
	}
	panic("lanscaping")
}

func (r *linuxRouter) addRouteDef(routeDef []string, cidr netip.Prefix) error {
	if !r.getV6Available() && cidr.Addr().Is6() {
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
	if !r.getV6Available() && cidr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		return r.delRouteDef([]string{normalizeCIDR(cidr), "dev", r.tunname}, cidr)
	}
	panic("lanscaping")
}

// delThrowRoute removes the throw route for the cidr. Fails if the route
// doesn't exist, or if removing the route fails.
func (r *linuxRouter) delThrowRoute(cidr netip.Prefix) error {
	if !r.ipRuleAvailable {
		return nil
	}
	if !r.getV6Available() && cidr.Addr().Is6() {
		return nil
	}
	if r.useIPCommand() {
		return r.delRouteDef([]string{"throw", normalizeCIDR(cidr)}, cidr)
	}
	panic("lanscaping")

}

func (r *linuxRouter) delRouteDef(routeDef []string, cidr netip.Prefix) error {
	if !r.getV6Available() && cidr.Addr().Is6() {
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

// routeTable returns the route table to use.
func (r *linuxRouter) routeTable() int {
	if r.ipRuleAvailable {
		return tailscaleRouteTable.Num
	}
	return 0
}

// upInterface brings up the tunnel interface.
func (r *linuxRouter) upInterface() error {
	if r.useIPCommand() {
		return r.cmd.run("ip", "link", "set", "dev", r.tunname, "up")
	}
	panic("lanscaping")

}

func (r *linuxRouter) enableIPForwarding() {
	sysctls := map[string]string{
		"net.ipv4.ip_forward":          "1",
		"net.ipv6.conf.all.forwarding": "1",
	}
	for k, v := range sysctls {
		if err := writeSysctl(k, v); err != nil {
			r.logf("warning: %v", k, v, err)
			continue
		}
		r.logf("sysctl(%v=%v): ok", k, v)
	}
}

func writeSysctl(key, val string) error {
	fn := "/proc/sys/" + strings.Replace(key, ".", "/", -1)
	if err := os.WriteFile(fn, []byte(val), 0644); err != nil {
		return fmt.Errorf("sysctl(%v=%v): %v", key, val, err)
	}
	return nil
}

// downInterface sets the tunnel interface administratively down.
func (r *linuxRouter) downInterface() error {
	if r.useIPCommand() {
		return r.cmd.run("ip", "link", "set", "dev", r.tunname, "down")
	}
	panic("lanscaping")

}

// fixupWSLMTU sets the MTU on the eth0 interface to 1360 bytes if running under
// WSL, eth0 is the default route, and has the MTU 1280 bytes.
func (r *linuxRouter) fixupWSLMTU() {
	if !distro.IsWSL() {
		return
	}

	if r.useIPCommand() {
		r.logf("fixupWSLMTU: not implemented by ip command")
		return
	}

	panic("lanscaping")
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

func (r *linuxRouter) addrFamilies() []addrFamily {
	if r.getV6Available() {
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

// RouteTable is a Linux routing table: both its name and number.
// See /etc/iproute2/rt_tables.
type RouteTable struct {
	Name string
	Num  int
}

var routeTableByNumber = map[int]RouteTable{}

// IpCmdArg returns the string form of the table to pass to the "ip" command.
func (rt RouteTable) ipCmdArg() string {
	if rt.Num >= 253 {
		return rt.Name
	}
	return strconv.Itoa(rt.Num)
}

func newRouteTable(name string, num int) RouteTable {
	rt := RouteTable{name, num}
	routeTableByNumber[num] = rt
	return rt
}

// MustRouteTable returns the RouteTable with the given number key.
// It panics if the number is unknown because this result is a part
// of IP rule argument and we don't want to continue with an invalid
// argument with table no exist.
func mustRouteTable(num int) RouteTable {
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

// justAddIPRules adds policy routing rule without deleting any first.
func (r *linuxRouter) justAddIPRules() error {
	return nil
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
	return nil
}

// addSNATRule adds a netfilter rule to SNAT traffic destined for
// local subnets.
func (r *linuxRouter) addSNATRule() error {
	if r.netfilterMode == netfilterOff {
		return nil
	}

	if err := r.nfr.AddSNATRule(); err != nil {
		return err
	}
	return nil
}

// delSNATRule removes the netfilter rule to SNAT traffic destined for
// local subnets. Fails if the rule does not exist.
func (r *linuxRouter) delSNATRule() error {
	if r.netfilterMode == netfilterOff {
		return nil
	}

	if err := r.nfr.DelSNATRule(); err != nil {
		return err
	}
	return nil
}

// addStatefulRule adds a netfilter rule to perform stateful filtering from
// subnets onto the tailnet.
func (r *linuxRouter) addStatefulRule() error {
	if r.netfilterMode == netfilterOff {
		return nil
	}

	return r.nfr.AddStatefulRule(r.tunname)
}

// delStatefulRule removes the netfilter rule to perform stateful filtering
// from subnets onto the tailnet.
func (r *linuxRouter) delStatefulRule() error {
	if r.netfilterMode == netfilterOff {
		return nil
	}

	return r.nfr.DelStatefulRule(r.tunname)
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

// normalizeCIDR returns cidr as an ip/mask string, with the host bits
// of the IP address zeroed out.
func normalizeCIDR(cidr netip.Prefix) string {
	return cidr.Masked().String()
}

// platformCanNetfilter reports whether the current distro/environment supports
// running iptables/nftables commands.
func platformCanNetfilter() bool {
	switch getDistroFunc() {
	case distro.Synology:
		// Synology doesn't support iptables or nftables. Attempting to run it
		// just blocks for a long time while it logs about failures.
		//
		// See https://github.com/tailscale/tailscale/issues/11737 for one such
		// prior regression where we tried to run iptables on Synology.
		return false
	}
	return true
}

// cleanUp removes all the rules and routes that were added by the linux router.
// The function calls cleanUp for both iptables and nftables since which ever
// netfilter runner is used, the cleanUp function for the other one doesn't do anything.
func cleanUp(logf logger.Logf, interfaceName string) {
	if interfaceName != "userspace-networking" && platformCanNetfilter() {
		linuxfw.IPTablesCleanUp(logf)
		linuxfw.NfTablesCleanUp(logf)
	}
}
