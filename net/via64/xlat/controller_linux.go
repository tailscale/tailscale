// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package xlat

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tailscale/netlink"
	"tailscale.com/net/via64"
	"tailscale.com/types/logger"
)

// Config configures a Controller.
type Config struct {
	Ingress      string // the Tailscale tun device
	RulePriority int    // priority of via64's policy rules, and RulePriority-1; must sort before Tailscale's own
	Table        int    // routing table for via64's routes, and Table+1 for replies the router fragments
	X4           netip.Addr
	NewBackend   func() (Backend, error)
	Logf         logger.Logf
	NetstackUDP  bool // translate only TCP and ICMP, leaving UDP to netstack

	// CheckInterval is how often Reassert runs; zero disables it (tests).
	CheckInterval time.Duration
}

// Controller owns the kernel 4via6 datapath: the pair, the translator, the nftables tables, routes and rules, and the via64 registry.
type Controller struct {
	cfg Config
	x   Xlat

	mu       sync.Mutex
	active   bool
	pair     Pair
	backend  Backend
	prefixes []netip.Prefix
	desired  Desired
	why      string // the last reason decide gave, so each is logged once
	failed   bool   // the last Update's install failed; Reassert waits for the next Update (a failed repair is retried at the next check)
	udpOff   bool   // UDP stays on netstack
	timeouts bool   // the kernel has conntrack timeout policies
	closed   bool
	stop     chan struct{}
}

func NewController(cfg Config) *Controller {
	return &Controller{cfg: cfg, x: Xlat{X4: cfg.X4}}
}

// Update makes the datapath match d and returns the via prefixes the kernel now translates. On any failure it tears the datapath down, so netstack keeps all 4via6, and returns the error.
func (c *Controller) Update(d Desired) ([]netip.Prefix, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil
	}
	c.desired = d
	c.failed = false
	if c.cfg.CheckInterval > 0 && c.stop == nil {
		c.stop = make(chan struct{})
		go c.watch(c.stop)
	}
	prefixes := c.decideLocked()
	if len(prefixes) == 0 {
		if !c.active {
			return nil, nil
		}
		return nil, c.teardownLocked()
	}
	if c.active && slices.Equal(prefixes, c.prefixes) && c.intactLocked() {
		return prefixes, nil
	}
	if err := c.installLocked(prefixes); err != nil {
		c.failed = true
		return nil, errors.Join(err, c.teardownLocked())
	}
	return prefixes, nil
}

// decideLocked runs decide with the current host state, logging each new reason it refuses.
func (c *Controller) decideLocked() []netip.Prefix {
	d := c.desired
	if _, why := decide(d, c.x); why == noViaRoutes { // the usual case; skip probing the host
		c.why = why
		return nil
	}
	d.ForwardingV4 = readSysctl("net/ipv4/ip_forward") == "1"
	d.ForwardingV6 = readSysctl("net/ipv6/conf/all/forwarding") == "1"
	d.Firewalld = firewalldRunning()
	d.ForwardDrop = forwardDropChain()
	prefixes, why := decide(d, c.x)
	if why != c.why && why != "" && why != noViaRoutes {
		c.cfg.Logf("via64: kernel 4via6 translation off: %s", why)
	}
	c.why = why
	return prefixes
}

// installLocked installs the datapath, or repairs it in place: flows in conntrack keep working, where handing them to netstack would reset them. Only a missing pair means starting afresh.
func (c *Controller) installLocked(prefixes []netip.Prefix) error {
	if !c.active || !c.pairIntactLocked() {
		if err := c.teardownLocked(); err != nil {
			return err
		}
		c.timeouts = ctTimeoutSupportedFunc()
		c.udpOff = c.cfg.NetstackUDP || !c.timeouts // without timeout policies UDP cannot get netstack's idle timeouts
		if !c.timeouts {
			c.cfg.Logf("via64: the kernel lacks conntrack timeout policies (CONFIG_NF_CONNTRACK_TIMEOUT); UDP stays on netstack")
		}
		p, err := createPair()
		if err != nil {
			return err
		}
		c.pair = p
		b, err := c.cfg.NewBackend()
		if err != nil {
			return err
		}
		c.backend = b
		if err := b.Install(p, c.x); err != nil {
			return fmt.Errorf("translator: %w", err)
		}
	}
	c.prefixes = prefixes
	if err := c.plumbLocked(); err != nil {
		return err
	}
	c.active = true
	via64.SetKernelHandled(prefixes, !c.udpOff) // last, once the datapath is complete
	udp := ""
	if c.udpOff {
		udp = " (UDP stays on netstack)"
	}
	c.cfg.Logf("via64: kernel 4via6 translation on for %v%s; each flow uses two of nf_conntrack_max's %s entries", prefixes, udp, readSysctl("net/netfilter/nf_conntrack_max"))
	return nil
}

// plumbLocked sets the pair up and installs whatever routes, nftables rules and policy rules are missing. Setting a device down deletes the routes through it, and the kernel refuses them again until it is up.
func (c *Controller) plumbLocked() error {
	for _, i := range []int{c.pair.PrimaryIndex, c.pair.PeerIndex} {
		l, err := netlink.LinkByIndex(i)
		if err != nil {
			return err
		}
		if l.Attrs().Flags&net.FlagUp == 0 {
			if err := netlink.LinkSetUp(l); err != nil {
				return fmt.Errorf("setting %s up: %w", l.Attrs().Name, err)
			}
		}
	}
	for _, r := range c.routes() {
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("adding route %v: %w", r.Dst, err)
		}
	}
	if err := installNAT(c.cfg.Ingress, c.prefixes, c.x, natOpts{netstackUDP: c.udpOff, timeouts: c.timeouts}); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	for _, r := range c.rules() {
		if ok, err := ruleExists(r); err != nil {
			return err
		} else if !ok {
			if err := netlink.RuleAdd(r); err != nil {
				return fmt.Errorf("adding rule to %v: %w", r.Dst, err)
			}
		}
	}
	return nil
}

func (c *Controller) routes() []*netlink.Route {
	return []*netlink.Route{
		steeringRoute(c.pair, c.cfg.Table),
		x4Route(c.pair, c.x.X4, c.cfg.Table, 0),
		x4Route(c.pair, c.x.X4, c.cfg.Table+1, fragMTU),
	}
}

// rules returns the policy rules, the steering rule last so traffic arrives only once the rest is in place.
func (c *Controller) rules() []*netlink.Rule {
	return []*netlink.Rule{
		fragRule(c.x.X4, c.cfg.Table+1, c.cfg.RulePriority-1),
		x4Rule(c.x.X4, c.cfg.Table, c.cfg.RulePriority),
		steeringRule(c.cfg.Table, c.cfg.RulePriority),
	}
}

// Reassert re-checks the host and repairs the datapath, or hands 4via6 back to netstack if the host no longer allows it.
func (c *Controller) Reassert() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if !c.active {
		// A failed install waits for the next Update, so a kernel lacking a feature is not retried every CheckInterval.
		if c.failed {
			return
		}
		if prefixes := c.decideLocked(); len(prefixes) > 0 {
			if err := c.installLocked(prefixes); err != nil {
				c.failed = true
				c.cfg.Logf("via64: kernel 4via6 translation unavailable: %v", errors.Join(err, c.teardownLocked()))
			}
		}
		return
	}
	if len(c.decideLocked()) == 0 {
		if err := c.teardownLocked(); err != nil {
			c.cfg.Logf("via64: %v", err)
		}
		return
	}
	if c.intactLocked() {
		return
	}
	c.cfg.Logf("via64: datapath incomplete; repairing")
	if err := c.installLocked(c.prefixes); err != nil {
		c.cfg.Logf("via64: repair failed, kernel 4via6 translation off until the next check: %v", errors.Join(err, c.teardownLocked()))
	}
}

func (c *Controller) pairIntactLocked() bool {
	l, err := netlink.LinkByName(PrimaryName)
	return err == nil && l.Attrs().Index == c.pair.PrimaryIndex
}

func (c *Controller) intactLocked() bool {
	if !c.pairIntactLocked() {
		return false
	}
	for _, i := range []int{c.pair.PrimaryIndex, c.pair.PeerIndex} {
		if l, err := netlink.LinkByIndex(i); err != nil || l.Attrs().Flags&net.FlagUp == 0 {
			return false
		}
	}
	for _, r := range c.rules() {
		if ok, err := ruleExists(r); err != nil || !ok {
			return false
		}
	}
	for _, r := range c.routes() {
		if ok, err := routeExists(r); err != nil || !ok {
			return false
		}
	}
	ok, err := natPresent()
	return err == nil && ok
}

func (c *Controller) watch(stop chan struct{}) {
	t := time.NewTicker(c.cfg.CheckInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			c.Reassert()
		}
	}
}

// Close removes the datapath. Later calls to Update do nothing.
func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.stop != nil {
		close(c.stop)
		c.stop = nil
	}
	return c.teardownLocked()
}

func (c *Controller) teardownLocked() error {
	via64.SetKernelHandled(nil, false) // first, so netstack takes 4via6 back before the datapath goes
	errs := []error{Cleanup(c.cfg.Table)}
	if c.backend != nil {
		errs = append(errs, c.backend.Close())
		c.backend = nil
	}
	c.active, c.prefixes, c.pair = false, nil, Pair{}
	return errors.Join(errs...)
}
