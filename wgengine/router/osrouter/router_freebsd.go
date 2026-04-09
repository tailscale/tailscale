// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router"
)

func init() {
	router.HookNewUserspaceRouter.Set(func(opts router.NewOpts) (router.Router, error) {
		return newFreeBSDRouter(opts.Logf, opts.Tun, opts.NetMon, opts.Health)
	})
	router.HookCleanUp.Set(func(logf logger.Logf, netMon *netmon.Monitor, ifName string) {
		cleanUp(logf, ifName)
	})
}

// freebsdRouter extends the shared BSD userspace router with FreeBSD-specific
// IP forwarding and PF-based NAT for native subnet routing.
type freebsdRouter struct {
	*userspaceBSDRouter
	snatSubnetRoutes bool
}

func newFreeBSDRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor, health *health.Tracker) (router.Router, error) {
	bsd, err := newUserspaceBSDRouter(logf, tundev, netMon, health)
	if err != nil {
		return nil, err
	}
	return &freebsdRouter{userspaceBSDRouter: bsd}, nil
}

func (r *freebsdRouter) Set(cfg *router.Config) (reterr error) {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	setErr := func(err error) {
		if reterr == nil {
			reterr = err
		}
	}

	// Base address and route management.
	if err := r.userspaceBSDRouter.Set(cfg); err != nil {
		setErr(err)
	}

	// Enable IP forwarding when advertising subnet routes.
	if len(cfg.SubnetRoutes) > 0 {
		r.enableIPForwarding()
	}

	// Manage PF NAT rules for subnet routing.
	switch {
	case cfg.SNATSubnetRoutes == r.snatSubnetRoutes:
		// No change needed.
	case cfg.SNATSubnetRoutes:
		if err := r.addPFNATRules(); err != nil {
			r.logf("adding PF NAT rules: %v", err)
			setErr(err)
		}
	default:
		if err := r.delPFNATRules(); err != nil {
			r.logf("removing PF NAT rules: %v", err)
			setErr(err)
		}
	}
	r.snatSubnetRoutes = cfg.SNATSubnetRoutes

	return reterr
}

func (r *freebsdRouter) enableIPForwarding() {
	for _, kv := range []string{
		"net.inet.ip.forwarding=1",
		"net.inet6.ip6.forwarding=1",
	} {
		if out, err := cmd("sysctl", kv).CombinedOutput(); err != nil {
			r.logf("warning: sysctl %s: %v (%s)", kv, err, strings.TrimSpace(string(out)))
		}
	}
}

// pfAnchorName is the PF anchor used for all Tailscale NAT/filter rules.
// Using an anchor keeps our rules isolated from the user's existing PF
// configuration; we only ever flush or modify rules inside this anchor.
const pfAnchorName = "tailscale"

// addPFNATRules configures PF to masquerade traffic from Tailscale addresses
// leaving via non-Tailscale interfaces. This is the FreeBSD equivalent of the
// Linux iptables MASQUERADE rule used for subnet routing.
//
// Rules are loaded into the "tailscale" PF anchor so that any pre-existing
// user rules in the main ruleset are left untouched.
func (r *freebsdRouter) addPFNATRules() error {
	// Ensure the PF kernel module is loaded.
	cmd("kldload", "pf").CombinedOutput() // may already be loaded

	// Enable PF (idempotent; returns error if already enabled).
	cmd("pfctl", "-e").CombinedOutput()

	// Ensure the main ruleset references our anchor so PF evaluates it.
	// We add both a nat-anchor (for NAT rules) and an anchor (for filter
	// rules, currently just "pass" to avoid blocking) if not already present.
	if err := ensurePFAnchorRef(); err != nil {
		return fmt.Errorf("ensuring PF anchor reference: %w", err)
	}

	// Load rules into the tailscale anchor.
	// Traffic from Tailscale CGNAT (100.64.0.0/10) or ULA (fd7a:115c:a1e0::/48)
	// addresses exiting any non-Tailscale interface is source-NATed to the
	// outgoing interface's address so that return traffic routes back through
	// this node.
	rules := fmt.Sprintf(
		"nat on ! %s inet from 100.64.0.0/10 to any -> (self)\n"+
			"nat on ! %s inet6 from fd7a:115c:a1e0::/48 to any -> (self)\n",
		r.tunname, r.tunname,
	)

	pfctl := exec.Command("pfctl", "-a", pfAnchorName, "-f", "-")
	pfctl.Stdin = strings.NewReader(rules)
	out, err := pfctl.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s -f: %v (%s)", pfAnchorName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// getPFMainRuleset reads the current main PF filter and NAT rules.
func getPFMainRuleset() (filterRules, natRules string) {
	if out, err := cmd("pfctl", "-s", "rules").CombinedOutput(); err == nil {
		filterRules = string(out)
	}
	if out, err := cmd("pfctl", "-s", "nat").CombinedOutput(); err == nil {
		natRules = string(out)
	}
	return
}

// loadPFMainRuleset replaces the main PF ruleset with the given combined
// NAT + filter rules.
func loadPFMainRuleset(rules string) error {
	pfctl := exec.Command("pfctl", "-f", "-")
	pfctl.Stdin = strings.NewReader(rules)
	out, err := pfctl.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -f: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensurePFAnchorRef makes sure the main PF ruleset contains nat-anchor and
// anchor references for "tailscale". Without these, PF won't evaluate our
// anchor even if it has rules loaded.
//
// We read the current main ruleset and prepend the references only if they're
// not already present, then reload the combined ruleset.
func ensurePFAnchorRef() error {
	filterRules, natRules := getPFMainRuleset()

	var additions string
	natAnchorRef := fmt.Sprintf("nat-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)

	if !strings.Contains(natRules, natAnchorRef) {
		additions += natAnchorRef + "\n"
	}
	if !strings.Contains(filterRules, anchorRef) {
		additions += anchorRef + "\n"
	}
	if additions == "" {
		return nil // already present
	}

	// Prepend our anchor references so they're evaluated, then include
	// all existing rules so we don't disrupt the user's configuration.
	return loadPFMainRuleset(additions + natRules + filterRules)
}

// removePFAnchorRef removes the nat-anchor and anchor references for
// "tailscale" from the main PF ruleset via read-modify-write, leaving
// all other rules intact.
func removePFAnchorRef() error {
	filterRules, natRules := getPFMainRuleset()

	natAnchorRef := fmt.Sprintf("nat-anchor \"%s\"", pfAnchorName)
	anchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)

	newNat := removeLines(natRules, natAnchorRef)
	newFilter := removeLines(filterRules, anchorRef)

	if newNat == natRules && newFilter == filterRules {
		return nil // nothing to remove
	}

	return loadPFMainRuleset(newNat + newFilter)
}

// removeLines removes all lines from s that contain substr.
func removeLines(s, substr string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(s, "\n") {
		if strings.Contains(line, substr) {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// delPFNATRules flushes rules inside the tailscale PF anchor and removes
// the anchor references from the main ruleset.
func (r *freebsdRouter) delPFNATRules() error {
	// Flush rules inside the anchor.
	if out, err := cmd("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl -a %s -F all: %v (%s)", pfAnchorName, err, strings.TrimSpace(string(out)))
	}
	// Remove the anchor references from the main ruleset.
	if err := removePFAnchorRef(); err != nil {
		return fmt.Errorf("removing PF anchor reference: %w", err)
	}
	return nil
}

func (r *freebsdRouter) Close() error {
	cleanUp(r.logf, r.tunname)
	return nil
}

func cleanUp(logf logger.Logf, interfaceName string) {
	// Flush only the tailscale PF anchor, leaving user rules intact.
	if out, err := cmd("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput(); err != nil {
		logf("pfctl flush anchor %s: %v (%s)", pfAnchorName, err, strings.TrimSpace(string(out)))
	}
	// Remove the anchor references from the main ruleset.
	if err := removePFAnchorRef(); err != nil {
		logf("removing PF anchor ref: %v", err)
	}

	// If the interface was left behind, ifconfig down will not remove it.
	// In fact, this will leave a system in a tainted state where starting tailscaled
	// will result in "interface tailscale0 already exists"
	// until the defunct interface is ifconfig-destroyed.
	if out, err := cmd("ifconfig", interfaceName, "destroy").CombinedOutput(); err != nil {
		logf("ifconfig destroy: %v\n%s", err, out)
	}
}
