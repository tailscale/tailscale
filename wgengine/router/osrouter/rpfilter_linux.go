// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package osrouter

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

// Underlay source rules keep strict reverse-path filtering (rp_filter=1, or
// a netfilter "fib saddr . iif oif" check) working while this node routes
// through an exit node, without touching net.ipv4.conf.*.src_valid_mark.
//
// The problem: with an exit node, table 52 holds a default route via the
// Tailscale interface, and the catch-all rule at ipPolicyPrefBase+70 sends
// every unmarked lookup there. When a reply to one of tailscaled's own
// (bypass-marked) sockets arrives on a physical interface, the kernel
// validates its source with a reverse lookup that has fwmark 0 (unless
// src_valid_mark=1), iif=lo, daddr=<remote peer/DERP/control IP> and
// saddr=<our underlay address>. That lookup falls into table 52, resolves to
// the Tailscale interface, mismatches the ingress interface, and the packet
// is dropped as a martian. See tailscale/tailscale#3310.
//
// Setting src_valid_mark=1 fixes that, but it is a host-global behavior
// change that breaks other fwmark users (TPROXY, Cilium L7, split-tunnel
// VPNs, multi-WAN PBR); see tailscale/tailscale#19796.
//
// Instead we install, for each local non-Tailscale address A, the rule
//
//	<ipPolicyPrefBase+60>: from A lookup main
//
// The reverse-path lookup always carries saddr=A (the reply's destination),
// so it now resolves via the main table and passes. Normal outbound traffic
// through the exit node is unaffected: its route lookup is done with no source
// (or with the Tailscale address selected from table 52), neither of which
// matches. Forwarded traffic (containers, LAN clients) carries a foreign
// source address and is likewise unaffected. tailscaled's own bypass-marked
// sockets already source from an underlay address via the main table.
//
// The rules are an ip rule mechanism only, so they work in every netfilter
// mode, including "off" and "nodivert".
//
// The rules are only installed for an address family while that family's
// default route (0.0.0.0/0 or ::/0) is in table 52, i.e. while using an exit
// node; that is the only configuration in which the catch-all hijacks
// reverse-path lookups for arbitrary Internet peers.
//
// Limitation: the rules send the reverse lookup to the main table. On
// multi-WAN / policy routing hosts whose underlay default route lives in
// another table (selected by fwmark or source rules), main may have no
// route to the peer, the lookup falls through to table 52 and the drop
// remains. Such setups (e.g. OpenWrt mwan3) usually have their own
// lower-priority "from <src> lookup <table>" rules that match first.

// underlaySrcRuleOffset is the priority of the underlay source rules
// relative to ipPolicyPrefBase. It must be below the catch-all table 52 rule
// (offset 70) and lives inside the ipPolicyPrefBase..+100 range that
// onIPRuleDeleted already watches.
const underlaySrcRuleOffset = 60

// maxUnderlaySrcRulesPerFamily bounds how many underlay source rules we
// install per address family. Every rule is walked linearly on each policy
// routing lookup that reaches it, so hosts with very many local addresses
// (e.g. kube-proxy IPVS nodes) would otherwise pay a per-packet cost.
const maxUnderlaySrcRulesPerFamily = 128

// disableUnderlaySrcRules is a kill switch for the underlay source rules,
// should they conflict with some host's policy routing setup.
var disableUnderlaySrcRules = envknob.RegisterBool("TS_DEBUG_DISABLE_RPFILTER_SRC_RULES")

var (
	metricUnderlaySrcRules       = clientmetric.NewGauge("router_linux_rpfilter_src_rules")
	metricUnderlaySrcRulesCapped = clientmetric.NewGauge("router_linux_rpfilter_src_rules_capped")
)

func (r *linuxRouter) underlaySrcRulePriority() int {
	return r.ipPolicyPrefBase + underlaySrcRuleOffset
}

// underlayAddrsFromNetMon returns the candidate underlay source addresses
// from the network monitor's current interface state.
func (r *linuxRouter) underlayAddrsFromNetMon() []netip.Addr {
	if r.netMon == nil {
		return nil
	}
	return underlayAddrsFromState(r.netMon.InterfaceState(), r.tunname)
}

// underlayAddrsFromState returns the de-duplicated local unicast addresses
// on up, non-Tailscale interfaces in st, in priority order for
// maxUnderlaySrcRulesPerFamily:
//
//  1. addresses on the default route interface, which is where tailscaled's
//     bypass-marked sockets (WireGuard, DERP, control) source from and so
//     where the replies that need fixing arrive;
//  2. then other interfaces, those with fewer addresses first, so a
//     handful of real NICs are never crowded out by an interface carrying
//     hundreds of service VIPs (e.g. kube-proxy's kube-ipvs0 dummy, which
//     holds every ClusterIP);
//  3. ties broken by interface name, and addresses within an interface in
//     address order, for determinism.
//
// Addresses on the loopback interface are included unless they are loopback
// addresses themselves: hosts commonly put service VIPs (anycast, BGP,
// keepalived) on lo, and replies to them face the same reverse-path check.
// Link-local addresses are included, as the Tailscale default route would
// otherwise capture reverse lookups for link-local peers too.
func underlayAddrsFromState(st *netmon.State, tunname string) []netip.Addr {
	if st == nil {
		return nil
	}
	type ifAddrs struct {
		name      string
		isDefault bool
		addrs     []netip.Addr
	}
	var ifs []ifAddrs
	for name, ifc := range st.Interface {
		if name == tunname || strings.HasPrefix(name, "tailscale") {
			continue
		}
		if !ifc.IsUp() {
			// Addresses on down interfaces aren't usable as local
			// destinations.
			continue
		}
		var addrs []netip.Addr
		for _, pfx := range st.InterfaceIPs[name] {
			a := pfx.Addr().WithZone("")
			if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
				continue
			}
			addrs = append(addrs, a)
		}
		if len(addrs) == 0 {
			continue
		}
		slices.SortFunc(addrs, netip.Addr.Compare)
		ifs = append(ifs, ifAddrs{
			name:      name,
			isDefault: name == st.DefaultRouteInterface,
			addrs:     slices.Compact(addrs),
		})
	}
	slices.SortFunc(ifs, func(a, b ifAddrs) int {
		if a.isDefault != b.isDefault {
			if a.isDefault {
				return -1
			}
			return 1
		}
		if c := len(a.addrs) - len(b.addrs); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	var out []netip.Addr
	seen := set.Set[netip.Addr]{}
	for _, ifa := range ifs {
		for _, a := range ifa.addrs {
			// The same address may be configured on more than one
			// interface; keep its highest-priority occurrence.
			if !seen.Contains(a) {
				seen.Add(a)
				out = append(out, a)
			}
		}
	}
	return out
}

// desiredUnderlaySrcRulesLocked returns the set of addresses that should
// currently have an underlay source rule.
//
// r.mu must be held.
func (r *linuxRouter) desiredUnderlaySrcRulesLocked() set.Set[netip.Addr] {
	want := set.Set[netip.Addr]{}
	if !r.ipRuleAvailable || r.closed.Load() || disableUnderlaySrcRules() {
		return want
	}
	wantV4 := r.routes[tsaddr.AllIPv4()]
	wantV6 := r.routes[tsaddr.AllIPv6()] && r.getV6Available()
	if !wantV4 && !wantV6 {
		r.setUnderlaySrcRulesCappedLocked(false)
		return want
	}

	// Never install a rule for one of our own Tailscale addresses.
	tsAddrs := set.Set[netip.Addr]{}
	for p := range r.addrs {
		tsAddrs.Add(p.Addr())
	}

	var n4, n6 int
	capped := false
	if r.underlayAddrs == nil {
		r.setUnderlaySrcRulesCappedLocked(false)
		return want
	}
	for _, a := range r.underlayAddrs() {
		if tsAddrs.Contains(a) {
			continue
		}
		switch {
		case a.Is4() && wantV4:
			if n4 >= maxUnderlaySrcRulesPerFamily {
				capped = true
				continue
			}
			n4++
		case a.Is6() && wantV6:
			if n6 >= maxUnderlaySrcRulesPerFamily {
				capped = true
				continue
			}
			n6++
		default:
			continue
		}
		want.Add(a)
	}
	r.setUnderlaySrcRulesCappedLocked(capped)
	return want
}

// setUnderlaySrcRulesCappedLocked records whether the per-family cap was hit,
// logging only on transitions to avoid spamming on every netmon change.
//
// r.mu must be held.
func (r *linuxRouter) setUnderlaySrcRulesCappedLocked(capped bool) {
	if capped == r.underlaySrcRulesCapped {
		return
	}
	r.underlaySrcRulesCapped = capped
	if capped {
		metricUnderlaySrcRulesCapped.Set(1)
	} else {
		metricUnderlaySrcRulesCapped.Set(0)
	}
	if capped {
		r.logf("warning: more than %d local addresses per address family; only the first %d get rp_filter underlay source rules, replies to the rest may be dropped by strict reverse path filtering while using an exit node", maxUnderlaySrcRulesPerFamily, maxUnderlaySrcRulesPerFamily)
	}
}

// updateUnderlaySrcRulesLocked reconciles the installed underlay source rules
// with the desired set. It is called from Set, on network changes, and after
// our ip rules have been externally deleted.
//
// r.mu must be held.
func (r *linuxRouter) updateUnderlaySrcRulesLocked() error {
	if r.underlaySrcRules == nil {
		r.underlaySrcRules = set.Set[netip.Addr]{}
	}
	want := r.desiredUnderlaySrcRulesLocked()

	var errs []error
	var added, removed int
	for a := range r.underlaySrcRules {
		if want.Contains(a) {
			continue
		}
		if err := r.delUnderlaySrcRule(a); err != nil {
			// Keep tracking it so we retry on the next reconcile.
			errs = append(errs, fmt.Errorf("deleting rp_filter source rule for %v: %w", a, err))
			continue
		}
		r.underlaySrcRules.Delete(a)
		removed++
	}
	// Add in sorted order for deterministic behavior (and test output).
	for _, a := range slices.SortedFunc(want.All(), netip.Addr.Compare) {
		if r.underlaySrcRules.Contains(a) {
			continue
		}
		if err := r.addUnderlaySrcRule(a); err != nil {
			errs = append(errs, fmt.Errorf("adding rp_filter source rule for %v: %w", a, err))
			continue
		}
		r.underlaySrcRules.Add(a)
		added++
	}
	if added > 0 || removed > 0 {
		r.logf("rp_filter underlay source rules: +%d -%d, now %d", added, removed, len(r.underlaySrcRules))
	}
	metricUnderlaySrcRules.Set(int64(len(r.underlaySrcRules)))
	return errors.Join(errs...)
}

// removeUnderlaySrcRulesLocked removes every underlay source rule we are
// tracking.
//
// r.mu must be held.
func (r *linuxRouter) removeUnderlaySrcRulesLocked() error {
	var errs []error
	for a := range r.underlaySrcRules {
		if err := r.delUnderlaySrcRule(a); err != nil {
			// Keep tracking it so a later reconcile or Close retries
			// (the next Up's sweep also catches it).
			errs = append(errs, fmt.Errorf("deleting rp_filter source rule for %v: %w", a, err))
			continue
		}
		r.underlaySrcRules.Delete(a)
	}
	return errors.Join(errs...)
}

// restoreUnderlaySrcRules re-installs underlay source rules after some other
// process (typically systemd-networkd) deleted ip rules in our priority range.
// We can't tell which of ours were deleted, so re-add everything we track.
//
// With netlink the re-add is idempotent (EEXIST is ignored), so this never
// deletes anything: deleting would emit RTM_DELRULE and feed back into
// onIPRuleDeleted. The ip command can't distinguish "exists" reliably
// enough, so there we delete and re-add; onIPRuleDeleted ignores deletions
// at our priority, so that doesn't loop either.
func (r *linuxRouter) restoreUnderlaySrcRules() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() || !r.ipRuleAvailable {
		return
	}
	if r.useIPCommand() {
		if err := r.removeUnderlaySrcRulesLocked(); err != nil {
			r.logf("restoring rp_filter source rules: %v", err)
		}
	} else {
		r.reAddUnderlaySrcRulesLocked()
	}
	if err := r.updateUnderlaySrcRulesLocked(); err != nil {
		r.logf("restoring rp_filter source rules: %v", err)
	}
}

// reAddUnderlaySrcRulesLocked re-adds, via netlink, every underlay source
// rule we track. It never deletes, so it emits no RTM_DELRULE and can't feed
// back into onIPRuleDeleted. Rules that already exist are left alone
// (EEXIST). It returns how many rules were actually missing.
//
// r.mu must be held.
func (r *linuxRouter) reAddUnderlaySrcRulesLocked() int {
	n := 0
	for a := range r.underlaySrcRules {
		err := netlink.RuleAdd(r.underlaySrcNetlinkRule(a))
		switch {
		case err == nil:
			n++
		case errors.Is(err, errEEXIST):
		default:
			r.logf("restoring rp_filter source rule for %v: %v", a, err)
			// Forget it so the next reconcile retries the add.
			r.underlaySrcRules.Delete(a)
		}
	}
	return n
}

// underlaySrcRepairDelay is how long after a deletion at our priority we
// check for missing underlay source rules, batching bursts of deletions.
const underlaySrcRepairDelay = 250 * time.Millisecond

// scheduleUnderlaySrcRuleRepair is called when a rule at the underlay source
// priority is deleted. Most such deletions are our own (address removed,
// exit node turned off), but another process may have deleted one of ours
// without touching the base rules, in which case nothing else would notice.
// After a short delay we re-add any tracked rule that is missing. Since that
// only ever adds, it can't cause further deletion events.
//
// It's a no-op with the ip command, which can't do an add that's silent when
// the rule already exists.
func (r *linuxRouter) scheduleUnderlaySrcRuleRepair() {
	if !r.ipRuleAvailable || r.useIPCommand() || r.closed.Load() {
		return
	}
	if r.underlaySrcRepairPending.Swap(true) {
		return
	}
	time.AfterFunc(underlaySrcRepairDelay, r.repairUnderlaySrcRules)
}

func (r *linuxRouter) repairUnderlaySrcRules() {
	r.underlaySrcRepairPending.Store(false)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return
	}
	if n := r.reAddUnderlaySrcRulesLocked(); n > 0 {
		r.logf("re-added %d rp_filter source rule(s) deleted by another process", n)
	}
}

// queueNetworkChange is the netmon.ChangeDelta eventbus callback. It must
// return quickly: the router's eventbus client delivers events one at a
// time, so blocking here (on r.mu behind a long Set, then on netlink
// syscalls) would delay RuleDeleted and PortUpdate delivery. It hands the
// work to a goroutine and coalesces bursts: while a reconcile is pending
// (waiting for r.mu), further changes are dropped, since the pending
// reconcile reads the latest interface state once it runs. At most one
// goroutine waits and one runs at a time.
func (r *linuxRouter) queueNetworkChange() {
	if r.closed.Load() || r.netChangePending.Swap(true) {
		return
	}
	go r.onNetworkChange()
}

// onNetworkChange reconciles the underlay source rules with the current
// interface state so they follow address changes (DHCP renewals, interfaces
// coming and going, IPv6 privacy address rotation).
func (r *linuxRouter) onNetworkChange() {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Clear only once we hold mu: changes arriving from here on queue a
	// new reconcile, as this one may already have read older state.
	r.netChangePending.Store(false)
	if r.closed.Load() {
		return
	}
	// No snapshotV6Usable here: it reads /proc eagerly, while a reconcile
	// calls getV6Available at most once, and only when ::/0 is routed.
	if err := r.updateUnderlaySrcRulesLocked(); err != nil {
		r.logf("updating rp_filter source rules: %v", err)
	}
}

// sweepStaleUnderlaySrcRulesLocked deletes underlay source rules left behind
// by a previous tailscaled that exited without cleaning up (crash, SIGKILL).
// It only matches rules of exactly the shape we install: our priority,
// table main, a single-address source and no other selectors. It matches on
// shape, not provenance: an identical rule added by an administrator at this
// priority would also be removed. That priority is inside the ip rule band
// Tailscale already owns (ipPolicyPrefBase..+99, where delIPRules likewise
// deletes by priority and table), and the kernel's rule protocol attribute,
// which could mark ownership, isn't exposed by our netlink package.
//
// It is a no-op when using the ip command, which can't cheaply enumerate
// rules in structured form.
//
// r.mu must be held.
func (r *linuxRouter) sweepStaleUnderlaySrcRulesLocked() {
	r.underlaySrcRules = set.Set[netip.Addr]{}
	if !r.ipRuleAvailable || r.useIPCommand() {
		return
	}
	if n := sweepUnderlaySrcRules(r.logf, r.underlaySrcRulePriority()); n > 0 {
		r.logf("removed %d stale rp_filter source rule(s) left by a previous instance", n)
	}
}

// sweepUnderlaySrcRules deletes, via netlink, all underlay source rules at
// priority pri in both address families. It returns the number deleted.
func sweepUnderlaySrcRules(logf func(string, ...any), pri int) int {
	n := 0
	// Sweep both families regardless of current IPv6 availability so we
	// also clean up after a previous run that had IPv6.
	for _, family := range []addrFamily{v4, v6} {
		rules, err := netlink.RuleList(family.netlinkInt())
		if err != nil {
			continue
		}
		for _, ru := range rules {
			if !isUnderlaySrcRule(ru, pri) {
				continue
			}
			ru.Family = family.netlinkInt()
			if err := netlink.RuleDel(&ru); err != nil && !errors.Is(err, errENOENT) {
				logf("warning: deleting stale rp_filter source rule %v: %v", ru.Src, err)
				continue
			}
			n++
		}
	}
	return n
}

// removeUnderlaySrcRulesForCleanup removes underlay source rules on the
// tailscaled --cleanup path, where there is no running router and we don't
// know whether the previous instance used the default or the mwan3 priority
// base, so both are swept.
func removeUnderlaySrcRulesForCleanup(logf func(string, ...any)) {
	n := 0
	for _, base := range []int{defaultIPPolicyPrefBase, mwan3IPPolicyPrefBase} {
		n += sweepUnderlaySrcRules(logf, base+underlaySrcRuleOffset)
	}
	if n > 0 {
		logf("removed %d stale rp_filter source rule(s) during cleanup", n)
	}
}

// isUnderlaySrcRule reports whether ru has exactly the shape of an underlay
// source rule at priority pri: a plain "lookup main" action for a single
// source address, with no other selectors or modifiers.
func isUnderlaySrcRule(ru netlink.Rule, pri int) bool {
	if ru.Priority != pri || ru.Table != mainRouteTable.Num || ru.Src == nil {
		return false
	}
	if ones, bits := ru.Src.Mask.Size(); bits == 0 || ones != bits {
		return false
	}
	return (ru.Type == unix.RTN_UNSPEC || ru.Type == unix.RTN_UNICAST) &&
		ru.Dst == nil &&
		ru.IifName == "" &&
		ru.OifName == "" &&
		ru.Mark <= 0 &&
		ru.Mask <= 0 &&
		ru.Tos == 0 &&
		ru.TunID == 0 &&
		ru.Goto < 0 &&
		ru.Flow <= 0 &&
		ru.SuppressPrefixlen < 0 &&
		ru.SuppressIfgroup < 0 &&
		!ru.Invert &&
		ru.Dport == nil &&
		ru.Sport == nil
	// Not checked: uidrange and ipproto selectors, which our netlink
	// package doesn't parse, so a rule that differs from ours only by
	// those would still match.
}

// isIPRuleNotFound reports whether err from 'ip rule del' means the rule
// didn't exist. iproute2 exits 2 (254 on some older versions) for any
// RTNETLINK error, including EPERM, so the exit code alone isn't enough; the
// real command runner includes iproute2's output in the error, which we
// match. The test fakeOS reports "not found" as exactly "exitcode:N".
func isIPRuleNotFound(err error) bool {
	c := errCode(err)
	if c != 2 && c != 254 {
		return false
	}
	return strings.Contains(err.Error(), "No such file or directory") ||
		err.Error() == "exitcode:"+strconv.Itoa(c)
}

func familyOf(a netip.Addr) addrFamily {
	if a.Is6() {
		return v6
	}
	return v4
}

func (r *linuxRouter) underlaySrcNetlinkRule(a netip.Addr) *netlink.Rule {
	ru := netlink.NewRule()
	ru.Priority = r.underlaySrcRulePriority()
	ru.Family = familyOf(a).netlinkInt()
	ru.Table = mainRouteTable.Num
	ru.Src = netipx.AddrIPNet(a)
	return ru
}

func (r *linuxRouter) underlaySrcIPCommandArgs(verb string, a netip.Addr) []string {
	return []string{
		"ip", familyOf(a).dashArg(),
		"rule", verb,
		"pref", strconv.Itoa(r.underlaySrcRulePriority()),
		"from", a.String(),
		"table", mainRouteTable.ipCmdArg(),
	}
}

// addUnderlaySrcRule installs the underlay source rule for a. An already
// existing identical rule is not an error.
func (r *linuxRouter) addUnderlaySrcRule(a netip.Addr) error {
	if r.useIPCommand() {
		err := r.cmd.run(r.underlaySrcIPCommandArgs("add", a)...)
		if err != nil && errCode(err) == 2 && strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return err
	}
	err := netlink.RuleAdd(r.underlaySrcNetlinkRule(a))
	if errors.Is(err, errEEXIST) {
		return nil
	}
	return err
}

// delUnderlaySrcRule removes the underlay source rule for a. A missing rule
// is not an error.
func (r *linuxRouter) delUnderlaySrcRule(a netip.Addr) error {
	if r.useIPCommand() {
		err := r.cmd.run(r.underlaySrcIPCommandArgs("del", a)...)
		if err == nil || isIPRuleNotFound(err) {
			return nil
		}
		return err
	}
	err := netlink.RuleDel(r.underlaySrcNetlinkRule(a))
	if errors.Is(err, errENOENT) {
		return nil
	}
	return err
}
