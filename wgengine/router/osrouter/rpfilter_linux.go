// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package osrouter

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/netmon"
	"tailscale.com/tsconst"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

// Underlay rules keep strict reverse-path filtering (rp_filter=1, or a
// netfilter "fib saddr . iif oif" check) working while this node routes
// through an exit node, without touching net.ipv4.conf.*.src_valid_mark.
//
// The problem: with an exit node, table 52 holds a default route via the
// Tailscale interface, and the catch-all rule at ipPolicyPrefBase+70 sends
// every unmarked lookup there. When a reply to one of tailscaled's own
// (bypass-marked) sockets arrives on a physical interface, the kernel
// validates its source with a reverse lookup that has fwmark 0 (unless
// src_valid_mark=1), iif=lo, uid 0, daddr=<remote peer/DERP/control IP> and
// saddr=<our underlay address>. That lookup falls into table 52, resolves to
// the Tailscale interface, mismatches the ingress interface, and the packet
// is dropped as a martian. See tailscale/tailscale#3310.
//
// Setting src_valid_mark=1 fixes that, but it is a host-global behavior
// change that breaks other fwmark users (TPROXY, Cilium L7, split-tunnel
// VPNs, multi-WAN PBR); see tailscale/tailscale#19796.
//
// Instead, per address family, we install
//
//	<base+55>: not fwmark <bypass> lookup 52 suppress_prefixlength 0
//	<base+60>: from A uidrange 0-0 lookup main
//
// with a base+60 rule for each underlay address A.
//
// The base+60 rule sends the reverse lookup (which carries saddr=A and uid
// 0) to the main table, where it finds the physical interface and passes.
//
// The base+55 rule runs first and consults table 52 without its default
// route. It keeps everything table 52 routes more specifically than the
// default on the Tailscale interface even for lookups from A: tailnet peers
// and subnet routes (so a peer can still reach the host's LAN address, and
// replies go back through the tunnel), and, with ExitNodeAllowLANAccess
// off, the LAN prefixes that table 52 claims so LAN traffic doesn't leak.
// Throw routes in table 52 (local routes) end the lookup there and fall
// through to the next rule, as before. It excludes bypass-marked packets,
// which must never use table 52.
//
// The base+55 rule also keeps the LAN block: a reply from a LAN host to one
// of tailscaled's own sockets fails reverse-path validation just like any
// other LAN packet, so with ExitNodeAllowLANAccess off and strict rp_filter
// those replies are still dropped, as they were before src_valid_mark. That
// includes magicsock's, so direct paths to peers on the LAN fall back to
// DERP.
//
// Mark-aware netfilter reverse-path checks (e.g. nftables "fib saddr . mark
// . iif oif") are covered by the connmark rules instead, when netfilter is
// on.
//
// The uidrange 0-0 selector limits the base+60 rule to lookups made as uid
// 0. The kernel's reverse-path lookups always are, so the fix works, but
// sockets of non-root processes bound to an underlay address (curl
// --interface, a torrent client) still use the exit node, as before.
// Sockets of root processes bound to an underlay address, and packets the
// kernel itself sends from it (ICMP errors, TCP resets, replies on inbound
// connections from root-owned sockets) use the physical interface.
//
// Unmarked lookups without an underlay source (normal outbound traffic,
// which gets the Tailscale source address) and forwarded traffic (foreign
// source addresses) match neither rule and are unaffected.
//
// The rules are an ip rule mechanism only, so they work in every netfilter
// mode, including "off" and "nodivert". They carry rule protocol
// ruleProtocolTailscale so we only ever remove our own rules.
//
// The rules are only installed for an address family while that family's
// default route (0.0.0.0/0 or ::/0) is in table 52, i.e. while using an exit
// node; that is the only configuration in which the catch-all hijacks
// reverse-path lookups for arbitrary Internet peers. The IPv4 rules are
// also only installed while the kernel's IPv4 rp_filter is strict on some
// interface (re-checked on every network change and Set); see
// rpFilterStrictV4FromSysctl.
//
// Limitations: the rules only exist while 0.0.0.0/0 or ::/0 is routed. Other
// table 52 routes that cover a peer, DERP or control address (an exit node
// split into 0.0.0.0/1 and 128.0.0.0/1, or an accepted subnet route such as
// 10.0.0.0/8) cause the same drop and aren't handled. Installing the rules
// for them wouldn't help either: the base+55 rule keeps those routes ahead
// of the base+60 rule, as it must for traffic that should use the tunnel.
// The reverse lookup for a reply to tailscaled from such an address is the
// same as for anything else from there. Telling them apart needs the
// packet's mark (src_valid_mark), or exceptions for the exact addresses
// tailscaled talks to.
//
// The rules send the reverse lookup to the main table. On
// multi-WAN / policy routing hosts whose underlay default route lives in
// another table (selected by fwmark or source rules), main may have no
// route to the peer, the lookup falls through to table 52 and the drop
// remains. Such setups (e.g. OpenWrt mwan3) usually have their own
// lower-priority "from <src> lookup <table>" rules that match first.
// Kernels before 4.10 ignore uidrange, so there the base+60 rule applies to
// all processes. Kernels before 4.17 don't store the rule protocol; there we
// recognize our rules by their exact shape instead.

const (
	// underlaySuppressRuleOffset and underlaySrcRuleOffset are the
	// priorities of the underlay rules relative to ipPolicyPrefBase. Both
	// must be below the table 52 catch-all (offset 70), the suppress rule
	// below the source rules, and both inside the ipPolicyPrefBase..+99
	// range that onIPRuleDeleted watches.
	underlaySuppressRuleOffset = 55
	underlaySrcRuleOffset      = 60
)

// kernelVersion returns the running kernel's major and minor version, or
// 0, 0 if unknown.
var kernelVersion = sync.OnceValues(func() (major, minor int) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return 0, 0
	}
	rel := unix.ByteSliceToString(u.Release[:])
	maj, rest, _ := strings.Cut(rel, ".")
	mnr, _, _ := strings.Cut(rest, ".")
	major, _ = strconv.Atoi(maj)
	minor, _ = strconv.Atoi(strings.TrimRightFunc(mnr, func(r rune) bool { return r < '0' || r > '9' }))
	return major, minor
})

func kernelAtLeast(major, minor int) bool {
	ma, mi := kernelVersion()
	return ma > major || (ma == major && mi >= minor)
}

// maxUnderlaySrcRulesPerFamily bounds how many underlay source rules we
// install per address family. Every rule is walked linearly on each policy
// routing lookup that reaches it, so hosts with very many local addresses
// (e.g. kube-proxy IPVS nodes) would otherwise pay a per-packet cost.
const maxUnderlaySrcRulesPerFamily = 128

// disableUnderlaySrcRules is a kill switch for the underlay rules, should
// they conflict with some host's policy routing setup.
var disableUnderlaySrcRules = envknob.RegisterBool("TS_DEBUG_DISABLE_RPFILTER_SRC_RULES")

var (
	metricUnderlaySrcRules       = clientmetric.NewGauge("router_linux_rpfilter_src_rules")
	metricUnderlaySrcRulesCapped = clientmetric.NewGauge("router_linux_rpfilter_src_rules_capped")
)

// underlayRule identifies one rule we manage: the source rule for src or,
// when src isn't set, the family's table 52 suppress rule.
type underlayRule struct {
	fam addrFamily
	src netip.Addr
}

func (u underlayRule) isSuppress() bool { return !u.src.IsValid() }

// rank orders rule kinds for adding: suppress, then source.
func (u underlayRule) rank() int {
	if u.isSuppress() {
		return 0
	}
	return 1
}

func (u underlayRule) String() string {
	if u.isSuppress() {
		return fmt.Sprintf("v%d table %d suppress rule", u.fam, tailscaleRouteTable.Num)
	}
	return "source rule for " + u.src.String()
}

// compareUnderlayRules orders suppress rules before source rules (the order
// to add them in), then by family and address.
func compareUnderlayRules(a, b underlayRule) int {
	return cmp.Or(
		cmp.Compare(a.rank(), b.rank()),
		cmp.Compare(a.fam, b.fam),
		a.src.Compare(b.src))
}

func (r *linuxRouter) underlaySrcRulePriority() int {
	return r.ipPolicyPrefBase + underlaySrcRuleOffset
}

func (r *linuxRouter) underlaySuppressRulePriority() int {
	return r.ipPolicyPrefBase + underlaySuppressRuleOffset
}

// isUnderlayRulePriority reports whether pri is one of the underlay rule
// priorities.
func (r *linuxRouter) isUnderlayRulePriority(pri int) bool {
	return pri == r.underlaySrcRulePriority() ||
		pri == r.underlaySuppressRulePriority()
}

// rpFilterStrictV4FromSysctl reports whether the kernel's strict IPv4
// reverse path filter applies to any up, non-Tailscale interface. The
// effective mode of an interface is the larger of conf/all/rp_filter and
// conf/<if>/rp_filter, so 1 (strict) only applies when neither is 2 (loose).
func (r *linuxRouter) rpFilterStrictV4FromSysctl() bool {
	read := func(dev string) int {
		b, err := os.ReadFile(filepath.Join("/proc/sys/net/ipv4/conf", dev, "rp_filter"))
		if err != nil {
			return 0
		}
		v, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return v
	}
	all := read("all")
	var st *netmon.State
	if r.netMon != nil {
		st = r.netMon.InterfaceState()
	}
	if st == nil {
		return all == 1
	}
	for name, ifc := range st.Interface {
		if name == r.tunname || strings.HasPrefix(name, "tailscale") || !ifc.IsUp() || ifc.IsLoopback() {
			continue
		}
		if max(all, read(name)) == 1 {
			return true
		}
	}
	return false
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
//  1. all addresses on the default route interface, which is where
//     tailscaled's bypass-marked sockets (WireGuard, DERP, control) source
//     from and so where the replies that need fixing arrive;
//  2. then non-link-local addresses on other interfaces, interfaces with
//     fewer such addresses first, so a handful of real NICs are never
//     crowded out by an interface carrying hundreds of service VIPs (e.g.
//     kube-proxy's kube-ipvs0 dummy, which holds every ClusterIP);
//  3. then link-local addresses on other interfaces, so the fe80::
//     addresses of many container veths can't crowd out another NIC's
//     global addresses either;
//  4. ties broken by interface name, and addresses within an interface in
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
		global    []netip.Addr // not link-local
		linkLocal []netip.Addr
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
		ia := ifAddrs{name: name, isDefault: name == st.DefaultRouteInterface}
		for _, pfx := range st.InterfaceIPs[name] {
			a := pfx.Addr().WithZone("")
			if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
				continue
			}
			if a.IsLinkLocalUnicast() {
				ia.linkLocal = append(ia.linkLocal, a)
			} else {
				ia.global = append(ia.global, a)
			}
		}
		if len(ia.global) == 0 && len(ia.linkLocal) == 0 {
			continue
		}
		for _, as := range []*[]netip.Addr{&ia.global, &ia.linkLocal} {
			slices.SortFunc(*as, netip.Addr.Compare)
			*as = slices.Compact(*as)
		}
		ifs = append(ifs, ia)
	}
	slices.SortFunc(ifs, func(a, b ifAddrs) int {
		if a.isDefault != b.isDefault {
			if a.isDefault {
				return -1
			}
			return 1
		}
		if c := len(a.global) - len(b.global); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	var out []netip.Addr
	seen := set.Set[netip.Addr]{}
	add := func(as []netip.Addr) {
		for _, a := range as {
			// The same address may be configured on more than one
			// interface; keep its highest-priority occurrence.
			if !seen.Contains(a) {
				seen.Add(a)
				out = append(out, a)
			}
		}
	}
	for _, ia := range ifs {
		if ia.isDefault {
			add(ia.global)
			add(ia.linkLocal)
		}
	}
	for _, ia := range ifs {
		if !ia.isDefault {
			add(ia.global)
		}
	}
	for _, ia := range ifs {
		if !ia.isDefault {
			add(ia.linkLocal)
		}
	}
	return out
}

// desiredUnderlayRulesLocked returns the set of underlay rules that should
// currently be installed.
//
// r.mu must be held.
func (r *linuxRouter) desiredUnderlayRulesLocked() set.Set[underlayRule] {
	want := set.Set[underlayRule]{}
	if !r.ipRuleAvailable || r.closed.Load() || disableUnderlaySrcRules() || r.underlayAddrs == nil {
		r.setUnderlaySrcRulesCappedLocked(false)
		return want
	}
	// The kernel's IPv4 rp_filter is the only IPv4 check we know of that
	// needs these rules (mark-aware netfilter checks are covered by the
	// connmark rules), so skip them unless it's in strict mode: they make
	// root sockets bound to an underlay address bypass the exit node, and
	// hosts without the problem shouldn't get that. IPv6 has no kernel
	// reverse path filter; its netfilter checks can't be detected
	// reliably, so the IPv6 rules are always installed.
	wantV4 := false
	if r.exitRouteV4 && r.rpFilterStrictV4 != nil {
		wantV4 = r.rpFilterStrictV4()
		r.rpFilterStrictV4Seen = wantV4
	}
	wantV6 := r.exitRouteV6 && r.getV6Available()
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
		want.Add(underlayRule{fam: familyOf(a), src: a})
	}
	// A family's suppress rule exists whenever it has source rules.
	if n4 > 0 {
		want.Add(underlayRule{fam: v4})
	}
	if n6 > 0 {
		want.Add(underlayRule{fam: v6})
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

// updateUnderlaySrcRulesLocked reconciles the installed underlay rules with
// the desired set. If addOnly, it only adds missing rules; Set uses that
// before it installs exit node routes, so the rules are in place before the
// default route that makes them necessary.
//
// Adds happen suppress rule first, then source rules; removals the
// reverse. That way a source rule never exists without its family's
// suppress rule, which would briefly cut tailnet traffic to the underlay
// addresses.
//
// r.mu must be held.
func (r *linuxRouter) updateUnderlaySrcRulesLocked(addOnly bool) error {
	if r.underlaySrcRules == nil {
		r.underlaySrcRules = set.Set[underlayRule]{}
	}
	want := r.desiredUnderlayRulesLocked()

	var errs []error
	var added, removed int
	if !addOnly {
		stale := slices.SortedFunc(func(yield func(underlayRule) bool) {
			for u := range r.underlaySrcRules {
				if !want.Contains(u) && !yield(u) {
					return
				}
			}
		}, compareUnderlayRules)
		for _, u := range slices.Backward(stale) {
			if err := r.delUnderlayRule(u); err != nil {
				// Keep tracking it so we retry on the next reconcile.
				errs = append(errs, fmt.Errorf("deleting rp_filter %v: %w", u, err))
				continue
			}
			r.underlaySrcRules.Delete(u)
			removed++
		}
	}
	for _, u := range slices.SortedFunc(want.All(), compareUnderlayRules) {
		if r.underlaySrcRules.Contains(u) {
			continue
		}
		if !u.isSuppress() && !r.underlaySrcRules.Contains(underlayRule{fam: u.fam}) {
			// Its suppress rule failed to install; don't add a source
			// rule without it.
			continue
		}
		if err := r.addUnderlayRule(u); err != nil {
			errs = append(errs, fmt.Errorf("adding rp_filter %v: %w", u, err))
			continue
		}
		r.underlaySrcRules.Add(u)
		added++
	}
	if added > 0 || removed > 0 {
		r.logf("rp_filter underlay rules: +%d -%d, now %d", added, removed, len(r.underlaySrcRules))
	}
	metricUnderlaySrcRules.Set(int64(len(r.underlaySrcRules)))
	r.scheduleRPFilterRecheckLocked()
	return errors.Join(errs...)
}

// rpFilterRecheckInterval is how often, while an exit node's 0.0.0.0/0 is
// routed, we re-read the IPv4 rp_filter sysctls that gate the IPv4 rules.
const rpFilterRecheckInterval = 10 * time.Second

// scheduleRPFilterRecheckLocked arranges for the IPv4 rp_filter mode to be
// read again after rpFilterRecheckInterval, while it gates rules we might
// need. A sysctl write raises no netlink event, so without this a switch to
// strict mode with the exit node already on would leave the IPv4 rules out
// until some unrelated network change or Set (review finding).
//
// r.mu must be held.
func (r *linuxRouter) scheduleRPFilterRecheckLocked() {
	if !r.exitRouteV4 || !r.ipRuleAvailable || r.rpFilterStrictV4 == nil ||
		r.closed.Load() || disableUnderlaySrcRules() {
		return
	}
	if r.rpFilterRecheckPending.Swap(true) {
		return
	}
	r.after(rpFilterRecheckInterval, r.recheckRPFilter)
}

// recheckRPFilter reconciles the underlay rules if the IPv4 rp_filter mode
// changed since they were last computed, and otherwise schedules the next
// check. Reading the sysctls is a handful of small /proc reads.
func (r *linuxRouter) recheckRPFilter() {
	strict := r.rpFilterStrictV4()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rpFilterRecheckPending.Store(false)
	if r.closed.Load() || !r.exitRouteV4 {
		return
	}
	if strict == r.rpFilterStrictV4Seen {
		r.scheduleRPFilterRecheckLocked()
		return
	}
	r.logf("IPv4 rp_filter is now %s; updating rp_filter underlay rules", map[bool]string{true: "strict", false: "not strict"}[strict])
	// This reschedules the next check.
	r.logUnderlayErrLocked(r.updateUnderlaySrcRulesLocked(false))
}

// removeUnderlaySrcRulesLocked removes every underlay rule we are tracking,
// source rules first.
//
// r.mu must be held.
func (r *linuxRouter) removeUnderlaySrcRulesLocked() error {
	var errs []error
	for _, u := range slices.Backward(slices.SortedFunc(r.underlaySrcRules.All(), compareUnderlayRules)) {
		if err := r.delUnderlayRule(u); err != nil {
			// Keep tracking it so a later reconcile or Close retries
			// (the next Up's sweep also catches it).
			errs = append(errs, fmt.Errorf("deleting rp_filter %v: %w", u, err))
			continue
		}
		r.underlaySrcRules.Delete(u)
	}
	return errors.Join(errs...)
}

// underlayNetlinkUsable reports whether we can manage underlay rules via
// netlink directly: always on a real system, even when the ip command is
// forced (TS_DEBUG_USE_IP_COMMAND), as the ip command adds identical rules.
// Not with the tests' fake command runner.
func (r *linuxRouter) underlayNetlinkUsable() bool {
	_, ok := r.cmd.(osCommandRunner)
	return ok
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

// onNetworkChange reconciles the underlay rules with the current interface
// state so they follow address changes (DHCP renewals, interfaces coming
// and going, IPv6 privacy address rotation).
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
	r.logUnderlayErrLocked(r.updateUnderlaySrcRulesLocked(false))
}

// logUnderlayErrLocked logs err from a reconcile of the underlay rules,
// unless it's the same as the last one logged: a rule that can't be added
// is retried on every network change, which on a container host happens
// all the time. A nil err resets that, so a later failure logs again.
//
// r.mu must be held.
func (r *linuxRouter) logUnderlayErrLocked(err error) {
	if err == nil {
		r.lastUnderlayErr = ""
		return
	}
	if msg := err.Error(); msg != r.lastUnderlayErr {
		r.lastUnderlayErr = msg
		r.logf("warning: rp_filter underlay rules: %v", err)
	}
}

// sweepStaleUnderlaySrcRulesLocked deletes underlay rules left behind by a
// previous tailscaled that exited without cleaning up (crash, SIGKILL).
// See isOurUnderlayRule for how they're recognized.
//
// It needs netlink; see underlayNetlinkUsable.
//
// r.mu must be held.
func (r *linuxRouter) sweepStaleUnderlaySrcRulesLocked() {
	r.underlaySrcRules = set.Set[underlayRule]{}
	if !r.ipRuleAvailable || !r.underlayNetlinkUsable() {
		return
	}
	if n := sweepUnderlaySrcRules(r.logf, r.ipPolicyPrefBase); n > 0 {
		r.logf("removed %d stale rp_filter underlay rule(s) left by a previous instance", n)
	}
}

// sweepUnderlaySrcRules deletes, via netlink, all of our underlay rules for
// priority base in both address families. It returns the number deleted.
func sweepUnderlaySrcRules(logf func(string, ...any), base int) int {
	n := 0
	// Sweep both families regardless of current IPv6 availability so we
	// also clean up after a previous run that had IPv6.
	for _, family := range []addrFamily{v4, v6} {
		rules, err := listIPRules(family)
		if err != nil {
			continue
		}
		for _, ru := range rules {
			if !isOurUnderlayRule(ru, base) {
				continue
			}
			if err := delIPRule(ru); err != nil && !errors.Is(err, errENOENT) {
				logf("warning: deleting stale rp_filter underlay rule (pref %d, from %v): %v", ru.priority, ru.src, err)
				continue
			}
			n++
		}
	}
	return n
}

// removeUnderlaySrcRulesForCleanup removes leftover underlay rules from the
// router cleanup that tailscaled runs at every start (and for --cleanup),
// when no router is running. It only sweeps the priority base this host
// would use, determined the same way newLinuxRouter does.
func removeUnderlaySrcRulesForCleanup(logf func(string, ...any)) {
	base := defaultIPPolicyPrefBase
	if isMWAN3, err := checkOpenWRTUsingMWAN3(); err == nil && isMWAN3 {
		base = mwan3IPPolicyPrefBase
	}
	if n := sweepUnderlaySrcRules(logf, base); n > 0 {
		logf("removed %d stale rp_filter underlay rule(s) during cleanup", n)
	}
}

// isOurUnderlayRule reports whether ru is an underlay rule installed by
// tailscaled for priority base. On kernels that store the rule protocol
// (4.17+), that's exactly the rules at our priorities with protocol
// ruleProtocolTailscale, whatever their shape. On older kernels it falls
// back to the exact shape of the rules we install there.
func isOurUnderlayRule(ru ipRule, base int) bool {
	return isOurUnderlayRuleFor(ru, base, kernelAtLeast(4, 10))
}

// isOurUnderlayRuleFor is isOurUnderlayRule for a kernel that does
// (uidRangeOK) or doesn't support uidrange selectors.
func isOurUnderlayRuleFor(ru ipRule, base int, uidRangeOK bool) bool {
	src := int(ru.priority) == base+underlaySrcRuleOffset
	sup := int(ru.priority) == base+underlaySuppressRuleOffset
	if !src && !sup {
		return false
	}
	if ru.hasProtocol {
		return ru.protocol == ruleProtocolTailscale
	}
	if ru.other || ru.invert != sup || src && ru.suppressPrefixlen != -1 {
		return false
	}
	// Our source rules carry uidrange 0-0, which kernels from 4.10 keep and
	// older ones drop.
	uidOK := ru.uidRange == nil
	if uidRangeOK {
		uidOK = ru.uidRange != nil && *ru.uidRange == [2]uint32{0, 0}
	}
	if src {
		return ru.table == uint32(mainRouteTable.Num) &&
			ru.src.IsValid() &&
			ru.fwmask == 0 &&
			ru.ipProto == 0 && ru.sportRange == nil &&
			uidOK
	}
	return ru.table == uint32(tailscaleRouteTable.Num) &&
		!ru.src.IsValid() &&
		ru.fwmark == tsconst.LinuxBypassMarkNum &&
		ru.fwmask == tsconst.LinuxFwmarkMaskNum &&
		ru.suppressPrefixlen == 0 &&
		ru.ipProto == 0 && ru.sportRange == nil &&
		ru.uidRange == nil
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

// underlayIPRule returns the kernel rule for u.
func (r *linuxRouter) underlayIPRule(u underlayRule) ipRule {
	if u.isSuppress() {
		return ipRule{
			family:            u.fam,
			priority:          uint32(r.underlaySuppressRulePriority()),
			table:             uint32(tailscaleRouteTable.Num),
			invert:            true,
			fwmark:            tsconst.LinuxBypassMarkNum,
			fwmask:            tsconst.LinuxFwmarkMaskNum,
			suppressPrefixlen: 0,
			protocol:          ruleProtocolTailscale,
		}
	}
	return ipRule{
		family:            u.fam,
		priority:          uint32(r.underlaySrcRulePriority()),
		table:             uint32(mainRouteTable.Num),
		src:               u.src,
		suppressPrefixlen: -1,
		uidRange:          &[2]uint32{0, 0},
		protocol:          ruleProtocolTailscale,
	}
}

// underlayIPCommandArgs returns the ip command for verb ("add" or "del") on
// u. It sets the rule protocol, so the netlink sweep recognizes these rules
// too; that needs iproute2 4.17 or later (busybox lacks it, and uidrange).
func (r *linuxRouter) underlayIPCommandArgs(verb string, u underlayRule) []string {
	if u.isSuppress() {
		mark := fmt.Sprintf("0x%x", tsconst.LinuxBypassMarkNum)
		if r.fwmaskWorks() {
			mark += "/" + tsconst.LinuxFwmarkMask
		}
		return []string{
			"ip", u.fam.dashArg(),
			"rule", verb,
			"pref", strconv.Itoa(r.underlaySuppressRulePriority()),
			"not", "fwmark", mark,
			"table", tailscaleRouteTable.ipCmdArg(),
			"suppress_prefixlength", "0",
			"protocol", strconv.Itoa(ruleProtocolTailscale),
		}
	}
	return []string{
		"ip", u.fam.dashArg(),
		"rule", verb,
		"pref", strconv.Itoa(r.underlaySrcRulePriority()),
		"from", u.src.String(),
		"uidrange", "0-0",
		"table", mainRouteTable.ipCmdArg(),
		"protocol", strconv.Itoa(ruleProtocolTailscale),
	}
}

// addUnderlayRule installs u. An already existing identical rule is not an
// error.
func (r *linuxRouter) addUnderlayRule(u underlayRule) error {
	if r.useIPCommand() {
		err := r.cmd.run(r.underlayIPCommandArgs("add", u)...)
		if err != nil && errCode(err) == 2 && strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return err
	}
	err := addIPRule(r.underlayIPRule(u))
	if errors.Is(err, errEEXIST) {
		return nil
	}
	return err
}

// delUnderlayRule removes u. A missing rule is not an error.
func (r *linuxRouter) delUnderlayRule(u underlayRule) error {
	if r.useIPCommand() {
		err := r.cmd.run(r.underlayIPCommandArgs("del", u)...)
		if err == nil || isIPRuleNotFound(err) {
			return nil
		}
		return err
	}
	err := delIPRule(r.underlayIPRule(u))
	if errors.Is(err, errENOENT) {
		return nil
	}
	return err
}
