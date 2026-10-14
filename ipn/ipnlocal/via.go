// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"

	"go4.org/netipx"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
)

// v4BroadcastAddr is 255.255.255.255, the limited broadcast address.
var v4BroadcastAddr = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// viaAdditionsEnv is the name of an environment variable that can be set to
// override the 4via6 host-scoped address restrictions. Only use this if you are
// certain that there is not a better solution (e.g. perhaps tailscale serve,
// possibly using a Service). Use of this feature will have security
// implications: ensure that your ACLs/Grants are written appropriately.
// The value of the environment variable is a comma separated list of IPv4
// ranges (two IPv4 addresses separated by a hyphen), IPv4 prefixes (CIDR
// notation), or IPv4 addresses. Spaces are permitted around the commas.
const viaAdditionsEnv = "TS_4VIA6_ALLOW_LOCAL"

// viaAllowLocalCap is a node attribute that is the policy-managed equivalent
// of the TS_4VIA6_ALLOW_LOCAL environment variable, and is named after it. Like
// other node attributes that carry values (such as "tailscale.com/app-connectors"),
// it is set via the "app" field of a nodeAttrs entry in the policy file.
// Each value is a JSON object of the form {"ranges": [...]}, where each entry
// is an IPv4 range ("a-b"), prefix, or address, in the same syntax as the
// environment variable. Values are merged, and combined with the environment
// variable.
const viaAllowLocalCap nodecap.Cap = "tailscale.com/4via6-allow-local"

var viaTargetAdditions = sync.OnceValue(func() *netipx.IPSet {
	v, err := generateViaTargetAdditions(envknob.String(viaAdditionsEnv))
	if err != nil {
		log.Print(err)
	}

	if v != nil {
		has4via6AdditionsMetric := clientmetric.NewGauge("4via6_allow_local")
		has4via6AdditionsMetric.Set(1)
	}

	return v
})

func generateViaTargetAdditions(rawAdditions string) (*netipx.IPSet, error) {
	rawAdditions = strings.TrimSpace(rawAdditions)
	if rawAdditions == "" {
		return nil, nil
	}

	var ips netipx.IPSetBuilder

	rawAddrs := strings.Split(rawAdditions, ",")
	errs := make([]error, 0, len(rawAddrs))
	for _, rawAddr := range rawAddrs {
		rawAddr = strings.TrimSpace(rawAddr)
		if rawAddr == "" {
			continue
		}
		if err := addViaTargetAddition(&ips, viaAdditionsEnv, rawAddr); err != nil {
			errs = append(errs, err)
		}
	}

	ipSet, err := ips.IPSet()
	if err != nil {
		errs = append(errs, err)
	}

	return ipSet, errors.Join(errs...)
}

// addViaTargetAddition parses rawAddr as an IPv4 range, prefix, or address and
// adds it to ips. source names where the value came from, for error messages.
func addViaTargetAddition(ips *netipx.IPSetBuilder, source, rawAddr string) error {
	if ipRange, err := netipx.ParseIPRange(rawAddr); err == nil {
		if !ipRange.From().Is4() || !ipRange.To().Is4() {
			return fmt.Errorf("rejecting %v range %v: not IPv4", source, ipRange)
		}
		ips.AddRange(ipRange)
		return nil
	}

	if prefix, err := netip.ParsePrefix(rawAddr); err == nil {
		if !prefix.Addr().Is4() {
			return fmt.Errorf("rejecting %v prefix %v: not IPv4", source, prefix)
		}
		ips.AddPrefix(prefix)
		return nil
	}

	if addr, err := netip.ParseAddr(rawAddr); err == nil {
		if !addr.Is4() {
			return fmt.Errorf("rejecting %v address %v: not IPv4", source, addr)
		}
		ips.Add(addr)
		return nil
	}

	return fmt.Errorf("rejecting %v value %q: not a range, prefix, or address", source, rawAddr)
}

// viaAllowLocalAttr is the JSON value of the [viaAllowLocalCap] node
// attribute.
type viaAllowLocalAttr struct {
	// Ranges holds IPv4 ranges ("a-b"), prefixes, or addresses, in the same
	// syntax as the TS_4VIA6_ALLOW_LOCAL environment variable.
	Ranges []string `json:"ranges"`
}

// viaTargetAdditionsFromCapMap returns the host-scoped 4via6 destinations
// permitted by the [viaAllowLocalCap] node attribute, merging all of
// its values. It returns a nil set if the attribute is absent. Invalid
// entries are skipped and reported in the returned error.
func viaTargetAdditionsFromCapMap(cm views.MapSlice[nodecap.Cap, tailcfg.RawMessage]) (*netipx.IPSet, error) {
	attrs, err := tailcfg.UnmarshalNodeCapViewJSON[viaAllowLocalAttr](cm, viaAllowLocalCap)
	if err != nil {
		return nil, err
	}
	if len(attrs) == 0 {
		return nil, nil
	}

	var ips netipx.IPSetBuilder
	var errs []error
	for _, attr := range attrs {
		for _, rawAddr := range attr.Ranges {
			rawAddr = strings.TrimSpace(rawAddr)
			if rawAddr == "" {
				continue
			}
			if err := addViaTargetAddition(&ips, string(viaAllowLocalCap), rawAddr); err != nil {
				errs = append(errs, err)
			}
		}
	}

	ipSet, err := ips.IPSet()
	if err != nil {
		errs = append(errs, err)
	}
	return ipSet, errors.Join(errs...)
}

// viaTargetAllowed reports whether ip may be forwarded to after unmapping a
// 4via6 destination. The packet filter only sees the outer via address, so
// this is the sole check on the embedded IPv4 target.
//
// policyAdditions holds host-scoped destinations permitted by the
// [viaAllowLocalCap] node attribute; it may be nil. Destinations in it,
// or in the TS_4VIA6_ALLOW_LOCAL environment variable, are allowed.
func viaTargetAllowed(ip netip.Addr, policyAdditions *netipx.IPSet) bool {
	if !ip.Is4() {
		return false // UnmapVia only returns IPv4
	}
	if additions := viaTargetAdditions(); additions != nil {
		// Permit unusual configurations to use host-scoped IP addresses as
		// 4via6 destinations when provided in an envknob.
		if additions.Contains(ip) {
			return true
		}
	}
	if policyAdditions != nil && policyAdditions.Contains(ip) {
		return true
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip == v4BroadcastAddr {
		return false
	}
	if tsaddr.IsTailscaleIP(ip) {
		// A CGNAT-range target may route to tailscale0 or to a site LAN
		// depending on the tailnet and OS (see shouldUseOneCGNATRoute);
		// it's hard to detect when forwarding would be OK, so deny always
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

// setViaAllowLocalLocked refreshes the host-scoped 4via6 destinations
// permitted by the [viaAllowLocalCap] node attribute from nm, so that
// policy changes take effect on the next netmap without a restart.
func (b *LocalBackend) setViaAllowLocalLocked(nm *netmap.NetworkMap) {
	var cm views.MapSlice[nodecap.Cap, tailcfg.RawMessage]
	if nm != nil && nm.SelfNode.Valid() {
		cm = nm.SelfNode.CapMap()
	}
	ips, changed, err := b.viaAllowLocal.update(cm)
	if !changed {
		return
	}
	if err != nil {
		b.logf("4via6: parsing %s node attribute: %v", viaAllowLocalCap, err)
	}
	if ips != nil {
		metricViaAllowLocalNodeAttr.Set(1)
		b.logf("4via6: %s node attribute allows %d host-scoped range(s)", viaAllowLocalCap, len(ips.Ranges()))
	} else {
		metricViaAllowLocalNodeAttr.Set(0)
		b.logf("4via6: %s node attribute removed", viaAllowLocalCap)
	}
	b.viaAllowLocalAtomic.Store(ips)
}

// metricViaAllowLocalNodeAttr is 1 while the [viaAllowLocalCap] node attribute
// is present, mirroring the "4via6_allow_local" gauge for the environment
// variable.
var metricViaAllowLocalNodeAttr = clientmetric.NewGauge("4via6_allow_local_nodeattr")

// viaAllowLocalState remembers the last seen value of the [viaAllowLocalCap]
// node attribute, so that it is only re-parsed, and only logged, when the
// value changes rather than on every netmap.
type viaAllowLocalState struct {
	raw string        // last seen raw values, or "" if the attribute was absent
	ips *netipx.IPSet // parsed from raw
}

// update returns the host-scoped destinations permitted by the
// [viaAllowLocalCap] node attribute in cm, and whether its value changed since
// the previous call. err is only non-nil when the value changed, so callers can
// log it without repeating themselves on every netmap.
func (s *viaAllowLocalState) update(cm views.MapSlice[nodecap.Cap, tailcfg.RawMessage]) (ips *netipx.IPSet, changed bool, err error) {
	var raw strings.Builder
	for _, v := range cm.Get(viaAllowLocalCap).All() {
		raw.WriteString(string(v))
		raw.WriteByte('\n')
	}
	if raw.String() == s.raw {
		return s.ips, false, nil
	}
	s.raw = raw.String()
	s.ips, err = viaTargetAdditionsFromCapMap(cm)
	return s.ips, true, err
}
