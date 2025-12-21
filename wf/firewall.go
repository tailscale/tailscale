// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

// Package wf controls the Windows Filtering Platform to change Windows firewall rules.
package wf

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"tailscale.com/net/netaddr"
)

// Known addresses.
var (
	linkLocalRange           = netip.MustParsePrefix("fe80::/10")
	linkLocalDHCPMulticast   = netip.MustParseAddr("ff02::1:2")
	siteLocalDHCPMulticast   = netip.MustParseAddr("ff05::1:3")
	linkLocalRouterMulticast = netip.MustParseAddr("ff02::2")

	linkLocalMulticastIPv4Range = netip.MustParsePrefix("224.0.0.0/24")
	linkLocalMulticastIPv6Range = netip.MustParsePrefix("ff02::/16")
)

type direction int

const (
	directionInbound direction = iota
	directionOutbound
	directionBoth
)

type protocol int

const (
	protocolV4 protocol = iota
	protocolV6
	protocolAll
)

// getLayers returns the wf.LayerIDs where the rules should be added based
// on the protocol and direction.
func (p protocol) getLayers(d direction) []wf.LayerID {
	var layers []wf.LayerID
	if p == protocolAll || p == protocolV4 {
		if d == directionBoth || d == directionInbound {
			layers = append(layers, wf.LayerALEAuthRecvAcceptV4)
		}
		if d == directionBoth || d == directionOutbound {
			layers = append(layers, wf.LayerALEAuthConnectV4)
		}
	}
	if p == protocolAll || p == protocolV6 {
		if d == directionBoth || d == directionInbound {
			layers = append(layers, wf.LayerALEAuthRecvAcceptV6)
		}
		if d == directionBoth || d == directionOutbound {
			layers = append(layers, wf.LayerALEAuthConnectV6)
		}
	}
	return layers
}

func ruleName(action wf.Action, layerID wf.LayerID, name string) string {
	switch layerID {
	case wf.LayerALEAuthConnectV4:
		return fmt.Sprintf("%s outbound %s (IPv4)", action, name)
	case wf.LayerALEAuthConnectV6:
		return fmt.Sprintf("%s outbound %s (IPv6)", action, name)
	case wf.LayerALEAuthRecvAcceptV4:
		return fmt.Sprintf("%s inbound %s (IPv4)", action, name)
	case wf.LayerALEAuthRecvAcceptV6:
		return fmt.Sprintf("%s inbound %s (IPv6)", action, name)
	}
	return ""
}

// Firewall uses the Windows Filtering Platform to implement a network firewall.
type Firewall struct {
	luid       uint64
	providerID wf.ProviderID
	sublayerID wf.SublayerID
	session    *wf.Session

	permittedRoutes map[netip.Prefix][]*wf.Rule
}

// New returns a new Firewall for the provided interface ID.
func New(luid uint64) (*Firewall, error) {
	session, err := wf.New(&wf.Options{
		Name:    "Tailscale firewall",
		Dynamic: true,
	})
	if err != nil {
		return nil, err
	}
	wguid, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	providerID := wf.ProviderID(wguid)
	if err := session.AddProvider(&wf.Provider{
		ID:   providerID,
		Name: "Tailscale provider",
	}); err != nil {
		return nil, err
	}
	wguid, err = windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	sublayerID := wf.SublayerID(wguid)
	if err := session.AddSublayer(&wf.Sublayer{
		ID:     sublayerID,
		Name:   "Tailscale permissive and blocking filters",
		Weight: 0,
	}); err != nil {
		return nil, err
	}
	f := &Firewall{
		luid:            luid,
		session:         session,
		providerID:      providerID,
		sublayerID:      sublayerID,
		permittedRoutes: make(map[netip.Prefix][]*wf.Rule),
	}
	if err := f.enable(); err != nil {
		return nil, err
	}
	return f, nil
}

type weight uint64

const (
	weightTailscaleTraffic weight = 15
	weightKnownTraffic     weight = 12
	weightCatchAll         weight = 0
)

func (f *Firewall) enable() error {
	if err := f.permitTailscaleService(weightTailscaleTraffic); err != nil {
		return fmt.Errorf("permitTailscaleService failed: %w", err)
	}

	if err := f.permitTunInterface(weightTailscaleTraffic); err != nil {
		return fmt.Errorf("permitTunInterface failed: %w", err)
	}

	if err := f.permitDNS(weightTailscaleTraffic); err != nil {
		return fmt.Errorf("permitDNS failed: %w", err)
	}

	if err := f.permitLoopback(weightTailscaleTraffic); err != nil {
		return fmt.Errorf("permitLoopback failed: %w", err)
	}

	if err := f.permitDHCPv4(weightKnownTraffic); err != nil {
		return fmt.Errorf("permitDHCPv4 failed: %w", err)
	}

	if err := f.permitDHCPv6(weightKnownTraffic); err != nil {
		return fmt.Errorf("permitDHCPv6 failed: %w", err)
	}

	if err := f.permitNDP(weightKnownTraffic); err != nil {
		return fmt.Errorf("permitNDP failed: %w", err)
	}

	/* TODO: actually evaluate if this does anything and if we need this. It's layer 2; our other rules are layer 3.
	 *  In other words, if somebody complains, try enabling it. For now, keep it off.
	 * TODO(maisem): implement this.
	err = permitHyperV(session, baseObjects, weightKnownTraffic)
	if err != nil {
		return wrapErr(err)
	}
	*/

	if err := f.blockAll(weightCatchAll); err != nil {
		return fmt.Errorf("blockAll failed: %w", err)
	}
	return nil
}

// UpdatedPermittedRoutes adds rules to allow incoming and outgoing connections
// from the provided prefixes. It will also remove rules for routes that were
// previously added but have been removed.
func (f *Firewall) UpdatePermittedRoutes(newRoutes []netip.Prefix) error {
	var routesToAdd []netip.Prefix
	routeMap := make(map[netip.Prefix]bool)
	for _, r := range newRoutes {
		routeMap[r] = true
		if _, ok := f.permittedRoutes[r]; !ok {
			routesToAdd = append(routesToAdd, r)
		}
	}
	var routesToRemove []netip.Prefix
	for r := range f.permittedRoutes {
		if !routeMap[r] {
			routesToRemove = append(routesToRemove, r)
		}
	}
	for _, r := range routesToRemove {
		for _, rule := range f.permittedRoutes[r] {
			if err := f.session.DeleteRule(rule.ID); err != nil {
				return err
			}
		}
		delete(f.permittedRoutes, r)
	}
	for _, r := range routesToAdd {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: r,
			},
		}
		var p protocol
		if r.Addr().Is4() {
			p = protocolV4
		} else {
			p = protocolV6
		}
		name := "local route - " + r.String()
		rules, err := f.addRules(name, weightKnownTraffic, conditions, wf.ActionPermit, p, directionBoth)
		if err != nil {
			return err
		}

		name = "link-local multicast - " + r.String()
		conditions = matchLinkLocalMulticast(r, false)
		multicastRules, err := f.addRules(name, weightKnownTraffic, conditions, wf.ActionPermit, p, directionOutbound)
		if err != nil {
			return err
		}
		rules = append(rules, multicastRules...)

		conditions = matchLinkLocalMulticast(r, true)
		multicastRules, err = f.addRules(name, weightKnownTraffic, conditions, wf.ActionPermit, p, directionInbound)
		if err != nil {
			return err
		}
		rules = append(rules, multicastRules...)

		f.permittedRoutes[r] = rules
	}
	return nil
}

// matchLinkLocalMulticast returns a list of conditions that match
// outbound or inbound link-local multicast traffic to or from the
// specified network.
func matchLinkLocalMulticast(pfx netip.Prefix, inbound bool) []*wf.Match {
	var linkLocalMulticastRange netip.Prefix
	if pfx.Addr().Is4() {
		linkLocalMulticastRange = linkLocalMulticastIPv4Range
	} else {
		linkLocalMulticastRange = linkLocalMulticastIPv6Range
	}
	var localAddr, remoteAddr netip.Prefix
	if inbound {
		localAddr, remoteAddr = linkLocalMulticastRange, pfx
	} else {
		localAddr, remoteAddr = pfx, linkLocalMulticastRange
	}
	return []*wf.Match{
		{
			Field: wf.FieldIPProtocol,
			Op:    wf.MatchTypeEqual,
			Value: wf.IPProtoUDP,
		},
		{
			Field: wf.FieldIPLocalAddress,
			Op:    wf.MatchTypeEqual,
			Value: localAddr,
		},
		{
			Field: wf.FieldIPRemoteAddress,
			Op:    wf.MatchTypeEqual,
			Value: remoteAddr,
		},
	}
}

func (f *Firewall) newRule(name string, w weight, layer wf.LayerID, conditions []*wf.Match, action wf.Action) (*wf.Rule, error) {
	id, err := windows.GenerateGUID()
	if err != nil {
		return nil, err
	}
	return &wf.Rule{
		Name:       ruleName(action, layer, name),
		ID:         wf.RuleID(id),
		Provider:   f.providerID,
		Sublayer:   f.sublayerID,
		Layer:      layer,
		Weight:     uint64(w),
		Conditions: conditions,
		Action:     action,
	}, nil
}

func (f *Firewall) addRules(name string, w weight, conditions []*wf.Match, action wf.Action, p protocol, d direction) ([]*wf.Rule, error) {
	var rules []*wf.Rule
	for _, layer := range p.getLayers(d) {
		r, err := f.newRule(name, w, layer, conditions, action)
		if err != nil {
			return nil, err
		}
		if err := f.session.AddRule(r); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (f *Firewall) blockAll(w weight) error {
	_, err := f.addRules("all", w, nil, wf.ActionBlock, protocolAll, directionBoth)
	return err
}

func (f *Firewall) permitNDP(w weight) error {
	// These are aliased according to:
	// https://social.msdn.microsoft.com/Forums/azure/en-US/eb2aa3cd-5f1c-4461-af86-61e7d43ccc23/filtering-icmp-by-type-code?forum=wfp
	fieldICMPType := wf.FieldIPLocalPort
	fieldICMPCode := wf.FieldIPRemotePort

	var icmpConditions = func(t, c uint16, remoteAddress any) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoICMPV6,
			},
			{
				Field: fieldICMPType,
				Op:    wf.MatchTypeEqual,
				Value: t,
			},
			{
				Field: fieldICMPCode,
				Op:    wf.MatchTypeEqual,
				Value: c,
			},
		}
		if remoteAddress != nil {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: linkLocalRouterMulticast,
			})
		}
		return conditions
	}
	/* TODO: actually handle the hop limit somehow! The rules should vaguely be:
	 *  - icmpv6 133: must be outgoing, dst must be FF02::2/128, hop limit must be 255
	 *  - icmpv6 134: must be incoming, src must be FE80::/10, hop limit must be 255
	 *  - icmpv6 135: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 136: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 137: must be incoming, src must be FE80::/10, hop limit must be 255
	 */

	//
	// Router Solicitation Message
	// ICMP type 133, code 0. Outgoing.
	//
	conditions := icmpConditions(133, 0, linkLocalRouterMulticast)
	if _, err := f.addRules("NDP type 133", w, conditions, wf.ActionPermit, protocolV6, directionOutbound); err != nil {
		return err
	}

	//
	// Router Advertisement Message
	// ICMP type 134, code 0. Incoming.
	//
	conditions = icmpConditions(134, 0, linkLocalRange)
	if _, err := f.addRules("NDP type 134", w, conditions, wf.ActionPermit, protocolV6, directionInbound); err != nil {
		return err
	}

	//
	// Neighbor Solicitation Message
	// ICMP type 135, code 0. Bi-directional.
	//
	conditions = icmpConditions(135, 0, nil)
	if _, err := f.addRules("NDP type 135", w, conditions, wf.ActionPermit, protocolV6, directionBoth); err != nil {
		return err
	}

	//
	// Neighbor Advertisement Message
	// ICMP type 136, code 0. Bi-directional.
	//
	conditions = icmpConditions(136, 0, nil)
	if _, err := f.addRules("NDP type 136", w, conditions, wf.ActionPermit, protocolV6, directionBoth); err != nil {
		return err
	}

	//
	// Redirect Message
	// ICMP type 137, code 0. Incoming.
	//
	conditions = icmpConditions(137, 0, linkLocalRange)
	if _, err := f.addRules("NDP type 137", w, conditions, wf.ActionPermit, protocolV6, directionInbound); err != nil {
		return err
	}
	return nil
}

func (f *Firewall) permitDHCPv6(w weight) error {
	var dhcpConditions = func(remoteAddrs ...any) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalAddress,
				Op:    wf.MatchTypeEqual,
				Value: linkLocalRange,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(546),
			},
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(547),
			},
		}
		for _, a := range remoteAddrs {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: a,
			})
		}
		return conditions
	}
	conditions := dhcpConditions(linkLocalDHCPMulticast, siteLocalDHCPMulticast)
	if _, err := f.addRules("DHCP request", w, conditions, wf.ActionPermit, protocolV6, directionOutbound); err != nil {
		return err
	}
	conditions = dhcpConditions(linkLocalRange)
	if _, err := f.addRules("DHCP response", w, conditions, wf.ActionPermit, protocolV6, directionInbound); err != nil {
		return err
	}
	return nil
}

func (f *Firewall) permitDHCPv4(w weight) error {
	var dhcpConditions = func(remoteAddrs ...any) []*wf.Match {
		conditions := []*wf.Match{
			{
				Field: wf.FieldIPProtocol,
				Op:    wf.MatchTypeEqual,
				Value: wf.IPProtoUDP,
			},
			{
				Field: wf.FieldIPLocalPort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(68),
			},
			{
				Field: wf.FieldIPRemotePort,
				Op:    wf.MatchTypeEqual,
				Value: uint16(67),
			},
		}
		for _, a := range remoteAddrs {
			conditions = append(conditions, &wf.Match{
				Field: wf.FieldIPRemoteAddress,
				Op:    wf.MatchTypeEqual,
				Value: a,
			})
		}
		return conditions
	}
	conditions := dhcpConditions(netaddr.IPv4(255, 255, 255, 255))
	if _, err := f.addRules("DHCP request", w, conditions, wf.ActionPermit, protocolV4, directionOutbound); err != nil {
		return err
	}

	conditions = dhcpConditions()
	if _, err := f.addRules("DHCP response", w, conditions, wf.ActionPermit, protocolV4, directionInbound); err != nil {
		return err
	}
	return nil
}

func (f *Firewall) permitTunInterface(w weight) error {
	condition := []*wf.Match{
		{
			Field: wf.FieldIPLocalInterface,
			Op:    wf.MatchTypeEqual,
			Value: f.luid,
		},
	}
	_, err := f.addRules("on TUN", w, condition, wf.ActionPermit, protocolAll, directionBoth)
	return err
}

func (f *Firewall) permitLoopback(w weight) error {
	condition := []*wf.Match{
		{
			Field: wf.FieldFlags,
			Op:    wf.MatchTypeFlagsAllSet,
			Value: wf.ConditionFlagIsLoopback,
		},
	}
	_, err := f.addRules("on loopback", w, condition, wf.ActionPermit, protocolAll, directionBoth)
	return err
}

func (f *Firewall) permitDNS(w weight) error {
	conditions := []*wf.Match{
		{
			Field: wf.FieldIPRemotePort,
			Op:    wf.MatchTypeEqual,
			Value: uint16(53),
		},
		// Repeat the condition type for logical OR.
		{
			Field: wf.FieldIPProtocol,
			Op:    wf.MatchTypeEqual,
			Value: wf.IPProtoUDP,
		},
		{
			Field: wf.FieldIPProtocol,
			Op:    wf.MatchTypeEqual,
			Value: wf.IPProtoTCP,
		},
	}
	_, err := f.addRules("DNS", w, conditions, wf.ActionPermit, protocolAll, directionBoth)
	return err
}

func (f *Firewall) permitTailscaleService(w weight) error {
	currentFile, err := os.Executable()
	if err != nil {
		return err
	}

	appID, err := wf.AppID(currentFile)
	if err != nil {
		return fmt.Errorf("could not get app id for %q: %w", currentFile, err)
	}
	conditions := []*wf.Match{
		{
			Field: wf.FieldALEAppID,
			Op:    wf.MatchTypeEqual,
			Value: appID,
		},
	}
	_, err = f.addRules("unrestricted traffic for Tailscale service", w, conditions, wf.ActionPermit, protocolAll, directionBoth)
	return err
}
