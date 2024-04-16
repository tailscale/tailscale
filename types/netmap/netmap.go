// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netmap contains the netmap.NetworkMap type.
package netmap

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/filter"
)

// NetworkMap is the current state of the world.
//
// The fields should all be considered read-only. They might
// alias parts of previous NetworkMap values.
type NetworkMap struct {
	SelfNode   tailcfg.NodeView
	AllCaps    set.Set[tailcfg.NodeCapability] // set version of SelfNode.Capabilities + SelfNode.CapMap
	NodeKey    key.NodePublic
	PrivateKey key.NodePrivate
	Expiry     time.Time
	// Name is the DNS name assigned to this node.
	// It is the MapResponse.Node.Name value and ends with a period.
	Name string

	MachineKey key.MachinePublic

	Peers []tailcfg.NodeView // sorted by Node.ID
	DNS   tailcfg.DNSConfig

	PacketFilter      []filter.Match
	PacketFilterRules views.Slice[tailcfg.FilterRule]
	SSHPolicy         *tailcfg.SSHPolicy // or nil, if not enabled/allowed

	// CollectServices reports whether this node's Tailnet has
	// requested that info about services be included in HostInfo.
	// If set, Hostinfo.ShieldsUp blocks services collection; that
	// takes precedence over this field.
	CollectServices bool

	// DERPMap is the last DERP server map received. It's reused
	// between updates and should not be modified.
	DERPMap *tailcfg.DERPMap

	// ControlHealth are the list of health check problems for this
	// node from the perspective of the control plane.
	// If empty, there are no known problems from the control plane's
	// point of view, but the node might know about its own health
	// check problems.
	ControlHealth []string

	// TKAEnabled indicates whether the tailnet key authority should be
	// enabled, from the perspective of the control plane.
	TKAEnabled bool
	// TKAHead indicates the control plane's understanding of 'head' (the
	// hash of the latest update message to tick through TKA).
	TKAHead tka.AUMHash

	// Domain is the current Tailnet name.
	Domain string

	// DomainAuditLogID is an audit log ID provided by control and
	// only populated if the domain opts into data-plane audit logging.
	// If this is empty, then data-plane audit logging is disabled.
	DomainAuditLogID string

	UserProfiles map[tailcfg.UserID]tailcfg.UserProfile

	// MaxKeyDuration describes the MaxKeyDuration setting for the tailnet.
	MaxKeyDuration time.Duration
}

// User returns nm.SelfNode.User if nm.SelfNode is non-nil, otherwise it returns
// 0.
func (nm *NetworkMap) User() tailcfg.UserID {
	if nm.SelfNode.Valid() {
		return nm.SelfNode.User()
	}
	return 0
}

// GetAddresses returns the self node's addresses, or the zero value
// if SelfNode is invalid.
func (nm *NetworkMap) GetAddresses() views.Slice[netip.Prefix] {
	var zero views.Slice[netip.Prefix]
	if !nm.SelfNode.Valid() {
		return zero
	}
	return nm.SelfNode.Addresses()
}

// AnyPeersAdvertiseRoutes reports whether any peer is advertising non-exit node routes.
func (nm *NetworkMap) AnyPeersAdvertiseRoutes() bool {
	for _, p := range nm.Peers {
		if p.PrimaryRoutes().Len() > 0 {
			return true
		}
	}
	return false
}

// GetMachineStatus returns the MachineStatus of the local node.
func (nm *NetworkMap) GetMachineStatus() tailcfg.MachineStatus {
	if !nm.SelfNode.Valid() {
		return tailcfg.MachineUnknown
	}
	if nm.SelfNode.MachineAuthorized() {
		return tailcfg.MachineAuthorized
	}
	return tailcfg.MachineUnauthorized
}

// HasCap reports whether nm is non-nil and nm.AllCaps contains c.
func (nm *NetworkMap) HasCap(c tailcfg.NodeCapability) bool {
	return nm != nil && nm.AllCaps.Contains(c)
}

// PeerByTailscaleIP returns a peer's Node based on its Tailscale IP.
//
// If nm is nil or no peer is found, ok is false.
func (nm *NetworkMap) PeerByTailscaleIP(ip netip.Addr) (peer tailcfg.NodeView, ok bool) {
	// TODO(bradfitz):
	if nm == nil {
		return tailcfg.NodeView{}, false
	}
	for _, n := range nm.Peers {
		ad := n.Addresses()
		for i := range ad.Len() {
			a := ad.At(i)
			if a.Addr() == ip {
				return n, true
			}
		}
	}
	return tailcfg.NodeView{}, false
}

// PeerIndexByNodeID returns the index of the peer with the given nodeID
// in nm.Peers, or -1 if nm is nil or not found.
//
// It assumes nm.Peers is sorted by Node.ID.
func (nm *NetworkMap) PeerIndexByNodeID(nodeID tailcfg.NodeID) int {
	if nm == nil {
		return -1
	}
	idx, ok := sort.Find(len(nm.Peers), func(i int) int {
		return cmp.Compare(nodeID, nm.Peers[i].ID())
	})
	if !ok {
		return -1
	}
	return idx
}

// MagicDNSSuffix returns the domain's MagicDNS suffix (even if MagicDNS isn't
// necessarily in use) of the provided Node.Name value.
//
// It will neither start nor end with a period.
func MagicDNSSuffixOfNodeName(nodeName string) string {
	name := strings.Trim(nodeName, ".")
	if _, rest, ok := strings.Cut(name, "."); ok {
		return rest
	}
	return name
}

// MagicDNSSuffix returns the domain's MagicDNS suffix (even if
// MagicDNS isn't necessarily in use).
//
// It will neither start nor end with a period.
func (nm *NetworkMap) MagicDNSSuffix() string {
	if nm == nil {
		return ""
	}
	return MagicDNSSuffixOfNodeName(nm.Name)
}

// DomainName returns the name of the NetworkMap's
// current tailnet. If the map is nil, it returns
// an empty string.
func (nm *NetworkMap) DomainName() string {
	if nm == nil {
		return ""
	}
	return nm.Domain
}

// SelfCapabilities returns SelfNode.Capabilities if nm and nm.SelfNode are
// non-nil. This is a method so we can use it in envknob/logknob without a
// circular dependency.
func (nm *NetworkMap) SelfCapabilities() views.Slice[tailcfg.NodeCapability] {
	var zero views.Slice[tailcfg.NodeCapability]
	if nm == nil || !nm.SelfNode.Valid() {
		return zero
	}
	out := nm.SelfNode.Capabilities().AsSlice()
	nm.SelfNode.CapMap().Range(func(k tailcfg.NodeCapability, _ views.Slice[tailcfg.RawMessage]) (cont bool) {
		out = append(out, k)
		return true
	})

	return views.SliceOf(out)
}

func (nm *NetworkMap) String() string {
	return nm.Concise()
}

func (nm *NetworkMap) Concise() string {
	buf := new(strings.Builder)

	nm.printConciseHeader(buf)
	for _, p := range nm.Peers {
		printPeerConcise(buf, p)
	}
	return buf.String()
}

func (nm *NetworkMap) VeryConcise() string {
	buf := new(strings.Builder)
	nm.printConciseHeader(buf)
	return buf.String()
}

// PeerWithStableID finds and returns the peer associated to the inputted StableNodeID.
func (nm *NetworkMap) PeerWithStableID(pid tailcfg.StableNodeID) (_ tailcfg.NodeView, ok bool) {
	for _, p := range nm.Peers {
		if p.StableID() == pid {
			return p, true
		}
	}
	return tailcfg.NodeView{}, false
}

// printConciseHeader prints a concise header line representing nm to buf.
//
// If this function is changed to access different fields of nm, keep
// in equalConciseHeader in sync.
func (nm *NetworkMap) printConciseHeader(buf *strings.Builder) {
	fmt.Fprintf(buf, "netmap: self: %v auth=%v",
		nm.NodeKey.ShortString(), nm.GetMachineStatus())
	login := nm.UserProfiles[nm.User()].LoginName
	if login == "" {
		if nm.User().IsZero() {
			login = "?"
		} else {
			login = fmt.Sprint(nm.User())
		}
	}
	fmt.Fprintf(buf, " u=%s", login)
	fmt.Fprintf(buf, " %v", nm.GetAddresses().AsSlice())
	buf.WriteByte('\n')
}

// equalConciseHeader reports whether a and b are equal for the fields
// used by printConciseHeader.
func (a *NetworkMap) equalConciseHeader(b *NetworkMap) bool {
	return a.NodeKey == b.NodeKey &&
		a.GetMachineStatus() == b.GetMachineStatus() &&
		a.User() == b.User() &&
		views.SliceEqual(a.GetAddresses(), b.GetAddresses())
}

// printPeerConcise appends to buf a line representing the peer p.
//
// If this function is changed to access different fields of p, keep
// in nodeConciseEqual in sync.
func printPeerConcise(buf *strings.Builder, p tailcfg.NodeView) {
	aip := make([]string, p.AllowedIPs().Len())
	for i := range aip {
		a := p.AllowedIPs().At(i)
		s := strings.TrimSuffix(fmt.Sprint(a), "/32")
		aip[i] = s
	}

	ep := make([]string, p.Endpoints().Len())
	for i := range ep {
		e := p.Endpoints().At(i).String()
		// Align vertically on the ':' between IP and port
		colon := strings.IndexByte(e, ':')
		spaces := 0
		for colon > 0 && len(e)+spaces-colon < 6 {
			spaces++
			colon--
		}
		ep[i] = fmt.Sprintf("%21v", e+strings.Repeat(" ", spaces))
	}

	derp := p.DERP()
	const derpPrefix = "127.3.3.40:"
	if strings.HasPrefix(derp, derpPrefix) {
		derp = "D" + derp[len(derpPrefix):]
	}
	var discoShort string
	if !p.DiscoKey().IsZero() {
		discoShort = p.DiscoKey().ShortString() + " "
	}

	// Most of the time, aip is just one element, so format the
	// table to look good in that case. This will also make multi-
	// subnet nodes stand out visually.
	fmt.Fprintf(buf, " %v %s%-2v %-15v : %v\n",
		p.Key().ShortString(),
		discoShort,
		derp,
		strings.Join(aip, " "),
		strings.Join(ep, " "))
}

// nodeConciseEqual reports whether a and b are equal for the fields accessed by printPeerConcise.
func nodeConciseEqual(a, b tailcfg.NodeView) bool {
	return a.Key() == b.Key() &&
		a.DERP() == b.DERP() &&
		a.DiscoKey() == b.DiscoKey() &&
		views.SliceEqual(a.AllowedIPs(), b.AllowedIPs()) &&
		views.SliceEqual(a.Endpoints(), b.Endpoints())
}

func (b *NetworkMap) ConciseDiffFrom(a *NetworkMap) string {
	var diff strings.Builder

	// See if header (non-peers, "bare") part of the network map changed.
	// If so, print its diff lines first.
	if !a.equalConciseHeader(b) {
		diff.WriteByte('-')
		a.printConciseHeader(&diff)
		diff.WriteByte('+')
		b.printConciseHeader(&diff)
	}

	aps, bps := a.Peers, b.Peers
	for len(aps) > 0 && len(bps) > 0 {
		pa, pb := aps[0], bps[0]
		switch {
		case pa.ID() == pb.ID():
			if !nodeConciseEqual(pa, pb) {
				diff.WriteByte('-')
				printPeerConcise(&diff, pa)
				diff.WriteByte('+')
				printPeerConcise(&diff, pb)
			}
			aps, bps = aps[1:], bps[1:]
		case pa.ID() > pb.ID():
			// New peer in b.
			diff.WriteByte('+')
			printPeerConcise(&diff, pb)
			bps = bps[1:]
		case pb.ID() > pa.ID():
			// Deleted peer in b.
			diff.WriteByte('-')
			printPeerConcise(&diff, pa)
			aps = aps[1:]
		}
	}
	for _, pa := range aps {
		diff.WriteByte('-')
		printPeerConcise(&diff, pa)
	}
	for _, pb := range bps {
		diff.WriteByte('+')
		printPeerConcise(&diff, pb)
	}
	return diff.String()
}

func (nm *NetworkMap) JSON() string {
	b, err := json.MarshalIndent(*nm, "", "  ")
	if err != nil {
		return fmt.Sprintf("[json error: %v]", err)
	}
	return string(b)
}

// WGConfigFlags is a bitmask of flags to control the behavior of the
// wireguard configuration generation done by NetMap.WGCfg.
type WGConfigFlags int

const (
	AllowSingleHosts WGConfigFlags = 1 << iota
	AllowSubnetRoutes
)
