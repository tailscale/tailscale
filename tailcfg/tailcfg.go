// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tailcfg contains types used by the Tailscale protocol with between
// the node and the coordination server.
package tailcfg

//go:generate go run tailscale.com/cmd/viewer --type=User,Node,Hostinfo,NetInfo,Login,DNSConfig,RegisterResponse,RegisterResponseAuth,RegisterRequest,DERPHomeParams,DERPRegion,DERPMap,DERPNode,SSHRule,SSHAction,SSHPrincipal,ControlDialPlan,Location,UserProfile --clonefunc

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/types/structs"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/slicesx"
)

// CapabilityVersion represents the client's capability level. That
// is, it can be thought of as the client's simple version number: a
// single monotonically increasing integer, rather than the relatively
// complex x.y.z-xxxxx semver+hash(es). Whenever the client gains a
// capability or wants to negotiate a change in semantics with the
// server (control plane),  peers (over PeerAPI), or frontend (over
// LocalAPI), bump this number and document what's new.
//
// Previously (prior to 2022-03-06), it was known as the "MapRequest
// version" or "mapVer" or "map cap" and that name and usage persists
// in places.
type CapabilityVersion int

// CurrentCapabilityVersion is the current capability version of the codebase.
//
// History of versions:
//
//   - 3: implicit compression, keep-alives
//   - 4: opt-in keep-alives via KeepAlive field, opt-in compression via Compress
//   - 5: 2020-10-19, implies IncludeIPv6, delta Peers/UserProfiles, supports MagicDNS
//   - 6: 2020-12-07: means MapResponse.PacketFilter nil means unchanged
//   - 7: 2020-12-15: FilterRule.SrcIPs accepts CIDRs+ranges, doesn't warn about 0.0.0.0/::
//   - 8: 2020-12-19: client can buggily receive IPv6 addresses and routes if beta enabled server-side
//   - 9: 2020-12-30: client doesn't auto-add implicit search domains from peers; only DNSConfig.Domains
//   - 10: 2021-01-17: client understands MapResponse.PeerSeenChange
//   - 11: 2021-03-03: client understands IPv6, multiple default routes, and goroutine dumping
//   - 12: 2021-03-04: client understands PingRequest
//   - 13: 2021-03-19: client understands FilterRule.IPProto
//   - 14: 2021-04-07: client understands DNSConfig.Routes and DNSConfig.Resolvers
//   - 15: 2021-04-12: client treats nil MapResponse.DNSConfig as meaning unchanged
//   - 16: 2021-04-15: client understands Node.Online, MapResponse.OnlineChange
//   - 17: 2021-04-18: MapResponse.Domain empty means unchanged
//   - 18: 2021-04-19: MapResponse.Node nil means unchanged (all fields now omitempty)
//   - 19: 2021-04-21: MapResponse.Debug.SleepSeconds
//   - 20: 2021-06-11: MapResponse.LastSeen used even less (https://github.com/tailscale/tailscale/issues/2107)
//   - 21: 2021-06-15: added MapResponse.DNSConfig.CertDomains
//   - 22: 2021-06-16: added MapResponse.DNSConfig.ExtraRecords
//   - 23: 2021-08-25: DNSConfig.Routes values may be empty (for ExtraRecords support in 1.14.1+)
//   - 24: 2021-09-18: MapResponse.Health from control to node; node shows in "tailscale status"
//   - 25: 2021-11-01: MapResponse.Debug.Exit
//   - 26: 2022-01-12: (nothing, just bumping for 1.20.0)
//   - 27: 2022-02-18: start of SSHPolicy being respected
//   - 28: 2022-03-09: client can communicate over Noise.
//   - 29: 2022-03-21: MapResponse.PopBrowserURL
//   - 30: 2022-03-22: client can request id tokens.
//   - 31: 2022-04-15: PingRequest & PingResponse TSMP & disco support
//   - 32: 2022-04-17: client knows FilterRule.CapMatch
//   - 33: 2022-07-20: added MapResponse.PeersChangedPatch (DERPRegion + Endpoints)
//   - 34: 2022-08-02: client understands CapabilityFileSharingTarget
//   - 36: 2022-08-02: added PeersChangedPatch.{Key,DiscoKey,Online,LastSeen,KeyExpiry,Capabilities}
//   - 37: 2022-08-09: added Debug.{SetForceBackgroundSTUN,SetRandomizeClientPort}; Debug are sticky
//   - 38: 2022-08-11: added PingRequest.URLIsNoise
//   - 39: 2022-08-15: clients can talk Noise over arbitrary HTTPS port
//   - 40: 2022-08-22: added Node.KeySignature, PeersChangedPatch.KeySignature
//   - 41: 2022-08-30: uses 100.100.100.100 for route-less ExtraRecords if global nameservers is set
//   - 42: 2022-09-06: NextDNS DoH support; see https://github.com/tailscale/tailscale/pull/5556
//   - 43: 2022-09-21: clients can return usernames for SSH
//   - 44: 2022-09-22: MapResponse.ControlDialPlan
//   - 45: 2022-09-26: c2n /debug/{goroutines,prefs,metrics}
//   - 46: 2022-10-04: c2n /debug/component-logging
//   - 47: 2022-10-11: Register{Request,Response}.NodeKeySignature
//   - 48: 2022-11-02: Node.UnsignedPeerAPIOnly
//   - 49: 2022-11-03: Client understands EarlyNoise
//   - 50: 2022-11-14: Client understands CapabilityIngress
//   - 51: 2022-11-30: Client understands CapabilityTailnetLockAlpha
//   - 52: 2023-01-05: client can handle c2n POST /logtail/flush
//   - 53: 2023-01-18: client respects explicit Node.Expired + auto-sets based on Node.KeyExpiry
//   - 54: 2023-01-19: Node.Cap added, PeersChangedPatch.Cap, uses Node.Cap for ExitDNS before Hostinfo.Services fallback
//   - 55: 2023-01-23: start of c2n GET+POST /update handler
//   - 56: 2023-01-24: Client understands CapabilityDebugTSDNSResolution
//   - 57: 2023-01-25: Client understands CapabilityBindToInterfaceByRoute
//   - 58: 2023-03-10: Client retries lite map updates before restarting map poll.
//   - 59: 2023-03-16: Client understands Peers[].SelfNodeV4MasqAddrForThisPeer
//   - 60: 2023-04-06: Client understands IsWireGuardOnly
//   - 61: 2023-04-18: Client understand SSHAction.SSHRecorderFailureAction
//   - 62: 2023-05-05: Client can notify control over noise for SSHEventNotificationRequest recording failure events
//   - 63: 2023-06-08: Client understands SSHAction.AllowRemotePortForwarding.
//   - 64: 2023-07-11: Client understands s/CapabilityTailnetLockAlpha/CapabilityTailnetLock
//   - 65: 2023-07-12: Client understands DERPMap.HomeParams + incremental DERPMap updates with params
//   - 66: 2023-07-23: UserProfile.Groups added (available via WhoIs) (removed in 87)
//   - 67: 2023-07-25: Client understands PeerCapMap
//   - 68: 2023-08-09: Client has dedicated updateRoutine; MapRequest.Stream true means ignore Hostinfo+Endpoints
//   - 69: 2023-08-16: removed Debug.LogHeap* + GoroutineDumpURL; added c2n /debug/logheap
//   - 70: 2023-08-16: removed most Debug fields; added NodeAttrDisable*, NodeAttrDebug* instead
//   - 71: 2023-08-17: added NodeAttrOneCGNATEnable, NodeAttrOneCGNATDisable
//   - 72: 2023-08-23: TS-2023-006 UPnP issue fixed; UPnP can now be used again
//   - 73: 2023-09-01: Non-Windows clients expect to receive ClientVersion
//   - 74: 2023-09-18: Client understands NodeCapMap
//   - 75: 2023-09-12: Client understands NodeAttrDNSForwarderDisableTCPRetries
//   - 76: 2023-09-20: Client understands ExitNodeDNSResolvers for IsWireGuardOnly nodes
//   - 77: 2023-10-03: Client understands Peers[].SelfNodeV6MasqAddrForThisPeer
//   - 78: 2023-10-05: can handle c2n Wake-on-LAN sending
//   - 79: 2023-10-05: Client understands UrgentSecurityUpdate in ClientVersion
//   - 80: 2023-11-16: can handle c2n GET /tls-cert-status
//   - 81: 2023-11-17: MapResponse.PacketFilters (incremental packet filter updates)
//   - 82: 2023-12-01: Client understands NodeAttrLinuxMustUseIPTables, NodeAttrLinuxMustUseNfTables, c2n /netfilter-kind
//   - 83: 2023-12-18: Client understands DefaultAutoUpdate
//   - 84: 2024-01-04: Client understands SeamlessKeyRenewal
//   - 85: 2024-01-05: Client understands MaxKeyDuration
//   - 86: 2024-01-23: Client understands NodeAttrProbeUDPLifetime
//   - 87: 2024-02-11: UserProfile.Groups removed (added in 66)
//   - 88: 2024-03-05: Client understands NodeAttrSuggestExitNode
//   - 89: 2024-03-23: Client no longer respects deleted PeerChange.Capabilities (use CapMap)
//   - 90: 2024-04-03: Client understands PeerCapabilityTaildrive.
//   - 91: 2024-04-24: Client understands PeerCapabilityTaildriveSharer.
//   - 92: 2024-05-06: Client understands NodeAttrUserDialUseRoutes.
//   - 93: 2024-05-06: added support for stateful firewalling.
//   - 94: 2024-05-06: Client understands Node.IsJailed.
//   - 95: 2024-05-06: Client uses NodeAttrUserDialUseRoutes to change DNS dialing behavior.
//   - 96: 2024-05-29: Client understands NodeAttrSSHBehaviorV1
//   - 97: 2024-06-06: Client understands NodeAttrDisableSplitDNSWhenNoCustomResolvers
//   - 98: 2024-06-13: iOS/tvOS clients may provide serial number as part of posture information
//   - 99: 2024-06-14: Client understands NodeAttrDisableLocalDNSOverrideViaNRPT
//   - 100: 2024-06-18: Client supports filtertype.Match.SrcCaps (issue #12542)
//   - 101: 2024-07-01: Client supports SSH agent forwarding when handling connections with /bin/su
//   - 102: 2024-07-12: NodeAttrDisableMagicSockCryptoRouting support
//   - 103: 2024-07-24: Client supports NodeAttrDisableCaptivePortalDetection
//   - 104: 2024-08-03: SelfNodeV6MasqAddrForThisPeer now works
const CurrentCapabilityVersion CapabilityVersion = 104

type StableID string

type ID int64

type UserID ID

func (u UserID) IsZero() bool {
	return u == 0
}

type LoginID ID

func (u LoginID) IsZero() bool {
	return u == 0
}

type NodeID ID

func (u NodeID) IsZero() bool {
	return u == 0
}

type StableNodeID StableID

func (u StableNodeID) IsZero() bool {
	return u == ""
}

// User is an IPN user.
//
// A user can have multiple logins associated with it (e.g. gmail and github oauth).
// (Note: none of our UIs support this yet.)
//
// Some properties are inherited from the logins and can be overridden, such as
// display name and profile picture.
//
// Other properties must be the same for all logins associated with a user.
// In particular: domain. If a user has a "tailscale.io" domain login, they cannot
// have a general gmail address login associated with the user.
type User struct {
	ID            UserID
	LoginName     string `json:"-"` // not stored, filled from Login // TODO REMOVE
	DisplayName   string // if non-empty overrides Login field
	ProfilePicURL string // if non-empty overrides Login field
	Logins        []LoginID
	Created       time.Time
}

type Login struct {
	_             structs.Incomparable
	ID            LoginID
	Provider      string
	LoginName     string
	DisplayName   string
	ProfilePicURL string
}

// A UserProfile is display-friendly data for a user.
// It includes the LoginName for display purposes but *not* the Provider.
// It also includes derived data from one of the user's logins.
type UserProfile struct {
	ID            UserID
	LoginName     string // "alice@smith.com"; for display purposes only (provider is not listed)
	DisplayName   string // "Alice Smith"
	ProfilePicURL string

	// Roles exists for legacy reasons, to keep old macOS clients
	// happy. It JSON marshals as [].
	Roles emptyStructJSONSlice
}

func (p *UserProfile) Equal(p2 *UserProfile) bool {
	if p == nil && p2 == nil {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}
	return p.ID == p2.ID &&
		p.LoginName == p2.LoginName &&
		p.DisplayName == p2.DisplayName &&
		p.ProfilePicURL == p2.ProfilePicURL
}

type emptyStructJSONSlice struct{}

var emptyJSONSliceBytes = []byte("[]")

func (emptyStructJSONSlice) MarshalJSON() ([]byte, error) {
	return emptyJSONSliceBytes, nil
}

func (emptyStructJSONSlice) UnmarshalJSON([]byte) error { return nil }

// RawMessage is a raw encoded JSON value. It implements Marshaler and
// Unmarshaler and can be used to delay JSON decoding or precompute a JSON
// encoding.
//
// It is like json.RawMessage but is a string instead of a []byte to better
// portray immutable data.
type RawMessage string

// MarshalJSON returns m as the JSON encoding of m.
func (m RawMessage) MarshalJSON() ([]byte, error) {
	if m == "" {
		return []byte("null"), nil
	}
	return []byte(m), nil
}

// UnmarshalJSON sets *m to a copy of data.
func (m *RawMessage) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("RawMessage: UnmarshalJSON on nil pointer")
	}
	*m = RawMessage(data)
	return nil
}

// MarshalCapJSON returns a capability rule in RawMessage string format.
func MarshalCapJSON[T any](capRule T) (RawMessage, error) {
	bs, err := json.Marshal(capRule)
	if err != nil {
		return "", fmt.Errorf("error marshalling capability rule: %w", err)
	}
	return RawMessage(string(bs)), nil
}

type Node struct {
	ID       NodeID
	StableID StableNodeID

	// Name is the FQDN of the node.
	// It is also the MagicDNS name for the node.
	// It has a trailing dot.
	// e.g. "host.tail-scale.ts.net."
	Name string

	// User is the user who created the node. If ACL tags are in use for the
	// node then it doesn't reflect the ACL identity that the node is running
	// as.
	User UserID

	// Sharer, if non-zero, is the user who shared this node, if different than User.
	Sharer UserID `json:",omitempty"`

	Key          key.NodePublic
	KeyExpiry    time.Time                  // the zero value if this node does not expire
	KeySignature tkatype.MarshaledSignature `json:",omitempty"`
	Machine      key.MachinePublic
	DiscoKey     key.DiscoPublic
	Addresses    []netip.Prefix   // IP addresses of this Node directly
	AllowedIPs   []netip.Prefix   // range of IP addresses to route to this node
	Endpoints    []netip.AddrPort `json:",omitempty"` // IP+port (public via STUN, and local LANs)

	// DERP is this node's home DERP region ID integer, but shoved into an
	// IP:port string for legacy reasons. The IP address is always "127.3.3.40"
	// (a loopback address (127) followed by the digits over the letters DERP on
	// a QWERTY keyboard (3.3.40)). The "port number" is the home DERP region ID
	// integer.
	//
	// TODO(bradfitz): simplify this legacy mess; add a new HomeDERPRegionID int
	// field behind a new capver bump.
	DERP string `json:",omitempty"` // DERP-in-IP:port ("127.3.3.40:N") endpoint

	Hostinfo HostinfoView
	Created  time.Time
	Cap      CapabilityVersion `json:",omitempty"` // if non-zero, the node's capability version; old servers might not send

	// Tags are the list of ACL tags applied to this node.
	// Tags take the form of `tag:<value>` where value starts
	// with a letter and only contains alphanumerics and dashes `-`.
	// Some valid tag examples:
	//   `tag:prod`
	//   `tag:database`
	//   `tag:lab-1`
	Tags []string `json:",omitempty"`

	// PrimaryRoutes are the routes from AllowedIPs that this node
	// is currently the primary subnet router for, as determined
	// by the control plane. It does not include the self address
	// values from Addresses that are in AllowedIPs.
	PrimaryRoutes []netip.Prefix `json:",omitempty"`

	// LastSeen is when the node was last online. It is not
	// updated when Online is true. It is nil if the current
	// node doesn't have permission to know, or the node
	// has never been online.
	LastSeen *time.Time `json:",omitempty"`

	// Online is whether the node is currently connected to the
	// coordination server.  A value of nil means unknown, or the
	// current node doesn't have permission to know.
	Online *bool `json:",omitempty"`

	MachineAuthorized bool `json:",omitempty"` // TODO(crawshaw): replace with MachineStatus

	// Capabilities are capabilities that the node has.
	// They're free-form strings, but should be in the form of URLs/URIs
	// such as:
	//    "https://tailscale.com/cap/is-admin"
	//    "https://tailscale.com/cap/file-sharing"
	//
	// Deprecated: use CapMap instead. See https://github.com/tailscale/tailscale/issues/11508
	Capabilities []NodeCapability `json:",omitempty"`

	// CapMap is a map of capabilities to their optional argument/data values.
	//
	// It is valid for a capability to not have any argument/data values; such
	// capabilities can be tested for using the HasCap method. These type of
	// capabilities are used to indicate that a node has a capability, but there
	// is no additional data associated with it. These were previously
	// represented by the Capabilities field, but can now be represented by
	// CapMap with an empty value.
	//
	// See NodeCapability for more information on keys.
	//
	// Metadata about nodes can be transmitted in 3 ways:
	// 1. MapResponse.Node.CapMap describes attributes that affect behavior for
	//    this node, such as which features have been enabled through the admin
	//    panel and any associated configuration details.
	// 2. MapResponse.PacketFilter(s) describes access (both IP and application
	//    based) that should be granted to peers.
	// 3. MapResponse.Peers[].CapMap describes attributes regarding a peer node,
	//    such as which features the peer supports or if that peer is preferred
	//    for a particular task vs other peers that could also be chosen.
	CapMap NodeCapMap `json:",omitempty"`

	// UnsignedPeerAPIOnly means that this node is not signed nor subject to TKA
	// restrictions. However, in exchange for that privilege, it does not get
	// network access. It can only access this node's peerapi, which may not let
	// it do anything. It is the tailscaled client's job to double-check the
	// MapResponse's PacketFilter to verify that its AllowedIPs will not be
	// accepted by the packet filter.
	UnsignedPeerAPIOnly bool `json:",omitempty"`

	// The following three computed fields hold the various names that can
	// be used for this node in UIs. They are populated from controlclient
	// (not from control) by calling node.InitDisplayNames. These can be
	// used directly or accessed via node.DisplayName or node.DisplayNames.

	ComputedName            string `json:",omitempty"` // MagicDNS base name (for normal non-shared-in nodes), FQDN (without trailing dot, for shared-in nodes), or Hostname (if no MagicDNS)
	computedHostIfDifferent string // hostname, if different than ComputedName, otherwise empty
	ComputedNameWithHost    string `json:",omitempty"` // either "ComputedName" or "ComputedName (computedHostIfDifferent)", if computedHostIfDifferent is set

	// DataPlaneAuditLogID is the per-node logtail ID used for data plane audit logging.
	DataPlaneAuditLogID string `json:",omitempty"`

	// Expired is whether this node's key has expired. Control may send
	// this; clients are only allowed to set this from false to true. On
	// the client, this is calculated client-side based on a timestamp sent
	// from control, to avoid clock skew issues.
	Expired bool `json:",omitempty"`

	// SelfNodeV4MasqAddrForThisPeer is the IPv4 that this peer knows the current node as.
	// It may be empty if the peer knows the current node by its native
	// IPv4 address.
	// This field is only populated in a MapResponse for peers and not
	// for the current node.
	//
	// If set, it should be used to masquerade traffic originating from the
	// current node to this peer. The masquerade address is only relevant
	// for this peer and not for other peers.
	//
	// This only applies to traffic originating from the current node to the
	// peer or any of its subnets. Traffic originating from subnet routes will
	// not be masqueraded (e.g. in case of --snat-subnet-routes).
	SelfNodeV4MasqAddrForThisPeer *netip.Addr `json:",omitempty"`

	// SelfNodeV6MasqAddrForThisPeer is the IPv6 that this peer knows the current node as.
	// It may be empty if the peer knows the current node by its native
	// IPv6 address.
	// This field is only populated in a MapResponse for peers and not
	// for the current node.
	//
	// If set, it should be used to masquerade traffic originating from the
	// current node to this peer. The masquerade address is only relevant
	// for this peer and not for other peers.
	//
	// This only applies to traffic originating from the current node to the
	// peer or any of its subnets. Traffic originating from subnet routes will
	// not be masqueraded (e.g. in case of --snat-subnet-routes).
	SelfNodeV6MasqAddrForThisPeer *netip.Addr `json:",omitempty"`

	// IsWireGuardOnly indicates that this is a non-Tailscale WireGuard peer, it
	// is not expected to speak Disco or DERP, and it must have Endpoints in
	// order to be reachable.
	IsWireGuardOnly bool `json:",omitempty"`

	// IsJailed indicates that this node is jailed and should not be allowed
	// initiate connections, however outbound connections to it should still be
	// allowed.
	IsJailed bool `json:",omitempty"`

	// ExitNodeDNSResolvers is the list of DNS servers that should be used when this
	// node is marked IsWireGuardOnly and being used as an exit node.
	ExitNodeDNSResolvers []*dnstype.Resolver `json:",omitempty"`
}

// HasCap reports whether the node has the given capability.
// It is safe to call on an invalid NodeView.
func (v NodeView) HasCap(cap NodeCapability) bool {
	return v.ж.HasCap(cap)
}

// HasCap reports whether the node has the given capability.
// It is safe to call on a nil Node.
func (v *Node) HasCap(cap NodeCapability) bool {
	return v != nil && v.CapMap.Contains(cap)
}

// DisplayName returns the user-facing name for a node which should
// be shown in client UIs.
//
// Parameter forOwner specifies whether the name is requested by
// the owner of the node. When forOwner is false, the hostname is
// never included in the return value.
//
// Return value is either "Name" or "Name (Hostname)", where
// Name is the node's MagicDNS base name (for normal non-shared-in
// nodes), FQDN (without trailing dot, for shared-in nodes), or
// Hostname (if no MagicDNS). Hostname is only included in the
// return value if it varies from Name and forOwner is provided true.
//
// DisplayName is only valid if InitDisplayNames has been called.
func (n *Node) DisplayName(forOwner bool) string {
	if forOwner {
		return n.ComputedNameWithHost
	}
	return n.ComputedName
}

// DisplayName returns the decomposed user-facing name for a node.
//
// Parameter forOwner specifies whether the name is requested by
// the owner of the node. When forOwner is false, hostIfDifferent
// is always returned empty.
//
// Return value name is the node's primary name, populated with the
// node's MagicDNS base name (for normal non-shared-in nodes), FQDN
// (without trailing dot, for shared-in nodes), or Hostname (if no
// MagicDNS).
//
// Return value hostIfDifferent, when non-empty, is the node's
// hostname. hostIfDifferent is only populated when the hostname
// varies from name and forOwner is provided as true.
//
// DisplayNames is only valid if InitDisplayNames has been called.
func (n *Node) DisplayNames(forOwner bool) (name, hostIfDifferent string) {
	if forOwner {
		return n.ComputedName, n.computedHostIfDifferent
	}
	return n.ComputedName, ""
}

// IsTagged reports whether the node has any tags.
func (n *Node) IsTagged() bool {
	return len(n.Tags) > 0
}

// SharerOrUser Sharer if set, else User.
func (n *Node) SharerOrUser() UserID {
	return cmp.Or(n.Sharer, n.User)
}

// IsTagged reports whether the node has any tags.
func (n NodeView) IsTagged() bool { return n.ж.IsTagged() }

// DisplayName wraps Node.DisplayName.
func (n NodeView) DisplayName(forOwner bool) string { return n.ж.DisplayName(forOwner) }

// SharerOrUser wraps Node.SharerOrUser.
func (n NodeView) SharerOrUser() UserID { return n.ж.SharerOrUser() }

// InitDisplayNames computes and populates n's display name
// fields: n.ComputedName, n.computedHostIfDifferent, and
// n.ComputedNameWithHost.
func (n *Node) InitDisplayNames(networkMagicDNSSuffix string) {
	name := dnsname.TrimSuffix(n.Name, networkMagicDNSSuffix)
	var hostIfDifferent string
	if n.Hostinfo.Valid() {
		hostIfDifferent = dnsname.SanitizeHostname(n.Hostinfo.Hostname())
	}

	if strings.EqualFold(name, hostIfDifferent) {
		hostIfDifferent = ""
	}
	if name == "" {
		if hostIfDifferent != "" {
			name = hostIfDifferent
			hostIfDifferent = ""
		} else {
			name = n.Key.String()
		}
	}

	var nameWithHost string
	if hostIfDifferent != "" {
		nameWithHost = fmt.Sprintf("%s (%s)", name, hostIfDifferent)
	} else {
		nameWithHost = name
	}

	n.ComputedName = name
	n.computedHostIfDifferent = hostIfDifferent
	n.ComputedNameWithHost = nameWithHost
}

type MachineStatus int

const (
	MachineUnknown      = MachineStatus(iota)
	MachineUnauthorized // server has yet to approve
	MachineAuthorized   // server has approved
	MachineInvalid      // server has explicitly rejected this machine key
)

func (m MachineStatus) AppendText(b []byte) ([]byte, error) {
	return append(b, m.String()...), nil
}

func (m MachineStatus) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func (m *MachineStatus) UnmarshalText(b []byte) error {
	switch string(b) {
	case "machine-unknown":
		*m = MachineUnknown
	case "machine-unauthorized":
		*m = MachineUnauthorized
	case "machine-authorized":
		*m = MachineAuthorized
	case "machine-invalid":
		*m = MachineInvalid
	default:
		var val int
		if _, err := fmt.Sscanf(string(b), "machine-unknown(%d)", &val); err != nil {
			*m = MachineStatus(val)
		} else {
			*m = MachineUnknown
		}
	}
	return nil
}

func (m MachineStatus) String() string {
	switch m {
	case MachineUnknown:
		return "machine-unknown"
	case MachineUnauthorized:
		return "machine-unauthorized"
	case MachineAuthorized:
		return "machine-authorized"
	case MachineInvalid:
		return "machine-invalid"
	default:
		return fmt.Sprintf("machine-unknown(%d)", int(m))
	}
}

func isNum(b byte) bool {
	return b >= '0' && b <= '9'
}

func isAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// CheckTag validates tag for use as an ACL tag.
// For now we allow only ascii alphanumeric tags, and they need to start
// with a letter. No unicode shenanigans allowed, and we reserve punctuation
// marks other than '-' for a possible future URI scheme.
//
// Because we're ignoring unicode entirely, we can treat utf-8 as a series of
// bytes. Anything >= 128 is disqualified anyway.
//
// We might relax these rules later.
func CheckTag(tag string) error {
	var ok bool
	tag, ok = strings.CutPrefix(tag, "tag:")
	if !ok {
		return errors.New("tags must start with 'tag:'")
	}
	if tag == "" {
		return errors.New("tag names must not be empty")
	}
	if !isAlpha(tag[0]) {
		return errors.New("tag names must start with a letter, after 'tag:'")
	}

	for _, b := range []byte(tag) {
		if !isNum(b) && !isAlpha(b) && b != '-' {
			return errors.New("tag names can only contain numbers, letters, or dashes")
		}
	}

	return nil
}

// CheckRequestTags checks that all of h.RequestTags are valid.
func (h *Hostinfo) CheckRequestTags() error {
	if h == nil {
		return nil
	}
	for _, tag := range h.RequestTags {
		if err := CheckTag(tag); err != nil {
			return fmt.Errorf("tag(%#v): %w", tag, err)
		}
	}
	return nil
}

// ServiceProto is a service type. It's usually
// TCP ("tcp") or UDP ("udp"), but it can also have
// meta service values as defined in Service.Proto.
type ServiceProto string

const (
	TCP        = ServiceProto("tcp")
	UDP        = ServiceProto("udp")
	PeerAPI4   = ServiceProto("peerapi4")
	PeerAPI6   = ServiceProto("peerapi6")
	PeerAPIDNS = ServiceProto("peerapi-dns-proxy")
)

// Service represents a service running on a node.
type Service struct {
	_ structs.Incomparable

	// Proto is the type of service. It's usually the constant TCP
	// or UDP ("tcp" or "udp"), but it can also be one of the
	// following meta service values:
	//
	//     * "peerapi4": peerapi is available on IPv4; Port is the
	//        port number that the peerapi is running on the
	//        node's Tailscale IPv4 address.
	//     * "peerapi6": peerapi is available on IPv6; Port is the
	//        port number that the peerapi is running on the
	//        node's Tailscale IPv6 address.
	//     * "peerapi-dns-proxy": the local peerapi service supports
	//        being a DNS proxy (when the node is an exit
	//        node). For this service, the Port number must only be 1.
	Proto ServiceProto

	// Port is the port number.
	//
	// For Proto "peerapi-dns", it must be 1.
	Port uint16

	// Description is the textual description of the service,
	// usually the process name that's running.
	Description string `json:",omitempty"`

	// TODO(apenwarr): allow advertising services on subnet IPs?
	// TODO(apenwarr): add "tags" here for each service?
}

// Location represents geographical location data about a
// Tailscale host. Location is optional and only set if
// explicitly declared by a node.
type Location struct {
	Country     string `json:",omitempty"` // User friendly country name, with proper capitalization ("Canada")
	CountryCode string `json:",omitempty"` // ISO 3166-1 alpha-2 in upper case ("CA")
	City        string `json:",omitempty"` // User friendly city name, with proper capitalization ("Squamish")

	// CityCode is a short code representing the city in upper case.
	// CityCode is used to disambiguate a city from another location
	// with the same city name. It uniquely identifies a particular
	// geographical location, within the tailnet.
	// IATA, ICAO or ISO 3166-2 codes are recommended ("YSE")
	CityCode string `json:",omitempty"`

	// Latitude, Longitude are optional geographical coordinates of the node, in degrees.
	// No particular accuracy level is promised; the coordinates may simply be the center of the city or country.
	Latitude  float64 `json:",omitempty"`
	Longitude float64 `json:",omitempty"`

	// Priority determines the order of use of an exit node when a
	// location based preference matches more than one exit node,
	// the node with the highest priority wins. Nodes of equal
	// probability may be selected arbitrarily.
	//
	// A value of 0 means the exit node does not have a priority
	// preference. A negative int is not allowed.
	Priority int `json:",omitempty"`
}

// Hostinfo contains a summary of a Tailscale host.
//
// Because it contains pointers (slices), this type should not be used
// as a value type.
type Hostinfo struct {
	IPNVersion    string `json:",omitempty"` // version of this code (in version.Long format)
	FrontendLogID string `json:",omitempty"` // logtail ID of frontend instance
	BackendLogID  string `json:",omitempty"` // logtail ID of backend instance
	OS            string `json:",omitempty"` // operating system the client runs on (a version.OS value)

	// OSVersion is the version of the OS, if available.
	//
	// For Android, it's like "10", "11", "12", etc. For iOS and macOS it's like
	// "15.6.1" or "12.4.0". For Windows it's like "10.0.19044.1889". For
	// FreeBSD it's like "12.3-STABLE".
	//
	// For Linux, prior to Tailscale 1.32, we jammed a bunch of fields into this
	// string on Linux, like "Debian 10.4; kernel=xxx; container; env=kn" and so
	// on. As of Tailscale 1.32, this is simply the kernel version on Linux, like
	// "5.10.0-17-amd64".
	OSVersion string `json:",omitempty"`

	Container      opt.Bool `json:",omitempty"` // whether the client is running in a container
	Env            string   `json:",omitempty"` // a hostinfo.EnvType in string form
	Distro         string   `json:",omitempty"` // "debian", "ubuntu", "nixos", ...
	DistroVersion  string   `json:",omitempty"` // "20.04", ...
	DistroCodeName string   `json:",omitempty"` // "jammy", "bullseye", ...

	// App is used to disambiguate Tailscale clients that run using tsnet.
	App string `json:",omitempty"` // "k8s-operator", "golinks", ...

	Desktop         opt.Bool       `json:",omitempty"` // if a desktop was detected on Linux
	Package         string         `json:",omitempty"` // Tailscale package to disambiguate ("choco", "appstore", etc; "" for unknown)
	DeviceModel     string         `json:",omitempty"` // mobile phone model ("Pixel 3a", "iPhone12,3")
	PushDeviceToken string         `json:",omitempty"` // macOS/iOS APNs device token for notifications (and Android in the future)
	Hostname        string         `json:",omitempty"` // name of the host the client runs on
	ShieldsUp       bool           `json:",omitempty"` // indicates whether the host is blocking incoming connections
	ShareeNode      bool           `json:",omitempty"` // indicates this node exists in netmap because it's owned by a shared-to user
	NoLogsNoSupport bool           `json:",omitempty"` // indicates that the user has opted out of sending logs and support
	WireIngress     bool           `json:",omitempty"` // indicates that the node wants the option to receive ingress connections
	AllowsUpdate    bool           `json:",omitempty"` // indicates that the node has opted-in to admin-console-drive remote updates
	Machine         string         `json:",omitempty"` // the current host's machine type (uname -m)
	GoArch          string         `json:",omitempty"` // GOARCH value (of the built binary)
	GoArchVar       string         `json:",omitempty"` // GOARM, GOAMD64, etc (of the built binary)
	GoVersion       string         `json:",omitempty"` // Go version binary was built with
	RoutableIPs     []netip.Prefix `json:",omitempty"` // set of IP ranges this client can route
	RequestTags     []string       `json:",omitempty"` // set of ACL tags this node wants to claim
	WoLMACs         []string       `json:",omitempty"` // MAC address(es) to send Wake-on-LAN packets to wake this node (lowercase hex w/ colons)
	Services        []Service      `json:",omitempty"` // services advertised by this machine
	NetInfo         *NetInfo       `json:",omitempty"`
	SSH_HostKeys    []string       `json:"sshHostKeys,omitempty"` // if advertised
	Cloud           string         `json:",omitempty"`
	Userspace       opt.Bool       `json:",omitempty"` // if the client is running in userspace (netstack) mode
	UserspaceRouter opt.Bool       `json:",omitempty"` // if the client's subnet router is running in userspace (netstack) mode
	AppConnector    opt.Bool       `json:",omitempty"` // if the client is running the app-connector service

	// Location represents geographical location data about a
	// Tailscale host. Location is optional and only set if
	// explicitly declared by a node.
	Location *Location `json:",omitempty"`

	// NOTE: any new fields containing pointers in this type
	//       require changes to Hostinfo.Equal.
}

// TailscaleSSHEnabled reports whether or not this node is acting as a
// Tailscale SSH server.
func (hi *Hostinfo) TailscaleSSHEnabled() bool {
	// Currently, we use `SSH_HostKeys` as a proxy for this. However, we may later
	// include non-Tailscale host keys, and will add a separate flag to rely on.
	return hi != nil && len(hi.SSH_HostKeys) > 0
}

func (v HostinfoView) TailscaleSSHEnabled() bool { return v.ж.TailscaleSSHEnabled() }

// TailscaleFunnelEnabled reports whether or not this node has explicitly
// enabled Funnel.
func (hi *Hostinfo) TailscaleFunnelEnabled() bool {
	return hi != nil && hi.WireIngress
}

func (v HostinfoView) TailscaleFunnelEnabled() bool { return v.ж.TailscaleFunnelEnabled() }

// NetInfo contains information about the host's network state.
type NetInfo struct {
	// MappingVariesByDestIP says whether the host's NAT mappings
	// vary based on the destination IP.
	MappingVariesByDestIP opt.Bool

	// HairPinning is their router does hairpinning.
	// It reports true even if there's no NAT involved.
	HairPinning opt.Bool

	// WorkingIPv6 is whether the host has IPv6 internet connectivity.
	WorkingIPv6 opt.Bool

	// OSHasIPv6 is whether the OS supports IPv6 at all, regardless of
	// whether IPv6 internet connectivity is available.
	OSHasIPv6 opt.Bool

	// WorkingUDP is whether the host has UDP internet connectivity.
	WorkingUDP opt.Bool

	// WorkingICMPv4 is whether ICMPv4 works.
	// Empty means not checked.
	WorkingICMPv4 opt.Bool

	// HavePortMap is whether we have an existing portmap open
	// (UPnP, PMP, or PCP).
	HavePortMap bool `json:",omitempty"`

	// UPnP is whether UPnP appears present on the LAN.
	// Empty means not checked.
	UPnP opt.Bool

	// PMP is whether NAT-PMP appears present on the LAN.
	// Empty means not checked.
	PMP opt.Bool

	// PCP is whether PCP appears present on the LAN.
	// Empty means not checked.
	PCP opt.Bool

	// PreferredDERP is this node's preferred (home) DERP region ID.
	// This is where the node expects to be contacted to begin a
	// peer-to-peer connection. The node might be be temporarily
	// connected to multiple DERP servers (to speak to other nodes
	// that are located elsewhere) but PreferredDERP is the region ID
	// that the node subscribes to traffic at.
	// Zero means disconnected or unknown.
	PreferredDERP int

	// LinkType is the current link type, if known.
	LinkType string `json:",omitempty"` // "wired", "wifi", "mobile" (LTE, 4G, 3G, etc)

	// DERPLatency is the fastest recent time to reach various
	// DERP STUN servers, in seconds. The map key is the
	// "regionID-v4" or "-v6"; it was previously the DERP server's
	// STUN host:port.
	//
	// This should only be updated rarely, or when there's a
	// material change, as any change here also gets uploaded to
	// the control plane.
	DERPLatency map[string]float64 `json:",omitempty"`

	// FirewallMode encodes both which firewall mode was selected and why.
	// It is Linux-specific (at least as of 2023-08-19) and is meant to help
	// debug iptables-vs-nftables issues. The string is of the form
	// "{nft,ift}-REASON", like "nft-forced" or "ipt-default". Empty means
	// either not Linux or a configuration in which the host firewall rules
	// are not managed by tailscaled.
	FirewallMode string `json:",omitempty"`

	// Update BasicallyEqual when adding fields.
}

func (ni *NetInfo) String() string {
	if ni == nil {
		return "NetInfo(nil)"
	}
	return fmt.Sprintf("NetInfo{varies=%v hairpin=%v ipv6=%v ipv6os=%v udp=%v icmpv4=%v derp=#%v portmap=%v link=%q firewallmode=%q}",
		ni.MappingVariesByDestIP, ni.HairPinning, ni.WorkingIPv6,
		ni.OSHasIPv6, ni.WorkingUDP, ni.WorkingICMPv4,
		ni.PreferredDERP, ni.portMapSummary(), ni.LinkType, ni.FirewallMode)
}

func (ni *NetInfo) portMapSummary() string {
	if !ni.HavePortMap && ni.UPnP == "" && ni.PMP == "" && ni.PCP == "" {
		return "?"
	}
	var prefix string
	if ni.HavePortMap {
		prefix = "active-"
	}
	return prefix + conciseOptBool(ni.UPnP, "U") + conciseOptBool(ni.PMP, "M") + conciseOptBool(ni.PCP, "C")
}

func conciseOptBool(b opt.Bool, trueVal string) string {
	if b == "" {
		return "_"
	}
	v, ok := b.Get()
	if !ok {
		return "x"
	}
	if v {
		return trueVal
	}
	return ""
}

// BasicallyEqual reports whether ni and ni2 are basically equal, ignoring
// changes in DERP ServerLatency & RegionLatency.
func (ni *NetInfo) BasicallyEqual(ni2 *NetInfo) bool {
	if (ni == nil) != (ni2 == nil) {
		return false
	}
	if ni == nil {
		return true
	}
	return ni.MappingVariesByDestIP == ni2.MappingVariesByDestIP &&
		ni.HairPinning == ni2.HairPinning &&
		ni.WorkingIPv6 == ni2.WorkingIPv6 &&
		ni.OSHasIPv6 == ni2.OSHasIPv6 &&
		ni.WorkingUDP == ni2.WorkingUDP &&
		ni.WorkingICMPv4 == ni2.WorkingICMPv4 &&
		ni.HavePortMap == ni2.HavePortMap &&
		ni.UPnP == ni2.UPnP &&
		ni.PMP == ni2.PMP &&
		ni.PCP == ni2.PCP &&
		ni.PreferredDERP == ni2.PreferredDERP &&
		ni.LinkType == ni2.LinkType &&
		ni.FirewallMode == ni2.FirewallMode
}

// Equal reports whether h and h2 are equal.
func (h *Hostinfo) Equal(h2 *Hostinfo) bool {
	if h == nil && h2 == nil {
		return true
	}
	if (h == nil) != (h2 == nil) {
		return false
	}
	return reflect.DeepEqual(h, h2)
}

// HowUnequal returns a list of paths through Hostinfo where h and h2 differ.
// If they differ in nil-ness, the path is "nil", otherwise the path is like
// "ShieldsUp" or "NetInfo.nil" or "NetInfo.PCP".
func (h *Hostinfo) HowUnequal(h2 *Hostinfo) (path []string) {
	return appendStructPtrDiff(nil, "", reflect.ValueOf(h), reflect.ValueOf(h2))
}

func appendStructPtrDiff(base []string, pfx string, p1, p2 reflect.Value) (ret []string) {
	ret = base
	if p1.IsNil() && p2.IsNil() {
		return base
	}
	mkPath := func(b string) string {
		if pfx == "" {
			return b
		}
		return pfx + "." + b
	}
	if p1.IsNil() || p2.IsNil() {
		return append(base, mkPath("nil"))
	}
	v1, v2 := p1.Elem(), p2.Elem()
	t := v1.Type()
	for i, n := 0, t.NumField(); i < n; i++ {
		sf := t.Field(i)
		switch sf.Type.Kind() {
		case reflect.String:
			if v1.Field(i).String() != v2.Field(i).String() {
				ret = append(ret, mkPath(sf.Name))
			}
			continue
		case reflect.Bool:
			if v1.Field(i).Bool() != v2.Field(i).Bool() {
				ret = append(ret, mkPath(sf.Name))
			}
			continue
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if v1.Field(i).Int() != v2.Field(i).Int() {
				ret = append(ret, mkPath(sf.Name))
			}
			continue
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			if v1.Field(i).Uint() != v2.Field(i).Uint() {
				ret = append(ret, mkPath(sf.Name))
			}
			continue
		case reflect.Slice, reflect.Map:
			if !reflect.DeepEqual(v1.Field(i).Interface(), v2.Field(i).Interface()) {
				ret = append(ret, mkPath(sf.Name))
			}
			continue
		case reflect.Ptr:
			if sf.Type.Elem().Kind() == reflect.Struct {
				ret = appendStructPtrDiff(ret, sf.Name, v1.Field(i), v2.Field(i))
				continue
			}
		}
		panic(fmt.Sprintf("unsupported type at %s: %s", mkPath(sf.Name), sf.Type.String()))
	}
	return ret
}

// SignatureType specifies a scheme for signing RegisterRequest messages. It
// specifies the crypto algorithms to use, the contents of what is signed, and
// any other relevant details. Historically, requests were unsigned so the zero
// value is SignatureNone.
type SignatureType int

const (
	// SignatureNone indicates that there is no signature, no Timestamp is
	// required (but may be specified if desired), and both DeviceCert and
	// Signature should be empty.
	SignatureNone = SignatureType(iota)
	// SignatureUnknown represents an unknown signature scheme, which should
	// be considered an error if seen.
	SignatureUnknown
	// SignatureV1 is computed as RSA-PSS-Sign(privateKeyForDeviceCert,
	// SHA256(Timestamp || ServerIdentity || DeviceCert || ServerShortPubKey ||
	// MachineShortPubKey)). The PSS salt length is equal to hash length
	// (rsa.PSSSaltLengthEqualsHash). Device cert is required.
	// Deprecated: uses old key serialization format.
	SignatureV1
	// SignatureV2 is computed as RSA-PSS-Sign(privateKeyForDeviceCert,
	// SHA256(Timestamp || ServerIdentity || DeviceCert || ServerPubKey ||
	// MachinePubKey)). The PSS salt length is equal to hash length
	// (rsa.PSSSaltLengthEqualsHash). Device cert is required.
	SignatureV2
)

func (st SignatureType) AppendText(b []byte) ([]byte, error) {
	return append(b, st.String()...), nil
}

func (st SignatureType) MarshalText() ([]byte, error) {
	return []byte(st.String()), nil
}

func (st *SignatureType) UnmarshalText(b []byte) error {
	switch string(b) {
	case "signature-none":
		*st = SignatureNone
	case "signature-v1":
		*st = SignatureV1
	case "signature-v2":
		*st = SignatureV2
	default:
		var val int
		if _, err := fmt.Sscanf(string(b), "signature-unknown(%d)", &val); err != nil {
			*st = SignatureType(val)
		} else {
			*st = SignatureUnknown
		}
	}
	return nil
}

func (st SignatureType) String() string {
	switch st {
	case SignatureNone:
		return "signature-none"
	case SignatureUnknown:
		return "signature-unknown"
	case SignatureV1:
		return "signature-v1"
	case SignatureV2:
		return "signature-v2"
	default:
		return fmt.Sprintf("signature-unknown(%d)", int(st))
	}
}

// RegisterResponseAuth is the authentication information returned by the server
// in response to a RegisterRequest.
type RegisterResponseAuth struct {
	_ structs.Incomparable

	// At most one of Oauth2Token or AuthKey is set.

	Oauth2Token *Oauth2Token `json:",omitempty"` // used by pre-1.66 Android only
	AuthKey     string       `json:",omitempty"`
}

// RegisterRequest is sent by a client to register the key for a node.
// It is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
//
//	https://login.tailscale.com/machine/<mkey hex>
type RegisterRequest struct {
	_ structs.Incomparable

	// Version is the client's capabilities when using the Noise
	// transport.
	//
	// When using the original nacl crypto_box transport, the
	// value must be 1.
	Version CapabilityVersion

	NodeKey    key.NodePublic
	OldNodeKey key.NodePublic
	NLKey      key.NLPublic
	Auth       *RegisterResponseAuth `json:",omitempty"`
	// Expiry optionally specifies the requested key expiry.
	// The server policy may override.
	// As a special case, if Expiry is in the past and NodeKey is
	// the node's current key, the key is expired.
	Expiry   time.Time
	Followup string // response waits until AuthURL is visited
	Hostinfo *Hostinfo

	// Ephemeral is whether the client is requesting that this
	// node be considered ephemeral and be automatically deleted
	// when it stops being active.
	Ephemeral bool `json:",omitempty"`

	// NodeKeySignature is the node's own node-key signature, re-signed
	// for its new node key using its network-lock key.
	//
	// This field is set when the client retries registration after learning
	// its NodeKeySignature (which is in need of rotation).
	NodeKeySignature tkatype.MarshaledSignature

	// The following fields are not used for SignatureNone and are required for
	// SignatureV1:
	SignatureType SignatureType `json:",omitempty"`
	Timestamp     *time.Time    `json:",omitempty"` // creation time of request to prevent replay
	DeviceCert    []byte        `json:",omitempty"` // X.509 certificate for client device
	Signature     []byte        `json:",omitempty"` // as described by SignatureType

	// Tailnet is an optional identifier specifying the name of the recommended or required
	// network that the node should join. Its exact form should not be depended on; new
	// forms are coming later. The identifier is generally a domain name (for an organization)
	// or e-mail address (for a personal account on a shared e-mail provider). It is the same name
	// used by the API, as described in /api.md#tailnet.
	// If Tailnet begins with the prefix "required:" then the server should prevent logging in to a different
	// network than the one specified. Otherwise, the server should recommend the specified network
	// but still permit logging in to other networks.
	// If empty, no recommendation is offered to the server and the login page should show all options.
	Tailnet string `json:",omitempty"`
}

// RegisterResponse is returned by the server in response to a RegisterRequest.
type RegisterResponse struct {
	User              User
	Login             Login
	NodeKeyExpired    bool   // if true, the NodeKey needs to be replaced
	MachineAuthorized bool   // TODO(crawshaw): move to using MachineStatus
	AuthURL           string // if set, authorization pending

	// If set, this is the current node-key signature that needs to be
	// re-signed for the node's new node-key.
	NodeKeySignature tkatype.MarshaledSignature

	// Error indicates that authorization failed. If this is non-empty,
	// other status fields should be ignored.
	Error string
}

// EndpointType distinguishes different sources of MapRequest.Endpoint values.
type EndpointType int

const (
	EndpointUnknownType    = EndpointType(0)
	EndpointLocal          = EndpointType(1)
	EndpointSTUN           = EndpointType(2)
	EndpointPortmapped     = EndpointType(3)
	EndpointSTUN4LocalPort = EndpointType(4) // hard NAT: STUN'ed IPv4 address + local fixed port
	EndpointExplicitConf   = EndpointType(5) // explicitly configured (routing to be done by client)
)

func (et EndpointType) String() string {
	switch et {
	case EndpointUnknownType:
		return "?"
	case EndpointLocal:
		return "local"
	case EndpointSTUN:
		return "stun"
	case EndpointPortmapped:
		return "portmap"
	case EndpointSTUN4LocalPort:
		return "stun4localport"
	case EndpointExplicitConf:
		return "explicitconf"
	}
	return "other"
}

// Endpoint is an endpoint IPPort and an associated type.
// It doesn't currently go over the wire as is but is instead
// broken up into two parallel slices in MapRequest, for compatibility
// reasons. But this type is used in the codebase.
type Endpoint struct {
	Addr netip.AddrPort
	Type EndpointType
}

// MapRequest is sent by a client to either update the control plane
// about its current state, or to start a long-poll of network map updates.
//
// The request includes a copy of the client's current set of WireGuard
// endpoints and general host information.
//
// The request is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
//
//	https://login.tailscale.com/machine/<mkey hex>/map
type MapRequest struct {
	// Version is incremented whenever the client code changes enough that
	// we want to signal to the control server that we're capable of something
	// different.
	//
	// For current values and history, see the CapabilityVersion type's docs.
	Version CapabilityVersion

	Compress  string // "zstd" or "" (no compression)
	KeepAlive bool   // whether server should send keep-alives back to us
	NodeKey   key.NodePublic
	DiscoKey  key.DiscoPublic

	// Stream is whether the client wants to receive multiple MapResponses over
	// the same HTTP connection.
	//
	// If false, the server will send a single MapResponse and then close the
	// connection.
	//
	// If true and Version >= 68, the server should treat this as a read-only
	// request and ignore any Hostinfo or other fields that might be set.
	Stream bool

	// Hostinfo is the client's current Hostinfo. Although it is always included
	// in the request, the server may choose to ignore it when Stream is true
	// and Version >= 68.
	Hostinfo *Hostinfo

	// MapSessionHandle, if non-empty, is a request to reattach to a previous
	// map session after a previous map session was interrupted for whatever
	// reason. Its value is an opaque string as returned by
	// MapResponse.MapSessionHandle.
	//
	// When set, the client must also send MapSessionSeq to specify the last
	// processed message in that prior session.
	//
	// The server may choose to ignore the request for any reason and start a
	// new map session. This is only applicable when Stream is true.
	MapSessionHandle string `json:",omitempty"`

	// MapSessionSeq is the sequence number in the map session identified by
	// MapSesssionHandle that was most recently processed by the client.
	// It is only applicable when MapSessionHandle is specified.
	// If the server chooses to honor the MapSessionHandle request, only sequence
	// numbers greater than this value will be returned.
	MapSessionSeq int64 `json:",omitempty"`

	// Endpoints are the client's magicsock UDP ip:port endpoints (IPv4 or IPv6).
	// These can be ignored if Stream is true and Version >= 68.
	Endpoints []netip.AddrPort `json:",omitempty"`
	// EndpointTypes are the types of the corresponding endpoints in Endpoints.
	EndpointTypes []EndpointType `json:",omitempty"`

	// TKAHead describes the hash of the latest AUM applied to the local
	// tailnet key authority, if one is operating.
	// It is encoded as tka.AUMHash.MarshalText.
	TKAHead string `json:",omitempty"`

	// ReadOnly was set when client just wanted to fetch the MapResponse,
	// without updating their Endpoints. The intended use was for clients to
	// discover the DERP map at start-up before their first real endpoint
	// update.
	//
	// Deprecated: always false as of Version 68.
	ReadOnly bool `json:",omitempty"`

	// OmitPeers is whether the client is okay with the Peers list being omitted
	// in the response.
	//
	// The behavior of OmitPeers being true varies based on Stream and ReadOnly:
	//
	// If OmitPeers is true, Stream is false, and ReadOnly is false,
	// then the server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
	// In this case, the server can omit the entire response; the client
	// only checks the HTTP response status code.
	//
	// If OmitPeers is true, Stream is false, but ReadOnly is true,
	// then all the response fields are included. (This is what the client does
	// when initially fetching the DERP map.)
	OmitPeers bool `json:",omitempty"`

	// DebugFlags is a list of strings specifying debugging and
	// development features to enable in handling this map
	// request. The values are deliberately unspecified, as they get
	// added and removed all the time during development, and offer no
	// compatibility promise. To roll out semantic changes, bump
	// Version instead.
	//
	// Current DebugFlags values are:
	//     * "warn-ip-forwarding-off": client is trying to be a subnet
	//       router but their IP forwarding is broken.
	//     * "warn-router-unhealthy": client's Router implementation is
	//       having problems.
	DebugFlags []string `json:",omitempty"`
}

// PortRange represents a range of UDP or TCP port numbers.
type PortRange struct {
	First uint16
	Last  uint16
}

// Contains reports whether port is in pr.
func (pr PortRange) Contains(port uint16) bool {
	return port >= pr.First && port <= pr.Last
}

var PortRangeAny = PortRange{0, 65535}

// NetPortRange represents a range of ports that's allowed for one or more IPs.
type NetPortRange struct {
	_     structs.Incomparable
	IP    string // IP, CIDR, Range, or "*" (same formats as FilterRule.SrcIPs)
	Bits  *int   // deprecated; the 2020 way to turn IP into a CIDR. See FilterRule.SrcBits.
	Ports PortRange
}

// CapGrant grants capabilities in a FilterRule.
type CapGrant struct {
	// Dsts are the destination IP ranges that this capability
	// grant matches.
	Dsts []netip.Prefix

	// Caps are the capabilities the source IP matched by
	// FilterRule.SrcIPs are granted to the destination IP,
	// matched by Dsts.
	// Deprecated: use CapMap instead.
	Caps []PeerCapability `json:",omitempty"`

	// CapMap is a map of capabilities to their values.
	// The key is the capability name, and the value is a list of
	// values for that capability.
	CapMap PeerCapMap `json:",omitempty"`
}

// PeerCapability represents a capability granted to a peer by a FilterRule when
// the peer communicates with the node that has this rule. Its meaning is
// application-defined.
//
// It must be a URL like "https://tailscale.com/cap/file-send".
type PeerCapability string

const (
	// PeerCapabilityFileSharingTarget grants the current node the ability to send
	// files to the peer which has this capability.
	PeerCapabilityFileSharingTarget PeerCapability = "https://tailscale.com/cap/file-sharing-target"
	// PeerCapabilityFileSharingSend grants the ability to receive files from a
	// node that's owned by a different user.
	PeerCapabilityFileSharingSend PeerCapability = "https://tailscale.com/cap/file-send"
	// PeerCapabilityDebugPeer grants the ability for a peer to read this node's
	// goroutines, metrics, magicsock internal state, etc.
	PeerCapabilityDebugPeer PeerCapability = "https://tailscale.com/cap/debug-peer"
	// PeerCapabilityWakeOnLAN grants the ability to send a Wake-On-LAN packet.
	PeerCapabilityWakeOnLAN PeerCapability = "https://tailscale.com/cap/wake-on-lan"
	// PeerCapabilityIngress grants the ability for a peer to send ingress traffic.
	PeerCapabilityIngress PeerCapability = "https://tailscale.com/cap/ingress"
	// PeerCapabilityWebUI grants the ability for a peer to edit features from the
	// device Web UI.
	PeerCapabilityWebUI PeerCapability = "tailscale.com/cap/webui"
	// PeerCapabilityTaildrive grants the ability for a peer to access Taildrive
	// shares.
	PeerCapabilityTaildrive PeerCapability = "tailscale.com/cap/drive"
	// PeerCapabilityTaildriveSharer indicates that a peer has the ability to
	// share folders with us.
	PeerCapabilityTaildriveSharer PeerCapability = "tailscale.com/cap/drive-sharer"

	// PeerCapabilityKubernetes grants a peer Kubernetes-specific
	// capabilities, such as the ability to impersonate specific Tailscale
	// user groups as Kubernetes user groups. This capability is read by
	// peers that are Tailscale Kubernetes operator instances.
	PeerCapabilityKubernetes PeerCapability = "tailscale.com/cap/kubernetes"
)

// NodeCapMap is a map of capabilities to their optional values. It is valid for
// a capability to have no values (nil slice); such capabilities can be tested
// for by using the Contains method.
//
// See [NodeCapability] for more information on keys.
type NodeCapMap map[NodeCapability][]RawMessage

// Equal reports whether c and c2 are equal.
func (c NodeCapMap) Equal(c2 NodeCapMap) bool {
	return maps.EqualFunc(c, c2, slices.Equal)
}

// UnmarshalNodeCapJSON unmarshals each JSON value in cm[cap] as T.
// If cap does not exist in cm, it returns (nil, nil).
// It returns an error if the values cannot be unmarshaled into the provided type.
func UnmarshalNodeCapJSON[T any](cm NodeCapMap, cap NodeCapability) ([]T, error) {
	vals, ok := cm[cap]
	if !ok {
		return nil, nil
	}
	out := make([]T, 0, len(vals))
	for _, v := range vals {
		var t T
		if err := json.Unmarshal([]byte(v), &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// Contains reports whether c has the capability cap. This is used to test for
// the existence of a capability, especially when the capability has no
// associated argument/data values.
func (c NodeCapMap) Contains(cap NodeCapability) bool {
	_, ok := c[cap]
	return ok
}

// PeerCapMap is a map of capabilities to their optional values. It is valid for
// a capability to have no values (nil slice); such capabilities can be tested
// for by using the HasCapability method.
//
// The values are opaque to Tailscale, but are passed through from the ACLs to
// the application via the WhoIs API.
type PeerCapMap map[PeerCapability][]RawMessage

// UnmarshalCapJSON unmarshals each JSON value in cm[cap] as T.
// If cap does not exist in cm, it returns (nil, nil).
// It returns an error if the values cannot be unmarshaled into the provided type.
func UnmarshalCapJSON[T any](cm PeerCapMap, cap PeerCapability) ([]T, error) {
	vals, ok := cm[cap]
	if !ok {
		return nil, nil
	}
	out := make([]T, 0, len(vals))
	for _, v := range vals {
		var t T
		if err := json.Unmarshal([]byte(v), &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// HasCapability reports whether c has the capability cap. This is used to test
// for the existence of a capability, especially when the capability has no
// associated argument/data values.
func (c PeerCapMap) HasCapability(cap PeerCapability) bool {
	_, ok := c[cap]
	return ok
}

// FilterRule represents one rule in a packet filter.
//
// A rule is logically a set of source CIDRs to match (described by
// SrcIPs), and a set of destination targets that are then
// allowed if a source IP is matches of those CIDRs.
type FilterRule struct {
	// SrcIPs are the source IPs/networks to match.
	//
	// It may take the following forms:
	//     * an IP address (IPv4 or IPv6)
	//     * the string "*" to match everything (both IPv4 & IPv6)
	//     * a CIDR (e.g. "192.168.0.0/16")
	//     * a range of two IPs, inclusive, separated by hyphen ("2eff::1-2eff::0800")
	//     * a string "cap:<capability>" with NodeCapMap cap name
	SrcIPs []string

	// SrcBits is deprecated; it was the old way to specify a CIDR
	// prior to CapabilityVersion 7. Its values correspond to the
	// SrcIPs above.
	//
	// If an entry of SrcBits is present for the same index as a
	// SrcIPs entry, it changes the SrcIP above to be a network
	// with /n CIDR bits. If the slice is nil or insufficiently
	// long, the default value (for an IPv4 address) for a
	// position is 32, as if the SrcIPs above were a /32 mask. For
	// a "*" SrcIPs value, the corresponding SrcBits value is
	// ignored.
	//
	// This is still present in this file because the Tailscale control plane
	// code still uses this type, for 118 clients that are still connected as of
	// 2024-06-18, 3.5 years after the last release that used this type.
	SrcBits []int `json:",omitempty"`

	// DstPorts are the port ranges to allow once a source IP
	// matches (is in the CIDR described by SrcIPs).
	//
	// CapGrant and DstPorts are mutually exclusive: at most one can be non-nil.
	DstPorts []NetPortRange `json:",omitempty"`

	// IPProto are the IP protocol numbers to match.
	//
	// As a special case, nil or empty means TCP, UDP, and ICMP.
	//
	// Numbers outside the uint8 range (below 0 or above 255) are
	// reserved for Tailscale's use. Unknown ones are ignored.
	//
	// Depending on the IPProto values, DstPorts may or may not be
	// used.
	IPProto []int `json:",omitempty"`

	// CapGrant, if non-empty, are the capabilities to
	// conditionally grant to the source IP in SrcIPs.
	//
	// Think of DstPorts as "capabilities for networking" and
	// CapGrant as arbitrary application-defined capabilities
	// defined between the admin's ACLs and the application
	// doing WhoIs lookups, looking up the remote IP address's
	// application-level capabilities.
	//
	// CapGrant and DstPorts are mutually exclusive: at most one can be non-nil.
	CapGrant []CapGrant `json:",omitempty"`
}

var FilterAllowAll = []FilterRule{
	{
		SrcIPs: []string{"*"},
		DstPorts: []NetPortRange{{
			IP:    "*",
			Ports: PortRange{0, 65535},
		}},
	},
}

// DNSConfig is the DNS configuration.
type DNSConfig struct {
	// Resolvers are the DNS resolvers to use, in order of preference.
	Resolvers []*dnstype.Resolver `json:",omitempty"`

	// Routes maps DNS name suffixes to a set of DNS resolvers to
	// use. It is used to implement "split DNS" and other advanced DNS
	// routing overlays.
	//
	// Map keys are fully-qualified DNS name suffixes; they may
	// optionally contain a trailing dot but no leading dot.
	//
	// If the value is an empty slice, that means the suffix should still
	// be handled by Tailscale's built-in resolver (100.100.100.100), such
	// as for the purpose of handling ExtraRecords.
	Routes map[string][]*dnstype.Resolver `json:",omitempty"`

	// FallbackResolvers is like Resolvers, but is only used if a
	// split DNS configuration is requested in a configuration that
	// doesn't work yet without explicit default resolvers.
	// https://github.com/tailscale/tailscale/issues/1743
	FallbackResolvers []*dnstype.Resolver `json:",omitempty"`
	// Domains are the search domains to use.
	// Search domains must be FQDNs, but *without* the trailing dot.
	Domains []string `json:",omitempty"`
	// Proxied turns on automatic resolution of hostnames for devices
	// in the network map, aka MagicDNS.
	// Despite the (legacy) name, does not necessarily cause request
	// proxying to be enabled.
	Proxied bool `json:",omitempty"`

	// The following fields are only set and used by
	// MapRequest.Version >=9 and <14.

	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netip.Addr `json:",omitempty"`

	// CertDomains are the set of DNS names for which the control
	// plane server will assist with provisioning TLS
	// certificates. See SetDNSRequest, which can be used to
	// answer dns-01 ACME challenges for e.g. LetsEncrypt.
	// These names are FQDNs without trailing periods, and without
	// any "_acme-challenge." prefix.
	CertDomains []string `json:",omitempty"`

	// ExtraRecords contains extra DNS records to add to the
	// MagicDNS config.
	ExtraRecords []DNSRecord `json:",omitempty"`

	// ExitNodeFilteredSuffixes are the DNS suffixes that the
	// node, when being an exit node DNS proxy, should not answer.
	//
	// The entries do not contain trailing periods and are always
	// all lowercase.
	//
	// If an entry starts with a period, it's a suffix match (but
	// suffix ".a.b" doesn't match "a.b"; a prefix is required).
	//
	// If an entry does not start with a period, it's an exact
	// match.
	//
	// Matches are case insensitive.
	ExitNodeFilteredSet []string `json:",omitempty"`

	// TempCorpIssue13969 is a temporary (2023-08-16) field for an internal hack day prototype.
	// It contains a user inputed URL that should have a list of domains to be blocked.
	// See https://github.com/tailscale/corp/issues/13969.
	TempCorpIssue13969 string `json:",omitempty"`
}

// DNSRecord is an extra DNS record to add to MagicDNS.
type DNSRecord struct {
	// Name is the fully qualified domain name of
	// the record to add. The trailing dot is optional.
	Name string

	// Type is the DNS record type.
	// Empty means A or AAAA, depending on value.
	// Other values are currently ignored.
	Type string `json:",omitempty"`

	// Value is the IP address in string form.
	// TODO(bradfitz): if we ever add support for record types
	// with non-UTF8 binary data, add ValueBytes []byte that
	// would take precedence.
	Value string
}

// PingType is a string representing the kind of ping to perform.
type PingType string

const (
	// PingDisco performs a ping, without involving IP at either end.
	PingDisco PingType = "disco"
	// PingTSMP performs a ping, using the IP layer, but avoiding the OS IP stack.
	PingTSMP PingType = "TSMP"
	// PingICMP performs a ping between two tailscale nodes using ICMP that is
	// received by the target systems IP stack.
	PingICMP PingType = "ICMP"
	// PingPeerAPI performs a ping between two tailscale nodes using ICMP that is
	// received by the target systems IP stack.
	PingPeerAPI PingType = "peerapi"
)

// PingRequest with no IP and Types is a request to send an HTTP request to prove the
// long-polling client is still connected.
// PingRequest with Types and IP, will send a ping to the IP and send a POST
// request containing a PingResponse to the URL containing results.
type PingRequest struct {
	// URL is the URL to reply to the PingRequest to.
	// It will be a unique URL each time. No auth headers are necessary.
	// If the client sees multiple PingRequests with the same URL,
	// subsequent ones should be ignored.
	//
	// The HTTP method that the node should make back to URL depends on the other
	// fields of the PingRequest. If Types is defined, then URL is the URL to
	// send a POST request to. Otherwise, the node should just make a HEAD
	// request to URL.
	URL string

	// URLIsNoise, if true, means that the client should hit URL over the Noise
	// transport instead of TLS.
	URLIsNoise bool `json:",omitempty"`

	// Log is whether to log about this ping in the success case.
	// For failure cases, the client will log regardless.
	Log bool `json:",omitempty"`

	// Types is the types of ping that are initiated. Can be any PingType, comma
	// separated, e.g. "disco,TSMP"
	//
	// As a special case, if Types is "c2n", then this PingRequest is a
	// client-to-node HTTP request. The HTTP request should be handled by this
	// node's c2n handler and the HTTP response sent in a POST to URL. For c2n,
	// the value of URLIsNoise is ignored and only the Noise transport (back to
	// the control plane) will be used, as if URLIsNoise were true.
	Types string `json:",omitempty"`

	// IP is the ping target, when needed by the PingType(s) given in Types.
	IP netip.Addr

	// Payload is the ping payload.
	//
	// It is only used for c2n requests, in which case it's an HTTP/1.0 or
	// HTTP/1.1-formatted HTTP request as parsable with http.ReadRequest.
	Payload []byte `json:",omitempty"`
}

// PingResponse provides result information for a TSMP or Disco PingRequest.
// Typically populated from an ipnstate.PingResult used in `tailscale ping`.
type PingResponse struct {
	Type PingType // ping type, such as TSMP or disco.

	IP       string `json:",omitempty"` // ping destination
	NodeIP   string `json:",omitempty"` // Tailscale IP of node handling IP (different for subnet routers)
	NodeName string `json:",omitempty"` // DNS name base or (possibly not unique) hostname

	// Err contains a short description of error conditions if the PingRequest
	// could not be fulfilled for some reason.
	// e.g. "100.1.2.3 is local Tailscale IP"
	Err string `json:",omitempty"`

	// LatencySeconds reports measurement of the round-trip time of a message to
	// the requested target, if it could be determined. If LatencySeconds is
	// omitted, Err should contain information as to the cause.
	LatencySeconds float64 `json:",omitempty"`

	// Endpoint is the ip:port if direct UDP was used.
	// It is not currently set for TSMP pings.
	Endpoint string `json:",omitempty"`

	// DERPRegionID is non-zero DERP region ID if DERP was used.
	// It is not currently set for TSMP pings.
	DERPRegionID int `json:",omitempty"`

	// DERPRegionCode is the three-letter region code
	// corresponding to DERPRegionID.
	// It is not currently set for TSMP pings.
	DERPRegionCode string `json:",omitempty"`

	// PeerAPIPort is set by TSMP ping responses for peers that
	// are running a peerapi server. This is the port they're
	// running the server on.
	PeerAPIPort uint16 `json:",omitempty"`

	// IsLocalIP is whether the ping request error is due to it being
	// a ping to the local node.
	IsLocalIP bool `json:",omitempty"`
}

// MapResponse is the response to a MapRequest. It describes the state of the
// local node, the peer nodes, the DNS configuration, the packet filter, and
// more. A MapRequest, depending on its parameters, may result in the control
// plane coordination server sending 0, 1 or a stream of multiple MapResponse
// values.
//
// When the client sets MapRequest.Stream, the server sends a stream of
// MapResponses. That long-lived HTTP transaction is called a "map poll". In a
// map poll, the first MapResponse will be complete and subsequent MapResponses
// will be incremental updates with only changed information.
//
// The zero value for all fields means "unchanged". Unfortunately, several
// fields were defined before that convention was established, so they use a
// slice with omitempty, meaning this type can't be used to marshal JSON
// containing non-nil zero-length slices (meaning explicitly now empty). The
// control plane uses a separate type to marshal these fields. This type is
// primarily used for unmarshaling responses so the omitempty annotations are
// mostly useless, except that this type is also used for the integration test's
// fake control server. (It's not necessary to marshal a non-nil zero-length
// slice for the things we've needed to test in the integration tests as of
// 2023-09-09).
type MapResponse struct {
	// MapSessionHandle optionally specifies a unique opaque handle for this
	// stateful MapResponse session. Servers may choose not to send it, and it's
	// only sent on the first MapResponse in a stream. The client can determine
	// whether it's reattaching to a prior stream by seeing whether this value
	// matches the requested MapRequest.MapSessionHandle.
	MapSessionHandle string `json:",omitempty"`

	// Seq is a sequence number within a named map session (a response where the
	// first message contains a MapSessionHandle). The Seq number may be omitted
	// on responses that don't change the state of the stream, such as KeepAlive
	// or certain types of PingRequests. This is the value to be sent in
	// MapRequest.MapSessionSeq to resume after this message.
	Seq int64 `json:",omitempty"`

	// KeepAlive, if set, represents an empty message just to keep
	// the connection alive. When true, all other fields except
	// PingRequest, ControlTime, and PopBrowserURL are ignored.
	KeepAlive bool `json:",omitempty"`

	// PingRequest, if non-empty, is a request to the client to
	// prove it's still there by sending an HTTP request to the
	// provided URL. No auth headers are necessary.
	// PingRequest may be sent on any MapResponse (ones with
	// KeepAlive true or false).
	PingRequest *PingRequest `json:",omitempty"`

	// PopBrowserURL, if non-empty, is a URL for the client to
	// open to complete an action. The client should dup suppress
	// identical URLs and only open it once for the same URL.
	PopBrowserURL string `json:",omitempty"`

	// Networking

	// Node describes the node making the map request.
	// Starting with MapRequest.Version 18, nil means unchanged.
	Node *Node `json:",omitempty"`

	// DERPMap describe the set of DERP servers available.
	// A nil value means unchanged.
	DERPMap *DERPMap `json:",omitempty"`

	// Peers, if non-empty, is the complete list of peers.
	// It will be set in the first MapResponse for a long-polled request/response.
	// Subsequent responses will be delta-encoded if MapRequest.Version >= 5 and server
	// chooses, in which case Peers will be nil or zero length.
	// If Peers is non-empty, PeersChanged and PeersRemoved should
	// be ignored (and should be empty).
	// Peers is always returned sorted by Node.ID.
	Peers []*Node `json:",omitempty"`
	// PeersChanged are the Nodes (identified by their ID) that
	// have changed or been added since the past update on the
	// HTTP response. It's not used by the server if MapRequest.Version < 5.
	// PeersChanged is always returned sorted by Node.ID.
	PeersChanged []*Node `json:",omitempty"`
	// PeersRemoved are the NodeIDs that are no longer in the peer list.
	PeersRemoved []NodeID `json:",omitempty"`

	// PeersChangedPatch, if non-nil, means that node(s) have changed.
	// This is a lighter version of the older PeersChanged support that
	// only supports certain types of updates
	//
	// These are applied after Peers* above, but in practice the
	// control server should only send these on their own, without
	// the Peers* fields also set.
	PeersChangedPatch []*PeerChange `json:",omitempty"`

	// PeerSeenChange contains information on how to update peers' LastSeen
	// times. If the value is false, the peer is gone. If the value is true,
	// the LastSeen time is now. Absent means unchanged.
	PeerSeenChange map[NodeID]bool `json:",omitempty"`

	// OnlineChange changes the value of a Peer Node.Online value.
	OnlineChange map[NodeID]bool `json:",omitempty"`

	// DNSConfig contains the DNS settings for the client to use.
	// A nil value means no change from an earlier non-nil value.
	DNSConfig *DNSConfig `json:",omitempty"`

	// Domain is the name of the network that this node is
	// in. It's either of the form "example.com" (for user
	// foo@example.com, for multi-user networks) or
	// "foo@gmail.com" (for siloed users on shared email
	// providers). Its exact form should not be depended on; new
	// forms are coming later.
	// If empty, the value is unchanged.
	Domain string `json:",omitempty"`

	// CollectServices reports whether this node's Tailnet has
	// requested that info about services be included in HostInfo.
	// If unset, the most recent non-empty MapResponse value in
	// the HTTP response stream is used.
	CollectServices opt.Bool `json:",omitempty"`

	// PacketFilter are the firewall rules.
	//
	// For MapRequest.Version >= 6, a nil value means the most
	// previously streamed non-nil MapResponse.PacketFilter within
	// the same HTTP response. A non-nil but empty list always means
	// no PacketFilter (that is, to block everything).
	//
	// Note that this package's type, due its use of a slice and omitempty, is
	// unable to marshal a zero-length non-nil slice. The control server needs
	// to marshal this type using a separate type. See MapResponse docs.
	//
	// See PacketFilters for the newer way to send PacketFilter updates.
	PacketFilter []FilterRule `json:",omitempty"`

	// PacketFilters encodes incremental packet filter updates to the client
	// without having to send the entire packet filter on any changes as
	// required by the older PacketFilter (singular) field above. The map keys
	// are server-assigned arbitrary strings. The map values are the new rules
	// for that key, or nil to delete it. The client then concatenates all the
	// rules together to generate the final packet filter. Because the
	// FilterRules can only match or not match, the ordering of filter rules
	// doesn't matter. (That said, the client generates the file merged packet
	// filter rules by concananting all the packet filter rules sorted by the
	// map key name. But it does so for stability and testability, not
	// correctness. If something needs to rely on that property, something has
	// gone wrong.)
	//
	// If the server sends a non-nil PacketFilter (above), that is equivalent to
	// a named packet filter with the key "base". It is valid for the server to
	// send both PacketFilter and PacketFilters in the same MapResponse or
	// alternate between them within a session. The PacketFilter is applied
	// first (if set) and then the PacketFilters.
	//
	// As a special case, the map key "*" with a value of nil means to clear all
	// prior named packet filters (including any implicit "base") before
	// processing the other map entries.
	PacketFilters map[string][]FilterRule `json:",omitempty"`

	// UserProfiles are the user profiles of nodes in the network.
	// As as of 1.1.541 (mapver 5), this contains new or updated
	// user profiles only.
	UserProfiles []UserProfile `json:",omitempty"`

	// Health, if non-nil, sets the health state of the node from the control
	// plane's perspective. A nil value means no change from the previous
	// MapResponse. A non-nil 0-length slice restores the health to good (no
	// known problems). A non-zero length slice are the list of problems that
	// the control place sees.
	//
	// Note that this package's type, due its use of a slice and omitempty, is
	// unable to marshal a zero-length non-nil slice. The control server needs
	// to marshal this type using a separate type. See MapResponse docs.
	Health []string `json:",omitempty"`

	// SSHPolicy, if non-nil, updates the SSH policy for how incoming
	// SSH connections should be handled.
	SSHPolicy *SSHPolicy `json:",omitempty"`

	// ControlTime, if non-zero, is the current timestamp according to the control server.
	ControlTime *time.Time `json:",omitempty"`

	// TKAInfo describes the control plane's view of tailnet
	// key authority (TKA) state.
	//
	// An initial nil TKAInfo indicates that the control plane
	// believes TKA should not be enabled. An initial non-nil TKAInfo
	// indicates the control plane believes TKA should be enabled.
	// A nil TKAInfo in a mapresponse stream (i.e. a 'delta' mapresponse)
	// indicates no change from the value sent earlier.
	TKAInfo *TKAInfo `json:",omitempty"`

	// DomainDataPlaneAuditLogID, if non-empty, is the per-tailnet log ID to be
	// used when writing data plane audit logs.
	DomainDataPlaneAuditLogID string `json:",omitempty"`

	// Debug is normally nil, except for when the control server
	// is setting debug settings on a node.
	Debug *Debug `json:",omitempty"`

	// ControlDialPlan tells the client how to connect to the control
	// server. An initial nil is equivalent to new(ControlDialPlan).
	// A subsequent streamed nil means no change.
	ControlDialPlan *ControlDialPlan `json:",omitempty"`

	// ClientVersion describes the latest client version that's available for
	// download and whether the client is using it. A nil value means no change
	// or nothing to report.
	ClientVersion *ClientVersion `json:",omitempty"`

	// DefaultAutoUpdate is the default node auto-update setting for this
	// tailnet. The node is free to opt-in or out locally regardless of this
	// value. This value is only used on first MapResponse from control, the
	// auto-update setting doesn't change if the tailnet admin flips the
	// default after the node registered.
	DefaultAutoUpdate opt.Bool `json:",omitempty"`

	// MaxKeyDuration describes the MaxKeyDuration setting for the tailnet.
	// If zero, the value is unchanged.
	MaxKeyDuration time.Duration `json:",omitempty"`
}

// ClientVersion is information about the latest client version that's available
// for the client (and whether they're already running it).
//
// It does not include a URL to download the client, as that varies by platform.
type ClientVersion struct {
	// RunningLatest is true if the client is running the latest build.
	RunningLatest bool `json:",omitempty"`

	// LatestVersion is the latest version.Short ("1.34.2") version available
	// for download for the client's platform and packaging type.
	// It won't be populated if RunningLatest is true.
	LatestVersion string `json:",omitempty"`

	// UrgentSecurityUpdate is set when the client is missing an important
	// security update. That update may be in LatestVersion or earlier.
	// UrgentSecurityUpdate should not be set if RunningLatest is false.
	UrgentSecurityUpdate bool `json:",omitempty"`

	// Notify is whether the client should do an OS-specific notification about
	// a new version being available. This should not be populated if
	// RunningLatest is true. The client should not notify multiple times for
	// the same LatestVersion value.
	Notify bool `json:",omitempty"`

	// NotifyURL is a URL to open in the browser when the user clicks on the
	// notification, when Notify is true.
	NotifyURL string `json:",omitempty"`

	// NotifyText is the text to show in the notification, when Notify is true.
	NotifyText string `json:",omitempty"`
}

// ControlDialPlan is instructions from the control server to the client on how
// to connect to the control server; this is useful for maintaining connection
// if the client's network state changes after the initial connection, or due
// to the configuration that the control server pushes.
type ControlDialPlan struct {
	// An empty list means the default: use DNS (unspecified which DNS).
	Candidates []ControlIPCandidate
}

// ControlIPCandidate represents a single candidate address to use when
// connecting to the control server.
type ControlIPCandidate struct {
	// IP is the address to attempt connecting to.
	IP netip.Addr

	// DialStartSec is the number of seconds after the beginning of the
	// connection process to wait before trying this candidate.
	DialStartDelaySec float64 `json:",omitempty"`

	// DialTimeoutSec is the timeout for a connection to this candidate,
	// starting after DialStartDelaySec.
	DialTimeoutSec float64 `json:",omitempty"`

	// Priority is the relative priority of this candidate; candidates with
	// a higher priority are preferred over candidates with a lower
	// priority.
	Priority int `json:",omitempty"`
}

// Debug used to be a miscellaneous set of declarative debug config changes and
// imperative debug commands. They've since been mostly migrated to node
// attributes (MapResponse.Node.Capabilities) for the declarative things and c2n
// requests for the imperative things. Not much remains here. Don't add more.
type Debug struct {
	// SleepSeconds requests that the client sleep for the
	// provided number of seconds.
	// The client can (and should) limit the value (such as 5
	// minutes). This exists as a safety measure to slow down
	// spinning clients, in case we introduce a bug in the
	// state machine.
	SleepSeconds float64 `json:",omitempty"`

	// DisableLogTail disables the logtail package. Once disabled it can't be
	// re-enabled for the lifetime of the process.
	//
	// This is primarily used by Headscale.
	DisableLogTail bool `json:",omitempty"`

	// Exit optionally specifies that the client should os.Exit
	// with this code. This is a safety measure in case a client is crash
	// looping or in an unsafe state and we need to remotely shut it down.
	Exit *int `json:",omitempty"`
}

func (id ID) String() string      { return fmt.Sprintf("id:%x", int64(id)) }
func (id UserID) String() string  { return fmt.Sprintf("userid:%x", int64(id)) }
func (id LoginID) String() string { return fmt.Sprintf("loginid:%x", int64(id)) }
func (id NodeID) String() string  { return fmt.Sprintf("nodeid:%x", int64(id)) }

// Equal reports whether n and n2 are equal.
func (n *Node) Equal(n2 *Node) bool {
	if n == nil && n2 == nil {
		return true
	}
	return n != nil && n2 != nil &&
		n.ID == n2.ID &&
		n.StableID == n2.StableID &&
		n.Name == n2.Name &&
		n.User == n2.User &&
		n.Sharer == n2.Sharer &&
		n.UnsignedPeerAPIOnly == n2.UnsignedPeerAPIOnly &&
		n.Key == n2.Key &&
		n.KeyExpiry.Equal(n2.KeyExpiry) &&
		bytes.Equal(n.KeySignature, n2.KeySignature) &&
		n.Machine == n2.Machine &&
		n.DiscoKey == n2.DiscoKey &&
		eqPtr(n.Online, n2.Online) &&
		slicesx.EqualSameNil(n.Addresses, n2.Addresses) &&
		slicesx.EqualSameNil(n.AllowedIPs, n2.AllowedIPs) &&
		slicesx.EqualSameNil(n.PrimaryRoutes, n2.PrimaryRoutes) &&
		slicesx.EqualSameNil(n.Endpoints, n2.Endpoints) &&
		n.DERP == n2.DERP &&
		n.Cap == n2.Cap &&
		n.Hostinfo.Equal(n2.Hostinfo) &&
		n.Created.Equal(n2.Created) &&
		eqTimePtr(n.LastSeen, n2.LastSeen) &&
		n.MachineAuthorized == n2.MachineAuthorized &&
		slices.Equal(n.Capabilities, n2.Capabilities) &&
		n.CapMap.Equal(n2.CapMap) &&
		n.ComputedName == n2.ComputedName &&
		n.computedHostIfDifferent == n2.computedHostIfDifferent &&
		n.ComputedNameWithHost == n2.ComputedNameWithHost &&
		slicesx.EqualSameNil(n.Tags, n2.Tags) &&
		n.Expired == n2.Expired &&
		eqPtr(n.SelfNodeV4MasqAddrForThisPeer, n2.SelfNodeV4MasqAddrForThisPeer) &&
		eqPtr(n.SelfNodeV6MasqAddrForThisPeer, n2.SelfNodeV6MasqAddrForThisPeer) &&
		n.IsWireGuardOnly == n2.IsWireGuardOnly &&
		n.IsJailed == n2.IsJailed
}

func eqPtr[T comparable](a, b *T) bool {
	if a == b { // covers nil
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func eqTimePtr(a, b *time.Time) bool {
	return ((a == nil) == (b == nil)) && (a == nil || a.Equal(*b))
}

// Oauth2Token is a copy of golang.org/x/oauth2.Token, to avoid the
// go.mod dependency on App Engine and grpc, which was causing problems.
// All we actually needed was this struct on the client side.
type Oauth2Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`
}

// NodeCapability represents a capability granted to the self node as listed in
// MapResponse.Node.Capabilities.
//
// It must be a URL like "https://tailscale.com/cap/file-sharing", or a
// well-known capability name like "funnel". The latter is only allowed for
// Tailscale-defined capabilities.
//
// Unlike PeerCapability, NodeCapability is not in context of a peer and is
// granted to the node itself.
//
// These are also referred to as "Node Attributes" in the ACL policy file.
type NodeCapability string

const (
	CapabilityFileSharing        NodeCapability = "https://tailscale.com/cap/file-sharing"
	CapabilityAdmin              NodeCapability = "https://tailscale.com/cap/is-admin"
	CapabilitySSH                NodeCapability = "https://tailscale.com/cap/ssh"                   // feature enabled/available
	CapabilitySSHRuleIn          NodeCapability = "https://tailscale.com/cap/ssh-rule-in"           // some SSH rule reach this node
	CapabilityDataPlaneAuditLogs NodeCapability = "https://tailscale.com/cap/data-plane-audit-logs" // feature enabled
	CapabilityDebug              NodeCapability = "https://tailscale.com/cap/debug"                 // exposes debug endpoints over the PeerAPI
	CapabilityHTTPS              NodeCapability = "https"

	// CapabilityBindToInterfaceByRoute changes how Darwin nodes create
	// sockets (in the net/netns package). See that package for more
	// details on the behaviour of this capability.
	CapabilityBindToInterfaceByRoute NodeCapability = "https://tailscale.com/cap/bind-to-interface-by-route"

	// CapabilityDebugDisableAlternateDefaultRouteInterface changes how Darwin
	// nodes get the default interface. There is an optional hook (used by the
	// macOS and iOS clients) to override the default interface, this capability
	// disables that and uses the default behavior (of parsing the routing
	// table).
	CapabilityDebugDisableAlternateDefaultRouteInterface NodeCapability = "https://tailscale.com/cap/debug-disable-alternate-default-route-interface"

	// CapabilityDebugDisableBindConnToInterface disables the automatic binding
	// of connections to the default network interface on Darwin nodes.
	CapabilityDebugDisableBindConnToInterface NodeCapability = "https://tailscale.com/cap/debug-disable-bind-conn-to-interface"

	// CapabilityTailnetLock indicates the node may initialize tailnet lock.
	CapabilityTailnetLock NodeCapability = "https://tailscale.com/cap/tailnet-lock"

	// Funnel warning capabilities used for reporting errors to the user.

	// CapabilityWarnFunnelNoInvite indicates whether Funnel is enabled for the tailnet.
	// This cap is no longer used 2023-08-09 onwards.
	CapabilityWarnFunnelNoInvite NodeCapability = "https://tailscale.com/cap/warn-funnel-no-invite"

	// CapabilityWarnFunnelNoHTTPS indicates HTTPS has not been enabled for the tailnet.
	// This cap is no longer used 2023-08-09 onwards.
	CapabilityWarnFunnelNoHTTPS NodeCapability = "https://tailscale.com/cap/warn-funnel-no-https"

	// Debug logging capabilities

	// CapabilityDebugTSDNSResolution enables verbose debug logging for DNS
	// resolution for Tailscale-controlled domains (the control server, log
	// server, DERP servers, etc.)
	CapabilityDebugTSDNSResolution NodeCapability = "https://tailscale.com/cap/debug-ts-dns-resolution"

	// CapabilityFunnelPorts specifies the ports that the Funnel is available on.
	// The ports are specified as a comma-separated list of port numbers or port
	// ranges (e.g. "80,443,8080-8090") in the ports query parameter.
	// e.g. https://tailscale.com/cap/funnel-ports?ports=80,443,8080-8090
	CapabilityFunnelPorts NodeCapability = "https://tailscale.com/cap/funnel-ports"

	// NodeAttrOnlyTCP443 specifies that the client should not attempt to generate
	// any outbound traffic that isn't TCP on port 443 (HTTPS). This is used for
	// clients in restricted environments where only HTTPS traffic is allowed
	// other types of traffic trips outbound firewall alarms. This thus implies
	// all traffic is over DERP.
	NodeAttrOnlyTCP443 NodeCapability = "only-tcp-443"

	// NodeAttrFunnel grants the ability for a node to host ingress traffic.
	NodeAttrFunnel NodeCapability = "funnel"
	// NodeAttrSSHAggregator grants the ability for a node to collect SSH sessions.
	NodeAttrSSHAggregator NodeCapability = "ssh-aggregator"

	// NodeAttrDebugForceBackgroundSTUN forces a node to always do background
	// STUN queries regardless of inactivity.
	NodeAttrDebugForceBackgroundSTUN NodeCapability = "debug-always-stun"

	// NodeAttrDebugDisableWGTrim disables the lazy WireGuard configuration,
	// always giving WireGuard the full netmap, even for idle peers.
	NodeAttrDebugDisableWGTrim NodeCapability = "debug-no-wg-trim"

	// NodeAttrDisableSubnetsIfPAC controls whether subnet routers should be
	// disabled if WPAD is present on the network.
	NodeAttrDisableSubnetsIfPAC NodeCapability = "debug-disable-subnets-if-pac"

	// NodeAttrDisableUPnP makes the client not perform a UPnP portmapping.
	// By default, we want to enable it to see if it works on more clients.
	//
	// If UPnP catastrophically fails for people, this should be set kill
	// new attempts at UPnP connections.
	NodeAttrDisableUPnP NodeCapability = "debug-disable-upnp"

	// NodeAttrDisableDeltaUpdates makes the client not process updates via the
	// delta update mechanism and should instead treat all netmap changes as
	// "full" ones as tailscaled did in 1.48.x and earlier.
	NodeAttrDisableDeltaUpdates NodeCapability = "disable-delta-updates"

	// NodeAttrRandomizeClientPort makes magicsock UDP bind to
	// :0 to get a random local port, ignoring any configured
	// fixed port.
	NodeAttrRandomizeClientPort NodeCapability = "randomize-client-port"

	// NodeAttrSilentDisco makes the client suppress disco heartbeats to its
	// peers.
	NodeAttrSilentDisco NodeCapability = "silent-disco"

	// NodeAttrOneCGNATEnable makes the client prefer one big CGNAT /10 route
	// rather than a /32 per peer. At most one of this or
	// NodeAttrOneCGNATDisable may be set; if neither are, it's automatic.
	NodeAttrOneCGNATEnable NodeCapability = "one-cgnat?v=true"

	// NodeAttrOneCGNATDisable makes the client prefer a /32 route per peer
	// rather than one big /10 CGNAT route. At most one of this or
	// NodeAttrOneCGNATEnable may be set; if neither are, it's automatic.
	NodeAttrOneCGNATDisable NodeCapability = "one-cgnat?v=false"

	// NodeAttrPeerMTUEnable makes the client do path MTU discovery to its
	// peers. If it isn't set, it defaults to the client default.
	NodeAttrPeerMTUEnable NodeCapability = "peer-mtu-enable"

	// NodeAttrDNSForwarderDisableTCPRetries disables retrying truncated
	// DNS queries over TCP if the response is truncated.
	NodeAttrDNSForwarderDisableTCPRetries NodeCapability = "dns-forwarder-disable-tcp-retries"

	// NodeAttrLinuxMustUseIPTables forces Linux clients to use iptables for
	// netfilter management.
	// This cannot be set simultaneously with NodeAttrLinuxMustUseNfTables.
	NodeAttrLinuxMustUseIPTables NodeCapability = "linux-netfilter?v=iptables"

	// NodeAttrLinuxMustUseNfTables forces Linux clients to use nftables for
	// netfilter management.
	// This cannot be set simultaneously with NodeAttrLinuxMustUseIPTables.
	NodeAttrLinuxMustUseNfTables NodeCapability = "linux-netfilter?v=nftables"

	// NodeAttrSeamlessKeyRenewal makes clients enable beta functionality
	// of renewing node keys without breaking connections.
	NodeAttrSeamlessKeyRenewal NodeCapability = "seamless-key-renewal"

	// NodeAttrProbeUDPLifetime makes the client probe UDP path lifetime at the
	// tail end of an active direct connection in magicsock.
	NodeAttrProbeUDPLifetime NodeCapability = "probe-udp-lifetime"

	// NodeAttrsTaildriveShare enables sharing via Taildrive.
	NodeAttrsTaildriveShare NodeCapability = "drive:share"

	// NodeAttrsTaildriveAccess enables accessing shares via Taildrive.
	NodeAttrsTaildriveAccess NodeCapability = "drive:access"

	// NodeAttrSuggestExitNode is applied to each exit node which the control plane has determined
	// is a recommended exit node.
	NodeAttrSuggestExitNode NodeCapability = "suggest-exit-node"

	// NodeAttrDisableWebClient disables using the web client.
	NodeAttrDisableWebClient NodeCapability = "disable-web-client"

	// NodeAttrLogExitFlows enables exit node destinations in network flow logs.
	NodeAttrLogExitFlows NodeCapability = "log-exit-flows"

	// NodeAttrAutoExitNode permits the automatic exit nodes feature.
	NodeAttrAutoExitNode NodeCapability = "auto-exit-node"

	// NodeAttrStoreAppCRoutes configures the node to store app connector routes persistently.
	NodeAttrStoreAppCRoutes NodeCapability = "store-appc-routes"

	// NodeAttrSuggestExitNodeUI allows the currently suggested exit node to appear in the client GUI.
	NodeAttrSuggestExitNodeUI NodeCapability = "suggest-exit-node-ui"

	// NodeAttrUserDialUseRoutes makes UserDial use either the peer dialer or the system dialer,
	// depending on the destination address and the configured routes. When present, it also makes
	// the DNS forwarder use UserDial instead of SystemDial when dialing resolvers.
	NodeAttrUserDialUseRoutes NodeCapability = "user-dial-routes"

	// NodeAttrSSHBehaviorV1 forces SSH to use the V1 behavior (no su, run SFTP in-process)
	// Added 2024-05-29 in Tailscale version 1.68.
	NodeAttrSSHBehaviorV1 NodeCapability = "ssh-behavior-v1"

	// NodeAttrDisableSplitDNSWhenNoCustomResolvers indicates that the node's
	// DNS manager should not adopt a split DNS configuration even though the
	// Config of the resolver only contains routes that do not specify custom
	// resolver(s), hence all DNS queries can be safely sent to the upstream
	// DNS resolver and the node's DNS forwarder doesn't need to handle all
	// DNS traffic.
	// This is for now (2024-06-06) an iOS-specific battery life optimization,
	// and this node attribute allows us to disable the optimization remotely
	// if needed.
	NodeAttrDisableSplitDNSWhenNoCustomResolvers NodeCapability = "disable-split-dns-when-no-custom-resolvers"

	// NodeAttrDisableLocalDNSOverrideViaNRPT indicates that the node's DNS manager should not
	// create a default (catch-all) Windows NRPT rule when "Override local DNS" is enabled.
	// Without this rule, Windows 8.1 and newer devices issue parallel DNS requests to DNS servers
	// associated with all network adapters, even when "Override local DNS" is enabled and/or
	// a Mullvad exit node is being used, resulting in DNS leaks.
	// We began creating this rule on 2024-06-14, and this node attribute
	// allows us to disable the new behavior remotely if needed.
	NodeAttrDisableLocalDNSOverrideViaNRPT NodeCapability = "disable-local-dns-override-via-nrpt"

	// NodeAttrDisableMagicSockCryptoRouting disables the use of the
	// magicsock cryptorouting hook. See tailscale/corp#20732.
	NodeAttrDisableMagicSockCryptoRouting NodeCapability = "disable-magicsock-crypto-routing"

	// NodeAttrDisableCaptivePortalDetection instructs the client to not perform captive portal detection
	// automatically when the network state changes.
	NodeAttrDisableCaptivePortalDetection NodeCapability = "disable-captive-portal-detection"
)

// SetDNSRequest is a request to add a DNS record.
//
// This is used for ACME DNS-01 challenges (so people can use
// LetsEncrypt, etc).
//
// The request is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
//
//	https://login.tailscale.com/machine/<mkey hex>/set-dns
type SetDNSRequest struct {
	// Version is the client's capabilities
	// (CurrentCapabilityVersion) when using the Noise transport.
	//
	// When using the original nacl crypto_box transport, the
	// value must be 1.
	Version CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// Name is the domain name for which to create a record.
	// For ACME DNS-01 challenges, it should be one of the domains
	// in MapResponse.DNSConfig.CertDomains with the prefix
	// "_acme-challenge.".
	Name string

	// Type is the DNS record type. For ACME DNS-01 challenges, it
	// should be "TXT".
	Type string

	// Value is the value to add.
	Value string
}

// SetDNSResponse is the response to a SetDNSRequest.
type SetDNSResponse struct{}

// HealthChangeRequest is the JSON request body type used to report
// node health changes to https://<control>/machine/<mkey hex>/update-health.
type HealthChangeRequest struct {
	Subsys string // a health.Subsystem value in string form
	Error  string // or empty if cleared

	// NodeKey is the client's current node key.
	// In clients <= 1.62.0 it was always the zero value.
	NodeKey key.NodePublic
}

// SSHPolicy is the policy for how to handle incoming SSH connections
// over Tailscale.
type SSHPolicy struct {
	// Rules are the rules to process for an incoming SSH connection. The first
	// matching rule takes its action and stops processing further rules.
	//
	// When an incoming connection first starts, all rules are evaluated in
	// "none" auth mode, where the client hasn't even been asked to send a
	// public key. All SSHRule.Principals requiring a public key won't match. If
	// a rule matches on the first pass and its Action is reject, the
	// authentication fails with that action's rejection message, if any.
	//
	// If the first pass rule evaluation matches nothing without matching an
	// Action with Reject set, the rules are considered to see whether public
	// keys might still result in a match. If not, "none" auth is terminated
	// before proceeding to public key mode. If so, the client is asked to try
	// public key authentication and the rules are evaluated again for each of
	// the client's present keys.
	Rules []*SSHRule `json:"rules"`
}

// An SSH rule is a match predicate and associated action for an incoming SSH connection.
type SSHRule struct {
	// RuleExpires, if non-nil, is when this rule expires.
	//
	// For example, a (principal,sshuser) tuple might be granted
	// prompt-free SSH access for N minutes, so this rule would be
	// before a expiration-free rule for the same principal that
	// required an auth prompt.  This permits the control plane to
	// be out of the path for already-authorized SSH pairs.
	//
	// Once a rule matches, the lifetime of any accepting connection
	// is subject to the SSHAction.SessionExpires time, if any.
	RuleExpires *time.Time `json:"ruleExpires,omitempty"`

	// Principals matches an incoming connection. If the connection
	// matches anything in this list and also matches SSHUsers,
	// then Action is applied.
	Principals []*SSHPrincipal `json:"principals"`

	// SSHUsers are the SSH users that this rule matches. It is a
	// map from either ssh-user|"*" => local-user.  The map must
	// contain a key for either ssh-user or, as a fallback, "*" to
	// match anything. If it does, the map entry's value is the
	// actual user that's logged in.
	// If the map value is the empty string (for either the
	// requested SSH user or "*"), the rule doesn't match.
	// If the map value is "=", it means the ssh-user should map
	// directly to the local-user.
	// It may be nil if the Action is reject.
	SSHUsers map[string]string `json:"sshUsers"`

	// Action is the outcome to task.
	// A nil or invalid action means to deny.
	Action *SSHAction `json:"action"`
}

// SSHPrincipal is either a particular node or a user on any node.
type SSHPrincipal struct {
	// Matching any one of the following four field causes a match.
	// It must also match Certs, if non-empty.

	Node      StableNodeID `json:"node,omitempty"`
	NodeIP    string       `json:"nodeIP,omitempty"`
	UserLogin string       `json:"userLogin,omitempty"` // email-ish: foo@example.com, bar@github
	Any       bool         `json:"any,omitempty"`       // if true, match any connection
	// TODO(bradfitz): add StableUserID, once that exists

	// PubKeys, if non-empty, means that this SSHPrincipal only
	// matches if one of these public keys is presented by the user.
	//
	// As a special case, if len(PubKeys) == 1 and PubKeys[0] starts
	// with "https://", then it's fetched (like https://github.com/username.keys).
	// In that case, the following variable expansions are also supported
	// in the URL:
	//   * $LOGINNAME_EMAIL ("foo@bar.com" or "foo@github")
	//   * $LOGINNAME_LOCALPART (the "foo" from either of the above)
	PubKeys []string `json:"pubKeys,omitempty"`
}

// SSHAction is how to handle an incoming connection.
// At most one field should be non-zero.
type SSHAction struct {
	// Message, if non-empty, is shown to the user before the
	// action occurs.
	Message string `json:"message,omitempty"`

	// Reject, if true, terminates the connection. This action
	// has higher priority that Accept, if given.
	// The reason this is exists is primarily so a response
	// from HoldAndDelegate has a way to stop the poll.
	Reject bool `json:"reject,omitempty"`

	// Accept, if true, accepts the connection immediately
	// without further prompts.
	Accept bool `json:"accept,omitempty"`

	// SessionDuration, if non-zero, is how long the session can stay open
	// before being forcefully terminated.
	SessionDuration time.Duration `json:"sessionDuration,omitempty"`

	// AllowAgentForwarding, if true, allows accepted connections to forward
	// the ssh agent if requested.
	AllowAgentForwarding bool `json:"allowAgentForwarding,omitempty"`

	// HoldAndDelegate, if non-empty, is a URL that serves an
	// outcome verdict.  The connection will be accepted and will
	// block until the provided long-polling URL serves a new
	// SSHAction JSON value. The URL must be fetched using the
	// Noise transport (in package control/control{base,http}).
	// If the long poll breaks before returning a complete HTTP
	// response, it should be re-fetched as long as the SSH
	// session is open.
	//
	// The following variables in the URL are expanded by tailscaled:
	//
	//   * $SRC_NODE_IP (URL escaped)
	//   * $SRC_NODE_ID (Node.ID as int64 string)
	//   * $DST_NODE_IP (URL escaped)
	//   * $DST_NODE_ID (Node.ID as int64 string)
	//   * $SSH_USER (URL escaped, ssh user requested)
	//   * $LOCAL_USER (URL escaped, local user mapped)
	HoldAndDelegate string `json:"holdAndDelegate,omitempty"`

	// AllowLocalPortForwarding, if true, allows accepted connections
	// to use local port forwarding if requested.
	AllowLocalPortForwarding bool `json:"allowLocalPortForwarding,omitempty"`

	// AllowRemotePortForwarding, if true, allows accepted connections
	// to use remote port forwarding if requested.
	AllowRemotePortForwarding bool `json:"allowRemotePortForwarding,omitempty"`

	// Recorders defines the destinations of the SSH session recorders.
	// The recording will be uploaded to http://addr:port/record.
	Recorders []netip.AddrPort `json:"recorders,omitempty"`

	// OnRecorderFailure is the action to take if recording fails.
	// If nil, the default action is to fail open.
	OnRecordingFailure *SSHRecorderFailureAction `json:"onRecordingFailure,omitempty"`
}

// SSHRecorderFailureAction is the action to take if recording fails.
type SSHRecorderFailureAction struct {
	// RejectSessionWithMessage, if not empty, specifies that the session should
	// be rejected if the recording fails to start.
	// The message will be shown to the user before the session is rejected.
	RejectSessionWithMessage string `json:",omitempty"`

	// TerminateSessionWithMessage, if not empty, specifies that the session
	// should be terminated if the recording fails after it has started. The
	// message will be shown to the user before the session is terminated.
	TerminateSessionWithMessage string `json:",omitempty"`

	// NotifyURL, if non-empty, specifies a HTTP POST URL to notify when the
	// recording fails. The payload is the JSON encoded
	// SSHRecordingFailureNotifyRequest struct. The host field in the URL is
	// ignored, and it will be sent to control over the Noise transport.
	NotifyURL string `json:",omitempty"`
}

// SSHEventNotifyRequest is the JSON payload sent to the NotifyURL
// for an SSH event.
type SSHEventNotifyRequest struct {
	// EventType is the type of notify request being sent.
	EventType SSHEventType

	// ConnectionID uniquely identifies a connection made to the SSH server.
	// It may be shared across multiple sessions over the same connection in
	// case a single connection creates multiple sessions.
	ConnectionID string

	// CapVersion is the client's current CapabilityVersion.
	CapVersion CapabilityVersion

	// NodeKey is the client's current node key.
	NodeKey key.NodePublic

	// SrcNode is the ID of the node that initiated the SSH session.
	SrcNode NodeID

	// SSHUser is the user that was presented to the SSH server.
	SSHUser string

	// LocalUser is the user that was resolved from the SSHUser for the local machine.
	LocalUser string

	// RecordingAttempts is the list of recorders that were attempted, in order.
	RecordingAttempts []*SSHRecordingAttempt
}

// SSHEventType defines the event type linked to a SSH action or state.
type SSHEventType int

const (
	UnspecifiedSSHEventType SSHEventType = 0
	// SSHSessionRecordingRejected is the event that
	// defines when a SSH session cannot be started
	// because no recorder is available for session
	// recording, and the SSHRecorderFailureAction
	// RejectSessionWithMessage is not empty.
	SSHSessionRecordingRejected SSHEventType = 1
	// SSHSessionRecordingTerminated is the event that
	// defines when session recording has failed
	// during the session and the SSHRecorderFailureAction
	// TerminateSessionWithMessage is not empty.
	SSHSessionRecordingTerminated SSHEventType = 2
	// SSHSessionRecordingFailed is the event that
	// defines when session recording is unavailable and
	// the SSHRecorderFailureAction RejectSessionWithMessage
	// or TerminateSessionWithMessage is empty.
	SSHSessionRecordingFailed SSHEventType = 3
)

// SSHRecordingAttempt is a single attempt to start a recording.
type SSHRecordingAttempt struct {
	// Recorder is the address of the recorder that was attempted.
	Recorder netip.AddrPort

	// FailureMessage is the error message of the failed attempt.
	FailureMessage string
}

// QueryFeatureRequest is a request sent to "/machine/feature/query"
// to get instructions on how to enable a feature, such as Funnel,
// for the node's tailnet.
//
// See QueryFeatureResponse for response structure.
type QueryFeatureRequest struct {
	// Feature is the string identifier for a feature.
	Feature string `json:",omitempty"`
	// NodeKey is the client's current node key.
	NodeKey key.NodePublic `json:",omitempty"`
}

// QueryFeatureResponse is the response to an QueryFeatureRequest.
// See cli.enableFeatureInteractive for usage.
type QueryFeatureResponse struct {
	// Complete is true when the feature is already enabled.
	Complete bool `json:",omitempty"`

	// Text holds lines to display in the CLI with information
	// about the feature and how to enable it.
	//
	// Lines are separated by newline characters. The final
	// newline may be omitted.
	Text string `json:",omitempty"`

	// URL is the link for the user to visit to take action on
	// enabling the feature.
	//
	// When empty, there is no action for this user to take.
	URL string `json:",omitempty"`

	// ShouldWait specifies whether the CLI should block and
	// wait for the user to enable the feature.
	//
	// If this is true, the enablement from the control server
	// is expected to be a quick and uninterrupted process for
	// the user, and blocking allows them to immediately start
	// using the feature once enabled without rerunning the
	// command (e.g. no need to re-run "funnel on").
	//
	// The CLI can watch the IPN notification bus for changes in
	// required node capabilities to know when to continue.
	ShouldWait bool `json:",omitempty"`
}

// WebClientAuthResponse is the response to a web client authentication request
// sent to "/machine/webclient/action" or "/machine/webclient/wait".
// See client/web for usage.
type WebClientAuthResponse struct {
	// ID is a unique identifier for the session auth request.
	// It can be supplied to "/machine/webclient/wait" to pause until
	// the session authentication has been completed.
	ID string `json:",omitempty"`

	// URL is the link for the user to visit to authenticate the session.
	//
	// When empty, there is no action for the user to take.
	URL string `json:",omitempty"`

	// Complete is true when the session authentication has been completed.
	Complete bool `json:",omitempty"`
}

// OverTLSPublicKeyResponse is the JSON response to /key?v=<n>
// over HTTPS (regular TLS) to the Tailscale control plane server,
// where the 'v' argument is the client's current capability version
// (previously known as the "MapRequest version").
//
// The "OverTLS" prefix is to loudly declare that this exchange
// doesn't happen over Noise and can be intercepted/MITM'ed by
// enterprise/corp proxies where the organization can put TLS roots
// on devices.
type OverTLSPublicKeyResponse struct {
	// LegacyPublic specifies the control plane server's original
	// NaCl crypto_box machine key.
	// It will be zero for sufficiently new clients, based on their
	// advertised "v" parameter (the CurrentMapRequestVersion).
	// In that case, only the newer Noise-based transport may be used
	// using the PublicKey field.
	LegacyPublicKey key.MachinePublic `json:"legacyPublicKey"`

	// PublicKey specifies the server's public key for the
	// Noise-based control plane protocol. (see packages
	// control/controlbase and control/controlhttp)
	PublicKey key.MachinePublic `json:"publicKey"`
}

// TokenRequest is a request to get an OIDC ID token for an audience.
// The token can be presented to any resource provider which offers OIDC
// Federation.
//
// It is JSON-encoded and sent over Noise to "/machine/id-token".
type TokenRequest struct {
	// CapVersion is the client's current CapabilityVersion.
	CapVersion CapabilityVersion
	// NodeKey is the client's current node key.
	NodeKey key.NodePublic
	// Audience the token is being requested for.
	Audience string
}

// TokenResponse is the response to a TokenRequest.
type TokenResponse struct {
	// IDToken is a JWT encoding the following standard claims:
	//
	//   `sub` | the MagicDNS name of the node
	//   `aud` | Audience from the request
	//   `exp` | Token expiry
	//   `iat` | Token issuance time
	//   `iss` | Issuer
	//   `jti` | Random token identifier
	//   `nbf` | Not before time
	//
	// It also encodes the following Tailscale specific claims:
	//
	//   `key`       | the node public key
	//   `addresses` | the Tailscale IPs of the node
	//   `nid`       | the node ID
	//   `node`      | the name of the node
	//   `domain`    | the domain of the node, it has the same format as MapResponse.Domain.
	//   `tags`      | an array of <domain:tag> on the node (like alice.github:tag:foo or example.com:tag:foo)
	//   `user`      | user emailish (like alice.github:alice@github or example.com:bob@example.com), if not tagged
	//   `uid`       | user ID, if not tagged
	IDToken string `json:"id_token"`
}

// PeerChange is an update to a node.
type PeerChange struct {
	// NodeID is the node ID being mutated. If the NodeID is not
	// known in the current netmap, this update should be
	// ignored. (But the server will try not to send such useless
	// updates.)
	NodeID NodeID

	// DERPRegion, if non-zero, means that NodeID's home DERP
	// region ID is now this number.
	DERPRegion int `json:",omitempty"`

	// Cap, if non-zero, means that NodeID's capability version has changed.
	Cap CapabilityVersion `json:",omitempty"`

	// CapMap, if non-nil, means that NodeID's capability map has changed.
	CapMap NodeCapMap `json:",omitempty"`

	// Endpoints, if non-empty, means that NodeID's UDP Endpoints
	// have changed to these.
	Endpoints []netip.AddrPort `json:",omitempty"`

	// Key, if non-nil, means that the NodeID's wireguard public key changed.
	Key *key.NodePublic `json:",omitempty"`

	// KeySignature, if non-nil, means that the signature of the wireguard
	// public key has changed.
	KeySignature tkatype.MarshaledSignature `json:",omitempty"`

	// DiscoKey, if non-nil, means that the NodeID's discokey changed.
	DiscoKey *key.DiscoPublic `json:",omitempty"`

	// Online, if non-nil, means that the NodeID's online status changed.
	Online *bool `json:",omitempty"`

	// LastSeen, if non-nil, means that the NodeID's online status changed.
	LastSeen *time.Time `json:",omitempty"`

	// KeyExpiry, if non-nil, changes the NodeID's key expiry.
	KeyExpiry *time.Time `json:",omitempty"`
}

// DerpMagicIP is a fake WireGuard endpoint IP address that means to
// use DERP. When used (in the Node.DERP field), the port number of
// the WireGuard endpoint is the DERP region ID number to use.
//
// Mnemonic: 3.3.40 are numbers above the keys D, E, R, P.
const DerpMagicIP = "127.3.3.40"

var DerpMagicIPAddr = netip.MustParseAddr(DerpMagicIP)

// EarlyNoise is the early payload that's sent over Noise but before the HTTP/2
// handshake when connecting to the coordination server.
//
// This exists to let the server push some early info to client for that
// stateful HTTP/2+Noise connection without incurring an extra round trip. (This
// would've used HTTP/2 server push, had Go's client-side APIs been available)
type EarlyNoise struct {
	// NodeKeyChallenge is a random per-connection public key to be used by
	// the client to prove possession of a wireguard private key.
	NodeKeyChallenge key.ChallengePublic `json:"nodeKeyChallenge"`
}

// LBHeader is the HTTP request header used to provide a load balancer or
// internal reverse proxy with information about the request body without the
// reverse proxy needing to read the body to parse it out. Think of it akin to
// an HTTP Host header or SNI. The value may be absent (notably for old clients)
// but if present, it should match the request. A non-empty value that doesn't
// match the request body's.
//
// The possible values depend on the request path, but for /machine (Noise)
// requests, they'll usually be a node public key (in key.NodePublic.String
// format), matching the Request JSON body's NodeKey.
//
// Note that this is not a security or authentication header; it's strictly
// denormalized redundant data as an optimization.
//
// For some request types, the header may have multiple values. (e.g. OldNodeKey
// vs NodeKey)
const LBHeader = "Ts-Lb"
