// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

//go:generate go run tailscale.com/cmd/cloner --type=User,Node,Hostinfo,NetInfo,Login,DNSConfig,RegisterResponse,DERPRegion,DERPMap,DERPNode --clonefunc=true --output=tailcfg_clone.go

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"inet.af/netaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/types/structs"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
)

// CapabilityVersion represents the client's capability level. That
// is, it can be thought of as the client's simple version number: a
// single monotonically increasing integer, rather than the relatively
// complex x.y.z-xxxxx semver+hash(es). Whenever the client gains a
// capability or wants to negotiate a change in semantics with the
// server (control plane), bump this number and document what's new.
//
// Previously (prior to 2022-03-06), it was known as the "MapRequest
// version" or "mapVer" or "map cap" and that name and usage persists
// in places.
type CapabilityVersion int

// CurrentCapabilityVersion is the current capability version of the codebase.
//
// History of versions:
//     3: implicit compression, keep-alives
//     4: opt-in keep-alives via KeepAlive field, opt-in compression via Compress
//     5: 2020-10-19, implies IncludeIPv6, delta Peers/UserProfiles, supports MagicDNS
//     6: 2020-12-07: means MapResponse.PacketFilter nil means unchanged
//     7: 2020-12-15: FilterRule.SrcIPs accepts CIDRs+ranges, doesn't warn about 0.0.0.0/::
//     8: 2020-12-19: client can buggily receive IPv6 addresses and routes if beta enabled server-side
//     9: 2020-12-30: client doesn't auto-add implicit search domains from peers; only DNSConfig.Domains
//    10: 2021-01-17: client understands MapResponse.PeerSeenChange
//    11: 2021-03-03: client understands IPv6, multiple default routes, and goroutine dumping
//    12: 2021-03-04: client understands PingRequest
//    13: 2021-03-19: client understands FilterRule.IPProto
//    14: 2021-04-07: client understands DNSConfig.Routes and DNSConfig.Resolvers
//    15: 2021-04-12: client treats nil MapResponse.DNSConfig as meaning unchanged
//    16: 2021-04-15: client understands Node.Online, MapResponse.OnlineChange
//    17: 2021-04-18: MapResponse.Domain empty means unchanged
//    18: 2021-04-19: MapResponse.Node nil means unchanged (all fields now omitempty)
//    19: 2021-04-21: MapResponse.Debug.SleepSeconds
//    20: 2021-06-11: MapResponse.LastSeen used even less (https://github.com/tailscale/tailscale/issues/2107)
//    21: 2021-06-15: added MapResponse.DNSConfig.CertDomains
//    22: 2021-06-16: added MapResponse.DNSConfig.ExtraRecords
//    23: 2021-08-25: DNSConfig.Routes values may be empty (for ExtraRecords support in 1.14.1+)
//    24: 2021-09-18: MapResponse.Health from control to node; node shows in "tailscale status"
//    25: 2021-11-01: MapResponse.Debug.Exit
//    26: 2022-01-12: (nothing, just bumping for 1.20.0)
//    27: 2022-02-18: start of SSHPolicy being respected
//    28: 2022-03-09: client can communicate over Noise.
const CurrentCapabilityVersion CapabilityVersion = 28

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
// Some properties are inhereted from the logins and can be overridden, such as
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
	Domain        string
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
	Domain        string
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

type emptyStructJSONSlice struct{}

var emptyJSONSliceBytes = []byte("[]")

func (emptyStructJSONSlice) MarshalJSON() ([]byte, error) {
	return emptyJSONSliceBytes, nil
}

func (emptyStructJSONSlice) UnmarshalJSON([]byte) error { return nil }

type Node struct {
	ID       NodeID
	StableID StableNodeID
	Name     string // DNS

	// User is the user who created the node. If ACL tags are in
	// use for the node then it doesn't reflect the ACL identity
	// that the node is running as.
	User UserID

	// Sharer, if non-zero, is the user who shared this node, if different than User.
	Sharer UserID `json:",omitempty"`

	Key        key.NodePublic
	KeyExpiry  time.Time
	Machine    key.MachinePublic
	DiscoKey   key.DiscoPublic
	Addresses  []netaddr.IPPrefix // IP addresses of this Node directly
	AllowedIPs []netaddr.IPPrefix // range of IP addresses to route to this node
	Endpoints  []string           `json:",omitempty"` // IP+port (public via STUN, and local LANs)
	DERP       string             `json:",omitempty"` // DERP-in-IP:port ("127.3.3.40:N") endpoint
	Hostinfo   HostinfoView
	Created    time.Time

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
	PrimaryRoutes []netaddr.IPPrefix `json:",omitempty"`

	// LastSeen is when the node was last online. It is not
	// updated when Online is true. It is nil if the current
	// node doesn't have permission to know, or the node
	// has never been online.
	LastSeen *time.Time `json:",omitempty"`

	// Online is whether the node is currently connected to the
	// coordination server.  A value of nil means unknown, or the
	// current node doesn't have permission to know.
	Online *bool `json:",omitempty"`

	KeepAlive bool `json:",omitempty"` // open and keep open a connection to this peer

	MachineAuthorized bool `json:",omitempty"` // TODO(crawshaw): replace with MachineStatus

	// Capabilities are capabilities that the node has.
	// They're free-form strings, but should be in the form of URLs/URIs
	// such as:
	//    "https://tailscale.com/cap/is-admin"
	//    "https://tailscale.com/cap/file-sharing"
	Capabilities []string `json:",omitempty"`

	// The following three computed fields hold the various names that can
	// be used for this node in UIs. They are populated from controlclient
	// (not from control) by calling node.InitDisplayNames. These can be
	// used directly or accessed via node.DisplayName or node.DisplayNames.

	ComputedName            string `json:",omitempty"` // MagicDNS base name (for normal non-shared-in nodes), FQDN (without trailing dot, for shared-in nodes), or Hostname (if no MagicDNS)
	computedHostIfDifferent string // hostname, if different than ComputedName, otherwise empty
	ComputedNameWithHost    string `json:",omitempty"` // either "ComputedName" or "ComputedName (computedHostIfDifferent)", if computedHostIfDifferent is set
}

// DisplayName returns the user-facing name for a node which should
// be shown in client UIs.
//
// Parameter forOwner specifies whether the name is requested by
// the owner of the node. When forOwner is false, the hostname is
// never included in the return value.
//
// Return value is either either "Name" or "Name (Hostname)", where
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
	if !strings.HasPrefix(tag, "tag:") {
		return errors.New("tags must start with 'tag:'")
	}
	tag = tag[4:]
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
	//     * "peerapi-dns": the local peerapi service supports
	//        being a DNS proxy (when the node is an exit
	//        node). For this service, the Port number is really
	//        the version number of the service.
	Proto ServiceProto

	// Port is the port number.
	//
	// For Proto "peerapi-dns", it's the version number of the DNS proxy,
	// currently 1.
	Port uint16

	// Description is the textual description of the service,
	// usually the process name that's running.
	Description string `json:",omitempty"`

	// TODO(apenwarr): allow advertising services on subnet IPs?
	// TODO(apenwarr): add "tags" here for each service?
}

// Hostinfo contains a summary of a Tailscale host.
//
// Because it contains pointers (slices), this type should not be used
// as a value type.
type Hostinfo struct {
	// TODO(crawshaw): mark all these fields ",omitempty" when all the
	// iOS apps are updated with the latest swift version of this struct.
	IPNVersion    string             `json:",omitempty"` // version of this code
	FrontendLogID string             `json:",omitempty"` // logtail ID of frontend instance
	BackendLogID  string             `json:",omitempty"` // logtail ID of backend instance
	OS            string             // operating system the client runs on (a version.OS value)
	OSVersion     string             `json:",omitempty"` // operating system version, with optional distro prefix ("Debian 10.4", "Windows 10 Pro 10.0.19041")
	Package       string             `json:",omitempty"` // Tailscale package to disambiguate ("choco", "appstore", etc; "" for unknown)
	DeviceModel   string             `json:",omitempty"` // mobile phone model ("Pixel 3a", "iPhone12,3")
	Hostname      string             // name of the host the client runs on
	ShieldsUp     bool               `json:",omitempty"` // indicates whether the host is blocking incoming connections
	ShareeNode    bool               `json:",omitempty"` // indicates this node exists in netmap because it's owned by a shared-to user
	GoArch        string             `json:",omitempty"` // the host's GOARCH value (of the running binary)
	RoutableIPs   []netaddr.IPPrefix `json:",omitempty"` // set of IP ranges this client can route
	RequestTags   []string           `json:",omitempty"` // set of ACL tags this node wants to claim
	Services      []Service          `json:",omitempty"` // services advertised by this machine
	NetInfo       *NetInfo           `json:",omitempty"`
	SSH_HostKeys  []string           `json:"sshHostKeys,omitempty"` // if advertised

	// NOTE: any new fields containing pointers in this type
	//       require changes to Hostinfo.Equal.
}

// View returns a read-only accessor for hi.
func (hi *Hostinfo) View() HostinfoView { return HostinfoView{hi} }

// HostinfoView is a read-only accessor for Hostinfo.
// See Hostinfo.
type HostinfoView struct {
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *Hostinfo
}

func (v HostinfoView) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.ж)
}

func (v *HostinfoView) UnmarshalJSON(b []byte) error {
	if v.ж != nil {
		return errors.New("HostinfoView is already initialized")
	}
	if len(b) == 0 {
		return nil
	}
	hi := &Hostinfo{}
	if err := json.Unmarshal(b, hi); err != nil {
		return err
	}
	v.ж = hi
	return nil
}

// Valid reports whether the underlying value is not nil.
func (v HostinfoView) Valid() bool { return v.ж != nil }

// AsStruct returns a deep-copy of the underlying value.
func (v HostinfoView) AsStruct() *Hostinfo { return v.ж.Clone() }

func (v HostinfoView) IPNVersion() string         { return v.ж.IPNVersion }
func (v HostinfoView) FrontendLogID() string      { return v.ж.FrontendLogID }
func (v HostinfoView) BackendLogID() string       { return v.ж.BackendLogID }
func (v HostinfoView) OS() string                 { return v.ж.OS }
func (v HostinfoView) OSVersion() string          { return v.ж.OSVersion }
func (v HostinfoView) Package() string            { return v.ж.Package }
func (v HostinfoView) DeviceModel() string        { return v.ж.DeviceModel }
func (v HostinfoView) Hostname() string           { return v.ж.Hostname }
func (v HostinfoView) ShieldsUp() bool            { return v.ж.ShieldsUp }
func (v HostinfoView) ShareeNode() bool           { return v.ж.ShareeNode }
func (v HostinfoView) GoArch() string             { return v.ж.GoArch }
func (v HostinfoView) Equal(v2 HostinfoView) bool { return v.ж.Equal(v2.ж) }

func (v HostinfoView) RoutableIPs() views.IPPrefixSlice {
	return views.IPPrefixSliceOf(v.ж.RoutableIPs)
}

func (v HostinfoView) RequestTags() views.StringSlice {
	return views.StringSliceOf(v.ж.RequestTags)
}

func (v HostinfoView) SSH_HostKeys() views.StringSlice {
	return views.StringSliceOf(v.ж.SSH_HostKeys)
}

func (v HostinfoView) Services() ServiceSlice {
	return ServiceSliceOf(v.ж.Services)
}

func (v HostinfoView) NetInfo() NetInfoView { return v.ж.NetInfo.View() }

// ServiceSlice is a read-only accessor for a slice of Services
type ServiceSlice struct {
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж []Service
}

// ServiceSliceOf returns a ServiceSlice for the provided slice.
func ServiceSliceOf(x []Service) ServiceSlice { return ServiceSlice{x} }

// Len returns the length of the slice.
func (v ServiceSlice) Len() int { return len(v.ж) }

// At returns the Service at index `i` of the slice.
func (v ServiceSlice) At(i int) Service { return v.ж[i] }

// Append appends the underlying slice values to dst.
func (v ServiceSlice) Append(dst []Service) []Service {
	return append(dst, v.ж...)
}

// AsSlice returns a copy of underlying slice.
func (v ServiceSlice) AsSlice() []Service {
	return v.Append(v.ж[:0:0])
}

// NetInfoView is a read-only accessor for NetInfo.
// See NetInfo.
type NetInfoView struct {
	// It is named distinctively to make you think of how dangerous it is to escape
	// to callers. You must not let callers be able to mutate it.
	ж *NetInfo
}

// Valid reports whether the underlying value is not nil.
func (v NetInfoView) Valid() bool { return v.ж != nil }

// AsStruct returns a deep-copy of the underlying value.
func (v NetInfoView) AsStruct() *NetInfo { return v.ж.Clone() }

func (v NetInfoView) MappingVariesByDestIP() opt.Bool { return v.ж.MappingVariesByDestIP }
func (v NetInfoView) HairPinning() opt.Bool           { return v.ж.HairPinning }
func (v NetInfoView) WorkingIPv6() opt.Bool           { return v.ж.WorkingIPv6 }
func (v NetInfoView) WorkingUDP() opt.Bool            { return v.ж.WorkingUDP }
func (v NetInfoView) HavePortMap() bool               { return v.ж.HavePortMap }
func (v NetInfoView) UPnP() opt.Bool                  { return v.ж.UPnP }
func (v NetInfoView) PMP() opt.Bool                   { return v.ж.PMP }
func (v NetInfoView) PCP() opt.Bool                   { return v.ж.PCP }
func (v NetInfoView) PreferredDERP() int              { return v.ж.PreferredDERP }
func (v NetInfoView) LinkType() string                { return v.ж.LinkType }
func (v NetInfoView) String() string                  { return v.ж.String() }

// DERPLatencyForEach calls fn for each value in the DERPLatency map.
func (v NetInfoView) DERPLatencyForEach(fn func(k string, v float64)) {
	for k, v := range v.ж.DERPLatency {
		fn(k, v)
	}
}

// NetInfo contains information about the host's network state.
type NetInfo struct {
	// MappingVariesByDestIP says whether the host's NAT mappings
	// vary based on the destination IP.
	MappingVariesByDestIP opt.Bool

	// HairPinning is their router does hairpinning.
	// It reports true even if there's no NAT involved.
	HairPinning opt.Bool

	// WorkingIPv6 is whether IPv6 works.
	WorkingIPv6 opt.Bool

	// WorkingUDP is whether UDP works.
	WorkingUDP opt.Bool

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

	// PreferredDERP is this node's preferred DERP server
	// for incoming traffic. The node might be be temporarily
	// connected to multiple DERP servers (to send to other nodes)
	// but PreferredDERP is the instance number that the node
	// subscribes to traffic at.
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

	// Update BasicallyEqual when adding fields.
}

func (ni *NetInfo) String() string {
	if ni == nil {
		return "NetInfo(nil)"
	}
	return fmt.Sprintf("NetInfo{varies=%v hairpin=%v ipv6=%v udp=%v derp=#%v portmap=%v link=%q}",
		ni.MappingVariesByDestIP, ni.HairPinning, ni.WorkingIPv6,
		ni.WorkingUDP, ni.PreferredDERP,
		ni.portMapSummary(),
		ni.LinkType)
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

// View returns a read-only accessor for ni.
func (ni *NetInfo) View() NetInfoView { return NetInfoView{ni} }

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
		ni.WorkingUDP == ni2.WorkingUDP &&
		ni.HavePortMap == ni2.HavePortMap &&
		ni.UPnP == ni2.UPnP &&
		ni.PMP == ni2.PMP &&
		ni.PCP == ni2.PCP &&
		ni.PreferredDERP == ni2.PreferredDERP &&
		ni.LinkType == ni2.LinkType
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

// RegisterRequest is sent by a client to register the key for a node.
// It is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
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
	Auth       struct {
		_ structs.Incomparable
		// One of Provider/LoginName, Oauth2Token, or AuthKey is set.
		Provider, LoginName string
		Oauth2Token         *Oauth2Token
		AuthKey             string
	}
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

	// The following fields are not used for SignatureNone and are required for
	// SignatureV1:
	SignatureType SignatureType `json:",omitempty"`
	Timestamp     *time.Time    `json:",omitempty"` // creation time of request to prevent replay
	DeviceCert    []byte        `json:",omitempty"` // X.509 certificate for client device
	Signature     []byte        `json:",omitempty"` // as described by SignatureType
}

// Clone makes a deep copy of RegisterRequest.
// The result aliases no memory with the original.
//
// TODO: extend cmd/cloner to generate this method.
func (req *RegisterRequest) Clone() *RegisterRequest {
	if req == nil {
		return nil
	}
	res := new(RegisterRequest)
	*res = *req
	if res.Hostinfo != nil {
		res.Hostinfo = res.Hostinfo.Clone()
	}
	if res.Auth.Oauth2Token != nil {
		tok := *res.Auth.Oauth2Token
		res.Auth.Oauth2Token = &tok
	}
	res.DeviceCert = append(res.DeviceCert[:0:0], res.DeviceCert...)
	res.Signature = append(res.Signature[:0:0], res.Signature...)
	return res
}

// RegisterResponse is returned by the server in response to a RegisterRequest.
type RegisterResponse struct {
	User              User
	Login             Login
	NodeKeyExpired    bool   // if true, the NodeKey needs to be replaced
	MachineAuthorized bool   // TODO(crawshaw): move to using MachineStatus
	AuthURL           string // if set, authorization pending

	// Error indiciates that authorization failed. If this is non-empty,
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
	}
	return "other"
}

// Endpoint is an endpoint IPPort and an associated type.
// It doesn't currently go over the wire as is but is instead
// broken up into two parallel slices in MapRequest, for compatibility
// reasons. But this type is used in the codebase.
type Endpoint struct {
	Addr netaddr.IPPort
	Type EndpointType
}

// MapRequest is sent by a client to start a long-poll network map updates.
// The request includes a copy of the client's current set of WireGuard
// endpoints and general host information.
//
// The request is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
//	https://login.tailscale.com/machine/<mkey hex>/map
type MapRequest struct {
	// Version is incremented whenever the client code changes enough that
	// we want to signal to the control server that we're capable of something
	// different.
	//
	// For current values and history, see the CapabilityVersion type's docs.
	Version CapabilityVersion

	Compress    string // "zstd" or "" (no compression)
	KeepAlive   bool   // whether server should send keep-alives back to us
	NodeKey     key.NodePublic
	DiscoKey    key.DiscoPublic
	IncludeIPv6 bool `json:",omitempty"` // include IPv6 endpoints in returned Node Endpoints (for Version 4 clients)
	Stream      bool // if true, multiple MapResponse objects are returned
	Hostinfo    *Hostinfo

	// Endpoints are the client's magicsock UDP ip:port endpoints (IPv4 or IPv6).
	Endpoints []string
	// EndpointTypes are the types of the corresponding endpoints in Endpoints.
	EndpointTypes []EndpointType `json:",omitempty"`

	// ReadOnly is whether the client just wants to fetch the
	// MapResponse, without updating their Endpoints. The
	// Endpoints field will be ignored and LastSeen will not be
	// updated and peers will not be notified of changes.
	//
	// The intended use is for clients to discover the DERP map at
	// start-up before their first real endpoint update.
	ReadOnly bool `json:",omitempty"`

	// OmitPeers is whether the client is okay with the Peers list
	// being omitted in the response. (For example, a client on
	// start up using ReadOnly to get the DERP map.)
	//
	// If OmitPeers is true, Stream is false, and ReadOnly is false,
	// then the server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
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
	//     * "v6-overlay": IPv6 development flag to have control send
	//       v6 node addrs
	//     * "minimize-netmap": have control minimize the netmap, removing
	//       peers that are unreachable per ACLS.
	DebugFlags []string `json:",omitempty"`
}

// PortRange represents a range of UDP or TCP port numbers.
type PortRange struct {
	First uint16
	Last  uint16
}

var PortRangeAny = PortRange{0, 65535}

// NetPortRange represents a range of ports that's allowed for one or more IPs.
type NetPortRange struct {
	_     structs.Incomparable
	IP    string // IP, CIDR, Range, or "*" (same formats as FilterRule.SrcIPs)
	Bits  *int   // deprecated; the old way to turn IP into a CIDR
	Ports PortRange
}

// FilterRule represents one rule in a packet filter.
//
// A rule is logically a set of source CIDRs to match (described by
// SrcIPs and SrcBits), and a set of destination targets that are then
// allowed if a source IP is mathces of those CIDRs.
type FilterRule struct {
	// SrcIPs are the source IPs/networks to match.
	//
	// It may take the following forms:
	//     * an IP address (IPv4 or IPv6)
	//     * the string "*" to match everything (both IPv4 & IPv6)
	//     * a CIDR (e.g. "192.168.0.0/16")
	//     * a range of two IPs, inclusive, separated by hyphen ("2eff::1-2eff::0800")
	SrcIPs []string

	// SrcBits is deprecated; it's the old way to specify a CIDR
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
	SrcBits []int `json:",omitempty"`

	// DstPorts are the port ranges to allow once a source IP
	// matches (is in the CIDR described by SrcIPs & SrcBits).
	DstPorts []NetPortRange

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
}

var FilterAllowAll = []FilterRule{
	{
		SrcIPs:  []string{"*"},
		SrcBits: nil,
		DstPorts: []NetPortRange{{
			IP:    "*",
			Bits:  nil,
			Ports: PortRange{0, 65535},
		}},
	},
}

// DNSConfig is the DNS configuration.
type DNSConfig struct {
	// Resolvers are the DNS resolvers to use, in order of preference.
	Resolvers []dnstype.Resolver `json:",omitempty"`

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
	Routes map[string][]dnstype.Resolver `json:",omitempty"`

	// FallbackResolvers is like Resolvers, but is only used if a
	// split DNS configuration is requested in a configuration that
	// doesn't work yet without explicit default resolvers.
	// https://github.com/tailscale/tailscale/issues/1743
	FallbackResolvers []dnstype.Resolver `json:",omitempty"`
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
	Nameservers []netaddr.IP `json:",omitempty"`

	// PerDomain is not set by the control server, and does nothing.
	PerDomain bool `json:",omitempty"`

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

	// ExitNodeFilteredSuffixes are the the DNS suffixes that the
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
	ExitNodeFilteredSet []string
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

// PingRequest with no IP and Types is a request to send an HTTP request to prove the
// long-polling client is still connected.
// PingRequest with Types and IP, will send a ping to the IP and send a
// POST request to the URL to prove that the ping succeeded.
type PingRequest struct {
	// URL is the URL to send a HEAD request to.
	// It will be a unique URL each time. No auth headers are necessary.
	//
	// If the client sees multiple PingRequests with the same URL,
	// subsequent ones should be ignored.
	// If Types and IP are defined, then URL is the URL to send a POST request to.
	URL string

	// Log is whether to log about this ping in the success case.
	// For failure cases, the client will log regardless.
	Log bool `json:",omitempty"`

	// Types is the types of ping that is initiated. Can be TSMP, ICMP or disco.
	// Types will be comma separated, such as TSMP,disco.
	Types string

	// IP is the ping target.
	// It is used in TSMP pings, if IP is invalid or empty then do a HEAD request to the URL.
	IP netaddr.IP
}

type MapResponse struct {
	// KeepAlive, if set, represents an empty message just to keep
	// the connection alive. When true, all other fields except
	// PingRequest are ignored.
	KeepAlive bool `json:",omitempty"`

	// PingRequest, if non-empty, is a request to the client to
	// prove it's still there by sending an HTTP request to the
	// provided URL. No auth headers are necessary.
	// PingRequest may be sent on any MapResponse (ones with
	// KeepAlive true or false).
	PingRequest *PingRequest `json:",omitempty"`

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

	// PeerSeenChange contains information on how to update peers' LastSeen
	// times. If the value is false, the peer is gone. If the value is true,
	// the LastSeen time is now. Absent means unchanged.
	PeerSeenChange map[NodeID]bool `json:",omitempty"`

	// OnlineChange changes the value of a Peer Node.Online value.
	OnlineChange map[NodeID]bool `json:",omitempty"`

	// DNS is the same as DNSConfig.Nameservers.
	// Only populated if MapRequest.Version < 9.
	DNS []netaddr.IP `json:",omitempty"`

	// SearchPaths is the old way to specify DNS search domains.
	// Only populated if MapRequest.Version < 9.
	SearchPaths []string `json:",omitempty"`

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
	PacketFilter []FilterRule `json:",omitempty"`

	// UserProfiles are the user profiles of nodes in the network.
	// As as of 1.1.541 (mapver 5), this contains new or updated
	// user profiles only.
	UserProfiles []UserProfile `json:",omitempty"`

	// Health, if non-nil, sets the health state
	// of the node from the control plane's perspective.
	// A nil value means no change from the previous MapResponse.
	// A non-nil 0-length slice restores the health to good (no known problems).
	// A non-zero length slice are the list of problems that the control place
	// sees.
	Health []string `json:",omitempty"`

	// SSHPolicy, if non-nil, updates the SSH policy for how incoming
	// SSH connections should be handled.
	SSHPolicy *SSHPolicy `json:",omitempty"`

	// ControlTime, if non-zero, is the current timestamp according to the control server.
	ControlTime *time.Time `json:",omitempty"`

	// Debug is normally nil, except for when the control server
	// is setting debug settings on a node.
	Debug *Debug `json:",omitempty"`
}

// Debug are instructions from the control server to the client
// to adjust debug settings.
type Debug struct {
	// LogHeapPprof controls whether the client should log
	// its heap pprof data. Each true value sent from the server
	// means that client should do one more log.
	LogHeapPprof bool `json:",omitempty"`

	// LogHeapURL is the URL to POST its heap pprof to.
	// Empty means to not log.
	LogHeapURL string `json:",omitempty"`

	// ForceBackgroundSTUN controls whether magicsock should
	// always do its background STUN queries (see magicsock's
	// periodicReSTUN), regardless of inactivity.
	ForceBackgroundSTUN bool `json:",omitempty"`

	// DERPRoute controls whether the DERP reverse path
	// optimization (see Issue 150) should be enabled or
	// disabled. The environment variable in magicsock is the
	// highest priority (if set), then this (if set), then the
	// binary default value.
	DERPRoute opt.Bool `json:",omitempty"`

	// TrimWGConfig controls whether Tailscale does lazy, on-demand
	// wireguard configuration of peers.
	TrimWGConfig opt.Bool `json:",omitempty"`

	// DisableSubnetsIfPAC controls whether subnet routers should be
	// disabled if WPAD is present on the network.
	DisableSubnetsIfPAC opt.Bool `json:",omitempty"`

	// GoroutineDumpURL, if non-empty, requests that the client do
	// a one-time dump of its active goroutines to the given URL.
	GoroutineDumpURL string `json:",omitempty"`

	// SleepSeconds requests that the client sleep for the
	// provided number of seconds.
	// The client can (and should) limit the value (such as 5
	// minutes).
	SleepSeconds float64 `json:",omitempty"`

	// RandomizeClientPort is whether magicsock should UDP bind to
	// :0 to get a random local port, ignoring any configured
	// fixed port.
	RandomizeClientPort bool `json:",omitempty"`

	// DisableUPnP is whether the client will attempt to perform a UPnP portmapping.
	// By default, we want to enable it to see if it works on more clients.
	//
	// If UPnP catastrophically fails for people, this should be set to True to kill
	// new attempts at UPnP connections.
	DisableUPnP opt.Bool `json:",omitempty"`

	// Exit optionally specifies that the client should os.Exit
	// with this code.
	Exit *int `json:",omitempty"`
}

func appendKey(base []byte, prefix string, k [32]byte) []byte {
	ret := append(base, make([]byte, len(prefix)+64)...)
	buf := ret[len(base):]
	copy(buf, prefix)
	hex.Encode(buf[len(prefix):], k[:])
	return ret
}

func keyMarshalText(prefix string, k [32]byte) []byte {
	return appendKey(nil, prefix, k)
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
		n.Key == n2.Key &&
		n.KeyExpiry.Equal(n2.KeyExpiry) &&
		n.Machine == n2.Machine &&
		n.DiscoKey == n2.DiscoKey &&
		eqBoolPtr(n.Online, n2.Online) &&
		eqCIDRs(n.Addresses, n2.Addresses) &&
		eqCIDRs(n.AllowedIPs, n2.AllowedIPs) &&
		eqCIDRs(n.PrimaryRoutes, n2.PrimaryRoutes) &&
		eqStrings(n.Endpoints, n2.Endpoints) &&
		n.DERP == n2.DERP &&
		n.Hostinfo.Equal(n2.Hostinfo) &&
		n.Created.Equal(n2.Created) &&
		eqTimePtr(n.LastSeen, n2.LastSeen) &&
		n.MachineAuthorized == n2.MachineAuthorized &&
		eqStrings(n.Capabilities, n2.Capabilities) &&
		n.ComputedName == n2.ComputedName &&
		n.computedHostIfDifferent == n2.computedHostIfDifferent &&
		n.ComputedNameWithHost == n2.ComputedNameWithHost &&
		eqStrings(n.Tags, n2.Tags)
}

func eqBoolPtr(a, b *bool) bool {
	if a == b { // covers nil
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b

}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) || ((a == nil) != (b == nil)) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func eqCIDRs(a, b []netaddr.IPPrefix) bool {
	if len(a) != len(b) || ((a == nil) != (b == nil)) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
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

const (
	CapabilityFileSharing = "https://tailscale.com/cap/file-sharing"
	CapabilityAdmin       = "https://tailscale.com/cap/is-admin"
)

// SetDNSRequest is a request to add a DNS record.
//
// This is used for ACME DNS-01 challenges (so people can use
// LetsEncrypt, etc).
//
// The request is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
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

// SSHPolicy is the policy for how to handle incoming SSH connections
// over Tailscale.
type SSHPolicy struct {
	// Rules are the rules to process for an incoming SSH
	// connection. The first matching rule takes its action and
	// stops processing further rules.
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
	// It may be nil if the Action is reject.
	SSHUsers map[string]string `json:"sshUsers"`

	// Action is the outcome to task.
	// A nil or invalid action means to deny.
	Action *SSHAction `json:"action"`
}

// SSHPrincipal is either a particular node or a user on any node.
// Any matching field causes a match.
type SSHPrincipal struct {
	Node      StableNodeID `json:"node,omitempty"`
	NodeIP    string       `json:"nodeIP,omitempty"`
	UserLogin string       `json:"userLogin,omitempty"` // email-ish: foo@example.com, bar@github

	// Any, if true, matches any user.
	Any bool `json:"any,omitempty"`

	// TODO(bradfitz): add StableUserID, once that exists
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

	// SesssionDuration, if non-zero, is how long the session can stay open
	// before being forcefully terminated.
	SesssionDuration time.Duration `json:"sessionDuration,omitempty"`

	// HoldAndDelegate, if non-empty, is a URL that serves an
	// outcome verdict.  The connection will be accepted and will
	// block until the provided long-polling URL serves a new
	// SSHAction JSON value. The URL must be fetched using the
	// Noise transport (in package control/control{base,http}).
	// If the long poll breaks before returning a complete HTTP
	// response, it should be re-fetched as long as the SSH
	// session is open.
	HoldAndDelegate string `json:"holdAndDelegate,omitempty"`

	// AllowLocalPortForwarding, if true, allows accepted connections
	// to use local port forwarding if requested.
	AllowLocalPortForwarding bool `json:"allowLocalPortForwarding,omitempty"`
}

// OverTLSPublicKeyResponse is the JSON response to /key?v=<n>
// over HTTPS (regular TLS) to the Tailscale control plane server,
// where the 'v' argument is the client's current capability version
// (previously known as the "MapRequest version").
//
// The "OverTLS" prefix is to loudly declare that this exchange
// doesn't happen over Noise and can be intercepted/MITM'ed by
// enterprise/corp proxies where the orgnanization can put TLS roots
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
