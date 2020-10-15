// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

//go:generate go run tailscale.com/cmd/cloner -type=User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse -output=tailcfg_clone.go

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"go4.org/mem"
	"golang.org/x/oauth2"
	"inet.af/netaddr"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/types/structs"
)

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

type GroupID ID

func (u GroupID) IsZero() bool {
	return u == 0
}

type RoleID ID

func (u RoleID) IsZero() bool {
	return u == 0
}

type CapabilityID ID

// MachineKey is the curve25519 public key for a machine.
type MachineKey [32]byte

// NodeKey is the curve25519 public key for a node.
type NodeKey [32]byte

// DiscoKey is the curve25519 public key for path discovery key.
// It's never written to disk or reused between network start-ups.
type DiscoKey [32]byte

type Group struct {
	ID      GroupID
	Name    string
	Members []ID
}

type Role struct {
	ID           RoleID
	Name         string
	Capabilities []CapabilityID
}

type CapType string

const (
	CapRead  = CapType("read")
	CapWrite = CapType("write")
)

type Capability struct {
	ID   CapabilityID
	Type CapType
	Val  ID
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
	Roles         []RoleID
	Created       time.Time

	// Note: be sure to update Clone when adding new fields
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
	Roles         []RoleID // deprecated; clients should not rely on Roles
}

type Node struct {
	ID         NodeID
	Name       string // DNS
	User       UserID
	Key        NodeKey
	KeyExpiry  time.Time
	Machine    MachineKey
	DiscoKey   DiscoKey
	Addresses  []wgcfg.CIDR // IP addresses of this Node directly
	AllowedIPs []wgcfg.CIDR // range of IP addresses to route to this node
	Endpoints  []string     `json:",omitempty"` // IP+port (public via STUN, and local LANs)
	DERP       string       `json:",omitempty"` // DERP-in-IP:port ("127.3.3.40:N") endpoint
	Hostinfo   Hostinfo
	Created    time.Time
	LastSeen   *time.Time `json:",omitempty"`

	KeepAlive bool // open and keep open a connection to this peer

	MachineAuthorized bool // TODO(crawshaw): replace with MachineStatus

	// NOTE: any new fields containing pointers in this type
	//       require changes to Node.Clone.
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

// CheckTag valids whether a given string can be used as an ACL tag.
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

type ServiceProto string

const (
	TCP = ServiceProto("tcp")
	UDP = ServiceProto("udp")
)

type Service struct {
	_           structs.Incomparable
	Proto       ServiceProto // TCP or UDP
	Port        uint16       // port number service is listening on
	Description string       // text description of service
	// TODO(apenwarr): allow advertising services on subnet IPs?
	// TODO(apenwarr): add "tags" here for each service?

	// NOTE: any new fields containing pointers in this type
	//       require changes to Hostinfo.Clone.
}

// Hostinfo contains a summary of a Tailscale host.
//
// Because it contains pointers (slices), this type should not be used
// as a value type.
type Hostinfo struct {
	// TODO(crawshaw): mark all these fields ",omitempty" when all the
	// iOS apps are updated with the latest swift version of this struct.
	IPNVersion    string       // version of this code
	FrontendLogID string       // logtail ID of frontend instance
	BackendLogID  string       // logtail ID of backend instance
	OS            string       // operating system the client runs on (a version.OS value)
	OSVersion     string       // operating system version, with optional distro prefix ("Debian 10.4", "Windows 10 Pro 10.0.19041")
	DeviceModel   string       // mobile phone model ("Pixel 3a", "iPhone 11 Pro")
	Hostname      string       // name of the host the client runs on
	GoArch        string       // the host's GOARCH value (of the running binary)
	RoutableIPs   []wgcfg.CIDR `json:",omitempty"` // set of IP ranges this client can route
	RequestTags   []string     `json:",omitempty"` // set of ACL tags this node wants to claim
	Services      []Service    `json:",omitempty"` // services advertised by this machine
	NetInfo       *NetInfo     `json:",omitempty"`

	// NOTE: any new fields containing pointers in this type
	//       require changes to Hostinfo.Clone and Hostinfo.Equal.
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
	LinkType string // "wired", "wifi", "mobile" (LTE, 4G, 3G, etc)

	// DERPLatency is the fastest recent time to reach various
	// DERP STUN servers, in seconds. The map key is the
	// "regionID-v4" or "-v6"; it was previously the DERP server's
	// STUN host:port.
	//
	// This should only be updated rarely, or when there's a
	// material change, as any change here also gets uploaded to
	// the control plane.
	DERPLatency map[string]float64 `json:",omitempty"`

	// Update Clone and BasicallyEqual when adding fields.
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
	if ni.UPnP == "" && ni.PMP == "" && ni.PCP == "" {
		return "?"
	}
	return conciseOptBool(ni.UPnP, "U") + conciseOptBool(ni.PMP, "M") + conciseOptBool(ni.PCP, "C")
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
		ni.WorkingUDP == ni2.WorkingUDP &&
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

// RegisterRequest is sent by a client to register the key for a node.
// It is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
//	https://login.tailscale.com/machine/<mkey hex>
type RegisterRequest struct {
	_          structs.Incomparable
	Version    int // currently 1
	NodeKey    NodeKey
	OldNodeKey NodeKey
	Auth       struct {
		_ structs.Incomparable
		// One of Provider/LoginName, Oauth2Token, or AuthKey is set.
		Provider, LoginName string
		Oauth2Token         *oauth2.Token
		AuthKey             string
	}
	Expiry   time.Time // requested key expiry, server policy may override
	Followup string    // response waits until AuthURL is visited
	Hostinfo *Hostinfo
}

// Clone makes a deep copy of RegisterRequest.
// The result aliases no memory with the original.
//
// TODO: extend cmd/cloner to generate this method.
func (req *RegisterRequest) Clone() *RegisterRequest {
	res := new(RegisterRequest)
	*res = *req
	if res.Hostinfo != nil {
		res.Hostinfo = res.Hostinfo.Clone()
	}
	if res.Auth.Oauth2Token != nil {
		tok := *res.Auth.Oauth2Token
		res.Auth.Oauth2Token = &tok
	}
	return res
}

// RegisterResponse is returned by the server in response to a RegisterRequest.
type RegisterResponse struct {
	User              User
	Login             Login
	NodeKeyExpired    bool   // if true, the NodeKey needs to be replaced
	MachineAuthorized bool   // TODO(crawshaw): move to using MachineStatus
	AuthURL           string // if set, authorization pending
}

// MapRequest is sent by a client to start a long-poll network map updates.
// The request includes a copy of the client's current set of WireGuard
// endpoints and general host information.
//
// The request is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
//	https://login.tailscale.com/machine/<mkey hex>/map
type MapRequest struct {
	Version     int    // current version is 4
	Compress    string // "zstd" or "" (no compression)
	KeepAlive   bool   // whether server should send keep-alives back to us
	NodeKey     NodeKey
	DiscoKey    DiscoKey
	Endpoints   []string // caller's endpoints (IPv4 or IPv6)
	IncludeIPv6 bool     // include IPv6 endpoints in returned Node Endpoints
	DeltaPeers  bool     // whether the 2nd+ network map in response should be deltas, using PeersChanged, PeersRemoved
	Stream      bool     // if true, multiple MapResponse objects are returned
	Hostinfo    *Hostinfo

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
	OmitPeers bool `json:",omitempty"`
}

// PortRange represents a range of UDP or TCP port numbers.
type PortRange struct {
	First uint16
	Last  uint16
}

var PortRangeAny = PortRange{0, 65535}

// NetPortRange represents a single subnet:portrange.
type NetPortRange struct {
	_     structs.Incomparable
	IP    string
	Bits  *int // backward compatibility: if missing, means "all" bits
	Ports PortRange
}

// FilterRule represents one rule in a packet filter.
type FilterRule struct {
	SrcIPs   []string
	SrcBits  []int
	DstPorts []NetPortRange
}

var FilterAllowAll = []FilterRule{
	FilterRule{
		SrcIPs:  []string{"*"},
		SrcBits: nil,
		DstPorts: []NetPortRange{NetPortRange{
			IP:    "*",
			Bits:  nil,
			Ports: PortRange{0, 65535},
		}},
	},
}

// DNSConfig is the DNS configuration.
type DNSConfig struct {
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netaddr.IP `json:",omitempty"`
	// Domains are the search domains to use.
	Domains []string `json:",omitempty"`
	// PerDomain indicates whether it is preferred to use Nameservers
	// only for DNS queries for subdomains of Domains.
	// Some OSes and OS configurations don't support per-domain DNS configuration,
	// in which case Nameservers applies to all DNS requests regardless of PerDomain's value.
	PerDomain bool
	// Proxied indicates whether DNS requests are proxied through a tsdns.Resolver.
	// This enables Magic DNS. It is togglable independently of PerDomain.
	Proxied bool
}

type MapResponse struct {
	KeepAlive bool `json:",omitempty"` // if set, all other fields are ignored

	// Networking
	Node    *Node
	DERPMap *DERPMap `json:",omitempty"` // if non-empty, a change in the DERP map.

	// Peers, if non-empty, is the complete list of peers.
	// It will be set in the first MapResponse for a long-polled request/response.
	// Subsequent responses will be delta-encoded if DeltaPeers was set in the request.
	// If Peers is non-empty, PeersChanged and PeersRemoved should
	// be ignored (and should be empty).
	// Peers is always returned sorted by Node.ID.
	Peers []*Node `json:",omitempty"`
	// PeersChanged are the Nodes (identified by their ID) that
	// have changed or been added since the past update on the
	// HTTP response. It's only set if MapRequest.DeltaPeers was true.
	// PeersChanged is always returned sorted by Node.ID.
	PeersChanged []*Node `json:",omitempty"`
	// PeersRemoved are the NodeIDs that are no longer in the peer list.
	PeersRemoved []NodeID `json:",omitempty"`

	// DNS is the same as DNSConfig.Nameservers.
	//
	// TODO(dmytro): should be sent in DNSConfig.Nameservers once clients have updated.
	DNS []wgcfg.IP `json:",omitempty"`
	// SearchPaths are the same as DNSConfig.Domains.
	//
	// TODO(dmytro): should be sent in DNSConfig.Domains once clients have updated.
	SearchPaths []string  `json:",omitempty"`
	DNSConfig   DNSConfig `json:",omitempty"`

	// ACLs
	Domain       string
	PacketFilter []FilterRule
	UserProfiles []UserProfile // as of 1.1.541: may be new or updated user profiles only
	Roles        []Role        // deprecated; clients should not rely on Roles
	// TODO: Groups       []Group
	// TODO: Capabilities []Capability

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
}

func (k MachineKey) String() string                   { return fmt.Sprintf("mkey:%x", k[:]) }
func (k MachineKey) MarshalText() ([]byte, error)     { return keyMarshalText("mkey:", k), nil }
func (k MachineKey) HexString() string                { return fmt.Sprintf("%x", k[:]) }
func (k *MachineKey) UnmarshalText(text []byte) error { return keyUnmarshalText(k[:], "mkey:", text) }

func keyMarshalText(prefix string, k [32]byte) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, len(prefix)+64))
	fmt.Fprintf(buf, "%s%x", prefix, k[:])
	return buf.Bytes()
}

func keyUnmarshalText(dst []byte, prefix string, text []byte) error {
	if len(text) < len(prefix) || string(text[:len(prefix)]) != prefix {
		return fmt.Errorf("UnmarshalText: missing %q prefix", prefix)
	}
	pub, err := key.NewPublicFromHexMem(mem.B(text[len(prefix):]))
	if err != nil {
		return fmt.Errorf("UnmarshalText: after %q: %v", prefix, err)
	}
	copy(dst[:], pub[:])
	return nil
}

func (k NodeKey) ShortString() string { return (key.Public(k)).ShortString() }

func (k NodeKey) String() string                   { return fmt.Sprintf("nodekey:%x", k[:]) }
func (k NodeKey) MarshalText() ([]byte, error)     { return keyMarshalText("nodekey:", k), nil }
func (k *NodeKey) UnmarshalText(text []byte) error { return keyUnmarshalText(k[:], "nodekey:", text) }

// IsZero reports whether k is the zero value.
func (k NodeKey) IsZero() bool { return k == NodeKey{} }

// IsZero reports whether k is the zero value.
func (k MachineKey) IsZero() bool { return k == MachineKey{} }

func (k DiscoKey) String() string                   { return fmt.Sprintf("discokey:%x", k[:]) }
func (k DiscoKey) MarshalText() ([]byte, error)     { return keyMarshalText("discokey:", k), nil }
func (k *DiscoKey) UnmarshalText(text []byte) error { return keyUnmarshalText(k[:], "discokey:", text) }
func (k DiscoKey) ShortString() string              { return fmt.Sprintf("d:%x", k[:8]) }

// IsZero reports whether k is the zero value.
func (k DiscoKey) IsZero() bool { return k == DiscoKey{} }

func (id ID) String() string           { return fmt.Sprintf("id:%x", int64(id)) }
func (id UserID) String() string       { return fmt.Sprintf("userid:%x", int64(id)) }
func (id LoginID) String() string      { return fmt.Sprintf("loginid:%x", int64(id)) }
func (id NodeID) String() string       { return fmt.Sprintf("nodeid:%x", int64(id)) }
func (id GroupID) String() string      { return fmt.Sprintf("groupid:%x", int64(id)) }
func (id RoleID) String() string       { return fmt.Sprintf("roleid:%x", int64(id)) }
func (id CapabilityID) String() string { return fmt.Sprintf("capid:%x", int64(id)) }

// Equal reports whether n and n2 are equal.
func (n *Node) Equal(n2 *Node) bool {
	if n == nil && n2 == nil {
		return true
	}
	return n != nil && n2 != nil &&
		n.ID == n2.ID &&
		n.Name == n2.Name &&
		n.User == n2.User &&
		n.Key == n2.Key &&
		n.KeyExpiry.Equal(n2.KeyExpiry) &&
		n.Machine == n2.Machine &&
		n.DiscoKey == n2.DiscoKey &&
		eqCIDRs(n.Addresses, n2.Addresses) &&
		eqCIDRs(n.AllowedIPs, n2.AllowedIPs) &&
		eqStrings(n.Endpoints, n2.Endpoints) &&
		n.DERP == n2.DERP &&
		n.Hostinfo.Equal(&n2.Hostinfo) &&
		n.Created.Equal(n2.Created) &&
		eqTimePtr(n.LastSeen, n2.LastSeen) &&
		n.MachineAuthorized == n2.MachineAuthorized
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

func eqCIDRs(a, b []wgcfg.CIDR) bool {
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
