// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/oauth2"
	"tailscale.com/types/opt"
	"tailscale.com/wgengine/filter"
)

type ID int64

type UserID ID

type LoginID ID

type NodeID ID

type GroupID ID

type RoleID ID

type CapabilityID ID

// MachineKey is the curve25519 public key for a machine.
type MachineKey [32]byte

// MachineKey is the curve25519 public key for a node.
type NodeKey [32]byte

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

// Clone returns a copy of u that aliases no memory with the original.
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	u2 := new(User)
	*u2 = *u
	u2.Logins = append([]LoginID(nil), u.Logins...)
	u2.Roles = append([]RoleID(nil), u.Roles...)
	return u2
}

type Login struct {
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
	LoginName     string // for display purposes only (provider is not listed)
	DisplayName   string
	ProfilePicURL string
	Roles         []RoleID
}

type Node struct {
	ID         NodeID
	Name       string // DNS
	User       UserID
	Key        NodeKey
	KeyExpiry  time.Time
	Machine    MachineKey
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

// Clone makes a deep copy of Node.
// The result aliases no memory with the original.
func (n *Node) Clone() (res *Node) {
	res = new(Node)
	*res = *n

	res.Addresses = append([]wgcfg.CIDR{}, res.Addresses...)
	res.AllowedIPs = append([]wgcfg.CIDR{}, res.AllowedIPs...)
	res.Endpoints = append([]string{}, res.Endpoints...)
	if res.LastSeen != nil {
		lastSeen := *res.LastSeen
		res.LastSeen = &lastSeen
	}
	res.Hostinfo = *res.Hostinfo.Clone()
	return res
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

type ServiceProto string

const (
	TCP = ServiceProto("tcp")
	UDP = ServiceProto("udp")
)

type Service struct {
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
	OS            string       // operating system the client runs on
	Hostname      string       // name of the host the client runs on
	RoutableIPs   []wgcfg.CIDR `json:",omitempty"` // set of IP ranges this client can route
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
	// DERP STUN servers, in seconds. The map key is the DERP
	// server's STUN host:port.
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
	return fmt.Sprintf("NetInfo{varies=%v hairpin=%v ipv6=%v udp=%v derp=#%v link=%q}",
		ni.MappingVariesByDestIP, ni.HairPinning, ni.WorkingIPv6,
		ni.WorkingUDP, ni.PreferredDERP, ni.LinkType)
}

// BasicallyEqual reports whether ni and ni2 are basically equal, ignoring
// changes in DERPLatency.
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
		ni.PreferredDERP == ni2.PreferredDERP &&
		ni.LinkType == ni2.LinkType
}

func (ni *NetInfo) Clone() (res *NetInfo) {
	if ni == nil {
		return nil
	}
	res = new(NetInfo)
	*res = *ni
	if ni.DERPLatency != nil {
		res.DERPLatency = map[string]float64{}
		for k, v := range ni.DERPLatency {
			res.DERPLatency[k] = v
		}
	}
	return res
}

// Clone makes a deep copy of Hostinfo.
// The result aliases no memory with the original.
func (h *Hostinfo) Clone() (res *Hostinfo) {
	res = new(Hostinfo)
	*res = *h

	res.RoutableIPs = append([]wgcfg.CIDR{}, h.RoutableIPs...)
	res.Services = append([]Service{}, h.Services...)
	res.NetInfo = h.NetInfo.Clone()
	return res
}

// Equal reports whether h and h2 are equal.
func (h *Hostinfo) Equal(h2 *Hostinfo) bool {
	return reflect.DeepEqual(h, h2)
}

// RegisterRequest is sent by a client to register the key for a node.
// It is encoded to JSON, encrypted with golang.org/x/crypto/nacl/box,
// using the local machine key, and sent to:
//	https://login.tailscale.com/machine/<mkey hex>
type RegisterRequest struct {
	Version    int // currently 1
	NodeKey    NodeKey
	OldNodeKey NodeKey
	Auth       struct {
		Provider  string
		LoginName string
		// One of LoginName or Oauth2Token is set.
		Oauth2Token *oauth2.Token
	}
	Expiry   time.Time // requested key expiry, server policy may override
	Followup string    // response waits until AuthURL is visited
	Hostinfo *Hostinfo
}

// Clone makes a deep copy of RegisterRequest.
// The result aliases no memory with the original.
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
	KeepAlive   bool   // server sends keep-alives
	NodeKey     NodeKey
	Endpoints   []string // caller's endpoints (IPv4 or IPv6)
	IncludeIPv6 bool     // include IPv6 endpoints in returned Node Endpoints
	Stream      bool     // if true, multiple MapResponse objects are returned
	Hostinfo    *Hostinfo
}

type MapResponse struct {
	KeepAlive bool // if set, all other fields are ignored

	// Networking
	Node        *Node
	Peers       []*Node
	DNS         []wgcfg.IP
	SearchPaths []string

	// ACLs
	Domain       string
	PacketFilter filter.Matches
	UserProfiles []UserProfile
	Roles        []Role
	// TODO: Groups       []Group
	// TODO: Capabilities []Capability
}

func (k MachineKey) String() string { return fmt.Sprintf("mkey:%x", k[:]) }

func (k MachineKey) MarshalText() ([]byte, error) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "mkey:%x", k[:])
	return buf.Bytes(), nil
}

func (k *MachineKey) UnmarshalText(text []byte) error {
	s := string(text)
	if !strings.HasPrefix(s, "mkey:") {
		return errors.New(`MachineKey.UnmarshalText: missing prefix`)
	}
	s = strings.TrimPrefix(s, `mkey:`)
	key, err := wgcfg.ParseHexKey(s)
	if err != nil {
		return fmt.Errorf("MachineKey.UnmarhsalText: %v", err)
	}
	copy(k[:], key[:])
	return nil
}

func (k NodeKey) String() string { return fmt.Sprintf("nodekey:%x", k[:]) }

func (k NodeKey) ShortString() string {
	pk := wgcfg.Key(k)
	return pk.ShortString()
}

func (k NodeKey) MarshalText() ([]byte, error) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "nodekey:%x", k[:])
	return buf.Bytes(), nil
}

func (k *NodeKey) UnmarshalText(text []byte) error {
	s := string(text)
	if !strings.HasPrefix(s, "nodekey:") {
		return errors.New(`Nodekey.UnmarshalText: missing prefix`)
	}
	s = strings.TrimPrefix(s, "nodekey:")
	key, err := wgcfg.ParseHexKey(s)
	if err != nil {
		return fmt.Errorf("tailcfg.Ukey.UnmarhsalText: %v", err)
	}
	copy(k[:], key[:])
	return nil
}

// IsZero reports whether k is the NodeKey zero value.
func (k NodeKey) IsZero() bool {
	return k == NodeKey{}
}

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
		reflect.DeepEqual(n.Addresses, n2.Addresses) &&
		reflect.DeepEqual(n.AllowedIPs, n2.AllowedIPs) &&
		reflect.DeepEqual(n.Endpoints, n2.Endpoints) &&
		reflect.DeepEqual(n.Hostinfo, n2.Hostinfo) &&
		n.Created.Equal(n2.Created) &&
		reflect.DeepEqual(n.LastSeen, n2.LastSeen) &&
		n.MachineAuthorized == n2.MachineAuthorized
}
