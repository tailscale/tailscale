// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse; DO NOT EDIT.

package tailcfg

import (
	"inet.af/netaddr"
	"tailscale.com/types/opt"
	"tailscale.com/types/structs"
	"time"
)

// Clone makes a deep copy of User.
// The result aliases no memory with the original.
func (src *User) Clone() *User {
	if src == nil {
		return nil
	}
	dst := new(User)
	*dst = *src
	dst.Logins = append(src.Logins[:0:0], src.Logins...)
	dst.Roles = append(src.Roles[:0:0], src.Roles...)
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _UserNeedsRegeneration = User(struct {
	ID            UserID
	LoginName     string
	DisplayName   string
	ProfilePicURL string
	Domain        string
	Logins        []LoginID
	Roles         []RoleID
	Created       time.Time
}{})

// Clone makes a deep copy of Node.
// The result aliases no memory with the original.
func (src *Node) Clone() *Node {
	if src == nil {
		return nil
	}
	dst := new(Node)
	*dst = *src
	dst.Addresses = append(src.Addresses[:0:0], src.Addresses...)
	dst.AllowedIPs = append(src.AllowedIPs[:0:0], src.AllowedIPs...)
	dst.Endpoints = append(src.Endpoints[:0:0], src.Endpoints...)
	dst.Hostinfo = *src.Hostinfo.Clone()
	if dst.LastSeen != nil {
		dst.LastSeen = new(time.Time)
		*dst.LastSeen = *src.LastSeen
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _NodeNeedsRegeneration = Node(struct {
	ID                NodeID
	StableID          StableNodeID
	Name              string
	User              UserID
	Sharer            UserID
	Key               NodeKey
	KeyExpiry         time.Time
	Machine           MachineKey
	DiscoKey          DiscoKey
	Addresses         []netaddr.IPPrefix
	AllowedIPs        []netaddr.IPPrefix
	Endpoints         []string
	DERP              string
	Hostinfo          Hostinfo
	Created           time.Time
	LastSeen          *time.Time
	KeepAlive         bool
	MachineAuthorized bool
}{})

// Clone makes a deep copy of Hostinfo.
// The result aliases no memory with the original.
func (src *Hostinfo) Clone() *Hostinfo {
	if src == nil {
		return nil
	}
	dst := new(Hostinfo)
	*dst = *src
	dst.RoutableIPs = append(src.RoutableIPs[:0:0], src.RoutableIPs...)
	dst.RequestTags = append(src.RequestTags[:0:0], src.RequestTags...)
	dst.Services = append(src.Services[:0:0], src.Services...)
	dst.NetInfo = src.NetInfo.Clone()
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _HostinfoNeedsRegeneration = Hostinfo(struct {
	IPNVersion    string
	FrontendLogID string
	BackendLogID  string
	OS            string
	OSVersion     string
	DeviceModel   string
	Hostname      string
	ShieldsUp     bool
	ShareeNode    bool
	GoArch        string
	RoutableIPs   []netaddr.IPPrefix
	RequestTags   []string
	Services      []Service
	NetInfo       *NetInfo
}{})

// Clone makes a deep copy of NetInfo.
// The result aliases no memory with the original.
func (src *NetInfo) Clone() *NetInfo {
	if src == nil {
		return nil
	}
	dst := new(NetInfo)
	*dst = *src
	if dst.DERPLatency != nil {
		dst.DERPLatency = map[string]float64{}
		for k, v := range src.DERPLatency {
			dst.DERPLatency[k] = v
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _NetInfoNeedsRegeneration = NetInfo(struct {
	MappingVariesByDestIP opt.Bool
	HairPinning           opt.Bool
	WorkingIPv6           opt.Bool
	WorkingUDP            opt.Bool
	UPnP                  opt.Bool
	PMP                   opt.Bool
	PCP                   opt.Bool
	PreferredDERP         int
	LinkType              string
	DERPLatency           map[string]float64
}{})

// Clone makes a deep copy of Group.
// The result aliases no memory with the original.
func (src *Group) Clone() *Group {
	if src == nil {
		return nil
	}
	dst := new(Group)
	*dst = *src
	dst.Members = append(src.Members[:0:0], src.Members...)
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _GroupNeedsRegeneration = Group(struct {
	ID      GroupID
	Name    string
	Members []ID
}{})

// Clone makes a deep copy of Role.
// The result aliases no memory with the original.
func (src *Role) Clone() *Role {
	if src == nil {
		return nil
	}
	dst := new(Role)
	*dst = *src
	dst.Capabilities = append(src.Capabilities[:0:0], src.Capabilities...)
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _RoleNeedsRegeneration = Role(struct {
	ID           RoleID
	Name         string
	Capabilities []CapabilityID
}{})

// Clone makes a deep copy of Capability.
// The result aliases no memory with the original.
func (src *Capability) Clone() *Capability {
	if src == nil {
		return nil
	}
	dst := new(Capability)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _CapabilityNeedsRegeneration = Capability(struct {
	ID   CapabilityID
	Type CapType
	Val  ID
}{})

// Clone makes a deep copy of Login.
// The result aliases no memory with the original.
func (src *Login) Clone() *Login {
	if src == nil {
		return nil
	}
	dst := new(Login)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _LoginNeedsRegeneration = Login(struct {
	_             structs.Incomparable
	ID            LoginID
	Provider      string
	LoginName     string
	DisplayName   string
	ProfilePicURL string
	Domain        string
}{})

// Clone makes a deep copy of DNSConfig.
// The result aliases no memory with the original.
func (src *DNSConfig) Clone() *DNSConfig {
	if src == nil {
		return nil
	}
	dst := new(DNSConfig)
	*dst = *src
	dst.Nameservers = append(src.Nameservers[:0:0], src.Nameservers...)
	dst.Domains = append(src.Domains[:0:0], src.Domains...)
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _DNSConfigNeedsRegeneration = DNSConfig(struct {
	Nameservers []netaddr.IP
	Domains     []string
	PerDomain   bool
	Proxied     bool
}{})

// Clone makes a deep copy of RegisterResponse.
// The result aliases no memory with the original.
func (src *RegisterResponse) Clone() *RegisterResponse {
	if src == nil {
		return nil
	}
	dst := new(RegisterResponse)
	*dst = *src
	dst.User = *src.User.Clone()
	return dst
}

// A compilation failure here means this code must be regenerated, with command:
//   tailscale.com/cmd/cloner -type User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse
var _RegisterResponseNeedsRegeneration = RegisterResponse(struct {
	User              User
	Login             Login
	NodeKeyExpired    bool
	MachineAuthorized bool
	AuthURL           string
}{})

// Clone duplicates src into dst and reports whether it succeeded.
// To succeed, <src, dst> must be of types <*T, *T> or <*T, **T>,
// where T is one of User,Node,Hostinfo,NetInfo,Group,Role,Capability,Login,DNSConfig,RegisterResponse.
func Clone(dst, src interface{}) bool {
	switch src := src.(type) {
	case *User:
		switch dst := dst.(type) {
		case *User:
			*dst = *src.Clone()
			return true
		case **User:
			*dst = src.Clone()
			return true
		}
	case *Node:
		switch dst := dst.(type) {
		case *Node:
			*dst = *src.Clone()
			return true
		case **Node:
			*dst = src.Clone()
			return true
		}
	case *Hostinfo:
		switch dst := dst.(type) {
		case *Hostinfo:
			*dst = *src.Clone()
			return true
		case **Hostinfo:
			*dst = src.Clone()
			return true
		}
	case *NetInfo:
		switch dst := dst.(type) {
		case *NetInfo:
			*dst = *src.Clone()
			return true
		case **NetInfo:
			*dst = src.Clone()
			return true
		}
	case *Group:
		switch dst := dst.(type) {
		case *Group:
			*dst = *src.Clone()
			return true
		case **Group:
			*dst = src.Clone()
			return true
		}
	case *Role:
		switch dst := dst.(type) {
		case *Role:
			*dst = *src.Clone()
			return true
		case **Role:
			*dst = src.Clone()
			return true
		}
	case *Capability:
		switch dst := dst.(type) {
		case *Capability:
			*dst = *src.Clone()
			return true
		case **Capability:
			*dst = src.Clone()
			return true
		}
	case *Login:
		switch dst := dst.(type) {
		case *Login:
			*dst = *src.Clone()
			return true
		case **Login:
			*dst = src.Clone()
			return true
		}
	case *DNSConfig:
		switch dst := dst.(type) {
		case *DNSConfig:
			*dst = *src.Clone()
			return true
		case **DNSConfig:
			*dst = src.Clone()
			return true
		}
	case *RegisterResponse:
		switch dst := dst.(type) {
		case *RegisterResponse:
			*dst = *src.Clone()
			return true
		case **RegisterResponse:
			*dst = src.Clone()
			return true
		}
	}
	return false
}
