// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Code generated by tailscale.com/cmd/cloner; DO NOT EDIT.

package ipn

import (
	"maps"
	"net/netip"

	"tailscale.com/drive"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/types/ptr"
)

// Clone makes a deep copy of LoginProfile.
// The result aliases no memory with the original.
func (src *LoginProfile) Clone() *LoginProfile {
	if src == nil {
		return nil
	}
	dst := new(LoginProfile)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _LoginProfileCloneNeedsRegeneration = LoginProfile(struct {
	ID             ProfileID
	Name           string
	NetworkProfile NetworkProfile
	Key            StateKey
	UserProfile    tailcfg.UserProfile
	NodeID         tailcfg.StableNodeID
	LocalUserID    WindowsUserID
	ControlURL     string
}{})

// Clone makes a deep copy of Prefs.
// The result aliases no memory with the original.
func (src *Prefs) Clone() *Prefs {
	if src == nil {
		return nil
	}
	dst := new(Prefs)
	*dst = *src
	dst.AdvertiseTags = append(src.AdvertiseTags[:0:0], src.AdvertiseTags...)
	dst.AdvertiseRoutes = append(src.AdvertiseRoutes[:0:0], src.AdvertiseRoutes...)
	dst.AdvertiseServices = append(src.AdvertiseServices[:0:0], src.AdvertiseServices...)
	if src.DriveShares != nil {
		dst.DriveShares = make([]*drive.Share, len(src.DriveShares))
		for i := range dst.DriveShares {
			if src.DriveShares[i] == nil {
				dst.DriveShares[i] = nil
			} else {
				dst.DriveShares[i] = src.DriveShares[i].Clone()
			}
		}
	}
	if dst.RelayServerPort != nil {
		dst.RelayServerPort = ptr.To(*src.RelayServerPort)
	}
	dst.Persist = src.Persist.Clone()
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _PrefsCloneNeedsRegeneration = Prefs(struct {
	ControlURL             string
	RouteAll               bool
	ExitNodeID             tailcfg.StableNodeID
	ExitNodeIP             netip.Addr
	InternalExitNodePrior  tailcfg.StableNodeID
	ExitNodeAllowLANAccess bool
	CorpDNS                bool
	RunSSH                 bool
	RunWebClient           bool
	WantRunning            bool
	LoggedOut              bool
	ShieldsUp              bool
	AdvertiseTags          []string
	Hostname               string
	NotepadURLs            bool
	ForceDaemon            bool
	Egg                    bool
	AdvertiseRoutes        []netip.Prefix
	AdvertiseServices      []string
	NoSNAT                 bool
	NoStatefulFiltering    opt.Bool
	NetfilterMode          preftype.NetfilterMode
	OperatorUser           string
	ProfileName            string
	AutoUpdate             AutoUpdatePrefs
	AppConnector           AppConnectorPrefs
	PostureChecking        bool
	NetfilterKind          string
	DriveShares            []*drive.Share
	RelayServerPort        *int
	AllowSingleHosts       marshalAsTrueInJSON
	Persist                *persist.Persist
}{})

// Clone makes a deep copy of ServeConfig.
// The result aliases no memory with the original.
func (src *ServeConfig) Clone() *ServeConfig {
	if src == nil {
		return nil
	}
	dst := new(ServeConfig)
	*dst = *src
	if dst.TCP != nil {
		dst.TCP = map[uint16]*TCPPortHandler{}
		for k, v := range src.TCP {
			if v == nil {
				dst.TCP[k] = nil
			} else {
				dst.TCP[k] = ptr.To(*v)
			}
		}
	}
	if dst.Web != nil {
		dst.Web = map[HostPort]*WebServerConfig{}
		for k, v := range src.Web {
			if v == nil {
				dst.Web[k] = nil
			} else {
				dst.Web[k] = v.Clone()
			}
		}
	}
	if dst.Services != nil {
		dst.Services = map[tailcfg.ServiceName]*ServiceConfig{}
		for k, v := range src.Services {
			if v == nil {
				dst.Services[k] = nil
			} else {
				dst.Services[k] = v.Clone()
			}
		}
	}
	dst.AllowFunnel = maps.Clone(src.AllowFunnel)
	if dst.Foreground != nil {
		dst.Foreground = map[string]*ServeConfig{}
		for k, v := range src.Foreground {
			if v == nil {
				dst.Foreground[k] = nil
			} else {
				dst.Foreground[k] = v.Clone()
			}
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _ServeConfigCloneNeedsRegeneration = ServeConfig(struct {
	TCP         map[uint16]*TCPPortHandler
	Web         map[HostPort]*WebServerConfig
	Services    map[tailcfg.ServiceName]*ServiceConfig
	AllowFunnel map[HostPort]bool
	Foreground  map[string]*ServeConfig
	ETag        string
}{})

// Clone makes a deep copy of ServiceConfig.
// The result aliases no memory with the original.
func (src *ServiceConfig) Clone() *ServiceConfig {
	if src == nil {
		return nil
	}
	dst := new(ServiceConfig)
	*dst = *src
	if dst.TCP != nil {
		dst.TCP = map[uint16]*TCPPortHandler{}
		for k, v := range src.TCP {
			if v == nil {
				dst.TCP[k] = nil
			} else {
				dst.TCP[k] = ptr.To(*v)
			}
		}
	}
	if dst.Web != nil {
		dst.Web = map[HostPort]*WebServerConfig{}
		for k, v := range src.Web {
			if v == nil {
				dst.Web[k] = nil
			} else {
				dst.Web[k] = v.Clone()
			}
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _ServiceConfigCloneNeedsRegeneration = ServiceConfig(struct {
	TCP map[uint16]*TCPPortHandler
	Web map[HostPort]*WebServerConfig
	Tun bool
}{})

// Clone makes a deep copy of TCPPortHandler.
// The result aliases no memory with the original.
func (src *TCPPortHandler) Clone() *TCPPortHandler {
	if src == nil {
		return nil
	}
	dst := new(TCPPortHandler)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _TCPPortHandlerCloneNeedsRegeneration = TCPPortHandler(struct {
	HTTPS        bool
	HTTP         bool
	TCPForward   string
	TerminateTLS string
}{})

// Clone makes a deep copy of HTTPHandler.
// The result aliases no memory with the original.
func (src *HTTPHandler) Clone() *HTTPHandler {
	if src == nil {
		return nil
	}
	dst := new(HTTPHandler)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _HTTPHandlerCloneNeedsRegeneration = HTTPHandler(struct {
	Path  string
	Proxy string
	Text  string
}{})

// Clone makes a deep copy of WebServerConfig.
// The result aliases no memory with the original.
func (src *WebServerConfig) Clone() *WebServerConfig {
	if src == nil {
		return nil
	}
	dst := new(WebServerConfig)
	*dst = *src
	if dst.Handlers != nil {
		dst.Handlers = map[string]*HTTPHandler{}
		for k, v := range src.Handlers {
			if v == nil {
				dst.Handlers[k] = nil
			} else {
				dst.Handlers[k] = ptr.To(*v)
			}
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _WebServerConfigCloneNeedsRegeneration = WebServerConfig(struct {
	Handlers map[string]*HTTPHandler
}{})
