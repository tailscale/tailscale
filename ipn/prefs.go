// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/atomicfile"
	"tailscale.com/control/controlclient"
	"tailscale.com/wgengine/router"
)

//go:generate go run tailscale.com/cmd/cloner -type=Prefs -output=prefs_clone.go

// Prefs are the user modifiable settings of the Tailscale node agent.
type Prefs struct {
	// ControlURL is the URL of the control server to use.
	ControlURL string

	// RouteAll specifies whether to accept subnet and default routes
	// advertised by other nodes on the Tailscale network.
	RouteAll bool

	// AllowSingleHosts specifies whether to install routes for each
	// node IP on the tailscale network, in addition to a route for
	// the whole network.
	// This corresponds to the "tailscale up --host-routes" value,
	// which defaults to true.
	//
	// TODO(danderson): why do we have this? It dumps a lot of stuff
	// into the routing table, and a single network route _should_ be
	// all that we need. But when I turn this off in my tailscaled,
	// packets stop flowing. What's up with that?
	AllowSingleHosts bool

	// CorpDNS specifies whether to install the Tailscale network's
	// DNS configuration, if it exists.
	CorpDNS bool

	// WantRunning indicates whether networking should be active on
	// this node.
	WantRunning bool

	// ShieldsUp indicates whether to block all incoming connections,
	// regardless of the control-provided packet filter. If false, we
	// use the packet filter as provided. If true, we block incoming
	// connections.
	ShieldsUp bool

	// AdvertiseTags specifies groups that this node wants to join, for
	// purposes of ACL enforcement. These can be referenced from the ACL
	// security policy. Note that advertising a tag doesn't guarantee that
	// the control server will allow you to take on the rights for that
	// tag.
	AdvertiseTags []string

	// Hostname is the hostname to use for identifying the node. If
	// not set, os.Hostname is used.
	Hostname string

	// OSVersion overrides tailcfg.Hostinfo's OSVersion.
	OSVersion string

	// DeviceModel overrides tailcfg.Hostinfo's DeviceModel.
	DeviceModel string

	// NotepadURLs is a debugging setting that opens OAuth URLs in
	// notepad.exe on Windows, rather than loading them in a browser.
	//
	// apenwarr 2020-04-29: Unfortunately this is still needed sometimes.
	// Windows' default browser setting is sometimes screwy and this helps
	// users narrow it down a bit.
	NotepadURLs bool

	// ForceDaemon specifies whether a platform that normally
	// operates in "client mode" (that is, requires an active user
	// logged in with the GUI app running) should keep running after the
	// GUI ends and/or the user logs out.
	//
	// The only current applicable platform is Windows. This
	// forced Windows to go into "server mode" where Tailscale is
	// running even with no users logged in. This might also be
	// used for macOS in the future. This setting has no effect
	// for Linux/etc, which always operate in daemon mode.
	ForceDaemon bool `json:"ForceDaemon,omitempty"`

	// The following block of options only have an effect on Linux.

	// AdvertiseRoutes specifies CIDR prefixes to advertise into the
	// Tailscale network as reachable through the current
	// node.
	AdvertiseRoutes []wgcfg.CIDR

	// NoSNAT specifies whether to source NAT traffic going to
	// destinations in AdvertiseRoutes. The default is to apply source
	// NAT, which makes the traffic appear to come from the router
	// machine rather than the peer's Tailscale IP.
	//
	// Disabling SNAT requires additional manual configuration in your
	// network to route Tailscale traffic back to the subnet relay
	// machine.
	//
	// Linux-only.
	NoSNAT bool

	// NetfilterMode specifies how much to manage netfilter rules for
	// Tailscale, if at all.
	NetfilterMode router.NetfilterMode

	// The Persist field is named 'Config' in the file for backward
	// compatibility with earlier versions.
	// TODO(apenwarr): We should move this out of here, it's not a pref.
	//  We can maybe do that once we're sure which module should persist
	//  it (backend or frontend?)
	Persist *controlclient.Persist `json:"Config"`
}

// IsEmpty reports whether p is nil or pointing to a Prefs zero value.
func (p *Prefs) IsEmpty() bool { return p == nil || p.Equals(&Prefs{}) }

func (p *Prefs) Pretty() string { return p.pretty(runtime.GOOS) }
func (p *Prefs) pretty(goos string) string {
	var sb strings.Builder
	sb.WriteString("Prefs{")
	fmt.Fprintf(&sb, "ra=%v ", p.RouteAll)
	if !p.AllowSingleHosts {
		sb.WriteString("mesh=false ")
	}
	fmt.Fprintf(&sb, "dns=%v want=%v ", p.CorpDNS, p.WantRunning)
	if p.ForceDaemon {
		sb.WriteString("server=true ")
	}
	if p.NotepadURLs {
		sb.WriteString("notepad=true ")
	}
	if p.ShieldsUp {
		sb.WriteString("shields=true ")
	}
	if len(p.AdvertiseRoutes) > 0 || goos == "linux" {
		fmt.Fprintf(&sb, "routes=%v ", p.AdvertiseRoutes)
	}
	if len(p.AdvertiseRoutes) > 0 || p.NoSNAT {
		fmt.Fprintf(&sb, "snat=%v ", !p.NoSNAT)
	}
	if goos == "linux" {
		fmt.Fprintf(&sb, "nf=%v ", p.NetfilterMode)
	}
	if p.Persist != nil {
		sb.WriteString(p.Persist.Pretty())
	} else {
		sb.WriteString("Persist=nil")
	}
	sb.WriteString("}")
	return sb.String()
}

func (p *Prefs) ToBytes() []byte {
	data, err := json.MarshalIndent(p, "", "\t")
	if err != nil {
		log.Fatalf("Prefs marshal: %v\n", err)
	}
	return data
}

func (p *Prefs) Equals(p2 *Prefs) bool {
	if p == nil && p2 == nil {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}

	return p != nil && p2 != nil &&
		p.ControlURL == p2.ControlURL &&
		p.RouteAll == p2.RouteAll &&
		p.AllowSingleHosts == p2.AllowSingleHosts &&
		p.CorpDNS == p2.CorpDNS &&
		p.WantRunning == p2.WantRunning &&
		p.NotepadURLs == p2.NotepadURLs &&
		p.ShieldsUp == p2.ShieldsUp &&
		p.NoSNAT == p2.NoSNAT &&
		p.NetfilterMode == p2.NetfilterMode &&
		p.Hostname == p2.Hostname &&
		p.OSVersion == p2.OSVersion &&
		p.DeviceModel == p2.DeviceModel &&
		p.ForceDaemon == p2.ForceDaemon &&
		compareIPNets(p.AdvertiseRoutes, p2.AdvertiseRoutes) &&
		compareStrings(p.AdvertiseTags, p2.AdvertiseTags) &&
		p.Persist.Equals(p2.Persist)
}

func compareIPNets(a, b []wgcfg.CIDR) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].IP.Equal(b[i].IP) || a[i].Mask != b[i].Mask {
			return false
		}
	}
	return true
}

func compareStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func NewPrefs() *Prefs {
	return &Prefs{
		// Provide default values for options which might be missing
		// from the json data for any reason. The json can still
		// override them to false.
		ControlURL:       "https://login.tailscale.com",
		RouteAll:         true,
		AllowSingleHosts: true,
		CorpDNS:          true,
		WantRunning:      true,
		NetfilterMode:    router.NetfilterOn,
	}
}

// PrefsFromBytes deserializes Prefs from a JSON blob. If
// enforceDefaults is true, Prefs.RouteAll and Prefs.AllowSingleHosts
// are forced on.
func PrefsFromBytes(b []byte, enforceDefaults bool) (*Prefs, error) {
	p := NewPrefs()
	if len(b) == 0 {
		return p, nil
	}
	persist := &controlclient.Persist{}
	err := json.Unmarshal(b, persist)
	if err == nil && (persist.Provider != "" || persist.LoginName != "") {
		// old-style relaynode config; import it
		p.Persist = persist
	} else {
		err = json.Unmarshal(b, &p)
		if err != nil {
			log.Printf("Prefs parse: %v: %v\n", err, b)
		}
	}
	if enforceDefaults {
		p.RouteAll = true
		p.AllowSingleHosts = true
	}
	return p, err
}

// LoadPrefs loads a legacy relaynode config file into Prefs
// with sensible migration defaults set.
func LoadPrefs(filename string) (*Prefs, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("LoadPrefs open: %w", err) // err includes path
	}
	p, err := PrefsFromBytes(data, false)
	if err != nil {
		return nil, fmt.Errorf("LoadPrefs(%q) decode: %w", filename, err)
	}
	return p, nil
}

func SavePrefs(filename string, p *Prefs) {
	log.Printf("Saving prefs %v %v\n", filename, p.Pretty())
	data := p.ToBytes()
	os.MkdirAll(filepath.Dir(filename), 0700)
	if err := atomicfile.WriteFile(filename, data, 0666); err != nil {
		log.Printf("SavePrefs: %v\n", err)
	}
}
