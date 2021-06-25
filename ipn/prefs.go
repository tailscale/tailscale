// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/atomicfile"
	"tailscale.com/tailcfg"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
)

//go:generate go run tailscale.com/cmd/cloner -type=Prefs -output=prefs_clone.go

// DefaultControlURL returns the URL base of the control plane
// ("coordination server") for use when no explicit one is configured.
// The default control plane is the hosted version run by Tailscale.com.
const DefaultControlURL = "https://controlplane.tailscale.com"

// Prefs are the user modifiable settings of the Tailscale node agent.
type Prefs struct {
	// ControlURL is the URL of the control server to use.
	//
	// If empty, the default for new installs, DefaultControlURL
	// is used. It's set non-empty once the daemon has been started
	// for the first time.
	//
	// TODO(apenwarr): Make it safe to update this with SetPrefs().
	// Right now, you have to pass it in the initial prefs in Start(),
	// which is the only code that actually uses the ControlURL value.
	// It would be more consistent to restart controlclient
	// automatically whenever this variable changes.
	//
	// Meanwhile, you have to provide this as part of Options.Prefs or
	// Options.UpdatePrefs when calling Backend.Start().
	ControlURL string

	// RouteAll specifies whether to accept subnets advertised by
	// other nodes on the Tailscale network. Note that this does not
	// include default routes (0.0.0.0/0 and ::/0), those are
	// controlled by ExitNodeID/IP below.
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

	// ExitNodeID and ExitNodeIP specify the node that should be used
	// as an exit node for internet traffic. At most one of these
	// should be non-zero.
	//
	// The preferred way to express the chosen node is ExitNodeID, but
	// in some cases it's not possible to use that ID (e.g. in the
	// linux CLI, before tailscaled has a netmap). For those
	// situations, we allow specifying the exit node by IP, and
	// ipnlocal.LocalBackend will translate the IP into an ID when the
	// node is found in the netmap.
	//
	// If the selected exit node doesn't exist (e.g. it's not part of
	// the current tailnet), or it doesn't offer exit node services, a
	// blackhole route will be installed on the local system to
	// prevent any traffic escaping to the local network.
	ExitNodeID tailcfg.StableNodeID
	ExitNodeIP netaddr.IP

	// ExitNodeAllowLANAccess indicates whether locally accessible subnets should be
	// routed directly or via the exit node.
	ExitNodeAllowLANAccess bool

	// CorpDNS specifies whether to install the Tailscale network's
	// DNS configuration, if it exists.
	CorpDNS bool

	// WantRunning indicates whether networking should be active on
	// this node.
	WantRunning bool

	// LoggedOut indicates whether the user intends to be logged out.
	// There are other reasons we may be logged out, including no valid
	// keys.
	// We need to remember this state so that, on next startup, we can
	// generate the "Login" vs "Connect" buttons correctly, without having
	// to contact the server to confirm our nodekey status first.
	LoggedOut bool

	// ShieldsUp indicates whether to block all incoming connections,
	// regardless of the control-provided packet filter. If false, we
	// use the packet filter as provided. If true, we block incoming
	// connections. This overrides tailcfg.Hostinfo's ShieldsUp.
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
	AdvertiseRoutes []netaddr.IPPrefix

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
	NetfilterMode preftype.NetfilterMode

	// OperatorUser is the local machine user name who is allowed to
	// operate tailscaled without being root or using sudo.
	OperatorUser string `json:",omitempty"`

	// The Persist field is named 'Config' in the file for backward
	// compatibility with earlier versions.
	// TODO(apenwarr): We should move this out of here, it's not a pref.
	//  We can maybe do that once we're sure which module should persist
	//  it (backend or frontend?)
	Persist *persist.Persist `json:"Config"`
}

// MaskedPrefs is a Prefs with an associated bitmask of which fields are set.
type MaskedPrefs struct {
	Prefs

	ControlURLSet             bool `json:",omitempty"`
	RouteAllSet               bool `json:",omitempty"`
	AllowSingleHostsSet       bool `json:",omitempty"`
	ExitNodeIDSet             bool `json:",omitempty"`
	ExitNodeIPSet             bool `json:",omitempty"`
	ExitNodeAllowLANAccessSet bool `json:",omitempty"`
	CorpDNSSet                bool `json:",omitempty"`
	WantRunningSet            bool `json:",omitempty"`
	LoggedOutSet              bool `json:",omitempty"`
	ShieldsUpSet              bool `json:",omitempty"`
	AdvertiseTagsSet          bool `json:",omitempty"`
	HostnameSet               bool `json:",omitempty"`
	OSVersionSet              bool `json:",omitempty"`
	DeviceModelSet            bool `json:",omitempty"`
	NotepadURLsSet            bool `json:",omitempty"`
	ForceDaemonSet            bool `json:",omitempty"`
	AdvertiseRoutesSet        bool `json:",omitempty"`
	NoSNATSet                 bool `json:",omitempty"`
	NetfilterModeSet          bool `json:",omitempty"`
	OperatorUserSet           bool `json:",omitempty"`
}

// ApplyEdits mutates p, assigning fields from m.Prefs for each MaskedPrefs
// Set field that's true.
func (p *Prefs) ApplyEdits(m *MaskedPrefs) {
	if p == nil {
		panic("can't edit nil Prefs")
	}
	pv := reflect.ValueOf(p).Elem()
	mv := reflect.ValueOf(m).Elem()
	mpv := reflect.ValueOf(&m.Prefs).Elem()
	fields := mv.NumField()
	for i := 1; i < fields; i++ {
		if mv.Field(i).Bool() {
			newFieldValue := mpv.Field(i - 1)
			pv.Field(i - 1).Set(newFieldValue)
		}
	}
}

func (m *MaskedPrefs) Pretty() string {
	if m == nil {
		return "MaskedPrefs{<nil>}"
	}
	var sb strings.Builder
	sb.WriteString("MaskedPrefs{")
	mv := reflect.ValueOf(m).Elem()
	mt := mv.Type()
	mpv := reflect.ValueOf(&m.Prefs).Elem()
	first := true
	for i := 1; i < mt.NumField(); i++ {
		name := mt.Field(i).Name
		if mv.Field(i).Bool() {
			if !first {
				sb.WriteString(" ")
			}
			first = false
			fmt.Fprintf(&sb, "%s=%#v",
				strings.TrimSuffix(name, "Set"),
				mpv.Field(i-1).Interface())
		}
	}
	sb.WriteString("}")
	return sb.String()
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
	if p.LoggedOut {
		sb.WriteString("loggedout=true ")
	}
	if p.ForceDaemon {
		sb.WriteString("server=true ")
	}
	if p.NotepadURLs {
		sb.WriteString("notepad=true ")
	}
	if p.ShieldsUp {
		sb.WriteString("shields=true ")
	}
	if !p.ExitNodeIP.IsZero() {
		fmt.Fprintf(&sb, "exit=%v lan=%t ", p.ExitNodeIP, p.ExitNodeAllowLANAccess)
	} else if !p.ExitNodeID.IsZero() {
		fmt.Fprintf(&sb, "exit=%v lan=%t ", p.ExitNodeID, p.ExitNodeAllowLANAccess)
	}
	if len(p.AdvertiseRoutes) > 0 || goos == "linux" {
		fmt.Fprintf(&sb, "routes=%v ", p.AdvertiseRoutes)
	}
	if len(p.AdvertiseRoutes) > 0 || p.NoSNAT {
		fmt.Fprintf(&sb, "snat=%v ", !p.NoSNAT)
	}
	if len(p.AdvertiseTags) > 0 {
		fmt.Fprintf(&sb, "tags=%s ", strings.Join(p.AdvertiseTags, ","))
	}
	if goos == "linux" {
		fmt.Fprintf(&sb, "nf=%v ", p.NetfilterMode)
	}
	if p.ControlURL != "" && p.ControlURL != DefaultControlURL {
		fmt.Fprintf(&sb, "url=%q ", p.ControlURL)
	}
	if p.Hostname != "" {
		fmt.Fprintf(&sb, "host=%q ", p.Hostname)
	}
	if p.OperatorUser != "" {
		fmt.Fprintf(&sb, "op=%q ", p.OperatorUser)
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
		p.ExitNodeID == p2.ExitNodeID &&
		p.ExitNodeIP == p2.ExitNodeIP &&
		p.ExitNodeAllowLANAccess == p2.ExitNodeAllowLANAccess &&
		p.CorpDNS == p2.CorpDNS &&
		p.WantRunning == p2.WantRunning &&
		p.LoggedOut == p2.LoggedOut &&
		p.NotepadURLs == p2.NotepadURLs &&
		p.ShieldsUp == p2.ShieldsUp &&
		p.NoSNAT == p2.NoSNAT &&
		p.NetfilterMode == p2.NetfilterMode &&
		p.OperatorUser == p2.OperatorUser &&
		p.Hostname == p2.Hostname &&
		p.OSVersion == p2.OSVersion &&
		p.DeviceModel == p2.DeviceModel &&
		p.ForceDaemon == p2.ForceDaemon &&
		compareIPNets(p.AdvertiseRoutes, p2.AdvertiseRoutes) &&
		compareStrings(p.AdvertiseTags, p2.AdvertiseTags) &&
		p.Persist.Equals(p2.Persist)
}

func compareIPNets(a, b []netaddr.IPPrefix) bool {
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

// NewPrefs returns the default preferences to use.
func NewPrefs() *Prefs {
	// Provide default values for options which might be missing
	// from the json data for any reason. The json can still
	// override them to false.
	return &Prefs{
		// ControlURL is explicitly not set to signal that
		// it's not yet configured, which relaxes the CLI "up"
		// safety net features. It will get set to DefaultControlURL
		// on first up. Or, if not, DefaultControlURL will be used
		// later anyway.
		ControlURL: "",

		RouteAll:         true,
		AllowSingleHosts: true,
		CorpDNS:          true,
		WantRunning:      false,
		NetfilterMode:    preftype.NetfilterOn,
	}
}

// ControlURLOrDefault returns the coordination server's URL base.
// If not configured, DefaultControlURL is returned instead.
func (p *Prefs) ControlURLOrDefault() string {
	if p.ControlURL != "" {
		return p.ControlURL
	}
	return DefaultControlURL
}

// PrefsFromBytes deserializes Prefs from a JSON blob. If
// enforceDefaults is true, Prefs.RouteAll and Prefs.AllowSingleHosts
// are forced on.
func PrefsFromBytes(b []byte, enforceDefaults bool) (*Prefs, error) {
	p := NewPrefs()
	if len(b) == 0 {
		return p, nil
	}
	persist := &persist.Persist{}
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
	if bytes.Contains(data, jsonEscapedZero) {
		// Tailscale 1.2.0 - 1.2.8 on Windows had a memory corruption bug
		// in the backend process that ended up sending NULL bytes over JSON
		// to the frontend which wrote them out to JSON files on disk.
		// So if we see one, treat is as corrupt and the user will need
		// to log in again. (better than crashing)
		return nil, os.ErrNotExist
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
	if err := atomicfile.WriteFile(filename, data, 0600); err != nil {
		log.Printf("SavePrefs: %v\n", err)
	}
}
