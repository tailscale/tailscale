// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"

	"tailscale.com/atomicfile"
	"tailscale.com/drive"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/version"
)

// DefaultControlURL is the URL base of the control plane
// ("coordination server") for use when no explicit one is configured.
// The default control plane is the hosted version run by Tailscale.com.
const DefaultControlURL = "https://controlplane.tailscale.com"

var (
	// ErrExitNodeIDAlreadySet is returned from (*Prefs).SetExitNodeIP when the
	// Prefs.ExitNodeID field is already set.
	ErrExitNodeIDAlreadySet = errors.New("cannot set ExitNodeIP when ExitNodeID is already set")
)

// IsLoginServerSynonym reports whether a URL is a drop-in replacement
// for the primary Tailscale login server.
func IsLoginServerSynonym(val any) bool {
	return val == "https://login.tailscale.com" || val == "https://controlplane.tailscale.com"
}

// Prefs are the user modifiable settings of the Tailscale node agent.
// When you add a Pref to this struct, remember to add a corresponding
// field in MaskedPrefs, and check your field for equality in Prefs.Equals().
type Prefs struct {
	// ControlURL is the URL of the control server to use.
	//
	// If empty, the default for new installs, DefaultControlURL
	// is used. It's set non-empty once the daemon has been started
	// for the first time.
	//
	// TODO(apenwarr): Make it safe to update this with EditPrefs().
	// Right now, you have to pass it in the initial prefs in Start(),
	// which is the only code that actually uses the ControlURL value.
	// It would be more consistent to restart controlclient
	// automatically whenever this variable changes.
	//
	// Meanwhile, you have to provide this as part of
	// Options.LegacyMigrationPrefs or Options.UpdatePrefs when
	// calling Backend.Start().
	ControlURL string

	// RouteAll specifies whether to accept subnets advertised by
	// other nodes on the Tailscale network. Note that this does not
	// include default routes (0.0.0.0/0 and ::/0), those are
	// controlled by ExitNodeID/IP below.
	RouteAll bool

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
	ExitNodeIP netip.Addr

	// AutoExitNode is an optional expression that specifies whether and how
	// tailscaled should pick an exit node automatically.
	//
	// If specified, tailscaled will use an exit node based on the expression,
	// and will re-evaluate the selection periodically as network conditions,
	// available exit nodes, or policy settings change. A blackhole route will
	// be installed to prevent traffic from escaping to the local network until
	// an exit node is selected. It takes precedence over ExitNodeID and ExitNodeIP.
	//
	// If empty, tailscaled will not automatically select an exit node.
	//
	// If the specified expression is invalid or unsupported by the client,
	// it falls back to the behavior of [AnyExitNode].
	//
	// As of 2025-07-02, the only supported value is [AnyExitNode].
	// It's a string rather than a boolean to allow future extensibility
	// (e.g., AutoExitNode = "mullvad" or AutoExitNode = "geo:us").
	AutoExitNode ExitNodeExpression `json:",omitempty"`

	// InternalExitNodePrior is the most recently used ExitNodeID in string form. It is set by
	// the backend on transition from exit node on to off and used by the
	// backend.
	//
	// As an Internal field, it can't be set by LocalAPI clients, rather it is set indirectly
	// when the ExitNodeID value is zero'd and via the set-use-exit-node-enabled endpoint.
	InternalExitNodePrior tailcfg.StableNodeID

	// ExitNodeAllowLANAccess indicates whether locally accessible subnets should be
	// routed directly or via the exit node.
	ExitNodeAllowLANAccess bool

	// CorpDNS specifies whether to install the Tailscale network's
	// DNS configuration, if it exists.
	CorpDNS bool

	// RunSSH bool is whether this node should run an SSH
	// server, permitting access to peers according to the
	// policies as configured by the Tailnet's admin(s).
	RunSSH bool

	// RunWebClient bool is whether this node should expose
	// its web client over Tailscale at port 5252,
	// permitting access to peers according to the
	// policies as configured by the Tailnet's admin(s).
	RunWebClient bool

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

	// AdvertiseTags specifies tags that should be applied to this node, for
	// purposes of ACL enforcement. These can be referenced from the ACL policy
	// document. Note that advertising a tag on the client doesn't guarantee
	// that the control server will allow the node to adopt that tag.
	AdvertiseTags []string

	// Hostname is the hostname to use for identifying the node. If
	// not set, os.Hostname is used.
	Hostname string

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

	// Egg is a optional debug flag.
	Egg bool `json:",omitempty"`

	// The following block of options only have an effect on Linux.

	// AdvertiseRoutes specifies CIDR prefixes to advertise into the
	// Tailscale network as reachable through the current
	// node.
	AdvertiseRoutes []netip.Prefix

	// AdvertiseServices specifies the list of services that this
	// node can serve as a destination for. Note that an advertised
	// service must still go through the approval process from the
	// control server.
	AdvertiseServices []string

	// Sync is whether this node should sync its configuration from
	// the control plane. If unset, this defaults to true.
	// This exists primarily for testing, to verify that netmap caching
	// and offline operation work correctly.
	Sync opt.Bool

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

	// NoStatefulFiltering specifies whether to apply stateful filtering when
	// advertising routes in AdvertiseRoutes. The default is to not apply
	// stateful filtering.
	//
	// To allow inbound connections from advertised routes, both NoSNAT and
	// NoStatefulFiltering must be true.
	//
	// This is an opt.Bool because it was first added after NoSNAT, with a
	// backfill based on the value of that parameter. The backfill has been
	// removed since then, but the field remains an opt.Bool.
	//
	// Linux-only.
	NoStatefulFiltering opt.Bool `json:",omitempty"`

	// NetfilterMode specifies how much to manage netfilter rules for
	// Tailscale, if at all.
	NetfilterMode preftype.NetfilterMode

	// OperatorUser is the local machine user name who is allowed to
	// operate tailscaled without being root or using sudo.
	OperatorUser string `json:",omitempty"`

	// ProfileName is the desired name of the profile. If empty, then the user's
	// LoginName is used. It is only used for display purposes in the client UI
	// and CLI.
	ProfileName string `json:",omitempty"`

	// AutoUpdate sets the auto-update preferences for the node agent. See
	// AutoUpdatePrefs docs for more details.
	AutoUpdate AutoUpdatePrefs

	// AppConnector sets the app connector preferences for the node agent. See
	// AppConnectorPrefs docs for more details.
	AppConnector AppConnectorPrefs

	// PostureChecking enables the collection of information used for device
	// posture checks.
	//
	// Note: this should be named ReportPosture, but it was shipped as
	// PostureChecking in some early releases and this JSON field is written to
	// disk, so we just keep its old name. (akin to CorpDNS which is an internal
	// pref name that doesn't match the public interface)
	PostureChecking bool

	// NetfilterKind specifies what netfilter implementation to use.
	//
	// It can be "iptables", "nftables", or "" to auto-detect.
	//
	// Linux-only.
	NetfilterKind string

	// LinuxPacketMarks configures Linux packet mark values used by Tailscale
	// for subnet routing and bypass routing. When nil, defaults from tsconst
	// are used.
	//
	// Linux-only.
	LinuxPacketMarks *preftype.LinuxPacketMarks `json:",omitempty"`

	// DriveShares are the configured DriveShares, stored in increasing order
	// by name.
	DriveShares []*drive.Share

	// RelayServerPort is the UDP port number for the relay server to bind to,
	// on all interfaces. A non-nil zero value signifies a random unused port
	// should be used. A nil value signifies relay server functionality
	// should be disabled.
	RelayServerPort *uint16 `json:",omitempty"`

	// RelayServerStaticEndpoints are static IP:port endpoints to advertise as
	// candidates for relay connections. Only relevant when RelayServerPort is
	// non-nil.
	RelayServerStaticEndpoints []netip.AddrPort `json:",omitempty"`

	// AllowSingleHosts was a legacy field that was always true
	// for the past 4.5 years. It controlled whether Tailscale
	// peers got /32 or /128 routes for each other.
	// As of 2024-05-17 we're starting to ignore it, but to let
	// people still downgrade Tailscale versions and not break
	// all peer-to-peer networking we still write it to disk (as JSON)
	// so it can be loaded back by old versions.
	// TODO(bradfitz): delete this in 2025 sometime. See #12058.
	AllowSingleHosts marshalAsTrueInJSON

	// The Persist field is named 'Config' in the file for backward
	// compatibility with earlier versions.
	// TODO(apenwarr): We should move this out of here, it's not a pref.
	//  We can maybe do that once we're sure which module should persist
	//  it (backend or frontend?)
	Persist *persist.Persist `json:"Config"`
}

// AutoUpdatePrefs are the auto update settings for the node agent.
type AutoUpdatePrefs struct {
	// Check specifies whether background checks for updates are enabled. When
	// enabled, tailscaled will periodically check for available updates and
	// notify the user about them.
	Check bool
	// Apply specifies whether background auto-updates are enabled. When
	// enabled, tailscaled will apply available updates in the background.
	// Check must also be set when Apply is set.
	Apply opt.Bool
}

func (au1 AutoUpdatePrefs) Equals(au2 AutoUpdatePrefs) bool {
	// This could almost be as easy as `au1.Apply == au2.Apply`, except that
	// opt.Bool("") and opt.Bool("unset") should be treated as equal.
	apply1, ok1 := au1.Apply.Get()
	apply2, ok2 := au2.Apply.Get()
	return au1.Check == au2.Check &&
		apply1 == apply2 &&
		ok1 == ok2
}

type marshalAsTrueInJSON struct{}

var trueJSON = []byte("true")

func (marshalAsTrueInJSON) MarshalJSON() ([]byte, error) { return trueJSON, nil }
func (*marshalAsTrueInJSON) UnmarshalJSON([]byte) error  { return nil }

// AppConnectorPrefs are the app connector settings for the node agent.
type AppConnectorPrefs struct {
	// Advertise specifies whether the app connector subsystem is advertising
	// this node as a connector.
	Advertise bool
}

// MaskedPrefs is a Prefs with an associated bitmask of which fields are set.
//
// Each FooSet field maps to a corresponding Foo field in Prefs. FooSet can be
// a struct, in which case inner fields of FooSet map to inner fields of Foo in
// Prefs (see AutoUpdateSet for example).
type MaskedPrefs struct {
	Prefs

	ControlURLSet                 bool                `json:",omitempty"`
	RouteAllSet                   bool                `json:",omitempty"`
	ExitNodeIDSet                 bool                `json:",omitempty"`
	ExitNodeIPSet                 bool                `json:",omitempty"`
	AutoExitNodeSet               bool                `json:",omitempty"`
	InternalExitNodePriorSet      bool                `json:",omitempty"` // Internal; can't be set by LocalAPI clients
	ExitNodeAllowLANAccessSet     bool                `json:",omitempty"`
	CorpDNSSet                    bool                `json:",omitempty"`
	RunSSHSet                     bool                `json:",omitempty"`
	RunWebClientSet               bool                `json:",omitempty"`
	WantRunningSet                bool                `json:",omitempty"`
	LoggedOutSet                  bool                `json:",omitempty"`
	ShieldsUpSet                  bool                `json:",omitempty"`
	AdvertiseTagsSet              bool                `json:",omitempty"`
	HostnameSet                   bool                `json:",omitempty"`
	NotepadURLsSet                bool                `json:",omitempty"`
	ForceDaemonSet                bool                `json:",omitempty"`
	EggSet                        bool                `json:",omitempty"`
	AdvertiseRoutesSet            bool                `json:",omitempty"`
	AdvertiseServicesSet          bool                `json:",omitempty"`
	SyncSet                       bool                `json:",omitzero"`
	NoSNATSet                     bool                `json:",omitempty"`
	NoStatefulFilteringSet        bool                `json:",omitempty"`
	NetfilterModeSet              bool                `json:",omitempty"`
	OperatorUserSet               bool                `json:",omitempty"`
	ProfileNameSet                bool                `json:",omitempty"`
	AutoUpdateSet                 AutoUpdatePrefsMask `json:",omitzero"`
	AppConnectorSet               bool                `json:",omitempty"`
	PostureCheckingSet            bool                `json:",omitempty"`
	NetfilterKindSet              bool                `json:",omitempty"`
	LinuxPacketMarksSet           bool                `json:",omitempty"`
	DriveSharesSet                bool                `json:",omitempty"`
	RelayServerPortSet            bool                `json:",omitempty"`
	RelayServerStaticEndpointsSet bool                `json:",omitzero"`
}

// SetsInternal reports whether mp has any of the Internal*Set field bools set
// to true.
func (mp *MaskedPrefs) SetsInternal() bool {
	return mp.InternalExitNodePriorSet
}

type AutoUpdatePrefsMask struct {
	CheckSet bool `json:",omitempty"`
	ApplySet bool `json:",omitempty"`
}

func (m AutoUpdatePrefsMask) Pretty(au AutoUpdatePrefs) string {
	var fields []string
	if m.CheckSet {
		fields = append(fields, fmt.Sprintf("Check=%v", au.Check))
	}
	if m.ApplySet {
		fields = append(fields, fmt.Sprintf("Apply=%v", au.Apply))
	}
	return strings.Join(fields, " ")
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
	applyPrefsEdits(mpv, pv, maskFields(mv))
}

func applyPrefsEdits(src, dst reflect.Value, mask map[string]reflect.Value) {
	for n, m := range mask {
		switch m.Kind() {
		case reflect.Bool:
			if m.Bool() {
				dst.FieldByName(n).Set(src.FieldByName(n))
			}
		case reflect.Struct:
			applyPrefsEdits(src.FieldByName(n), dst.FieldByName(n), maskFields(m))
		default:
			panic(fmt.Sprintf("unsupported mask field kind %v", m.Kind()))
		}
	}
}

func maskFields(v reflect.Value) map[string]reflect.Value {
	mask := make(map[string]reflect.Value)
	for i := range v.NumField() {
		f := v.Type().Field(i).Name
		if !strings.HasSuffix(f, "Set") {
			continue
		}
		mask[strings.TrimSuffix(f, "Set")] = v.Field(i)
	}
	return mask
}

// IsEmpty reports whether there are no masks set or if m is nil.
func (m *MaskedPrefs) IsEmpty() bool {
	if m == nil {
		return true
	}
	mv := reflect.ValueOf(m).Elem()
	fields := mv.NumField()
	for i := 1; i < fields; i++ {
		if !mv.Field(i).IsZero() {
			return false
		}
	}
	return true
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

	format := func(v reflect.Value) string {
		switch v.Type().Kind() {
		case reflect.String:
			return "%s=%q"
		case reflect.Slice:
			// []string
			if v.Type().Elem().Kind() == reflect.String {
				return "%s=%q"
			}
		case reflect.Struct:
			return "%s=%+v"
		case reflect.Pointer:
			if v.Type().Elem().Kind() == reflect.Struct {
				return "%s=%+v"
			}
		}
		return "%s=%v"
	}

	for i := 1; i < mt.NumField(); i++ {
		name := mt.Field(i).Name
		mf := mv.Field(i)
		switch mf.Kind() {
		case reflect.Bool:
			if mf.Bool() {
				if !first {
					sb.WriteString(" ")
				}
				first = false
				f := mpv.Field(i - 1)
				fmt.Fprintf(&sb, format(f),
					strings.TrimSuffix(name, "Set"),
					f.Interface())
			}
		case reflect.Struct:
			if mf.IsZero() {
				continue
			}
			mpf := mpv.Field(i - 1)
			// This would be much simpler with reflect.MethodByName("Pretty"),
			// but using MethodByName disables some linker optimizations and
			// makes our binaries much larger. See
			// https://github.com/tailscale/tailscale/issues/10627#issuecomment-1861211945
			//
			// Instead, have this explicit switch by field name to do type
			// assertions.
			switch name {
			case "AutoUpdateSet":
				p := mf.Interface().(AutoUpdatePrefsMask).Pretty(mpf.Interface().(AutoUpdatePrefs))
				fmt.Fprintf(&sb, "%s={%s}", strings.TrimSuffix(name, "Set"), p)
			default:
				panic(fmt.Sprintf("unexpected MaskedPrefs field %q", name))
			}
		}
	}
	sb.WriteString("}")
	return sb.String()
}

// IsEmpty reports whether p is nil or pointing to a Prefs zero value.
func (p *Prefs) IsEmpty() bool { return p == nil || p.Equals(&Prefs{}) }

func (p PrefsView) Pretty() string { return p.ж.Pretty() }

func (p *Prefs) Pretty() string { return p.pretty(runtime.GOOS) }
func (p *Prefs) pretty(goos string) string {
	var sb strings.Builder
	sb.WriteString("Prefs{")
	if buildfeatures.HasUseRoutes {
		fmt.Fprintf(&sb, "ra=%v ", p.RouteAll)
	}
	if buildfeatures.HasDNS {
		fmt.Fprintf(&sb, "dns=%v want=%v ", p.CorpDNS, p.WantRunning)
	}
	if buildfeatures.HasSSH && p.RunSSH {
		sb.WriteString("ssh=true ")
	}
	if buildfeatures.HasWebClient && p.RunWebClient {
		sb.WriteString("webclient=true ")
	}
	if p.LoggedOut {
		sb.WriteString("loggedout=true ")
	}
	if p.Sync.EqualBool(false) {
		sb.WriteString("sync=false ")
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
	if buildfeatures.HasUseExitNode {
		if p.ExitNodeIP.IsValid() {
			fmt.Fprintf(&sb, "exit=%v lan=%t ", p.ExitNodeIP, p.ExitNodeAllowLANAccess)
		} else if !p.ExitNodeID.IsZero() {
			fmt.Fprintf(&sb, "exit=%v lan=%t ", p.ExitNodeID, p.ExitNodeAllowLANAccess)
		}
		if p.AutoExitNode.IsSet() {
			fmt.Fprintf(&sb, "auto=%v ", p.AutoExitNode)
		}
	}
	if buildfeatures.HasAdvertiseRoutes {
		if len(p.AdvertiseRoutes) > 0 || goos == "linux" {
			fmt.Fprintf(&sb, "routes=%v ", p.AdvertiseRoutes)
		}
		if len(p.AdvertiseRoutes) > 0 || p.NoSNAT {
			fmt.Fprintf(&sb, "snat=%v ", !p.NoSNAT)
		}
		if len(p.AdvertiseRoutes) > 0 || p.NoStatefulFiltering.EqualBool(true) {
			// Only print if we're advertising any routes, or the user has
			// turned off stateful filtering (NoStatefulFiltering=true ⇒
			// StatefulFiltering=false).
			bb, _ := p.NoStatefulFiltering.Get()
			fmt.Fprintf(&sb, "statefulFiltering=%v ", !bb)
		}
	}
	if len(p.AdvertiseTags) > 0 {
		fmt.Fprintf(&sb, "tags=%s ", strings.Join(p.AdvertiseTags, ","))
	}
	if len(p.AdvertiseServices) > 0 {
		fmt.Fprintf(&sb, "services=%s ", strings.Join(p.AdvertiseServices, ","))
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
	if p.NetfilterKind != "" {
		fmt.Fprintf(&sb, "netfilterKind=%s ", p.NetfilterKind)
	}
	if buildfeatures.HasClientUpdate {
		sb.WriteString(p.AutoUpdate.Pretty())
	}
	if buildfeatures.HasAppConnectors {
		sb.WriteString(p.AppConnector.Pretty())
	}
	if buildfeatures.HasRelayServer && p.RelayServerPort != nil {
		fmt.Fprintf(&sb, "relayServerPort=%d ", *p.RelayServerPort)
	}
	if buildfeatures.HasRelayServer && len(p.RelayServerStaticEndpoints) > 0 {
		fmt.Fprintf(&sb, "relayServerStaticEndpoints=%v ", p.RelayServerStaticEndpoints)
	}
	if p.Persist != nil {
		sb.WriteString(p.Persist.Pretty())
	} else {
		sb.WriteString("Persist=nil")
	}
	sb.WriteString("}")
	return sb.String()
}

func (p PrefsView) ToBytes() []byte {
	return p.ж.ToBytes()
}

func (p *Prefs) ToBytes() []byte {
	data, err := json.MarshalIndent(p, "", "\t")
	if err != nil {
		log.Fatalf("Prefs marshal: %v\n", err)
	}
	return data
}

func (p PrefsView) Equals(p2 PrefsView) bool {
	return p.ж.Equals(p2.ж)
}

func (p *Prefs) Equals(p2 *Prefs) bool {
	if p == p2 {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}

	return p.ControlURL == p2.ControlURL &&
		p.RouteAll == p2.RouteAll &&
		p.ExitNodeID == p2.ExitNodeID &&
		p.ExitNodeIP == p2.ExitNodeIP &&
		p.AutoExitNode == p2.AutoExitNode &&
		p.InternalExitNodePrior == p2.InternalExitNodePrior &&
		p.ExitNodeAllowLANAccess == p2.ExitNodeAllowLANAccess &&
		p.CorpDNS == p2.CorpDNS &&
		p.RunSSH == p2.RunSSH &&
		p.Sync.Normalized() == p2.Sync.Normalized() &&
		p.RunWebClient == p2.RunWebClient &&
		p.WantRunning == p2.WantRunning &&
		p.LoggedOut == p2.LoggedOut &&
		p.NotepadURLs == p2.NotepadURLs &&
		p.ShieldsUp == p2.ShieldsUp &&
		p.NoSNAT == p2.NoSNAT &&
		p.NoStatefulFiltering == p2.NoStatefulFiltering &&
		p.NetfilterMode == p2.NetfilterMode &&
		p.OperatorUser == p2.OperatorUser &&
		p.Hostname == p2.Hostname &&
		p.ForceDaemon == p2.ForceDaemon &&
		slices.Equal(p.AdvertiseRoutes, p2.AdvertiseRoutes) &&
		slices.Equal(p.AdvertiseTags, p2.AdvertiseTags) &&
		slices.Equal(p.AdvertiseServices, p2.AdvertiseServices) &&
		p.Persist.Equals(p2.Persist) &&
		p.ProfileName == p2.ProfileName &&
		p.AutoUpdate.Equals(p2.AutoUpdate) &&
		p.AppConnector == p2.AppConnector &&
		p.PostureChecking == p2.PostureChecking &&
		slices.EqualFunc(p.DriveShares, p2.DriveShares, drive.SharesEqual) &&
		p.NetfilterKind == p2.NetfilterKind &&
		p.LinuxPacketMarks.Equals(p2.LinuxPacketMarks) &&
		compareUint16Ptrs(p.RelayServerPort, p2.RelayServerPort) &&
		slices.Equal(p.RelayServerStaticEndpoints, p2.RelayServerStaticEndpoints)
}

func (au AutoUpdatePrefs) Pretty() string {
	if au.Apply.EqualBool(true) {
		return "update=on "
	}
	if au.Check {
		return "update=check "
	}
	return "update=off "
}

func (ap AppConnectorPrefs) Pretty() string {
	if ap.Advertise {
		return "appconnector=advertise "
	}
	return ""
}

func compareUint16Ptrs(a, b *uint16) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	return *a == *b
}

// NewPrefs returns the default preferences to use.
func NewPrefs() *Prefs {
	// Provide default values for options which might be missing
	// from the json data for any reason. The json can still
	// override them to false.

	p := &Prefs{
		// ControlURL is explicitly not set to signal that
		// it's not yet configured, which relaxes the CLI "up"
		// safety net features. It will get set to DefaultControlURL
		// on first up. Or, if not, DefaultControlURL will be used
		// later anyway.
		ControlURL: "",

		CorpDNS:             true,
		WantRunning:         false,
		NetfilterMode:       preftype.NetfilterOn,
		NoStatefulFiltering: opt.NewBool(true),
		AutoUpdate: AutoUpdatePrefs{
			Check: true,
			Apply: opt.Bool("unset"),
		},
	}
	p.RouteAll = p.DefaultRouteAll(runtime.GOOS)
	return p
}

// ControlURLOrDefault returns the coordination server's URL base.
//
// If not configured, or if the configured value is a legacy name equivalent to
// the default, then DefaultControlURL is returned instead.
func (p PrefsView) ControlURLOrDefault(polc policyclient.Client) string {
	return p.ж.ControlURLOrDefault(polc)
}

// ControlURLOrDefault returns the coordination server's URL base.
//
// If not configured, or if the configured value is a legacy name equivalent to
// the default, then DefaultControlURL is returned instead.
func (p *Prefs) ControlURLOrDefault(polc policyclient.Client) string {
	controlURL, err := polc.GetString(pkey.ControlURL, p.ControlURL)
	if err != nil {
		controlURL = p.ControlURL
	}

	if controlURL != "" {
		if controlURL != DefaultControlURL && IsLoginServerSynonym(controlURL) {
			return DefaultControlURL
		}
		return controlURL
	}
	return DefaultControlURL
}

// DefaultRouteAll returns the default value of [Prefs.RouteAll] as a function
// of the platform it's running on.
func (p *Prefs) DefaultRouteAll(goos string) bool {
	switch goos {
	case "windows", "android", "ios":
		return true
	case "darwin":
		// Only true for macAppStore and macsys, false for darwin tailscaled.
		return version.IsSandboxedMacOS()
	default:
		return false
	}
}

// AdminPageURL returns the admin web site URL for the current ControlURL.
func (p PrefsView) AdminPageURL(polc policyclient.Client) string { return p.ж.AdminPageURL(polc) }

// AdminPageURL returns the admin web site URL for the current ControlURL.
func (p *Prefs) AdminPageURL(polc policyclient.Client) string {
	url := p.ControlURLOrDefault(polc)
	if IsLoginServerSynonym(url) {
		// TODO(crawshaw): In future release, make this https://console.tailscale.com
		url = "https://login.tailscale.com"
	}
	return url + "/admin"
}

// AdvertisesExitNode reports whether p is advertising both the v4 and
// v6 /0 exit node routes.
func (p PrefsView) AdvertisesExitNode() bool { return p.ж.AdvertisesExitNode() }

// AdvertisesExitNode reports whether p is advertising both the v4 and
// v6 /0 exit node routes.
func (p *Prefs) AdvertisesExitNode() bool {
	if p == nil {
		return false
	}
	return tsaddr.ContainsExitRoutes(views.SliceOf(p.AdvertiseRoutes))
}

// SetAdvertiseExitNode mutates p (if non-nil) to add or remove the two
// /0 exit node routes.
func (p *Prefs) SetAdvertiseExitNode(runExit bool) {
	if !buildfeatures.HasAdvertiseExitNode {
		return
	}
	if p == nil {
		return
	}
	all := p.AdvertiseRoutes
	p.AdvertiseRoutes = p.AdvertiseRoutes[:0]
	for _, r := range all {
		if r.Bits() != 0 {
			p.AdvertiseRoutes = append(p.AdvertiseRoutes, r)
		}
	}
	if !runExit {
		return
	}
	p.AdvertiseRoutes = append(p.AdvertiseRoutes,
		netip.PrefixFrom(netaddr.IPv4(0, 0, 0, 0), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0))
}

// peerWithTailscaleIP returns the peer in st with the provided
// Tailscale IP.
func peerWithTailscaleIP(st *ipnstate.Status, ip netip.Addr) (ps *ipnstate.PeerStatus, ok bool) {
	for _, ps := range st.Peer {
		for _, ip2 := range ps.TailscaleIPs {
			if ip == ip2 {
				return ps, true
			}
		}
	}
	return nil, false
}

func isRemoteIP(st *ipnstate.Status, ip netip.Addr) bool {
	for _, selfIP := range st.TailscaleIPs {
		if ip == selfIP {
			return false
		}
	}
	return true
}

// ClearExitNode sets the ExitNodeID and ExitNodeIP to their zero values.
func (p *Prefs) ClearExitNode() {
	p.ExitNodeID = ""
	p.ExitNodeIP = netip.Addr{}
	p.AutoExitNode = ""
}

// ExitNodeLocalIPError is returned when the requested IP address for an exit
// node belongs to the local machine.
type ExitNodeLocalIPError struct {
	hostOrIP string
}

func (e ExitNodeLocalIPError) Error() string {
	return fmt.Sprintf("cannot use %s as an exit node as it is a local IP address to this machine", e.hostOrIP)
}

func exitNodeIPOfArg(s string, st *ipnstate.Status) (ip netip.Addr, err error) {
	if s == "" {
		return ip, os.ErrInvalid
	}
	ip, err = netip.ParseAddr(s)
	if err == nil {
		if !isRemoteIP(st, ip) {
			return ip, ExitNodeLocalIPError{s}
		}
		// If we're online already and have a netmap, double check that the IP
		// address specified is valid.
		if st.BackendState == "Running" {
			ps, ok := peerWithTailscaleIP(st, ip)
			if !ok {
				return ip, fmt.Errorf("no node found in netmap with IP %v", ip)
			}
			if !ps.ExitNodeOption {
				return ip, fmt.Errorf("node %v is not advertising an exit node", ip)
			}
		}
		return ip, nil
	}
	match := 0
	for _, ps := range st.Peer {
		baseName := dnsname.TrimSuffix(ps.DNSName, st.MagicDNSSuffix)
		if !strings.EqualFold(s, baseName) && !strings.EqualFold(s, ps.DNSName) {
			continue
		}
		match++
		if len(ps.TailscaleIPs) == 0 {
			return ip, fmt.Errorf("node %q has no Tailscale IP?", s)
		}
		if !ps.ExitNodeOption {
			return ip, fmt.Errorf("node %q is not advertising an exit node", s)
		}
		ip = ps.TailscaleIPs[0]
	}
	switch match {
	case 0:
		return ip, fmt.Errorf("invalid value %q for --exit-node; must be IP or unique node name", s)
	case 1:
		if !isRemoteIP(st, ip) {
			return ip, ExitNodeLocalIPError{s}
		}
		return ip, nil
	default:
		return ip, fmt.Errorf("ambiguous exit node name %q", s)
	}
}

// SetExitNodeIP validates and sets the ExitNodeIP from a user-provided string
// specifying either an IP address or a MagicDNS base name ("foo", as opposed to
// "foo.bar.beta.tailscale.net"). This method does not mutate ExitNodeID and
// will fail if ExitNodeID is already set.
func (p *Prefs) SetExitNodeIP(s string, st *ipnstate.Status) error {
	if !p.ExitNodeID.IsZero() {
		return ErrExitNodeIDAlreadySet
	}
	ip, err := exitNodeIPOfArg(s, st)
	if err == nil {
		p.ExitNodeIP = ip
	}
	return err
}

// ShouldSSHBeRunning reports whether the SSH server should be running based on
// the prefs.
func (p PrefsView) ShouldSSHBeRunning() bool {
	return p.Valid() && p.ж.ShouldSSHBeRunning()
}

// ShouldSSHBeRunning reports whether the SSH server should be running based on
// the prefs.
func (p *Prefs) ShouldSSHBeRunning() bool {
	return p.WantRunning && p.RunSSH
}

// ShouldWebClientBeRunning reports whether the web client server should be running based on
// the prefs.
func (p PrefsView) ShouldWebClientBeRunning() bool {
	return p.Valid() && p.ж.ShouldWebClientBeRunning()
}

// ShouldWebClientBeRunning reports whether the web client server should be running based on
// the prefs.
func (p *Prefs) ShouldWebClientBeRunning() bool {
	return p.WantRunning && p.RunWebClient
}

// PrefsFromBytes deserializes Prefs from a JSON blob b into base. Values in
// base are preserved, unless they are populated in the JSON blob.
func PrefsFromBytes(b []byte, base *Prefs) error {
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, base)
}

func (p *Prefs) normalizeOptBools() {
	if p.Sync == opt.ExplicitlyUnset {
		p.Sync = ""
	}
}

var jsonEscapedZero = []byte(`\u0000`)

// LoadPrefsWindows loads a legacy relaynode config file into Prefs with
// sensible migration defaults set. Windows-only.
func LoadPrefsWindows(filename string) (*Prefs, error) {
	data, err := os.ReadFile(filename)
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
	p := NewPrefs()
	if err := PrefsFromBytes(data, p); err != nil {
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

// ProfileID is an auto-generated system-wide unique identifier for a login
// profile. It is a 4 character hex string like "1ab3".
type ProfileID string

// WindowsUserID is a userid (suitable for passing to ipnauth.LookupUserFromID
// or os/user.LookupId) but only set on Windows. It's empty on all other
// platforms, unless envknob.GOOS is in used, making Linux act like Windows for
// tests.
type WindowsUserID string

// NetworkProfile is a subset of netmap.NetworkMap
// that should be saved with each user profile.
type NetworkProfile struct {
	MagicDNSName string
	DomainName   string
	DisplayName  string
}

// RequiresBackfill returns whether this object does not have all the data
// expected. This is because this struct is a later addition to LoginProfile and
// this method can be checked to see if it's been backfilled to the current
// expectation or not. Note that for now, it just checks if the struct is empty.
// In the future, if we have new optional fields, this method can be changed to
// do more explicit checks to return whether it's apt for a backfill or not.
func (n NetworkProfile) RequiresBackfill() bool {
	return n == NetworkProfile{}
}

// DisplayNameOrDefault will always return a non-empty string.
// If there is a defined display name, it will return that.
// If they did not it will default to their domain name.
func (n NetworkProfile) DisplayNameOrDefault() string {
	return cmp.Or(n.DisplayName, n.DomainName)
}

// LoginProfile represents a single login profile as managed
// by the ProfileManager.
type LoginProfile struct {
	// ID is a unique identifier for this profile.
	// It is assigned on creation and never changes.
	// It may seem redundant to have both ID and UserProfile.ID
	// but they are different things. UserProfile.ID may change
	// over time (e.g. if a device is tagged).
	ID ProfileID

	// Name is the user-visible name of this profile.
	// It is filled in from the UserProfile.LoginName field.
	Name string

	// NetworkProfile is a subset of netmap.NetworkMap that we
	// store to remember information about the tailnet that this
	// profile was logged in with.
	//
	// This field was added on 2023-11-17.
	NetworkProfile NetworkProfile

	// Key is the StateKey under which the profile is stored.
	// It is assigned once at profile creation time and never changes.
	Key StateKey

	// UserProfile is the server provided UserProfile for this profile.
	// This is updated whenever the server provides a new UserProfile.
	UserProfile tailcfg.UserProfile

	// NodeID is the NodeID of the node that this profile is logged into.
	// This should be stable across tagging and untagging nodes.
	// It may seem redundant to check against both the UserProfile.UserID
	// and the NodeID. However the NodeID can change if the node is deleted
	// from the admin panel.
	NodeID tailcfg.StableNodeID

	// LocalUserID is the user ID of the user who created this profile.
	// It is only relevant on Windows where we have a multi-user system.
	// It is assigned once at profile creation time and never changes.
	LocalUserID WindowsUserID

	// ControlURL is the URL of the control server that this profile is logged
	// into.
	ControlURL string
}

// Equals reports whether p and p2 are equal.
func (p LoginProfileView) Equals(p2 LoginProfileView) bool {
	return p.ж.Equals(p2.ж)
}

// Equals reports whether p and p2 are equal.
func (p *LoginProfile) Equals(p2 *LoginProfile) bool {
	if p == p2 {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}
	return p.ID == p2.ID &&
		p.Name == p2.Name &&
		p.NetworkProfile == p2.NetworkProfile &&
		p.Key == p2.Key &&
		p.UserProfile.Equal(&p2.UserProfile) &&
		p.NodeID == p2.NodeID &&
		p.LocalUserID == p2.LocalUserID &&
		p.ControlURL == p2.ControlURL
}

// ExitNodeExpression is a string that specifies how an exit node
// should be selected. An empty string means that no exit node
// should be selected.
//
// As of 2025-07-02, the only supported value is [AnyExitNode].
type ExitNodeExpression string

// AnyExitNode indicates that the exit node should be automatically
// selected from the pool of available exit nodes, excluding any
// disallowed by policy (e.g., [syspolicy.AllowedSuggestedExitNodes]).
// The exact implementation is subject to change, but exit nodes
// offering the best performance will be preferred.
const AnyExitNode ExitNodeExpression = "any"

// IsSet reports whether the expression is non-empty and can be used
// to select an exit node.
func (e ExitNodeExpression) IsSet() bool {
	return e != ""
}

const (
	// AutoExitNodePrefix is the prefix used in [syspolicy.ExitNodeID] values and CLI
	// to indicate that the string following the prefix is an [ipn.ExitNodeExpression].
	AutoExitNodePrefix = "auto:"
)

// ParseAutoExitNodeString attempts to parse the given string
// as an [ExitNodeExpression].
//
// It returns the parsed expression and true on success,
// or an empty string and false if the input does not appear to be
// an [ExitNodeExpression] (i.e., it doesn't start with "auto:").
//
// It is mainly used to parse the [syspolicy.ExitNodeID] value
// when it is set to "auto:<expression>" (e.g., auto:any).
func ParseAutoExitNodeString[T ~string](s T) (_ ExitNodeExpression, ok bool) {
	if expr, ok := strings.CutPrefix(string(s), AutoExitNodePrefix); ok && expr != "" {
		return ExitNodeExpression(expr), true
	}
	return "", false
}
