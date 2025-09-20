// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The featuretags package is a registry of all the ts_omit-able build tags.
package featuretags

import "tailscale.com/util/set"

// CLI is a special feature in the [Features] map that works opposite
// from the others: it is opt-in, rather than opt-out, having a different
// build tag format.
const CLI FeatureTag = "cli"

// FeatureTag names a Tailscale feature that can be selectively added or removed
// via build tags.
type FeatureTag string

// IsOmittable reports whether this feature tag is one that can be
// omitted via a ts_omit_ build tag.
func (ft FeatureTag) IsOmittable() bool {
	switch ft {
	case CLI:
		return false
	}
	return true
}

// OmitTag returns the ts_omit_ build tag for this feature tag.
// It panics if the feature tag is not omitable.
func (ft FeatureTag) OmitTag() string {
	if !ft.IsOmittable() {
		panic("not omitable: " + string(ft))
	}
	return "ts_omit_" + string(ft)
}

// Requires returns the set of features that must be included to
// use the given feature, including the provided feature itself.
func Requires(ft FeatureTag) set.Set[FeatureTag] {
	s := set.Set[FeatureTag]{}
	var add func(FeatureTag)
	add = func(ft FeatureTag) {
		if !ft.IsOmittable() {
			return
		}
		s.Add(ft)
		for _, dep := range Features[ft].Deps {
			add(dep)
		}
	}
	add(ft)
	return s
}

// RequiredBy is the inverse of Requires: it returns the set of features that
// depend on the given feature (directly or indirectly), including the feature
// itself.
func RequiredBy(ft FeatureTag) set.Set[FeatureTag] {
	s := set.Set[FeatureTag]{}
	for f := range Features {
		if featureDependsOn(f, ft) {
			s.Add(f)
		}
	}
	return s
}

// featureDependsOn reports whether feature a (directly or indirectly) depends on b.
// It returns true if a == b.
func featureDependsOn(a, b FeatureTag) bool {
	if a == b {
		return true
	}
	for _, dep := range Features[a].Deps {
		if featureDependsOn(dep, b) {
			return true
		}
	}
	return false
}

// FeatureMeta describes a modular feature that can be conditionally linked into
// the binary.
type FeatureMeta struct {
	Sym  string       // exported Go symbol for boolean const
	Desc string       // human-readable description
	Deps []FeatureTag // other features this feature requires
}

// Features are the known Tailscale features that can be selectively included or
// excluded via build tags, and a description of each.
var Features = map[FeatureTag]FeatureMeta{
	"acme":          {"ACME", "ACME TLS certificate management", nil},
	"aws":           {"AWS", "AWS integration", nil},
	"bird":          {"Bird", "Bird BGP integration", nil},
	"capture":       {"Capture", "Packet capture", nil},
	"cli":           {"CLI", "embed the CLI into the tailscaled binary", nil},
	"completion":    {"Completion", "CLI shell completion", nil},
	"debugeventbus": {"DebugEventBus", "eventbus debug support", nil},
	"debugportmapper": {
		Sym:  "DebugPortMapper",
		Desc: "portmapper debug support",
		Deps: []FeatureTag{"portmapper"},
	},
	"desktop_sessions": {"DesktopSessions", "Desktop sessions support", nil},
	"drive":            {"Drive", "Tailscale Drive (file server) support", nil},
	"kube":             {"Kube", "Kubernetes integration", nil},
	"linuxdnsfight":    {"LinuxDNSFight", "Linux support for detecting DNS fights (inotify watching of /etc/resolv.conf)", nil},
	"oauthkey":         {"OAuthKey", "OAuth secret-to-authkey resolution support", nil},
	"outboundproxy": {
		Sym:  "OutboundProxy",
		Desc: "Outbound localhost HTTP/SOCK5 proxy support",
		Deps: []FeatureTag{"netstack"},
	},
	"portmapper":  {"PortMapper", "NAT-PMP/PCP/UPnP port mapping support", nil},
	"netstack":    {"Netstack", "gVisor netstack (userspace networking) support (TODO; not yet omittable)", nil},
	"relayserver": {"RelayServer", "Relay server", nil},
	"serve": {
		Sym:  "Serve",
		Desc: "Serve and Funnel support",
		Deps: []FeatureTag{"netstack"},
	},
	"ssh": {
		Sym:  "SSH",
		Desc: "Tailscale SSH support",
		Deps: []FeatureTag{"netstack"},
	},
	"syspolicy":   {"SystemPolicy", "System policy configuration (MDM) support", nil},
	"systray":     {"SysTray", "Linux system tray", nil},
	"taildrop":    {"Taildrop", "Taildrop (file sending) support", nil},
	"tailnetlock": {"TailnetLock", "Tailnet Lock support", nil},
	"tap":         {"Tap", "Experimental Layer 2 (ethernet) support", nil},
	"tpm":         {"TPM", "TPM support", nil},
	"wakeonlan":   {"WakeOnLAN", "Wake-on-LAN support", nil},
	"webclient": {
		Sym: "WebClient", Desc: "Web client support",
		Deps: []FeatureTag{"serve"},
	},
}
