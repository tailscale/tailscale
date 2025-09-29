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
	"captiveportal": {"CaptivePortal", "Captive portal detection", nil},
	"capture":       {"Capture", "Packet capture", nil},
	"cli":           {"CLI", "embed the CLI into the tailscaled binary", nil},
	"cliconndiag":   {"CLIConnDiag", "CLI connection error diagnostics", nil},
	"clientupdate":  {"ClientUpdate", "Client auto-update support", nil},
	"completion":    {"Completion", "CLI shell completion", nil},
	"dbus":          {"DBus", "Linux DBus support", nil},
	"debugeventbus": {"DebugEventBus", "eventbus debug support", nil},
	"debugportmapper": {
		Sym:  "DebugPortMapper",
		Desc: "portmapper debug support",
		Deps: []FeatureTag{"portmapper"},
	},
	"desktop_sessions": {"DesktopSessions", "Desktop sessions support", nil},
	"doctor":           {"Doctor", "Diagnose possible issues with Tailscale and its host environment", nil},
	"drive":            {"Drive", "Tailscale Drive (file server) support", nil},
	"gro": {
		Sym:  "GRO",
		Desc: "Generic Receive Offload support (performance)",
		Deps: []FeatureTag{"netstack"},
	},
	"iptables":      {"IPTables", "Linux iptables support", nil},
	"kube":          {"Kube", "Kubernetes integration", nil},
	"linuxdnsfight": {"LinuxDNSFight", "Linux support for detecting DNS fights (inotify watching of /etc/resolv.conf)", nil},
	"logtail": {
		Sym:  "LogTail",
		Desc: "upload logs to log.tailscale.com (debug logs for bug reports and also by network flow logs if enabled)",
	},
	"oauthkey": {"OAuthKey", "OAuth secret-to-authkey resolution support", nil},
	"outboundproxy": {
		Sym:  "OutboundProxy",
		Desc: "Outbound localhost HTTP/SOCK5 proxy support",
		Deps: []FeatureTag{"netstack"},
	},
	"osrouter": {
		Sym:  "OSRouter",
		Desc: "Configure the operating system's network stack, IPs, and routing tables",
		// TODO(bradfitz): if this is omitted, and netstack is too, then tailscaled needs
		// external config to be useful. Some people may want that, and we should support it,
		// but it's rare. Maybe there should be a way to declare here that this "Provides"
		// another feature (and netstack can too), and then if those required features provided
		// by some other feature are missing, then it's an error by default unless you accept
		// that it's okay to proceed without that meta feature.
	},
	"portlist":   {"PortList", "Optionally advertise listening service ports", nil},
	"portmapper": {"PortMapper", "NAT-PMP/PCP/UPnP port mapping support", nil},
	"posture":    {"Posture", "Device posture checking support", nil},
	"netlog": {
		Sym:  "NetLog",
		Desc: "Network flow logging support",
		Deps: []FeatureTag{"logtail"},
	},
	"netstack": {"Netstack", "gVisor netstack (userspace networking) support", nil},
	"networkmanager": {
		Sym:  "NetworkManager",
		Desc: "Linux NetworkManager integration",
		Deps: []FeatureTag{"dbus"},
	},
	"relayserver": {"RelayServer", "Relay server", nil},
	"resolved": {
		Sym:  "Resolved",
		Desc: "Linux systemd-resolved integration",
		Deps: []FeatureTag{"dbus"},
	},
	"sdnotify": {
		Sym:  "SDNotify",
		Desc: "systemd notification support",
	},
	"serve": {
		Sym:  "Serve",
		Desc: "Serve and Funnel support",
		Deps: []FeatureTag{"netstack"},
	},
	"ssh": {
		Sym:  "SSH",
		Desc: "Tailscale SSH support",
		Deps: []FeatureTag{"dbus", "netstack"},
	},
	"syspolicy": {"SystemPolicy", "System policy configuration (MDM) support", nil},
	"systray": {
		Sym:  "SysTray",
		Desc: "Linux system tray",
		Deps: []FeatureTag{"dbus"},
	},
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
