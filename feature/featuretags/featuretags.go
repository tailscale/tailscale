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

	// ImplementationDetail is whether the feature is an internal implementation
	// detail. That is, it's not something a user wuold care about having or not
	// having, but we'd like to able to omit from builds if no other
	// user-visible features depend on it.
	ImplementationDetail bool
}

// Features are the known Tailscale features that can be selectively included or
// excluded via build tags, and a description of each.
var Features = map[FeatureTag]FeatureMeta{
	"ace":           {Sym: "ACE", Desc: "Alternate Connectivity Endpoints"},
	"acme":          {Sym: "ACME", Desc: "ACME TLS certificate management"},
	"appconnectors": {Sym: "AppConnectors", Desc: "App Connectors support"},
	"aws":           {Sym: "AWS", Desc: "AWS integration"},
	"advertiseexitnode": {
		Sym:  "AdvertiseExitNode",
		Desc: "Run an exit node",
		Deps: []FeatureTag{
			"peerapiserver", // to run the ExitDNS server
			"advertiseroutes",
		},
	},
	"advertiseroutes": {
		Sym:  "AdvertiseRoutes",
		Desc: "Advertise routes for other nodes to use",
		Deps: []FeatureTag{
			"c2n", // for control plane to probe health for HA subnet router leader election
		},
	},
	"bakedroots": {Sym: "BakedRoots", Desc: "Embed CA (LetsEncrypt) x509 roots to use as fallback"},
	"bird": {
		Sym:  "Bird",
		Desc: "Bird BGP integration",
		Deps: []FeatureTag{"advertiseroutes"},
	},
	"c2n": {
		Sym:                  "C2N",
		Desc:                 "Control-to-node (C2N) support",
		ImplementationDetail: true,
	},
	"captiveportal": {Sym: "CaptivePortal", Desc: "Captive portal detection"},
	"capture":       {Sym: "Capture", Desc: "Packet capture"},
	"cli":           {Sym: "CLI", Desc: "embed the CLI into the tailscaled binary"},
	"cliconndiag":   {Sym: "CLIConnDiag", Desc: "CLI connection error diagnostics"},
	"clientmetrics": {Sym: "ClientMetrics", Desc: "Client metrics support"},
	"clientupdate": {
		Sym:  "ClientUpdate",
		Desc: "Client auto-update support",
		Deps: []FeatureTag{"c2n"},
	},
	"completion": {Sym: "Completion", Desc: "CLI shell completion"},
	"cloud":      {Sym: "Cloud", Desc: "detect cloud environment to learn instances IPs and DNS servers"},
	"dbus": {
		Sym:                  "DBus",
		Desc:                 "Linux DBus support",
		ImplementationDetail: true,
	},
	"debug":         {Sym: "Debug", Desc: "various debug support, for things that don't have or need their own more specific feature"},
	"debugeventbus": {Sym: "DebugEventBus", Desc: "eventbus debug support"},
	"debugportmapper": {
		Sym:  "DebugPortMapper",
		Desc: "portmapper debug support",
		Deps: []FeatureTag{"portmapper"},
	},
	"desktop_sessions": {Sym: "DesktopSessions", Desc: "Desktop sessions support"},
	"doctor":           {Sym: "Doctor", Desc: "Diagnose possible issues with Tailscale and its host environment"},
	"drive":            {Sym: "Drive", Desc: "Tailscale Drive (file server) support"},
	"gro": {
		Sym:  "GRO",
		Desc: "Generic Receive Offload support (performance)",
		Deps: []FeatureTag{"netstack"},
	},
	"health":        {Sym: "Health", Desc: "Health checking support"},
	"hujsonconf":    {Sym: "HuJSONConf", Desc: "HuJSON config file support"},
	"iptables":      {Sym: "IPTables", Desc: "Linux iptables support"},
	"kube":          {Sym: "Kube", Desc: "Kubernetes integration"},
	"lazywg":        {Sym: "LazyWG", Desc: "Lazy WireGuard configuration for memory-constrained devices with large netmaps"},
	"linuxdnsfight": {Sym: "LinuxDNSFight", Desc: "Linux support for detecting DNS fights (inotify watching of /etc/resolv.conf)"},
	"linkspeed": {
		Sym:  "LinkSpeed",
		Desc: "Set link speed on TUN device for better OS integration (Linux only)",
	},
	"listenrawdisco": {
		Sym:  "ListenRawDisco",
		Desc: "Use raw sockets for more robust disco (NAT traversal) message receiving (Linux only)",
	},
	"logtail": {
		Sym:  "LogTail",
		Desc: "upload logs to log.tailscale.com (debug logs for bug reports and also by network flow logs if enabled)",
	},
	"oauthkey": {Sym: "OAuthKey", Desc: "OAuth secret-to-authkey resolution support"},
	"outboundproxy": {
		Sym:  "OutboundProxy",
		Desc: "Support running an outbound localhost HTTP/SOCK5 proxy support that sends traffic over Tailscale",
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
	"peerapiclient": {
		Sym:                  "PeerAPIClient",
		Desc:                 "PeerAPI client support",
		ImplementationDetail: true,
	},
	"peerapiserver": {
		Sym:                  "PeerAPIServer",
		Desc:                 "PeerAPI server support",
		ImplementationDetail: true,
	},
	"portlist":   {Sym: "PortList", Desc: "Optionally advertise listening service ports"},
	"portmapper": {Sym: "PortMapper", Desc: "NAT-PMP/PCP/UPnP port mapping support"},
	"posture":    {Sym: "Posture", Desc: "Device posture checking support"},
	"dns": {
		Sym:  "DNS",
		Desc: "MagicDNS and system DNS configuration support",
	},
	"netlog": {
		Sym:  "NetLog",
		Desc: "Network flow logging support",
		Deps: []FeatureTag{"logtail"},
	},
	"netstack": {Sym: "Netstack", Desc: "gVisor netstack (userspace networking) support"},
	"networkmanager": {
		Sym:  "NetworkManager",
		Desc: "Linux NetworkManager integration",
		Deps: []FeatureTag{"dbus"},
	},
	"relayserver": {Sym: "RelayServer", Desc: "Relay server"},
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
		Deps: []FeatureTag{"c2n", "dbus", "netstack"},
	},
	"synology": {
		Sym:  "Synology",
		Desc: "Synology NAS integration (applies to Linux builds only)",
	},
	"syspolicy": {Sym: "SystemPolicy", Desc: "System policy configuration (MDM) support"},
	"systray": {
		Sym:  "SysTray",
		Desc: "Linux system tray",
		Deps: []FeatureTag{"dbus"},
	},
	"taildrop": {
		Sym:  "Taildrop",
		Desc: "Taildrop (file sending) support",
		Deps: []FeatureTag{
			"peerapiclient", "peerapiserver", // assume Taildrop is both sides for now
		},
	},
	"tailnetlock": {Sym: "TailnetLock", Desc: "Tailnet Lock support"},
	"tap":         {Sym: "Tap", Desc: "Experimental Layer 2 (ethernet) support"},
	"tpm":         {Sym: "TPM", Desc: "TPM support"},
	"unixsocketidentity": {
		Sym:  "UnixSocketIdentity",
		Desc: "differentiate between users accessing the LocalAPI over unix sockets (if omitted, all users have full access)",
	},
	"useroutes": {
		Sym:  "UseRoutes",
		Desc: "Use routes advertised by other nodes",
	},
	"useexitnode": {
		Sym:  "UseExitNode",
		Desc: "Use exit nodes",
		Deps: []FeatureTag{"peerapiclient", "useroutes"},
	},
	"useproxy": {
		Sym:  "UseProxy",
		Desc: "Support using system proxies as specified by env vars or the system configuration to reach Tailscale servers.",
	},
	"usermetrics": {
		Sym:  "UserMetrics",
		Desc: "Usermetrics (documented, stable) metrics support",
	},
	"wakeonlan": {Sym: "WakeOnLAN", Desc: "Wake-on-LAN support"},
	"webclient": {
		Sym: "WebClient", Desc: "Web client support",
		Deps: []FeatureTag{"serve"},
	},
}
