// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:generate go run gen-featuretags.go

// The featuretags package is a registry of all the ts_omit-able build tags.
package featuretags

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

// FeatureMeta describes a modular feature that can be conditionally linked into
// the binary.
type FeatureMeta struct {
	Sym  string // exported Go symbol for boolean const
	Desc string // human-readable description
}

// Features are the known Tailscale features that can be selectively included or
// excluded via build tags, and a description of each.
var Features = map[FeatureTag]FeatureMeta{
	"aws":              {"AWS", "AWS integration"},
	"bird":             {"Bird", "Bird BGP integration"},
	"capture":          {"Capture", "Packet capture"},
	"cli":              {"CLI", "embed the CLI into the tailscaled binary"},
	"completion":       {"Completion", "CLI shell completion"},
	"debugeventbus":    {"DebugEventBus", "eventbus debug support"},
	"desktop_sessions": {"DesktopSessions", "Desktop sessions support"},
	"drive":            {"Drive", "Tailscale Drive (file server) support"},
	"kube":             {"Kube", "Kubernetes integration"},
	"relayserver":      {"RelayServer", "Relay server"},
	"serve":            {"Serve", "Serve and Funnel support"},
	"ssh":              {"SSH", "Tailscale SSH support"},
	"syspolicy":        {"SystemPolicy", "System policy configuration (MDM) support"},
	"systray":          {"SysTray", "Linux system tray"},
	"taildrop":         {"Taildrop", "Taildrop (file sending) support"},
	"tailnetlock":      {"TailnetLock", "Tailnet Lock support"},
	"tap":              {"Tap", "Experimental Layer 2 (ethernet) support"},
	"tpm":              {"TPM", "TPM support"},
	"wakeonlan":        {"WakeOnLAN", "Wake-on-LAN support"},
	"webclient":        {"WebClient", "Web client support"},
}
