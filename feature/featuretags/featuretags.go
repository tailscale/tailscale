// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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

// Features are the known Tailscale features that can be selectively included or
// excluded via build tags, and a description of each.
var Features = map[FeatureTag]string{
	"aws":              "AWS integration",
	"bird":             "Bird BGP integration",
	"capture":          "Packet capture",
	"cli":              "embed the CLI into the tailscaled binary",
	"completion":       "CLI shell completion",
	"debugeventbus":    "eventbus debug support",
	"desktop_sessions": "Desktop sessions support",
	"drive":            "Tailscale Drive (file server) support",
	"kube":             "Kubernetes integration",
	"relayserver":      "Relay server",
	"ssh":              "Tailscale SSH support",
	"syspolicy":        "System policy configuration (MDM) support",
	"systray":          "Linux system tray",
	"taildrop":         "Taildrop (file sending) support",
	"tailnetlock":      "Tailnet Lock support",
	"tap":              "Experimental Layer 2 (ethernet) support",
	"tpm":              "TPM support",
	"wakeonlan":        "Wake-on-LAN support",
	"webclient":        "Web client support",
}
