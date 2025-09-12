// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The featuretags package is a registry of all the ts_omit-able build tags.
package featuretags

var Features = map[string]string{
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
	"tap":              "Experimental Layer 2 (ethernet) support",
	"tka":              "Tailnet Lock (TKA) support",
	"tpm":              "TPM support",
	"wakeonlan":        "Wake-on-LAN support",
	"webclient":        "Web client support",
}
