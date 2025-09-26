// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"errors"
	"os/exec"

	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/hostinfo"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

func detectFirewallMode(logf logger.Logf, prefHint string) FirewallMode {
	if distro.Get() == distro.Gokrazy {
		// Reduce startup logging on gokrazy. There's no way to do iptables on
		// gokrazy anyway.
		logf("GoKrazy should use nftables.")
		hostinfo.SetFirewallMode("nft-gokrazy")
		return FirewallModeNfTables
	}
	if distro.Get() == distro.JetKVM {
		// JetKVM doesn't have iptables.
		hostinfo.SetFirewallMode("nft-jetkvm")
		return FirewallModeNfTables
	}

	mode := envknob.String("TS_DEBUG_FIREWALL_MODE")
	// If the envknob isn't set, fall back to the pref suggested by c2n or
	// nodeattrs.
	if mode == "" {
		mode = prefHint
		logf("using firewall mode pref %s", prefHint)
	} else if prefHint != "" {
		logf("TS_DEBUG_FIREWALL_MODE set, overriding firewall mode from %s to %s", prefHint, mode)
	}

	var det linuxFWDetector
	if mode == "" {
		// We have no preference, so check if `iptables` is even available.
		if buildfeatures.HasIPTables {
			_, err := det.iptDetect()
			if err != nil && errors.Is(err, exec.ErrNotFound) {
				logf("iptables not found: %v; falling back to nftables", err)
				mode = "nftables"
			}
		}
	}

	// We now use iptables as default and have "auto" and "nftables" as
	// options for people to test further.
	switch mode {
	case "auto":
		return pickFirewallModeFromInstalledRules(logf, det)
	case "nftables":
		hostinfo.SetFirewallMode("nft-forced")
		return FirewallModeNfTables
	case "iptables":
		hostinfo.SetFirewallMode("ipt-forced")
		return FirewallModeIPTables
	}
	if buildfeatures.HasIPTables {
		logf("default choosing iptables")
		hostinfo.SetFirewallMode("ipt-default")
		return FirewallModeIPTables
	}
	logf("default choosing nftables")
	hostinfo.SetFirewallMode("nft-default")
	return FirewallModeNfTables
}

// tableDetector abstracts helpers to detect the firewall mode.
// It is implemented for testing purposes.
type tableDetector interface {
	iptDetect() (int, error)
	nftDetect() (int, error)
}

type linuxFWDetector struct{}

// iptDetect returns the number of iptables rules in the current namespace.
func (l linuxFWDetector) iptDetect() (int, error) {
	return detectIptables()
}

var hookDetectNetfilter feature.Hook[func() (int, error)]

// ErrUnsupported is the error returned from all functions on non-Linux
// platforms.
var ErrUnsupported = errors.New("linuxfw:unsupported")

// nftDetect returns the number of nftables rules in the current namespace.
func (l linuxFWDetector) nftDetect() (int, error) {
	if f, ok := hookDetectNetfilter.GetOk(); ok {
		return f()
	}
	return 0, ErrUnsupported
}

// pickFirewallModeFromInstalledRules returns the firewall mode to use based on
// the environment and the system's capabilities.
func pickFirewallModeFromInstalledRules(logf logger.Logf, det tableDetector) FirewallMode {
	if !buildfeatures.HasIPTables {
		hostinfo.SetFirewallMode("nft-noipt")
		return FirewallModeNfTables
	}
	if distro.Get() == distro.Gokrazy {
		// Reduce startup logging on gokrazy. There's no way to do iptables on
		// gokrazy anyway.
		return FirewallModeNfTables
	}

	iptAva, nftAva := true, true
	iptRuleCount, err := det.iptDetect()
	if err != nil {
		logf("detect iptables rule: %v", err)
		iptAva = false
	}
	nftRuleCount, err := det.nftDetect()
	if err != nil {
		logf("detect nftables rule: %v", err)
		nftAva = false
	}
	logf("nftables rule count: %d, iptables rule count: %d", nftRuleCount, iptRuleCount)
	switch {
	case nftRuleCount > 0 && iptRuleCount == 0:
		logf("nftables is currently in use")
		hostinfo.SetFirewallMode("nft-inuse")
		return FirewallModeNfTables
	case iptRuleCount > 0 && nftRuleCount == 0:
		logf("iptables is currently in use")
		hostinfo.SetFirewallMode("ipt-inuse")
		return FirewallModeIPTables
	case nftAva:
		// if both iptables and nftables are available but
		// neither/both are currently used, use nftables.
		logf("nftables is available")
		hostinfo.SetFirewallMode("nft")
		return FirewallModeNfTables
	case iptAva:
		logf("iptables is available")
		hostinfo.SetFirewallMode("ipt")
		return FirewallModeIPTables
	default:
		// if neither iptables nor nftables are available, use iptablesRunner as a dummy
		// runner which exists but won't do anything. Creating iptablesRunner errors only
		// if the iptables command is missing or doesn’t support "--version", as long as it
		// can determine a version then it’ll carry on.
		hostinfo.SetFirewallMode("ipt-fb")
		return FirewallModeIPTables
	}
}
