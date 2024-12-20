// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package controlknobs contains client options configurable from control which can be turned on
// or off. The ability to turn options on and off is for incrementally adding features in.
package controlknobs

import (
	"sync/atomic"

	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

// Knobs is the set of knobs that the control plane's coordination server can
// adjust at runtime.
type Knobs struct {
	// DisableUPnP indicates whether to attempt UPnP mapping.
	DisableUPnP atomic.Bool

	// KeepFullWGConfig is whether we should disable the lazy wireguard
	// programming and instead give WireGuard the full netmap always, even for
	// idle peers.
	KeepFullWGConfig atomic.Bool

	// RandomizeClientPort is whether control says we should randomize
	// the client port.
	RandomizeClientPort atomic.Bool

	// OneCGNAT is whether the the node should make one big CGNAT route
	// in the OS rather than one /32 per peer.
	OneCGNAT syncs.AtomicValue[opt.Bool]

	// ForceBackgroundSTUN forces netcheck STUN queries to keep
	// running in magicsock, even when idle.
	ForceBackgroundSTUN atomic.Bool

	// DisableDeltaUpdates is whether the node should not process
	// incremental (delta) netmap updates and should treat all netmap
	// changes as "full" ones as tailscaled did in 1.48.x and earlier.
	DisableDeltaUpdates atomic.Bool

	// PeerMTUEnable is whether the node should do peer path MTU discovery.
	PeerMTUEnable atomic.Bool

	// DisableDNSForwarderTCPRetries is whether the DNS forwarder should
	// skip retrying truncated queries over TCP.
	DisableDNSForwarderTCPRetries atomic.Bool

	// SilentDisco is whether the node should suppress disco heartbeats to its
	// peers.
	SilentDisco atomic.Bool

	// LinuxForceIPTables is whether the node should use iptables for Linux
	// netfiltering, unless overridden by the user.
	LinuxForceIPTables atomic.Bool

	// LinuxForceNfTables is whether the node should use nftables for Linux
	// netfiltering, unless overridden by the user.
	LinuxForceNfTables atomic.Bool

	// SeamlessKeyRenewal is whether to enable the alpha functionality of
	// renewing node keys without breaking connections.
	// http://go/seamless-key-renewal
	SeamlessKeyRenewal atomic.Bool

	// ProbeUDPLifetime is whether the node should probe UDP path lifetime on
	// the tail end of an active direct connection in magicsock.
	ProbeUDPLifetime atomic.Bool

	// AppCStoreRoutes is whether the node should store RouteInfo to StateStore
	// if it's an app connector.
	AppCStoreRoutes atomic.Bool

	// UserDialUseRoutes is whether tsdial.Dialer.UserDial should use routes to determine
	// how to dial the destination address. When true, it also makes the DNS forwarder
	// use UserDial instead of SystemDial when dialing resolvers.
	UserDialUseRoutes atomic.Bool

	// DisableSplitDNSWhenNoCustomResolvers indicates that the node's DNS manager
	// should not adopt a split DNS configuration even though the Config of the
	// resolver only contains routes that do not specify custom resolver(s), hence
	// all DNS queries can be safely sent to the upstream DNS resolver and the
	// node's DNS forwarder doesn't need to handle all DNS traffic.
	// This is for now (2024-06-06) an iOS-specific battery life optimization,
	// and this knob allows us to disable the optimization remotely if needed.
	DisableSplitDNSWhenNoCustomResolvers atomic.Bool

	// DisableLocalDNSOverrideViaNRPT indicates that the node's DNS manager should not
	// create a default (catch-all) Windows NRPT rule when "Override local DNS" is enabled.
	// Without this rule, Windows 8.1 and newer devices issue parallel DNS requests to DNS servers
	// associated with all network adapters, even when "Override local DNS" is enabled and/or
	// a Mullvad exit node is being used, resulting in DNS leaks.
	// We began creating this rule on 2024-06-14, and this knob
	// allows us to disable the new behavior remotely if needed.
	DisableLocalDNSOverrideViaNRPT atomic.Bool

	// DisableCryptorouting indicates that the node should not use the
	// magicsock crypto routing feature.
	DisableCryptorouting atomic.Bool

	// DisableCaptivePortalDetection is whether the node should not perform captive portal detection
	// automatically when the network state changes.
	DisableCaptivePortalDetection atomic.Bool

	// DisableExitNodeBehindCaptivePortal is whether the node should temporarily disable exit nodes
	// whenever a captive portal is detected.
	DisableExitNodeBehindCaptivePortal atomic.Bool
}

// UpdateFromNodeAttributes updates k (if non-nil) based on the provided self
// node attributes (Node.Capabilities).
func (k *Knobs) UpdateFromNodeAttributes(capMap tailcfg.NodeCapMap) {
	if k == nil {
		return
	}
	has := capMap.Contains
	var (
		keepFullWG                           = has(tailcfg.NodeAttrDebugDisableWGTrim)
		disableUPnP                          = has(tailcfg.NodeAttrDisableUPnP)
		randomizeClientPort                  = has(tailcfg.NodeAttrRandomizeClientPort)
		disableDeltaUpdates                  = has(tailcfg.NodeAttrDisableDeltaUpdates)
		oneCGNAT                             opt.Bool
		forceBackgroundSTUN                  = has(tailcfg.NodeAttrDebugForceBackgroundSTUN)
		peerMTUEnable                        = has(tailcfg.NodeAttrPeerMTUEnable)
		dnsForwarderDisableTCPRetries        = has(tailcfg.NodeAttrDNSForwarderDisableTCPRetries)
		silentDisco                          = has(tailcfg.NodeAttrSilentDisco)
		forceIPTables                        = has(tailcfg.NodeAttrLinuxMustUseIPTables)
		forceNfTables                        = has(tailcfg.NodeAttrLinuxMustUseNfTables)
		seamlessKeyRenewal                   = has(tailcfg.NodeAttrSeamlessKeyRenewal)
		probeUDPLifetime                     = has(tailcfg.NodeAttrProbeUDPLifetime)
		appCStoreRoutes                      = has(tailcfg.NodeAttrStoreAppCRoutes)
		userDialUseRoutes                    = has(tailcfg.NodeAttrUserDialUseRoutes)
		disableSplitDNSWhenNoCustomResolvers = has(tailcfg.NodeAttrDisableSplitDNSWhenNoCustomResolvers)
		disableLocalDNSOverrideViaNRPT       = has(tailcfg.NodeAttrDisableLocalDNSOverrideViaNRPT)
		disableCryptorouting                 = has(tailcfg.NodeAttrDisableMagicSockCryptoRouting)
		disableCaptivePortalDetection        = has(tailcfg.NodeAttrDisableCaptivePortalDetection)
		disableExitNodeBehindCaptivePortal   = has(tailcfg.NodeAttrDisableExitNodeBehindCaptivePortal)
	)

	if has(tailcfg.NodeAttrOneCGNATEnable) {
		oneCGNAT.Set(true)
	} else if has(tailcfg.NodeAttrOneCGNATDisable) {
		oneCGNAT.Set(false)
	}

	k.KeepFullWGConfig.Store(keepFullWG)
	k.DisableUPnP.Store(disableUPnP)
	k.RandomizeClientPort.Store(randomizeClientPort)
	k.OneCGNAT.Store(oneCGNAT)
	k.ForceBackgroundSTUN.Store(forceBackgroundSTUN)
	k.DisableDeltaUpdates.Store(disableDeltaUpdates)
	k.PeerMTUEnable.Store(peerMTUEnable)
	k.DisableDNSForwarderTCPRetries.Store(dnsForwarderDisableTCPRetries)
	k.SilentDisco.Store(silentDisco)
	k.LinuxForceIPTables.Store(forceIPTables)
	k.LinuxForceNfTables.Store(forceNfTables)
	k.SeamlessKeyRenewal.Store(seamlessKeyRenewal)
	k.ProbeUDPLifetime.Store(probeUDPLifetime)
	k.AppCStoreRoutes.Store(appCStoreRoutes)
	k.UserDialUseRoutes.Store(userDialUseRoutes)
	k.DisableSplitDNSWhenNoCustomResolvers.Store(disableSplitDNSWhenNoCustomResolvers)
	k.DisableLocalDNSOverrideViaNRPT.Store(disableLocalDNSOverrideViaNRPT)
	k.DisableCryptorouting.Store(disableCryptorouting)
	k.DisableCaptivePortalDetection.Store(disableCaptivePortalDetection)
	k.DisableExitNodeBehindCaptivePortal.Store(disableExitNodeBehindCaptivePortal)
}

// AsDebugJSON returns k as something that can be marshalled with json.Marshal
// for debug.
func (k *Knobs) AsDebugJSON() map[string]any {
	if k == nil {
		return nil
	}
	return map[string]any{
		"DisableUPnP":                          k.DisableUPnP.Load(),
		"KeepFullWGConfig":                     k.KeepFullWGConfig.Load(),
		"RandomizeClientPort":                  k.RandomizeClientPort.Load(),
		"OneCGNAT":                             k.OneCGNAT.Load(),
		"ForceBackgroundSTUN":                  k.ForceBackgroundSTUN.Load(),
		"DisableDeltaUpdates":                  k.DisableDeltaUpdates.Load(),
		"PeerMTUEnable":                        k.PeerMTUEnable.Load(),
		"DisableDNSForwarderTCPRetries":        k.DisableDNSForwarderTCPRetries.Load(),
		"SilentDisco":                          k.SilentDisco.Load(),
		"LinuxForceIPTables":                   k.LinuxForceIPTables.Load(),
		"LinuxForceNfTables":                   k.LinuxForceNfTables.Load(),
		"SeamlessKeyRenewal":                   k.SeamlessKeyRenewal.Load(),
		"ProbeUDPLifetime":                     k.ProbeUDPLifetime.Load(),
		"AppCStoreRoutes":                      k.AppCStoreRoutes.Load(),
		"UserDialUseRoutes":                    k.UserDialUseRoutes.Load(),
		"DisableSplitDNSWhenNoCustomResolvers": k.DisableSplitDNSWhenNoCustomResolvers.Load(),
		"DisableLocalDNSOverrideViaNRPT":       k.DisableLocalDNSOverrideViaNRPT.Load(),
		"DisableCryptorouting":                 k.DisableCryptorouting.Load(),
		"DisableCaptivePortalDetection":        k.DisableCaptivePortalDetection.Load(),
		"DisableExitNodeBehindCaptivePortal":   k.DisableExitNodeBehindCaptivePortal.Load(),
	}
}
