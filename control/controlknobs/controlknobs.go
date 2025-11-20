// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package controlknobs contains client options configurable from control which can be turned on
// or off. The ability to turn options on and off is for incrementally adding features in.
package controlknobs

import (
	"fmt"
	"reflect"
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

	// SeamlessKeyRenewal is whether to renew node keys without breaking connections.
	// This is enabled by default in 1.90 and later, but we but we can remotely disable
	// it from the control plane if there's a problem.
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

	// DisableCaptivePortalDetection is whether the node should not perform captive portal detection
	// automatically when the network state changes.
	DisableCaptivePortalDetection atomic.Bool

	// DisableSkipStatusQueue is whether the node should disable skipping
	// of queued netmap.NetworkMap between the controlclient and LocalBackend.
	// See tailscale/tailscale#14768.
	DisableSkipStatusQueue atomic.Bool
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
		disableSeamlessKeyRenewal            = has(tailcfg.NodeAttrDisableSeamlessKeyRenewal)
		probeUDPLifetime                     = has(tailcfg.NodeAttrProbeUDPLifetime)
		appCStoreRoutes                      = has(tailcfg.NodeAttrStoreAppCRoutes)
		userDialUseRoutes                    = has(tailcfg.NodeAttrUserDialUseRoutes)
		disableSplitDNSWhenNoCustomResolvers = has(tailcfg.NodeAttrDisableSplitDNSWhenNoCustomResolvers)
		disableLocalDNSOverrideViaNRPT       = has(tailcfg.NodeAttrDisableLocalDNSOverrideViaNRPT)
		disableCaptivePortalDetection        = has(tailcfg.NodeAttrDisableCaptivePortalDetection)
		disableSkipStatusQueue               = has(tailcfg.NodeAttrDisableSkipStatusQueue)
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
	k.ProbeUDPLifetime.Store(probeUDPLifetime)
	k.AppCStoreRoutes.Store(appCStoreRoutes)
	k.UserDialUseRoutes.Store(userDialUseRoutes)
	k.DisableSplitDNSWhenNoCustomResolvers.Store(disableSplitDNSWhenNoCustomResolvers)
	k.DisableLocalDNSOverrideViaNRPT.Store(disableLocalDNSOverrideViaNRPT)
	k.DisableCaptivePortalDetection.Store(disableCaptivePortalDetection)
	k.DisableSkipStatusQueue.Store(disableSkipStatusQueue)

	// If both attributes are present, then "enable" should win.  This reflects
	// the history of seamless key renewal.
	//
	// Before 1.90, seamless was a private alpha, opt-in feature.  Devices would
	// only seamless do if customers opted in using the seamless renewal attr.
	//
	// In 1.90 and later, seamless is the default behaviour, and devices will use
	// seamless unless explicitly told not to by control (e.g. if we discover
	// a bug and want clients to use the prior behaviour).
	//
	// If a customer has opted in to the pre-1.90 seamless implementation, we
	// don't want to switch it off for them -- we only want to switch it off for
	// devices that haven't opted in.
	k.SeamlessKeyRenewal.Store(seamlessKeyRenewal || !disableSeamlessKeyRenewal)
}

// AsDebugJSON returns k as something that can be marshalled with json.Marshal
// for debug.
func (k *Knobs) AsDebugJSON() map[string]any {
	if k == nil {
		return nil
	}
	ret := map[string]any{}
	rt := reflect.TypeFor[Knobs]()
	rv := reflect.ValueOf(k).Elem() // of *k
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		switch v := rv.Field(i).Addr().Interface().(type) {
		case *atomic.Bool:
			ret[name] = v.Load()
		case *syncs.AtomicValue[opt.Bool]:
			ret[name] = v.Load()
		default:
			panic(fmt.Sprintf("unknown field type %T for %v", v, name))
		}
	}
	return ret
}
