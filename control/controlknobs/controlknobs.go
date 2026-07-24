// Copyright (c) Tailscale Inc & contributors
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
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/opt"
)

// Knobs is the set of knobs that the control plane's coordination server can
// adjust at runtime.
type Knobs struct {
	// DisableUPnP indicates whether to attempt UPnP mapping.
	DisableUPnP atomic.Bool

	// RandomizeClientPort is whether control says we should randomize
	// the client port.
	RandomizeClientPort atomic.Bool

	// OneCGNAT is whether the node should make one big CGNAT route
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

	// DisableHostsFileUpdates indicates that the node's DNS manager should not create
	// hosts file entries when it normally would, such as when we're not the primary
	// resolver on Windows or when the host is domain-joined and its primary domain
	// takes precedence over MagicDNS. As of 2026-02-13, it is only used on Windows.
	DisableHostsFileUpdates atomic.Bool

	// ForceRegisterMagicDNSIPv4Only is whether the node should only register
	// its IPv4 MagicDNS service IP and not its IPv6 one. The IPv6 one,
	// tsaddr.TailscaleServiceIPv6String, still works in either case. This knob
	// controls only whether we tell systemd/etc about the IPv6 one.
	// See https://github.com/tailscale/tailscale/issues/15404.
	// TODO(bradfitz): remove this a few releases after 2026-02-16.
	ForceRegisterMagicDNSIPv4Only atomic.Bool

	// EmitRuntimeMetrics is whether the node should poll and emit [runtime/metrics]
	// as [tailscale.com/util/clientmetric]'s.
	EmitRuntimeMetrics atomic.Bool

	// DisableUDPGRO disables UDP GRO on the magicsock UDP socket. See
	// [tailcfg.NodeAttrDisableUDPGRO].
	DisableUDPGRO atomic.Bool

	// DisableUDPGSO disables UDP GSO on the magicsock UDP socket. See
	// [tailcfg.NodeAttrDisableUDPGSO].
	DisableUDPGSO atomic.Bool

	// DisableTUNUDPGRO disables UDP GRO on the Tailscale TUN device. See
	// [tailcfg.NodeAttrDisableTUNUDPGRO].
	DisableTUNUDPGRO atomic.Bool

	// DisableTUNTCPGRO disables TCP GRO on the Tailscale TUN device. See
	// [tailcfg.NodeAttrDisableTUNTCPGRO].
	DisableTUNTCPGRO atomic.Bool

	// NeverGSOEqualTail enables a UDP GSO sentinel-tail workaround in the
	// underlay UDP packet TX path on Linux. Applies to magicsock and peer relay
	// UDP sockets. See [tailcfg.NodeAttrNeverGSOEqualTail].
	NeverGSOEqualTail atomic.Bool

	// CacheNetworkMaps is whether the node should persistently cache network
	// maps and use them to establish peer connectivity on start, if doing so
	// is supported by the client and storage is available.
	CacheNetworkMaps atomic.Bool

	// ScopeQuad100OnMacOS is whether sandboxed macOS should scope quad-100 to
	// its match domains rather than installing it as the OS's primary resolver,
	// so a user's DoH system profile isn't shadowed. It has no effect on other
	// platforms. Off by default; when off, sandboxed macOS keeps the older
	// behavior of making quad-100 the default resolver, as iOS still does.
	// See tailscale/corp#45534.
	ScopeQuad100OnMacOS atomic.Bool
}

// UpdateFromNodeAttributes updates k (if non-nil) based on the provided self
// node attributes (Node.Capabilities).
func (k *Knobs) UpdateFromNodeAttributes(capMap tailcfg.NodeCapMap) {
	if k == nil {
		return
	}
	has := capMap.Contains
	var (
		disableUPnP                          = has(nodecap.DisableUPnP)
		randomizeClientPort                  = has(nodecap.RandomizeClientPort)
		disableDeltaUpdates                  = has(nodecap.DisableDeltaUpdates)
		oneCGNAT                             opt.Bool
		forceBackgroundSTUN                  = has(nodecap.DebugForceBackgroundSTUN)
		peerMTUEnable                        = has(nodecap.PeerMTUEnable)
		dnsForwarderDisableTCPRetries        = has(nodecap.DNSForwarderDisableTCPRetries)
		silentDisco                          = has(nodecap.SilentDisco)
		forceIPTables                        = has(nodecap.LinuxMustUseIPTables)
		forceNfTables                        = has(nodecap.LinuxMustUseNfTables)
		probeUDPLifetime                     = has(nodecap.ProbeUDPLifetime)
		appCStoreRoutes                      = has(nodecap.StoreAppCRoutes)
		userDialUseRoutes                    = has(nodecap.UserDialUseRoutes)
		disableSplitDNSWhenNoCustomResolvers = has(nodecap.DisableSplitDNSWhenNoCustomResolvers)
		disableLocalDNSOverrideViaNRPT       = has(nodecap.DisableLocalDNSOverrideViaNRPT)
		disableCaptivePortalDetection        = has(nodecap.DisableCaptivePortalDetection)
		disableSkipStatusQueue               = has(nodecap.DisableSkipStatusQueue)
		disableHostsFileUpdates              = has(nodecap.DisableHostsFileUpdates)
		forceRegisterMagicDNSIPv4Only        = has(nodecap.ForceRegisterMagicDNSIPv4Only)
		emitRuntimeMetrics                   = has(nodecap.EmitRuntimeMetrics)
		disableUDPGRO                        = has(nodecap.DisableUDPGRO)
		disableUDPGSO                        = has(nodecap.DisableUDPGSO)
		disableTUNUDPGRO                     = has(nodecap.DisableTUNUDPGRO)
		disableTUNTCPGRO                     = has(nodecap.DisableTUNTCPGRO)
		neverGSOEqualTail                    = has(nodecap.NeverGSOEqualTail)
		cacheNetworkMaps                     = has(nodecap.CacheNetworkMaps)
		scopeQuad100OnMacOS                  = has(nodecap.ScopeQuad100OnMacOS)
	)

	if has(nodecap.OneCGNATEnable) {
		oneCGNAT.Set(true)
	} else if has(nodecap.OneCGNATDisable) {
		oneCGNAT.Set(false)
	}

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
	k.DisableHostsFileUpdates.Store(disableHostsFileUpdates)
	k.ForceRegisterMagicDNSIPv4Only.Store(forceRegisterMagicDNSIPv4Only)
	k.EmitRuntimeMetrics.Store(emitRuntimeMetrics)
	k.DisableUDPGRO.Store(disableUDPGRO)
	k.DisableUDPGSO.Store(disableUDPGSO)
	k.DisableTUNUDPGRO.Store(disableTUNUDPGRO)
	k.DisableTUNTCPGRO.Store(disableTUNTCPGRO)
	k.NeverGSOEqualTail.Store(neverGSOEqualTail)
	k.CacheNetworkMaps.Store(cacheNetworkMaps)
	k.ScopeQuad100OnMacOS.Store(scopeQuad100OnMacOS)
}

// AsDebugJSON returns k as something that can be marshalled with json.Marshal
// for debug.
func (k *Knobs) AsDebugJSON() map[string]any {
	if k == nil {
		return nil
	}
	ret := map[string]any{}
	rv := reflect.ValueOf(k).Elem() // of *k
	for sf, fv := range rv.Fields() {
		switch v := fv.Addr().Interface().(type) {
		case *atomic.Bool:
			ret[sf.Name] = v.Load()
		case *syncs.AtomicValue[opt.Bool]:
			ret[sf.Name] = v.Load()
		default:
			panic(fmt.Sprintf("unknown field type %T for %v", v, sf.Name))
		}
	}
	return ret
}

// ShouldForceRegisterMagicDNSIPv4Only reports the value of
// ForceRegisterMagicDNSIPv4Only, or false if k is nil.
func (k *Knobs) ShouldForceRegisterMagicDNSIPv4Only() bool {
	return k != nil && k.ForceRegisterMagicDNSIPv4Only.Load()
}
