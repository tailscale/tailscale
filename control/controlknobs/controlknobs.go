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
	// Set by [nodecap.DisableUPnP].
	DisableUPnP atomic.Bool

	// RandomizeClientPort is whether control says we should randomize
	// the client port.
	// Set by [nodecap.RandomizeClientPort].
	RandomizeClientPort atomic.Bool

	// OneCGNAT is whether the node should make one big CGNAT route
	// in the OS rather than one /32 per peer.
	// Set by [nodecap.OneCGNATEnable] and [nodecap.OneCGNATDisable].
	OneCGNAT syncs.AtomicValue[opt.Bool]

	// ForceBackgroundSTUN forces netcheck STUN queries to keep
	// running in magicsock, even when idle.
	// Set by [nodecap.DebugForceBackgroundSTUN].
	ForceBackgroundSTUN atomic.Bool

	// DisableDeltaUpdates is whether the node should not process
	// incremental (delta) netmap updates and should treat all netmap
	// changes as "full" ones as tailscaled did in 1.48.x and earlier.
	// Set by [nodecap.DisableDeltaUpdates].
	DisableDeltaUpdates atomic.Bool

	// PeerMTUEnable is whether the node should do peer path MTU discovery.
	// Set by [nodecap.PeerMTUEnable].
	PeerMTUEnable atomic.Bool

	// DisableDNSForwarderTCPRetries is whether the DNS forwarder should
	// skip retrying truncated queries over TCP.
	// Set by [nodecap.DisableDNSForwarderTCPRetries].
	DisableDNSForwarderTCPRetries atomic.Bool

	// SilentDisco is whether the node should suppress disco heartbeats to its
	// peers.
	// Set by [nodecap.SilentDisco].
	SilentDisco atomic.Bool

	// LinuxForceIPTables is whether the node should use iptables for Linux
	// netfiltering, unless overridden by the user.
	// Set by [nodecap.LinuxMustUseIPTables].
	LinuxForceIPTables atomic.Bool

	// LinuxForceNfTables is whether the node should use nftables for Linux
	// netfiltering, unless overridden by the user.
	// Set by [nodecap.LinuxMustUseNfTables].
	LinuxForceNfTables atomic.Bool

	// ProbeUDPLifetime is whether the node should probe UDP path lifetime on
	// the tail end of an active direct connection in magicsock.
	// Set by [nodecap.ProbeUDPLifetime].
	ProbeUDPLifetime atomic.Bool

	// AppCStoreRoutes is whether the node should store RouteInfo to StateStore
	// if it's an app connector.
	// Set by [nodecap.StoreAppCRoutes].
	AppCStoreRoutes atomic.Bool

	// UserDialUseRoutes is whether tsdial.Dialer.UserDial should use routes to determine
	// how to dial the destination address. When true, it also makes the DNS forwarder
	// use UserDial instead of SystemDial when dialing resolvers.
	// Set by [nodecap.UserDialUseRoutes].
	UserDialUseRoutes atomic.Bool

	// DisableSplitDNSWhenNoCustomResolvers indicates that the node's DNS manager
	// should not adopt a split DNS configuration even though the Config of the
	// resolver only contains routes that do not specify custom resolver(s), hence
	// all DNS queries can be safely sent to the upstream DNS resolver and the
	// node's DNS forwarder doesn't need to handle all DNS traffic.
	// This is for now (2024-06-06) an iOS-specific battery life optimization,
	// and this knob allows us to disable the optimization remotely if needed.
	// Set by [nodecap.DisableSplitDNSWhenNoCustomResolvers].
	DisableSplitDNSWhenNoCustomResolvers atomic.Bool

	// DisableLocalDNSOverrideViaNRPT indicates that the node's DNS manager should not
	// create a default (catch-all) Windows NRPT rule when "Override local DNS" is enabled.
	// Without this rule, Windows 8.1 and newer devices issue parallel DNS requests to DNS servers
	// associated with all network adapters, even when "Override local DNS" is enabled and/or
	// a Mullvad exit node is being used, resulting in DNS leaks.
	// We began creating this rule on 2024-06-14, and this knob
	// allows us to disable the new behavior remotely if needed.
	// Set by [nodecap.DisableLocalDNSOverrideViaNRPT].
	DisableLocalDNSOverrideViaNRPT atomic.Bool

	// DisableCaptivePortalDetection is whether the node should not perform captive portal detection
	// automatically when the network state changes.
	// Set by [nodecap.DisableCaptivePortalDetection].
	DisableCaptivePortalDetection atomic.Bool

	// DisableSkipStatusQueue is whether the node should disable skipping
	// of queued netmap.NetworkMap between the controlclient and LocalBackend.
	// See tailscale/tailscale#14768.
	// Set by [nodecap.DisableSkipStatusQueue].
	DisableSkipStatusQueue atomic.Bool

	// DisableHostsFileUpdates indicates that the node's DNS manager should not create
	// hosts file entries when it normally would, such as when we're not the primary
	// resolver on Windows or when the host is domain-joined and its primary domain
	// takes precedence over MagicDNS. As of 2026-02-13, it is only used on Windows.
	// Set by [nodecap.DisableHostsFileUpdates].
	DisableHostsFileUpdates atomic.Bool

	// ForceRegisterMagicDNSIPv4Only is whether the node should only register
	// its IPv4 MagicDNS service IP and not its IPv6 one. The IPv6 one,
	// [tailscale.com/net/tsaddr.TailscaleServiceIPv6String], still works in either case.
	// This knob controls only whether we tell systemd/etc about the IPv6 one.
	// See https://github.com/tailscale/tailscale/issues/15404.
	// Set by [nodecap.ForceRegisterMagicDNSIPv4Only]
	// TODO(bradfitz): remove this a few releases after 2026-02-16.
	ForceRegisterMagicDNSIPv4Only atomic.Bool

	// EmitRuntimeMetrics is whether the node should poll and emit [runtime/metrics]
	// as [tailscale.com/util/clientmetric]'s.
	// Set by [nodecap.EmitRuntimeMetrics]
	EmitRuntimeMetrics atomic.Bool

	// DisableUDPGRO disables UDP GRO on the magicsock UDP socket.
	// Set by [nodecap.DisableUDPGRO].
	DisableUDPGRO atomic.Bool

	// DisableUDPGSO disables UDP GSO on the magicsock UDP socket.
	// Set by [nodecap.DisableUDPGSO].
	DisableUDPGSO atomic.Bool

	// DisableTUNUDPGRO disables UDP GRO on the Tailscale TUN device.
	// Set by [nodecap.DisableTUNUDPGRO].
	DisableTUNUDPGRO atomic.Bool

	// DisableTUNTCPGRO disables TCP GRO on the Tailscale TUN device.
	// Set by [nodecap.DisableTUNTCPGRO].
	DisableTUNTCPGRO atomic.Bool

	// NeverGSOEqualTail enables a UDP GSO sentinel-tail workaround in the
	// underlay UDP packet TX path on Linux. Applies to magicsock and peer relay
	// UDP sockets.
	// Set by [nodecap.NeverGSOEqualTail].
	NeverGSOEqualTail atomic.Bool

	// CacheNetworkMaps is whether the node should persistently cache network
	// maps and use them to establish peer connectivity on start, if doing so
	// is supported by the client and storage is available.
	// Set by [nodecap.CacheNetworkMaps].
	CacheNetworkMaps atomic.Bool

	// ScopeQuad100OnMacOS lets sandboxed macOS scope quad-100 for simple DNS
	// configs, so public queries can use the OS resolver (including DoH).
	// Custom split resolvers or unrouted forward/PTR records still require
	// quad-100 as primary. Off by default; has no effect on other platforms.
	// See tailscale/corp#45534 and tailscale/corp#48693.
	// Set by [nodecap.ScopeQuad100OnMacOS].
	ScopeQuad100OnMacOS atomic.Bool
}

// UpdateFromNodeAttributes updates k (if non-nil) based on the provided self
// node attributes (Node.Capabilities).
func (k *Knobs) UpdateFromNodeAttributes(capMap tailcfg.NodeCapMap) {
	if k == nil {
		return
	}

	setBool := func(b *atomic.Bool, cap nodecap.Cap) {
		b.Store(capMap.Contains(cap))
	}
	setOptBool := func(b *syncs.AtomicValue[opt.Bool], enable, disable nodecap.Cap) {
		var v opt.Bool
		if capMap.Contains(enable) {
			v.Set(true)
		} else if capMap.Contains(disable) {
			v.Set(false)
		}
		b.Store(v)
	}

	setBool(&k.DisableUPnP, nodecap.DisableUPnP)
	setBool(&k.RandomizeClientPort, nodecap.RandomizeClientPort)
	setOptBool(&k.OneCGNAT, nodecap.OneCGNATEnable, nodecap.OneCGNATDisable)
	setBool(&k.ForceBackgroundSTUN, nodecap.DebugForceBackgroundSTUN)
	setBool(&k.DisableDeltaUpdates, nodecap.DisableDeltaUpdates)
	setBool(&k.PeerMTUEnable, nodecap.PeerMTUEnable)
	setBool(&k.DisableDNSForwarderTCPRetries, nodecap.DNSForwarderDisableTCPRetries)
	setBool(&k.SilentDisco, nodecap.SilentDisco)
	setBool(&k.LinuxForceIPTables, nodecap.LinuxMustUseIPTables)
	setBool(&k.LinuxForceNfTables, nodecap.LinuxMustUseNfTables)
	setBool(&k.ProbeUDPLifetime, nodecap.ProbeUDPLifetime)
	setBool(&k.AppCStoreRoutes, nodecap.StoreAppCRoutes)
	setBool(&k.UserDialUseRoutes, nodecap.UserDialUseRoutes)
	setBool(&k.DisableSplitDNSWhenNoCustomResolvers, nodecap.DisableSplitDNSWhenNoCustomResolvers)
	setBool(&k.DisableLocalDNSOverrideViaNRPT, nodecap.DisableLocalDNSOverrideViaNRPT)
	setBool(&k.DisableCaptivePortalDetection, nodecap.DisableCaptivePortalDetection)
	setBool(&k.DisableSkipStatusQueue, nodecap.DisableSkipStatusQueue)
	setBool(&k.DisableHostsFileUpdates, nodecap.DisableHostsFileUpdates)
	setBool(&k.ForceRegisterMagicDNSIPv4Only, nodecap.ForceRegisterMagicDNSIPv4Only)
	setBool(&k.EmitRuntimeMetrics, nodecap.EmitRuntimeMetrics)
	setBool(&k.DisableUDPGRO, nodecap.DisableUDPGRO)
	setBool(&k.DisableUDPGSO, nodecap.DisableUDPGSO)
	setBool(&k.DisableTUNUDPGRO, nodecap.DisableTUNUDPGRO)
	setBool(&k.DisableTUNTCPGRO, nodecap.DisableTUNTCPGRO)
	setBool(&k.NeverGSOEqualTail, nodecap.NeverGSOEqualTail)
	setBool(&k.CacheNetworkMaps, nodecap.CacheNetworkMaps)
	setBool(&k.ScopeQuad100OnMacOS, nodecap.ScopeQuad100OnMacOS)
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
