// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlknobs

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	gcmp "github.com/google/go-cmp/cmp"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
)

// FuzzUpdateFromNodeAttributes proves that Knobs.UpdateFromNodeAttributes works like it used to.
// Remove this before merging.
func FuzzUpdateFromNodeAttributes(f *testing.F) {
	ref := func(k *Knobs, capMap tailcfg.NodeCapMap) {
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

	f.Add(string(nodecap.DisableUPnP))
	f.Add(string(nodecap.RandomizeClientPort))
	f.Add(string(nodecap.OneCGNATEnable))
	f.Add(string(nodecap.OneCGNATDisable))
	f.Add(string(nodecap.OneCGNATEnable) + " " + string(nodecap.OneCGNATDisable))
	f.Add(string(nodecap.OneCGNATDisable))
	f.Add(string(nodecap.DisableDeltaUpdates))
	f.Add(string(nodecap.DebugForceBackgroundSTUN))
	f.Add(string(nodecap.PeerMTUEnable))
	f.Add(string(nodecap.DNSForwarderDisableTCPRetries))
	f.Add(string(nodecap.SilentDisco))
	f.Add(string(nodecap.LinuxMustUseIPTables))
	f.Add(string(nodecap.LinuxMustUseNfTables))
	f.Add(string(nodecap.ProbeUDPLifetime))
	f.Add(string(nodecap.StoreAppCRoutes))
	f.Add(string(nodecap.UserDialUseRoutes))
	f.Add(string(nodecap.DisableSplitDNSWhenNoCustomResolvers))
	f.Add(string(nodecap.DisableLocalDNSOverrideViaNRPT))
	f.Add(string(nodecap.DisableCaptivePortalDetection))
	f.Add(string(nodecap.DisableSkipStatusQueue))
	f.Add(string(nodecap.DisableHostsFileUpdates))
	f.Add(string(nodecap.ForceRegisterMagicDNSIPv4Only))
	f.Add(string(nodecap.EmitRuntimeMetrics))
	f.Add(string(nodecap.DisableUDPGRO))
	f.Add(string(nodecap.DisableUDPGSO))
	f.Add(string(nodecap.DisableTUNUDPGRO))
	f.Add(string(nodecap.DisableTUNTCPGRO))
	f.Add(string(nodecap.NeverGSOEqualTail))
	f.Add(string(nodecap.CacheNetworkMaps))
	f.Add(string(nodecap.ScopeQuad100OnMacOS))

	f.Fuzz(func(t *testing.T, s string) {
		caps := strings.Fields(s)
		capMap := make(tailcfg.NodeCapMap, len(caps))
		for _, f := range caps {
			capMap[nodecap.Cap(f)] = nil
		}

		want := &Knobs{}
		ref(want, capMap)

		got := &Knobs{}
		got.UpdateFromNodeAttributes(capMap)

		if diff := gcmp.Diff(want.AsDebugJSON(), got.AsDebugJSON()); diff != "" {
			t.Errorf("Knobs (-want +got)\n%s", diff)
		}
	})
}

func TestAsDebugJSON(t *testing.T) {
	var nilPtr *Knobs
	if got := nilPtr.AsDebugJSON(); got != nil {
		t.Errorf("AsDebugJSON(nil) = %v; want nil", got)
	}

	var wantKeys []string
	for f := range reflect.TypeFor[Knobs]().Fields() {
		wantKeys = append(wantKeys, f.Name)
	}
	slices.Sort(wantKeys)

	k := new(Knobs)
	got := k.AsDebugJSON()
	gotKeys := slices.Sorted(maps.Keys(got))

	if diff := gcmp.Diff(wantKeys, gotKeys); diff != "" {
		t.Errorf("AsDebugJSON keys (-want +got)\n%s", diff)
	}
	t.Logf("Got: %v", logger.AsJSON(got))
}
