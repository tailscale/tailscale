// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"github.com/tailscale/wireguard-go/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"sync"
	"tailscale.com/log/filelogger"
	"tailscale.com/types/logger"
)

type ifaceWatcherEvent struct {
	luid         winipcfg.LUID
	family       winipcfg.AddressFamily
	nt           winipcfg.MibNotificationType
	iface        *winipcfg.MibIfRow2
	ifaceError   error
	ipIface      *winipcfg.MibIPInterfaceRow
	ipIfaceError error
}

type ifaceWatcher struct {
	lck          sync.Mutex
	logf         logger.Logf
	luid         winipcfg.LUID
	tun          *tun.NativeTun
	cb           *winipcfg.InterfaceChangeCallback
	buffer       map[winipcfg.LUID][]*ifaceWatcherEvent
	prevIpIfaces map[winipcfg.AddressFamily]*winipcfg.MibIPInterfaceRow
	prevIface    *winipcfg.MibIfRow2
}

// initWatcher initialize interface watcher and registers Windows SDK NotifyIpInterfaceChange callback.
func initWatcher(logf logger.Logf) (*ifaceWatcher, error) {
	iw := &ifaceWatcher{
		logf:         filelogger.New("iw_", "interfaceWatcher", logger.WithPrefix(logf, "ifaceWatcher: ")),
		buffer:       make(map[winipcfg.LUID][]*ifaceWatcherEvent),
		prevIpIfaces: make(map[winipcfg.AddressFamily]*winipcfg.MibIPInterfaceRow),
	}

	cb, err := winipcfg.RegisterInterfaceChangeCallback(iw.callback)
	if err != nil {
		iw.logf("winipcfg.RegisterInterfaceChangeCallback error: %v", err)
		if cb != nil {
			_ = cb.Unregister()
		}
		return nil, err
	}
	iw.logf("Initialized")
	iw.cb = cb
	return iw, nil
}

// setTun sets the interface once it's created. Should be called only once.
func (iw *ifaceWatcher) setTun(ifc interface{}) {
	iw.lck.Lock()
	defer iw.lck.Unlock()
	iw.tun = ifc.(*tun.NativeTun)
	iw.luid = winipcfg.LUID(iw.tun.LUID())
	iw.logf("setTun LUID=%v", iw.luid)
	if iw.buffer == nil {
		return
	}
	buf := iw.buffer[iw.luid]
	iw.buffer = nil
	if buf != nil {
		for _, e := range buf {
			iw.newEvent(e)
		}
	}
}

// Destroy unregisters Windows SDK NotifyIpInterfaceChange callback.
func (iw *ifaceWatcher) Destroy() {
	if iw.cb == nil {
		return
	}
	if err := iw.cb.Unregister(); err != nil {
		iw.logf("cb.Unregister() error: %v", err)
	}
	iw.cb = nil
	iw.logf("Destroy")
}

func (iw *ifaceWatcher) callback(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
	go iw.doCallback(notificationType, iface.InterfaceLUID, iface.Family)
}

func (iw *ifaceWatcher) doCallback(notificationType winipcfg.MibNotificationType, luid winipcfg.LUID,
	family winipcfg.AddressFamily) {
	iw.lck.Lock()
	defer iw.lck.Unlock()

	if iw.tun != nil && iw.luid != luid {
		// Not our tun
		return
	}

	ie := ifaceWatcherEvent{
		luid:   luid,
		family: family,
		nt:     notificationType,
	}

	ie.iface, ie.ifaceError = luid.Interface()
	ie.ipIface, ie.ipIfaceError = luid.IPInterface(family)

	if iw.tun == nil {
		// We still don't know the LUID, so just add to the buffer
		if iw.buffer[luid] == nil {
			iw.buffer[luid] = make([]*ifaceWatcherEvent, 0)
		}
		iw.buffer[luid] = append(iw.buffer[luid], &ie)
	} else {
		iw.newEvent(&ie)
	}
}

func (iw *ifaceWatcher) newEvent(e *ifaceWatcherEvent) {
	ifcLog := ""
	if e.ifaceError != nil {
		ifcLog = fmt.Sprintf("\n\tMibIfRow2 error: %v", e.ifaceError)
	} else if e.iface == nil {
		// Should not happen ever since e.ifaceError is nil
		ifcLog = "\n\tMibIfRow2 is nil"
	} else {
		if iw.prevIface == nil {
			ifcLog = "\n\tMibIfRow2 (full):" + stringifyMibIfRow2(e.iface)
		} else {
			ifcLog = getMibIfRow2Diff(iw.prevIface, e.iface)
			if ifcLog != "" {
				ifcLog = "\n\tMibIfRow2 (changes):" + ifcLog
			}
		}
		iw.prevIface = e.iface
	}

	ipIfcLog := ""
	if e.ipIfaceError != nil {
		ipIfcLog = fmt.Sprintf("\n\tMibIPInterfaceRow [AF=%v] error: %v", e.family, e.ipIfaceError)
	} else if e.ipIface == nil {
		// Should not happen ever since e.ipIfaceError is nil
		ipIfcLog = "\n\tMibIPInterfaceRow [AF=%v] is nil"
	} else {
		if ipIfcOld := iw.prevIpIfaces[e.family]; ipIfcOld != nil {
			ipIfcLog = getMibIPInterfaceRowDiff(ipIfcOld, e.ipIface)
			if ipIfcLog != "" {
				ipIfcLog = fmt.Sprintf("\n\tMibIPInterfaceRow [AF=%v] (changes):%s", e.family, ipIfcLog)
			}
		} else {
			ipIfcLog = fmt.Sprintf("\n\tMibIPInterfaceRow [AF=%v] (full):%s", e.family,
				stringifyMibIPInterfaceRow(e.ipIface))
		}
		iw.prevIpIfaces[e.family] = e.ipIface
	}

	// Log only if something changed, otherwise ignore.
	if ifcLog != "" || ipIfcLog != "" {
		iw.logf("LUID: %v; AF: %v; MibNotificationType: %v;%s %s", e.luid, e.family, e.nt, ifcLog, ipIfcLog)
	}
}

// stringifyMibIfRow2 used just for logging
func stringifyMibIfRow2(r *winipcfg.MibIfRow2) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("\n\t\tInterfaceIndex: %v\n\t\tInterfaceGUID: %v\n\t\tMTU: %v\n\t\tType: %v"+
		"\n\t\tTunnelType: %v\n\t\tMediaType: %v\n\t\tPhysicalMediumType: %v\n\t\tAccessType: %v\n\t\tDirectionType: %v"+
		"\n\t\tInterfaceAndOperStatusFlags: %v\n\t\tOperStatus: %v\n\t\tAdminStatus: %v\n\t\tMediaConnectState: %v"+
		"\n\t\tNetworkGUID: %v\n\t\tConnectionType %v",
		r.InterfaceIndex,
		r.InterfaceGUID,
		r.MTU,
		r.Type,
		r.TunnelType,
		r.MediaType,
		r.PhysicalMediumType,
		r.AccessType,
		r.DirectionType,
		r.InterfaceAndOperStatusFlags,
		r.OperStatus,
		r.AdminStatus,
		r.MediaConnectState,
		r.NetworkGUID,
		r.ConnectionType)
}

// getMibIfRow2Diff used just for logging
func getMibIfRow2Diff(r1, r2 *winipcfg.MibIfRow2) string {
	txt := ""

	if r2.InterfaceIndex != r1.InterfaceIndex {
		txt += fmt.Sprintf("\n\t\tInterfaceIndex: %v", r2.InterfaceIndex)
	}
	if r2.InterfaceGUID != r1.InterfaceGUID {
		txt += fmt.Sprintf("\n\t\tInterfaceGUID: %v", r2.InterfaceGUID)
	}
	if r2.MTU != r1.MTU {
		txt += fmt.Sprintf("\n\t\tMTU: %v", r2.MTU)
	}
	if r2.Type != r1.Type {
		txt += fmt.Sprintf("\n\t\tType: %v", r2.Type)
	}
	if r2.TunnelType != r1.TunnelType {
		txt += fmt.Sprintf("\n\t\tTunnelType: %v", r2.TunnelType)
	}
	if r2.MediaType != r1.MediaType {
		txt += fmt.Sprintf("\n\t\tMediaType: %v", r2.MediaType)
	}
	if r2.PhysicalMediumType != r1.PhysicalMediumType {
		txt += fmt.Sprintf("\n\t\tPhysicalMediumType: %v", r2.PhysicalMediumType)
	}
	if r2.AccessType != r1.AccessType {
		txt += fmt.Sprintf("\n\t\tAccessType: %v", r2.AccessType)
	}
	if r2.DirectionType != r1.DirectionType {
		txt += fmt.Sprintf("\n\t\tDirectionType: %v", r2.DirectionType)
	}
	if r2.InterfaceAndOperStatusFlags != r1.InterfaceAndOperStatusFlags {
		txt += fmt.Sprintf("\n\t\tInterfaceAndOperStatusFlags: %v", r2.InterfaceAndOperStatusFlags)
	}
	if r2.OperStatus != r1.OperStatus {
		txt += fmt.Sprintf("\n\t\tOperStatus: %v", r2.OperStatus)
	}
	if r2.AdminStatus != r1.AdminStatus {
		txt += fmt.Sprintf("\n\t\tAdminStatus: %v", r2.AdminStatus)
	}
	if r2.MediaConnectState != r1.MediaConnectState {
		txt += fmt.Sprintf("\n\t\tMediaConnectState: %v", r2.MediaConnectState)
	}
	if r2.NetworkGUID != r1.NetworkGUID {
		txt += fmt.Sprintf("\n\t\tNetworkGUID: %v", r2.NetworkGUID)
	}
	if r2.ConnectionType != r1.ConnectionType {
		txt += fmt.Sprintf("\n\t\tConnectionType: %v", r2.ConnectionType)
	}

	return txt
}

// stringifyMibIPInterfaceRow used just for logging
func stringifyMibIPInterfaceRow(r *winipcfg.MibIPInterfaceRow) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("\n\t\tFamily: %v\n\t\tInterfaceIndex: %v\n\t\tMaxReassemblySize: %v\n\t\tInterfaceIdentifier: %v"+
		"\n\t\tMinRouterAdvertisementInterval: %v\n\t\tMaxRouterAdvertisementInterval: %v\n\t\tAdvertisingEnabled: %v"+
		"\n\t\tForwardingEnabled: %v\n\t\tWeakHostSend: %v\n\t\tWeakHostReceive: %v\n\t\tUseAutomaticMetric: %v"+
		"\n\t\tUseNeighborUnreachabilityDetection: %v\n\t\tManagedAddressConfigurationSupported: %v"+
		"\n\t\tOtherStatefulConfigurationSupported: %v\n\t\tAdvertiseDefaultRoute: %v\n\t\tRouterDiscoveryBehavior: %v"+
		"\n\t\tDadTransmits: %v\n\t\tBaseReachableTime: %v\n\t\tRetransmitTime: %v\n\t\tPathMTUDiscoveryTimeout: %v"+
		"\n\t\tLinkLocalAddressBehavior: %v\n\t\tLinkLocalAddressTimeout: %v\n\t\tZoneIndices: %v\n\t\tSitePrefixLength: %v"+
		"\n\t\tMetric: %v\n\t\tNLMTU: %v\n\t\tConnected: %v\n\t\tSupportsWakeUpPatterns: %v\n\t\tSupportsNeighborDiscovery: %v"+
		"\n\t\tSupportsRouterDiscovery: %v\n\t\tReachableTime: %v\n\t\tTransmitOffload: %v\n\t\tReceiveOffload: %v"+
		"\n\t\tDisableDefaultRoutes: %v",
		r.Family,
		r.InterfaceIndex,
		r.MaxReassemblySize,
		r.InterfaceIdentifier,
		r.MinRouterAdvertisementInterval,
		r.MaxRouterAdvertisementInterval,
		r.AdvertisingEnabled,
		r.ForwardingEnabled,
		r.WeakHostSend,
		r.WeakHostReceive,
		r.UseAutomaticMetric,
		r.UseNeighborUnreachabilityDetection,
		r.ManagedAddressConfigurationSupported,
		r.OtherStatefulConfigurationSupported,
		r.AdvertiseDefaultRoute,
		r.RouterDiscoveryBehavior,
		r.DadTransmits,
		r.BaseReachableTime,
		r.RetransmitTime,
		r.PathMTUDiscoveryTimeout,
		r.LinkLocalAddressBehavior,
		r.LinkLocalAddressTimeout,
		r.ZoneIndices,
		r.SitePrefixLength,
		r.Metric,
		r.NLMTU,
		r.Connected,
		r.SupportsWakeUpPatterns,
		r.SupportsNeighborDiscovery,
		r.SupportsRouterDiscovery,
		r.ReachableTime,
		r.TransmitOffload,
		r.ReceiveOffload,
		r.DisableDefaultRoutes)
}

// getMibIPInterfaceRowDiff used just for logging
func getMibIPInterfaceRowDiff(r1, r2 *winipcfg.MibIPInterfaceRow) string {
	txt := ""

	if r2.Family != r1.Family {
		txt += fmt.Sprintf("\n\t\tFamily: %v", r2.Family)
	}
	if r2.InterfaceIndex != r1.InterfaceIndex {
		txt += fmt.Sprintf("\n\t\tInterfaceIndex: %v", r2.InterfaceIndex)
	}
	if r2.MaxReassemblySize != r1.MaxReassemblySize {
		txt += fmt.Sprintf("\n\t\tMaxReassemblySize: %v", r2.MaxReassemblySize)
	}
	if r2.InterfaceIdentifier != r1.InterfaceIdentifier {
		txt += fmt.Sprintf("\n\t\tInterfaceIdentifier: %v", r2.InterfaceIdentifier)
	}
	if r2.MinRouterAdvertisementInterval != r1.MinRouterAdvertisementInterval {
		txt += fmt.Sprintf("\n\t\tMinRouterAdvertisementInterval: %v", r2.MinRouterAdvertisementInterval)
	}
	if r2.MaxRouterAdvertisementInterval != r1.MaxRouterAdvertisementInterval {
		txt += fmt.Sprintf("\n\t\tMaxRouterAdvertisementInterval: %v", r2.MaxRouterAdvertisementInterval)
	}
	if r2.AdvertisingEnabled != r1.AdvertisingEnabled {
		txt += fmt.Sprintf("\n\t\tAdvertisingEnabled: %v", r2.AdvertisingEnabled)
	}
	if r2.ForwardingEnabled != r1.ForwardingEnabled {
		txt += fmt.Sprintf("\n\t\tForwardingEnabled: %v", r2.ForwardingEnabled)
	}
	if r2.WeakHostSend != r1.WeakHostSend {
		txt += fmt.Sprintf("\n\t\tWeakHostSend: %v", r2.WeakHostSend)
	}
	if r2.WeakHostReceive != r1.WeakHostReceive {
		txt += fmt.Sprintf("\n\t\tWeakHostReceive: %v", r2.WeakHostReceive)
	}
	if r2.UseAutomaticMetric != r1.UseAutomaticMetric {
		txt += fmt.Sprintf("\n\t\tUseAutomaticMetric: %v", r2.UseAutomaticMetric)
	}
	if r2.UseNeighborUnreachabilityDetection != r1.UseNeighborUnreachabilityDetection {
		txt += fmt.Sprintf("\n\t\tUseNeighborUnreachabilityDetection: %v", r2.UseNeighborUnreachabilityDetection)
	}
	if r2.ManagedAddressConfigurationSupported != r1.ManagedAddressConfigurationSupported {
		txt += fmt.Sprintf("\n\t\tManagedAddressConfigurationSupported: %v", r2.ManagedAddressConfigurationSupported)
	}
	if r2.OtherStatefulConfigurationSupported != r1.OtherStatefulConfigurationSupported {
		txt += fmt.Sprintf("\n\t\tOtherStatefulConfigurationSupported: %v", r2.OtherStatefulConfigurationSupported)
	}
	if r2.AdvertiseDefaultRoute != r1.AdvertiseDefaultRoute {
		txt += fmt.Sprintf("\n\t\tAdvertiseDefaultRoute: %v", r2.AdvertiseDefaultRoute)
	}
	if r2.RouterDiscoveryBehavior != r1.RouterDiscoveryBehavior {
		txt += fmt.Sprintf("\n\t\tRouterDiscoveryBehavior: %v", r2.RouterDiscoveryBehavior)
	}
	if r2.DadTransmits != r1.DadTransmits {
		txt += fmt.Sprintf("\n\t\tDadTransmits: %v", r2.DadTransmits)
	}
	if r2.BaseReachableTime != r1.BaseReachableTime {
		txt += fmt.Sprintf("\n\t\tBaseReachableTime: %v", r2.BaseReachableTime)
	}
	if r2.RetransmitTime != r1.RetransmitTime {
		txt += fmt.Sprintf("\n\t\tRetransmitTime: %v", r2.RetransmitTime)
	}
	if r2.PathMTUDiscoveryTimeout != r1.PathMTUDiscoveryTimeout {
		txt += fmt.Sprintf("\n\t\tPathMTUDiscoveryTimeout: %v", r2.PathMTUDiscoveryTimeout)
	}
	if r2.LinkLocalAddressBehavior != r1.LinkLocalAddressBehavior {
		txt += fmt.Sprintf("\n\t\tLinkLocalAddressBehavior: %v", r2.LinkLocalAddressBehavior)
	}
	if r2.LinkLocalAddressTimeout != r1.LinkLocalAddressTimeout {
		txt += fmt.Sprintf("\n\t\tLinkLocalAddressTimeout: %v", r2.LinkLocalAddressTimeout)
	}
	if r2.ZoneIndices != r1.ZoneIndices {
		txt += fmt.Sprintf("\n\t\tZoneIndices: %v", r2.ZoneIndices)
	}
	if r2.SitePrefixLength != r1.SitePrefixLength {
		txt += fmt.Sprintf("\n\t\tSitePrefixLength: %v", r2.SitePrefixLength)
	}
	if r2.Metric != r1.Metric {
		txt += fmt.Sprintf("\n\t\tMetric: %v", r2.Metric)
	}
	if r2.NLMTU != r1.NLMTU {
		txt += fmt.Sprintf("\n\t\tNLMTU: %v", r2.NLMTU)
	}
	if r2.Connected != r1.Connected {
		txt += fmt.Sprintf("\n\t\tConnected: %v", r2.Connected)
	}
	if r2.SupportsWakeUpPatterns != r1.SupportsWakeUpPatterns {
		txt += fmt.Sprintf("\n\t\tSupportsWakeUpPatterns: %v", r2.SupportsWakeUpPatterns)
	}
	if r2.SupportsNeighborDiscovery != r1.SupportsNeighborDiscovery {
		txt += fmt.Sprintf("\n\t\tSupportsNeighborDiscovery: %v", r2.SupportsNeighborDiscovery)
	}
	if r2.SupportsRouterDiscovery != r1.SupportsRouterDiscovery {
		txt += fmt.Sprintf("\n\t\tSupportsRouterDiscovery: %v", r2.SupportsRouterDiscovery)
	}
	if r2.ReachableTime != r1.ReachableTime {
		txt += fmt.Sprintf("\n\t\tReachableTime: %v", r2.ReachableTime)
	}
	if r2.TransmitOffload != r1.TransmitOffload {
		txt += fmt.Sprintf("\n\t\tTransmitOffload: %v", r2.TransmitOffload)
	}
	if r2.ReceiveOffload != r1.ReceiveOffload {
		txt += fmt.Sprintf("\n\t\tReceiveOffload: %v", r2.ReceiveOffload)
	}
	if r2.DisableDefaultRoutes != r1.DisableDefaultRoutes {
		txt += fmt.Sprintf("\n\t\tDisableDefaultRoutes: %v", r2.DisableDefaultRoutes)
	}

	return txt
}
