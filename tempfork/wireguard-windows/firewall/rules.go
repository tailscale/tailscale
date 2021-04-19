// +build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"inet.af/netaddr"
)

//
// Known addresses.
//
var (
	linkLocal = wtFwpV6AddrAndMask{[16]uint8{0xfe, 0x80}, 10}

	linkLocalDHCPMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x2}}
	siteLocalDHCPMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x3}}

	linkLocalRouterMulticast = wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2}}
)

func (f *Firewall) generateRouteFilter(r netaddr.IPPrefix, weight uint8, incoming bool) (*wtFwpmFilter0, unsafe.Pointer, error) {
	var (
		layerKey       windows.GUID
		conditionValue wtFwpConditionValue0
		cidrPtr        unsafe.Pointer
	)
	if r.IP.Is4() {
		b := r.IP.As4()
		mask := uint32(0xFFFFFFFF)
		if r.Bits < 32 {
			shift := 32 - r.Bits
			mask = ((mask >> shift) << shift)
		}
		cidr := &wtFwpV4AddrAndMask{
			addr: binary.BigEndian.Uint32(b[:]),
			mask: mask,
		}
		cidrPtr = unsafe.Pointer(cidr)

		conditionValue = wtFwpConditionValue0{
			_type: cFWP_V4_ADDR_MASK,
			value: (uintptr)(cidrPtr),
		}
		if incoming {
			layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
		} else {
			layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4
		}
	} else {
		cidr := &wtFwpV6AddrAndMask{
			addr:         r.IP.As16(),
			prefixLength: r.Bits,
		}
		cidrPtr = unsafe.Pointer(cidr)
		conditionValue = wtFwpConditionValue0{
			_type: cFWP_V6_ADDR_MASK,
			value: (uintptr)(cidrPtr),
		}
		if incoming {
			layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
		} else {
			layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6
		}
	}

	displayData, err := createWtFwpmDisplayData0(fmt.Sprintf("Permit traffic for %s", r.String()), "")
	if err != nil {
		return nil, nil, wrapErr(err)
	}
	return &wtFwpmFilter0{
		providerKey:         &f.providerID,
		subLayerKey:         f.sublayerID,
		layerKey:            layerKey,
		weight:              filterWeight(weight),
		displayData:         *displayData,
		numFilterConditions: 1,
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
		filterCondition: &wtFwpmFilterCondition0{
			fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: conditionValue,
		},
	}, cidrPtr, nil
}

func (f *Firewall) permitRoutes(weight uint8, newRoutes []netaddr.IPPrefix) error {
	fmt.Println("updating routes", newRoutes)
	return runTransaction(f.session, func() error {
		var routesToAdd []netaddr.IPPrefix
		routeMap := make(map[netaddr.IPPrefix]bool)
		for _, r := range newRoutes {
			routeMap[r] = true
			if _, ok := f.routes[r]; !ok {
				routesToAdd = append(routesToAdd, r)
			}
		}
		var routesToRemove []netaddr.IPPrefix
		for r := range f.routes {
			if !routeMap[r] {
				routesToRemove = append(routesToRemove, r)
			}
		}
		for _, r := range routesToRemove {
			fmt.Println("removing route", r)
			for _, id := range f.routes[r] {
				if err := fwpmFilterDeleteById0(f.session, id); err != nil {
					return err
				}
			}
			delete(f.routes, r)
		}
		for _, r := range routesToAdd {
			// Add incoming and outgoing filters.
			for _, incoming := range []bool{true, false} {
				fmt.Println("permitting route", r)
				filterID := uint64(0)
				filter, cidrPtr, err := f.generateRouteFilter(r, weight, incoming)
				if err != nil {
					return err
				}
				if err := fwpmFilterAdd0(f.session, filter, 0, &filterID); err != nil {
					return fmt.Errorf("adding route %v failed: %w", r, err)
				}
				runtime.KeepAlive(cidrPtr)
				f.routes[r] = append(f.routes[r], filterID)
			}
		}
		return nil
	})
}

func (f *Firewall) permitTunInterface(weight uint8) error {
	ifaceCondition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: (uintptr)(unsafe.Pointer(&f.luid)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &f.providerID,
		subLayerKey:         f.sublayerID,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     &ifaceCondition,
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func (f *Firewall) permitWireGuardService(weight uint8) error {
	var conditions [1]wtFwpmFilterCondition0

	//
	// First condition is the exe path of the current process.
	//
	appID, err := getCurrentProcessAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))

	conditions[0] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appID)),
		},
	}

	//
	// Assemble the filter.
	//
	filter := wtFwpmFilter0{
		providerKey:         &f.providerID,
		subLayerKey:         f.sublayerID,
		weight:              filterWeight(weight),
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func (f *Firewall) permitLoopback(weight uint8) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_FLAGS,
		matchType: cFWP_MATCH_FLAGS_ALL_SET,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_FLAG_IS_LOOPBACK),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &f.providerID,
		subLayerKey:         f.sublayerID,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Permit outbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func (f *Firewall) permitDHCPIPv4(weight uint8) error {
	//
	// #1 Outbound DHCP request on IPv4.
	//
	{
		var conditions [4]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT32
		conditions[3].conditionValue.value = uintptr(0xffffffff)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			providerKey:         &f.providerID,
			subLayerKey:         f.sublayerID,
			displayData:         *displayData,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv4.
	//
	{
		var conditions [3]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			providerKey:         &f.providerID,
			subLayerKey:         f.sublayerID,
			displayData:         *displayData,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func (f *Firewall) permitDHCPIPv6(weight uint8) error {
	//
	// #1 Outbound DHCP request on IPv6.
	//
	{
		var conditions [6]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalDHCPMulticast))

		// Repeat the condition type for logical OR.
		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[2].conditionValue.value = uintptr(unsafe.Pointer(&siteLocalDHCPMulticast))

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT16
		conditions[3].conditionValue.value = uintptr(547)

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[4].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[5].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[5].matchType = cFWP_MATCH_EQUAL
		conditions[5].conditionValue._type = cFWP_UINT16
		conditions[5].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			providerKey:         &f.providerID,
			subLayerKey:         f.sublayerID,
			displayData:         *displayData,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv6.
	//
	{
		var conditions [5]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(547)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_UINT16
		conditions[4].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			providerKey:         &f.providerID,
			subLayerKey:         f.sublayerID,
			displayData:         *displayData,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterID := uint64(0)

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func (f *Firewall) permitNdp(weight uint8) error {

	/* TODO: actually handle the hop limit somehow! The rules should vaguely be:
	 *  - icmpv6 133: must be outgoing, dst must be FF02::2/128, hop limit must be 255
	 *  - icmpv6 134: must be incoming, src must be FE80::/10, hop limit must be 255
	 *  - icmpv6 135: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 136: either incoming or outgoing, hop limit must be 255
	 *  - icmpv6 137: must be incoming, src must be FE80::/10, hop limit must be 255
	 */

	type filterDefinition struct {
		displayData *wtFwpmDisplayData0
		conditions  []wtFwpmFilterCondition0
		layer       windows.GUID
	}

	var defs []filterDefinition

	//
	// Router Solicitation Message
	// ICMP type 133, code 0. Outgoing.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(133)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalRouterMulticast))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 133", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})
	}

	//
	// Router Advertisement Message
	// ICMP type 134, code 0. Incoming.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(134)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 134", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Neighbor Solicitation Message
	// ICMP type 135, code 0. Bi-directional.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 3)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(135)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 135", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Neighbor Advertisement Message
	// ICMP type 136, code 0. Bi-directional.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 3)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(136)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 136", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
		})

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	//
	// Redirect Message
	// ICMP type 137, code 0. Incoming.
	//
	{
		conditions := make([]wtFwpmFilterCondition0, 4)

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMPV6)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(137)

		conditions[2].fieldKey = cFWPM_CONDITION_ICMP_CODE
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(0)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&linkLocal))

		displayData, err := createWtFwpmDisplayData0("Permit NDP type 137", "")
		if err != nil {
			return wrapErr(err)
		}

		defs = append(defs, filterDefinition{
			displayData: displayData,
			conditions:  conditions,
			layer:       cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
		})
	}

	filter := wtFwpmFilter0{
		providerKey: &f.providerID,
		subLayerKey: f.sublayerID,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	for _, definition := range defs {
		filter.displayData = *definition.displayData
		filter.layerKey = definition.layer
		filter.numFilterConditions = uint32(len(definition.conditions))
		filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&definition.conditions[0]))

		err := fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func (f *Firewall) permitHyperV(weight uint8) error {
	//
	// Only applicable on Win8+.
	//
	{
		major, minor, _ := windows.RtlGetNtVersionNumbers()
		win8plus := major > 6 || (major == 6 && minor >= 3)

		if !win8plus {
			return nil
		}
	}

	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_L2_FLAGS,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cFWP_CONDITION_L2_IS_VM2VM),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &f.providerID,
		subLayerKey:         f.sublayerID,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Outbound.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit Hyper-V => Hyper-V outbound", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit Hyper-V => Hyper-V inbound", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_INBOUND_MAC_FRAME_NATIVE

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Block all traffic except what is explicitly permitted by other rules.
func (f *Firewall) blockAll(weight uint8) error {
	filter := wtFwpmFilter0{
		providerKey: &f.providerID,
		subLayerKey: f.sublayerID,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Block outbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block inbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block outbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block inbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Allow DNS traffic. This is less ironclad than upstream
// wireguard-windows, but until we rework our DNS configuration
// capability, it's difficult for us to identify the correct DNS
// servers to specifically allow here.
func (f *Firewall) allowDNS() error {
	allowConditions := []wtFwpmFilterCondition0{
		{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT16,
				value: uintptr(53),
			},
		},
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_UDP),
			},
		},
		// Repeat the condition type for logical OR.
		{
			fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_UINT8,
				value: uintptr(cIPPROTO_TCP),
			},
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &f.providerID,
		subLayerKey:         f.sublayerID,
		weight:              filterWeight(15),
		numFilterConditions: uint32(len(allowConditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&allowConditions[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterID := uint64(0)

	//
	// #1 Allow IPv4 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Allow IPv4 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Allow IPv6 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Allow DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Allow IPv6 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Allow DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(f.session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}
