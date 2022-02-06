/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

//
// Common functions
//

//sys	freeMibTable(memory unsafe.Pointer) = iphlpapi.FreeMibTable

//
// Interface-related functions
//

//sys	initializeIPInterfaceEntry(row *MibIPInterfaceRow) = iphlpapi.InitializeIpInterfaceEntry
//sys	getIPInterfaceTable(family AddressFamily, table **mibIPInterfaceTable) (ret error) = iphlpapi.GetIpInterfaceTable
//sys	getIPInterfaceEntry(row *MibIPInterfaceRow) (ret error) = iphlpapi.GetIpInterfaceEntry
//sys	setIPInterfaceEntry(row *MibIPInterfaceRow) (ret error) = iphlpapi.SetIpInterfaceEntry
//sys	getIfEntry2(row *MibIfRow2) (ret error) = iphlpapi.GetIfEntry2
//sys	getIfTable2Ex(level MibIfEntryLevel, table **mibIfTable2) (ret error) = iphlpapi.GetIfTable2Ex
//sys	convertInterfaceLUIDToGUID(interfaceLUID *LUID, interfaceGUID *windows.GUID) (ret error) = iphlpapi.ConvertInterfaceLuidToGuid
//sys	convertInterfaceGUIDToLUID(interfaceGUID *windows.GUID, interfaceLUID *LUID) (ret error) = iphlpapi.ConvertInterfaceGuidToLuid
//sys	convertInterfaceIndexToLUID(interfaceIndex uint32, interfaceLUID *LUID) (ret error) = iphlpapi.ConvertInterfaceIndexToLuid

// GetAdaptersAddresses function retrieves the addresses associated with the adapters on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
func GetAdaptersAddresses(family AddressFamily, flags GAAFlags) ([]*IPAdapterAddresses, error) {
	var b []byte
	size := uint32(15000)

	for {
		b = make([]byte, size)
		err := windows.GetAdaptersAddresses(uint32(family), uint32(flags), 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(b)) {
			return nil, err
		}
	}

	result := make([]*IPAdapterAddresses, 0, uintptr(size)/unsafe.Sizeof(IPAdapterAddresses{}))
	for wtiaa := (*IPAdapterAddresses)(unsafe.Pointer(&b[0])); wtiaa != nil; wtiaa = wtiaa.Next {
		result = append(result, wtiaa)
	}

	return result, nil
}

// GetIPInterfaceTable function retrieves the IP interface entries on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipinterfacetable
func GetIPInterfaceTable(family AddressFamily) ([]MibIPInterfaceRow, error) {
	var tab *mibIPInterfaceTable
	err := getIPInterfaceTable(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibIPInterfaceRow, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}

// GetIfTable2Ex function retrieves the MIB-II interface table.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getiftable2ex
func GetIfTable2Ex(level MibIfEntryLevel) ([]MibIfRow2, error) {
	var tab *mibIfTable2
	err := getIfTable2Ex(level, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibIfRow2, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}

//
// Unicast IP address-related functions
//

//sys	getUnicastIPAddressTable(family AddressFamily, table **mibUnicastIPAddressTable) (ret error) = iphlpapi.GetUnicastIpAddressTable
//sys	initializeUnicastIPAddressEntry(row *MibUnicastIPAddressRow) = iphlpapi.InitializeUnicastIpAddressEntry
//sys	getUnicastIPAddressEntry(row *MibUnicastIPAddressRow) (ret error) = iphlpapi.GetUnicastIpAddressEntry
//sys	setUnicastIPAddressEntry(row *MibUnicastIPAddressRow) (ret error) = iphlpapi.SetUnicastIpAddressEntry
//sys	createUnicastIPAddressEntry(row *MibUnicastIPAddressRow) (ret error) = iphlpapi.CreateUnicastIpAddressEntry
//sys	deleteUnicastIPAddressEntry(row *MibUnicastIPAddressRow) (ret error) = iphlpapi.DeleteUnicastIpAddressEntry

// GetUnicastIPAddressTable function retrieves the unicast IP address table on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getunicastipaddresstable
func GetUnicastIPAddressTable(family AddressFamily) ([]MibUnicastIPAddressRow, error) {
	var tab *mibUnicastIPAddressTable
	err := getUnicastIPAddressTable(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibUnicastIPAddressRow, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}

//
// Anycast IP address-related functions
//

//sys	getAnycastIPAddressTable(family AddressFamily, table **mibAnycastIPAddressTable) (ret error) = iphlpapi.GetAnycastIpAddressTable
//sys	getAnycastIPAddressEntry(row *MibAnycastIPAddressRow) (ret error) = iphlpapi.GetAnycastIpAddressEntry
//sys	createAnycastIPAddressEntry(row *MibAnycastIPAddressRow) (ret error) = iphlpapi.CreateAnycastIpAddressEntry
//sys	deleteAnycastIPAddressEntry(row *MibAnycastIPAddressRow) (ret error) = iphlpapi.DeleteAnycastIpAddressEntry

// GetAnycastIPAddressTable function retrieves the anycast IP address table on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getanycastipaddresstable
func GetAnycastIPAddressTable(family AddressFamily) ([]MibAnycastIPAddressRow, error) {
	var tab *mibAnycastIPAddressTable
	err := getAnycastIPAddressTable(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibAnycastIPAddressRow, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}

//
// Routing-related functions
//

//sys	getIPForwardTable2(family AddressFamily, table **mibIPforwardTable2) (ret error) = iphlpapi.GetIpForwardTable2
//sys	initializeIPForwardEntry(route *MibIPforwardRow2) = iphlpapi.InitializeIpForwardEntry
//sys	getIPForwardEntry2(route *MibIPforwardRow2) (ret error) = iphlpapi.GetIpForwardEntry2
//sys	setIPForwardEntry2(route *MibIPforwardRow2) (ret error) = iphlpapi.SetIpForwardEntry2
//sys	createIPForwardEntry2(route *MibIPforwardRow2) (ret error) = iphlpapi.CreateIpForwardEntry2
//sys	deleteIPForwardEntry2(route *MibIPforwardRow2) (ret error) = iphlpapi.DeleteIpForwardEntry2

// GetIPForwardTable2 function retrieves the IP route entries on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipforwardtable2
func GetIPForwardTable2(family AddressFamily) ([]MibIPforwardRow2, error) {
	var tab *mibIPforwardTable2
	err := getIPForwardTable2(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibIPforwardRow2, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}

//
// Notifications-related functions
//

// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-notifyipinterfacechange
//sys	notifyIPInterfaceChange(family AddressFamily, callback uintptr, callerContext uintptr, initialNotification bool, notificationHandle *windows.Handle) (ret error) = iphlpapi.NotifyIpInterfaceChange

// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-notifyunicastipaddresschange
//sys	notifyUnicastIPAddressChange(family AddressFamily, callback uintptr, callerContext uintptr, initialNotification bool, notificationHandle *windows.Handle) (ret error) = iphlpapi.NotifyUnicastIpAddressChange

// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-notifyroutechange2
//sys	notifyRouteChange2(family AddressFamily, callback uintptr, callerContext uintptr, initialNotification bool, notificationHandle *windows.Handle) (ret error) = iphlpapi.NotifyRouteChange2

// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-cancelmibchangenotify2
//sys	cancelMibChangeNotify2(notificationHandle windows.Handle) (ret error) = iphlpapi.CancelMibChangeNotify2

//
// DNS-related functions
//

//sys	setInterfaceDnsSettingsByPtr(guid *windows.GUID, settings *DnsInterfaceSettings) (ret error) = iphlpapi.SetInterfaceDnsSettings?
//sys	setInterfaceDnsSettingsByQwords(guid1 uintptr, guid2 uintptr, settings *DnsInterfaceSettings) (ret error) = iphlpapi.SetInterfaceDnsSettings?
//sys	setInterfaceDnsSettingsByDwords(guid1 uintptr, guid2 uintptr, guid3 uintptr, guid4 uintptr, settings *DnsInterfaceSettings) (ret error) = iphlpapi.SetInterfaceDnsSettings?

// The GUID is passed by value, not by reference, which means different
// things on different calling conventions.  On amd64, this means it's
// passed by reference anyway, while on arm, arm64, and 386, it's split
// into words.
func SetInterfaceDnsSettings(guid windows.GUID, settings *DnsInterfaceSettings) error {
	words := (*[4]uintptr)(unsafe.Pointer(&guid))
	switch runtime.GOARCH {
	case "amd64":
		return setInterfaceDnsSettingsByPtr(&guid, settings)
	case "arm64":
		return setInterfaceDnsSettingsByQwords(words[0], words[1], settings)
	case "arm", "386":
		return setInterfaceDnsSettingsByDwords(words[0], words[1], words[2], words[3], settings)
	default:
		panic("unknown calling convention")
	}
}
