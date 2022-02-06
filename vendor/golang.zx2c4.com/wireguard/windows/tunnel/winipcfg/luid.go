/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"errors"
	"net"
	"strings"

	"golang.org/x/sys/windows"
)

// LUID represents a network interface.
type LUID uint64

// IPInterface method retrieves IP information for the specified interface on the local computer.
func (luid LUID) IPInterface(family AddressFamily) (*MibIPInterfaceRow, error) {
	row := &MibIPInterfaceRow{}
	row.Init()
	row.InterfaceLUID = luid
	row.Family = family
	err := row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

// Interface method retrieves information for the specified adapter on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getifentry2
func (luid LUID) Interface() (*MibIfRow2, error) {
	row := &MibIfRow2{}
	row.InterfaceLUID = luid
	err := row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GUID method converts a locally unique identifier (LUID) for a network interface to a globally unique identifier (GUID) for the interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-convertinterfaceluidtoguid
func (luid LUID) GUID() (*windows.GUID, error) {
	guid := &windows.GUID{}
	err := convertInterfaceLUIDToGUID(&luid, guid)
	if err != nil {
		return nil, err
	}
	return guid, nil
}

// LUIDFromGUID function converts a globally unique identifier (GUID) for a network interface to the locally unique identifier (LUID) for the interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-convertinterfaceguidtoluid
func LUIDFromGUID(guid *windows.GUID) (LUID, error) {
	var luid LUID
	err := convertInterfaceGUIDToLUID(guid, &luid)
	if err != nil {
		return 0, err
	}
	return luid, nil
}

// LUIDFromIndex function converts a local index for a network interface to the locally unique identifier (LUID) for the interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-convertinterfaceindextoluid
func LUIDFromIndex(index uint32) (LUID, error) {
	var luid LUID
	err := convertInterfaceIndexToLUID(index, &luid)
	if err != nil {
		return 0, err
	}
	return luid, nil
}

// IPAddress method returns MibUnicastIPAddressRow struct that matches to provided 'ip' argument. Corresponds to GetUnicastIpAddressEntry
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getunicastipaddressentry)
func (luid LUID) IPAddress(ip net.IP) (*MibUnicastIPAddressRow, error) {
	row := &MibUnicastIPAddressRow{InterfaceLUID: luid}

	err := row.Address.SetIP(ip, 0)
	if err != nil {
		return nil, err
	}

	err = row.get()
	if err != nil {
		return nil, err
	}

	return row, nil
}

// AddIPAddress method adds new unicast IP address to the interface. Corresponds to CreateUnicastIpAddressEntry function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry).
func (luid LUID) AddIPAddress(address net.IPNet) error {
	row := &MibUnicastIPAddressRow{}
	row.Init()
	row.InterfaceLUID = luid
	row.DadState = DadStatePreferred
	row.ValidLifetime = 0xffffffff
	row.PreferredLifetime = 0xffffffff
	err := row.Address.SetIP(address.IP, 0)
	if err != nil {
		return err
	}
	ones, _ := address.Mask.Size()
	row.OnLinkPrefixLength = uint8(ones)
	return row.Create()
}

// AddIPAddresses method adds multiple new unicast IP addresses to the interface. Corresponds to CreateUnicastIpAddressEntry function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry).
func (luid LUID) AddIPAddresses(addresses []net.IPNet) error {
	for i := range addresses {
		err := luid.AddIPAddress(addresses[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// SetIPAddresses method sets new unicast IP addresses to the interface.
func (luid LUID) SetIPAddresses(addresses []net.IPNet) error {
	err := luid.FlushIPAddresses(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
	return luid.AddIPAddresses(addresses)
}

// SetIPAddressesForFamily method sets new unicast IP addresses for a specific family to the interface.
func (luid LUID) SetIPAddressesForFamily(family AddressFamily, addresses []net.IPNet) error {
	err := luid.FlushIPAddresses(family)
	if err != nil {
		return err
	}
	for i := range addresses {
		asV4 := addresses[i].IP.To4()
		if asV4 == nil && family == windows.AF_INET {
			continue
		} else if asV4 != nil && family == windows.AF_INET6 {
			continue
		}
		err := luid.AddIPAddress(addresses[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteIPAddress method deletes interface's unicast IP address. Corresponds to DeleteUnicastIpAddressEntry function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteunicastipaddressentry).
func (luid LUID) DeleteIPAddress(address net.IPNet) error {
	row := &MibUnicastIPAddressRow{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.Address.SetIP(address.IP, 0)
	if err != nil {
		return err
	}
	// Note: OnLinkPrefixLength member is ignored by DeleteUnicastIpAddressEntry().
	ones, _ := address.Mask.Size()
	row.OnLinkPrefixLength = uint8(ones)
	return row.Delete()
}

// FlushIPAddresses method deletes all interface's unicast IP addresses.
func (luid LUID) FlushIPAddresses(family AddressFamily) error {
	var tab *mibUnicastIPAddressTable
	err := getUnicastIPAddressTable(family, &tab)
	if err != nil {
		return err
	}
	t := tab.get()
	for i := range t {
		if t[i].InterfaceLUID == luid {
			t[i].Delete()
		}
	}
	tab.free()
	return nil
}

// Route method returns route determined with the input arguments. Corresponds to GetIpForwardEntry2 function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipforwardentry2).
// NOTE: If the corresponding route isn't found, the method will return error.
func (luid LUID) Route(destination net.IPNet, nextHop net.IP) (*MibIPforwardRow2, error) {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	row.ValidLifetime = 0xffffffff
	row.PreferredLifetime = 0xffffffff
	err := row.DestinationPrefix.SetIPNet(destination)
	if err != nil {
		return nil, err
	}
	err = row.NextHop.SetIP(nextHop, 0)
	if err != nil {
		return nil, err
	}

	err = row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

// AddRoute method adds a route to the interface. Corresponds to CreateIpForwardEntry2 function, with added splitDefault feature.
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createipforwardentry2)
func (luid LUID) AddRoute(destination net.IPNet, nextHop net.IP, metric uint32) error {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.DestinationPrefix.SetIPNet(destination)
	if err != nil {
		return err
	}
	err = row.NextHop.SetIP(nextHop, 0)
	if err != nil {
		return err
	}
	row.Metric = metric
	return row.Create()
}

// AddRoutes method adds multiple routes to the interface.
func (luid LUID) AddRoutes(routesData []*RouteData) error {
	for _, rd := range routesData {
		err := luid.AddRoute(rd.Destination, rd.NextHop, rd.Metric)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetRoutes method sets (flush than add) multiple routes to the interface.
func (luid LUID) SetRoutes(routesData []*RouteData) error {
	err := luid.FlushRoutes(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
	return luid.AddRoutes(routesData)
}

// SetRoutesForFamily method sets (flush than add) multiple routes for a specific family to the interface.
func (luid LUID) SetRoutesForFamily(family AddressFamily, routesData []*RouteData) error {
	err := luid.FlushRoutes(family)
	if err != nil {
		return err
	}
	for _, rd := range routesData {
		asV4 := rd.Destination.IP.To4()
		if asV4 == nil && family == windows.AF_INET {
			continue
		} else if asV4 != nil && family == windows.AF_INET6 {
			continue
		}
		err := luid.AddRoute(rd.Destination, rd.NextHop, rd.Metric)
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteRoute method deletes a route that matches the criteria. Corresponds to DeleteIpForwardEntry2 function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteipforwardentry2).
func (luid LUID) DeleteRoute(destination net.IPNet, nextHop net.IP) error {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.DestinationPrefix.SetIPNet(destination)
	if err != nil {
		return err
	}
	err = row.NextHop.SetIP(nextHop, 0)
	if err != nil {
		return err
	}
	err = row.get()
	if err != nil {
		return err
	}
	return row.Delete()
}

// FlushRoutes method deletes all interface's routes.
// It continues on failures, and returns the last error afterwards.
func (luid LUID) FlushRoutes(family AddressFamily) error {
	var tab *mibIPforwardTable2
	err := getIPForwardTable2(family, &tab)
	if err != nil {
		return err
	}
	t := tab.get()
	for i := range t {
		if t[i].InterfaceLUID == luid {
			err2 := t[i].Delete()
			if err2 != nil {
				err = err2
			}
		}
	}
	tab.free()
	return err
}

// DNS method returns all DNS server addresses associated with the adapter.
func (luid LUID) DNS() ([]net.IP, error) {
	addresses, err := GetAdaptersAddresses(windows.AF_UNSPEC, GAAFlagDefault)
	if err != nil {
		return nil, err
	}
	r := make([]net.IP, 0, len(addresses))
	for _, addr := range addresses {
		if addr.LUID == luid {
			for dns := addr.FirstDNSServerAddress; dns != nil; dns = dns.Next {
				if ip := dns.Address.IP(); ip != nil {
					r = append(r, ip)
				} else {
					return nil, windows.ERROR_INVALID_PARAMETER
				}
			}
		}
	}
	return r, nil
}

// SetDNS method clears previous and associates new DNS servers and search domains with the adapter for a specific family.
func (luid LUID) SetDNS(family AddressFamily, servers []net.IP, domains []string) error {
	if family != windows.AF_INET && family != windows.AF_INET6 {
		return windows.ERROR_PROTOCOL_UNREACHABLE
	}

	var filteredServers []string
	for _, server := range servers {
		if v4 := server.To4(); v4 != nil && family == windows.AF_INET {
			filteredServers = append(filteredServers, v4.String())
		} else if v6 := server.To16(); v4 == nil && v6 != nil && family == windows.AF_INET6 {
			filteredServers = append(filteredServers, v6.String())
		}
	}
	servers16, err := windows.UTF16PtrFromString(strings.Join(filteredServers, ","))
	if err != nil {
		return err
	}
	domains16, err := windows.UTF16PtrFromString(strings.Join(domains, ","))
	if err != nil {
		return err
	}
	guid, err := luid.GUID()
	if err != nil {
		return err
	}
	dnsInterfaceSettings := &DnsInterfaceSettings{
		Version:    DnsInterfaceSettingsVersion1,
		Flags:      DnsInterfaceSettingsFlagNameserver | DnsInterfaceSettingsFlagSearchList,
		NameServer: servers16,
		SearchList: domains16,
	}
	if family == windows.AF_INET6 {
		dnsInterfaceSettings.Flags |= DnsInterfaceSettingsFlagIPv6
	}
	// For >= Windows 10 1809
	err = SetInterfaceDnsSettings(*guid, dnsInterfaceSettings)
	if err == nil || !errors.Is(err, windows.ERROR_PROC_NOT_FOUND) {
		return err
	}

	// For < Windows 10 1809
	err = luid.fallbackSetDNSForFamily(family, servers)
	if err != nil {
		return err
	}
	if len(domains) > 0 {
		return luid.fallbackSetDNSDomain(domains[0])
	} else {
		return luid.fallbackSetDNSDomain("")
	}
}

// FlushDNS method clears all DNS servers associated with the adapter.
func (luid LUID) FlushDNS(family AddressFamily) error {
	return luid.SetDNS(family, nil, nil)
}
