//go:build 386 || arm
// +build 386 arm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"golang.org/x/sys/windows"
)

// IPAdapterWINSServerAddress structure stores a single Windows Internet Name Service (WINS) server address in a linked list of WINS server addresses for a particular adapter.
// https://docs.microsoft.com/en-us/windows/desktop/api/iptypes/ns-iptypes-_ip_adapter_wins_server_address_lh
type IPAdapterWINSServerAddress struct {
	Length  uint32
	_       uint32
	Next    *IPAdapterWINSServerAddress
	Address windows.SocketAddress
	_       [4]byte
}

// IPAdapterGatewayAddress structure stores a single gateway address in a linked list of gateway addresses for a particular adapter.
// https://docs.microsoft.com/en-us/windows/desktop/api/iptypes/ns-iptypes-_ip_adapter_gateway_address_lh
type IPAdapterGatewayAddress struct {
	Length  uint32
	_       uint32
	Next    *IPAdapterGatewayAddress
	Address windows.SocketAddress
	_       [4]byte
}

// IPAdapterAddresses structure is the header node for a linked list of addresses for a particular adapter. This structure can simultaneously be used as part of a linked list of IP_ADAPTER_ADDRESSES structures.
// https://docs.microsoft.com/en-us/windows/desktop/api/iptypes/ns-iptypes-_ip_adapter_addresses_lh
// This is a modified and extended version of windows.IpAdapterAddresses.
type IPAdapterAddresses struct {
	Length                 uint32
	IfIndex                uint32
	Next                   *IPAdapterAddresses
	adapterName            *byte
	FirstUnicastAddress    *windows.IpAdapterUnicastAddress
	FirstAnycastAddress    *windows.IpAdapterAnycastAddress
	FirstMulticastAddress  *windows.IpAdapterMulticastAddress
	FirstDNSServerAddress  *windows.IpAdapterDnsServerAdapter
	dnsSuffix              *uint16
	description            *uint16
	friendlyName           *uint16
	physicalAddress        [windows.MAX_ADAPTER_ADDRESS_LENGTH]byte
	physicalAddressLength  uint32
	Flags                  IPAAFlags
	MTU                    uint32
	IfType                 IfType
	OperStatus             IfOperStatus
	IPv6IfIndex            uint32
	ZoneIndices            [16]uint32
	FirstPrefix            *windows.IpAdapterPrefix
	TransmitLinkSpeed      uint64
	ReceiveLinkSpeed       uint64
	FirstWINSServerAddress *IPAdapterWINSServerAddress
	FirstGatewayAddress    *IPAdapterGatewayAddress
	Ipv4Metric             uint32
	Ipv6Metric             uint32
	LUID                   LUID
	DHCPv4Server           windows.SocketAddress
	CompartmentID          uint32
	NetworkGUID            windows.GUID
	ConnectionType         NetIfConnectionType
	TunnelType             TunnelType
	DHCPv6Server           windows.SocketAddress
	dhcpv6ClientDUID       [maxDHCPv6DUIDLength]byte
	dhcpv6ClientDUIDLength uint32
	DHCPv6IAID             uint32
	FirstDNSSuffix         *IPAdapterDNSSuffix
	_                      [4]byte
}

// MibIPInterfaceRow structure stores interface management information for a particular IP address family on a network interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipinterface_row
type MibIPInterfaceRow struct {
	Family                               AddressFamily
	_                                    [4]byte
	InterfaceLUID                        LUID
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   bool
	ForwardingEnabled                    bool
	WeakHostSend                         bool
	WeakHostReceive                      bool
	UseAutomaticMetric                   bool
	UseNeighborUnreachabilityDetection   bool
	ManagedAddressConfigurationSupported bool
	OtherStatefulConfigurationSupported  bool
	AdvertiseDefaultRoute                bool
	RouterDiscoveryBehavior              RouterDiscoveryBehavior
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMTUDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             LinkLocalAddressBehavior
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [ScopeLevelCount]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NLMTU                                uint32
	Connected                            bool
	SupportsWakeUpPatterns               bool
	SupportsNeighborDiscovery            bool
	SupportsRouterDiscovery              bool
	ReachableTime                        uint32
	TransmitOffload                      OffloadRod
	ReceiveOffload                       OffloadRod
	DisableDefaultRoutes                 bool
}

// mibIPInterfaceTable structure contains a table of IP interface entries.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipinterface_table
type mibIPInterfaceTable struct {
	numEntries uint32
	_          [4]byte
	table      [anySize]MibIPInterfaceRow
}

// MibIfRow2 structure stores information about a particular interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_if_row2
type MibIfRow2 struct {
	InterfaceLUID               LUID
	InterfaceIndex              uint32
	InterfaceGUID               windows.GUID
	alias                       [ifMaxStringSize + 1]uint16
	description                 [ifMaxStringSize + 1]uint16
	physicalAddressLength       uint32
	physicalAddress             [ifMaxPhysAddressLength]byte
	permanentPhysicalAddress    [ifMaxPhysAddressLength]byte
	MTU                         uint32
	Type                        IfType
	TunnelType                  TunnelType
	MediaType                   NdisMedium
	PhysicalMediumType          NdisPhysicalMedium
	AccessType                  NetIfAccessType
	DirectionType               NetIfDirectionType
	InterfaceAndOperStatusFlags InterfaceAndOperStatusFlags
	OperStatus                  IfOperStatus
	AdminStatus                 NetIfAdminStatus
	MediaConnectState           NetIfMediaConnectState
	NetworkGUID                 windows.GUID
	ConnectionType              NetIfConnectionType
	_                           [4]byte
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

// mibIfTable2 structure contains a table of logical and physical interface entries.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_if_table2
type mibIfTable2 struct {
	numEntries uint32
	_          [4]byte
	table      [anySize]MibIfRow2
}

// MibUnicastIPAddressRow structure stores information about a unicast IP address.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_unicastipaddress_row
type MibUnicastIPAddressRow struct {
	Address            RawSockaddrInet
	_                  [4]byte
	InterfaceLUID      LUID
	InterfaceIndex     uint32
	PrefixOrigin       PrefixOrigin
	SuffixOrigin       SuffixOrigin
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       bool
	DadState           DadState
	ScopeID            uint32
	CreationTimeStamp  int64
}

// mibUnicastIPAddressTable structure contains a table of unicast IP address entries.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_unicastipaddress_table
type mibUnicastIPAddressTable struct {
	numEntries uint32
	_          [4]byte
	table      [anySize]MibUnicastIPAddressRow
}

// MibAnycastIPAddressRow structure stores information about an anycast IP address.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_anycastipaddress_row
type MibAnycastIPAddressRow struct {
	Address        RawSockaddrInet
	_              [4]byte
	InterfaceLUID  LUID
	InterfaceIndex uint32
	ScopeID        uint32
}

// mibAnycastIPAddressTable structure contains a table of anycast IP address entries.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-mib_anycastipaddress_table
type mibAnycastIPAddressTable struct {
	numEntries uint32
	_          [4]byte
	table      [anySize]MibAnycastIPAddressRow
}

// mibIPforwardTable2 structure contains a table of IP route entries.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipforward_table2
type mibIPforwardTable2 struct {
	numEntries uint32
	_          [4]byte
	table      [anySize]MibIPforwardRow2
}
