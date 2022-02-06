package dhcpv4

import (
	"fmt"

	"github.com/u-root/uio/uio"
)

// values from http://www.networksorcery.com/enp/protocol/dhcp.htm and
// http://www.networksorcery.com/enp/protocol/bootp/options.htm

// TransactionID represents a 4-byte DHCP transaction ID as defined in RFC 951,
// Section 3.
//
// The TransactionID is used to match DHCP replies to their original request.
type TransactionID [4]byte

// String prints a hex transaction ID.
func (xid TransactionID) String() string {
	return fmt.Sprintf("0x%x", xid[:])
}

// MessageType represents the possible DHCP message types - DISCOVER, OFFER, etc
type MessageType byte

// DHCP message types
const (
	// MessageTypeNone is not a real message type, it is used by certain
	// functions to signal that no explicit message type is requested
	MessageTypeNone     MessageType = 0
	MessageTypeDiscover MessageType = 1
	MessageTypeOffer    MessageType = 2
	MessageTypeRequest  MessageType = 3
	MessageTypeDecline  MessageType = 4
	MessageTypeAck      MessageType = 5
	MessageTypeNak      MessageType = 6
	MessageTypeRelease  MessageType = 7
	MessageTypeInform   MessageType = 8
)

// ToBytes returns the serialized version of this option described by RFC 2132,
// Section 9.6.
func (m MessageType) ToBytes() []byte {
	return []byte{byte(m)}
}

// String prints a human-readable message type name.
func (m MessageType) String() string {
	if s, ok := messageTypeToString[m]; ok {
		return s
	}
	return fmt.Sprintf("unknown (%d)", byte(m))
}

// FromBytes reads a message type from data as described by RFC 2132, Section
// 9.6.
func (m *MessageType) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	*m = MessageType(buf.Read8())
	return buf.FinError()
}

var messageTypeToString = map[MessageType]string{
	MessageTypeDiscover: "DISCOVER",
	MessageTypeOffer:    "OFFER",
	MessageTypeRequest:  "REQUEST",
	MessageTypeDecline:  "DECLINE",
	MessageTypeAck:      "ACK",
	MessageTypeNak:      "NAK",
	MessageTypeRelease:  "RELEASE",
	MessageTypeInform:   "INFORM",
}

// OpcodeType represents a DHCPv4 opcode.
type OpcodeType uint8

// constants that represent valid values for OpcodeType
const (
	OpcodeBootRequest OpcodeType = 1
	OpcodeBootReply   OpcodeType = 2
)

func (o OpcodeType) String() string {
	if s, ok := opcodeToString[o]; ok {
		return s
	}
	return fmt.Sprintf("unknown (%d)", uint8(o))
}

var opcodeToString = map[OpcodeType]string{
	OpcodeBootRequest: "BootRequest",
	OpcodeBootReply:   "BootReply",
}

// OptionCode is a single byte representing the code for a given Option.
//
// OptionCode is an interface purely to support different stringers on options
// with the same Code value, as vendor-specific options use option codes that
// have the same value, but mean a different thing.
type OptionCode interface {
	// Code is the 1 byte option code for the wire.
	Code() uint8

	// String returns the option's name.
	String() string
}

// optionCode is a DHCP option code.
type optionCode uint8

// Code implements OptionCode.Code.
func (o optionCode) Code() uint8 {
	return uint8(o)
}

// String returns an option name.
func (o optionCode) String() string {
	if s, ok := optionCodeToString[o]; ok {
		return s
	}
	return fmt.Sprintf("unknown (%d)", uint8(o))
}

// GenericOptionCode is an unnamed option code.
type GenericOptionCode uint8

// Code implements OptionCode.Code.
func (o GenericOptionCode) Code() uint8 {
	return uint8(o)
}

// String returns the option's name.
func (o GenericOptionCode) String() string {
	return fmt.Sprintf("unknown (%d)", uint8(o))
}

// DHCPv4 Options
const (
	OptionPad                                        optionCode = 0
	OptionSubnetMask                                 optionCode = 1
	OptionTimeOffset                                 optionCode = 2
	OptionRouter                                     optionCode = 3
	OptionTimeServer                                 optionCode = 4
	OptionNameServer                                 optionCode = 5
	OptionDomainNameServer                           optionCode = 6
	OptionLogServer                                  optionCode = 7
	OptionQuoteServer                                optionCode = 8
	OptionLPRServer                                  optionCode = 9
	OptionImpressServer                              optionCode = 10
	OptionResourceLocationServer                     optionCode = 11
	OptionHostName                                   optionCode = 12
	OptionBootFileSize                               optionCode = 13
	OptionMeritDumpFile                              optionCode = 14
	OptionDomainName                                 optionCode = 15
	OptionSwapServer                                 optionCode = 16
	OptionRootPath                                   optionCode = 17
	OptionExtensionsPath                             optionCode = 18
	OptionIPForwarding                               optionCode = 19
	OptionNonLocalSourceRouting                      optionCode = 20
	OptionPolicyFilter                               optionCode = 21
	OptionMaximumDatagramAssemblySize                optionCode = 22
	OptionDefaultIPTTL                               optionCode = 23
	OptionPathMTUAgingTimeout                        optionCode = 24
	OptionPathMTUPlateauTable                        optionCode = 25
	OptionInterfaceMTU                               optionCode = 26
	OptionAllSubnetsAreLocal                         optionCode = 27
	OptionBroadcastAddress                           optionCode = 28
	OptionPerformMaskDiscovery                       optionCode = 29
	OptionMaskSupplier                               optionCode = 30
	OptionPerformRouterDiscovery                     optionCode = 31
	OptionRouterSolicitationAddress                  optionCode = 32
	OptionStaticRoutingTable                         optionCode = 33
	OptionTrailerEncapsulation                       optionCode = 34
	OptionArpCacheTimeout                            optionCode = 35
	OptionEthernetEncapsulation                      optionCode = 36
	OptionDefaulTCPTTL                               optionCode = 37
	OptionTCPKeepaliveInterval                       optionCode = 38
	OptionTCPKeepaliveGarbage                        optionCode = 39
	OptionNetworkInformationServiceDomain            optionCode = 40
	OptionNetworkInformationServers                  optionCode = 41
	OptionNTPServers                                 optionCode = 42
	OptionVendorSpecificInformation                  optionCode = 43
	OptionNetBIOSOverTCPIPNameServer                 optionCode = 44
	OptionNetBIOSOverTCPIPDatagramDistributionServer optionCode = 45
	OptionNetBIOSOverTCPIPNodeType                   optionCode = 46
	OptionNetBIOSOverTCPIPScope                      optionCode = 47
	OptionXWindowSystemFontServer                    optionCode = 48
	OptionXWindowSystemDisplayManger                 optionCode = 49
	OptionRequestedIPAddress                         optionCode = 50
	OptionIPAddressLeaseTime                         optionCode = 51
	OptionOptionOverload                             optionCode = 52
	OptionDHCPMessageType                            optionCode = 53
	OptionServerIdentifier                           optionCode = 54
	OptionParameterRequestList                       optionCode = 55
	OptionMessage                                    optionCode = 56
	OptionMaximumDHCPMessageSize                     optionCode = 57
	OptionRenewTimeValue                             optionCode = 58
	OptionRebindingTimeValue                         optionCode = 59
	OptionClassIdentifier                            optionCode = 60
	OptionClientIdentifier                           optionCode = 61
	OptionNetWareIPDomainName                        optionCode = 62
	OptionNetWareIPInformation                       optionCode = 63
	OptionNetworkInformationServicePlusDomain        optionCode = 64
	OptionNetworkInformationServicePlusServers       optionCode = 65
	OptionTFTPServerName                             optionCode = 66
	OptionBootfileName                               optionCode = 67
	OptionMobileIPHomeAgent                          optionCode = 68
	OptionSimpleMailTransportProtocolServer          optionCode = 69
	OptionPostOfficeProtocolServer                   optionCode = 70
	OptionNetworkNewsTransportProtocolServer         optionCode = 71
	OptionDefaultWorldWideWebServer                  optionCode = 72
	OptionDefaultFingerServer                        optionCode = 73
	OptionDefaultInternetRelayChatServer             optionCode = 74
	OptionStreetTalkServer                           optionCode = 75
	OptionStreetTalkDirectoryAssistanceServer        optionCode = 76
	OptionUserClassInformation                       optionCode = 77
	OptionSLPDirectoryAgent                          optionCode = 78
	OptionSLPServiceScope                            optionCode = 79
	OptionRapidCommit                                optionCode = 80
	OptionFQDN                                       optionCode = 81
	OptionRelayAgentInformation                      optionCode = 82
	OptionInternetStorageNameService                 optionCode = 83
	// Option 84 returned in RFC 3679
	OptionNDSServers                       optionCode = 85
	OptionNDSTreeName                      optionCode = 86
	OptionNDSContext                       optionCode = 87
	OptionBCMCSControllerDomainNameList    optionCode = 88
	OptionBCMCSControllerIPv4AddressList   optionCode = 89
	OptionAuthentication                   optionCode = 90
	OptionClientLastTransactionTime        optionCode = 91
	OptionAssociatedIP                     optionCode = 92
	OptionClientSystemArchitectureType     optionCode = 93
	OptionClientNetworkInterfaceIdentifier optionCode = 94
	OptionLDAP                             optionCode = 95
	// Option 96 returned in RFC 3679
	OptionClientMachineIdentifier     optionCode = 97
	OptionOpenGroupUserAuthentication optionCode = 98
	OptionGeoConfCivic                optionCode = 99
	OptionIEEE10031TZString           optionCode = 100
	OptionReferenceToTZDatabase       optionCode = 101
	// Options 102-111 returned in RFC 3679
	OptionNetInfoParentServerAddress optionCode = 112
	OptionNetInfoParentServerTag     optionCode = 113
	OptionURL                        optionCode = 114
	// Option 115 returned in RFC 3679
	OptionAutoConfigure                   optionCode = 116
	OptionNameServiceSearch               optionCode = 117
	OptionSubnetSelection                 optionCode = 118
	OptionDNSDomainSearchList             optionCode = 119
	OptionSIPServers                      optionCode = 120
	OptionClasslessStaticRoute            optionCode = 121
	OptionCCC                             optionCode = 122
	OptionGeoConf                         optionCode = 123
	OptionVendorIdentifyingVendorClass    optionCode = 124
	OptionVendorIdentifyingVendorSpecific optionCode = 125
	// Options 126-127 returned in RFC 3679
	OptionTFTPServerIPAddress                   optionCode = 128
	OptionCallServerIPAddress                   optionCode = 129
	OptionDiscriminationString                  optionCode = 130
	OptionRemoteStatisticsServerIPAddress       optionCode = 131
	Option8021PVLANID                           optionCode = 132
	Option8021QL2Priority                       optionCode = 133
	OptionDiffservCodePoint                     optionCode = 134
	OptionHTTPProxyForPhoneSpecificApplications optionCode = 135
	OptionPANAAuthenticationAgent               optionCode = 136
	OptionLoSTServer                            optionCode = 137
	OptionCAPWAPAccessControllerAddresses       optionCode = 138
	OptionOPTIONIPv4AddressMoS                  optionCode = 139
	OptionOPTIONIPv4FQDNMoS                     optionCode = 140
	OptionSIPUAConfigurationServiceDomains      optionCode = 141
	OptionOPTIONIPv4AddressANDSF                optionCode = 142
	OptionOPTIONIPv6AddressANDSF                optionCode = 143
	// Options 144-149 returned in RFC 3679
	OptionTFTPServerAddress optionCode = 150
	OptionStatusCode        optionCode = 151
	OptionBaseTime          optionCode = 152
	OptionStartTimeOfState  optionCode = 153
	OptionQueryStartTime    optionCode = 154
	OptionQueryEndTime      optionCode = 155
	OptionDHCPState         optionCode = 156
	OptionDataSource        optionCode = 157
	// Options 158-174 returned in RFC 3679
	OptionEtherboot                        optionCode = 175
	OptionIPTelephone                      optionCode = 176
	OptionEtherbootPacketCableAndCableHome optionCode = 177
	// Options 178-207 returned in RFC 3679
	OptionPXELinuxMagicString  optionCode = 208
	OptionPXELinuxConfigFile   optionCode = 209
	OptionPXELinuxPathPrefix   optionCode = 210
	OptionPXELinuxRebootTime   optionCode = 211
	OptionOPTION6RD            optionCode = 212
	OptionOPTIONv4AccessDomain optionCode = 213
	// Options 214-219 returned in RFC 3679
	OptionSubnetAllocation        optionCode = 220
	OptionVirtualSubnetAllocation optionCode = 221
	// Options 222-223 returned in RFC 3679
	// Options 224-254 are reserved for private use
	OptionEnd optionCode = 255
)

var optionCodeToString = map[OptionCode]string{
	OptionPad:                                        "Pad",
	OptionSubnetMask:                                 "Subnet Mask",
	OptionTimeOffset:                                 "Time Offset",
	OptionRouter:                                     "Router",
	OptionTimeServer:                                 "Time Server",
	OptionNameServer:                                 "Name Server",
	OptionDomainNameServer:                           "Domain Name Server",
	OptionLogServer:                                  "Log Server",
	OptionQuoteServer:                                "Quote Server",
	OptionLPRServer:                                  "LPR Server",
	OptionImpressServer:                              "Impress Server",
	OptionResourceLocationServer:                     "Resource Location Server",
	OptionHostName:                                   "Host Name",
	OptionBootFileSize:                               "Boot File Size",
	OptionMeritDumpFile:                              "Merit Dump File",
	OptionDomainName:                                 "Domain Name",
	OptionSwapServer:                                 "Swap Server",
	OptionRootPath:                                   "Root Path",
	OptionExtensionsPath:                             "Extensions Path",
	OptionIPForwarding:                               "IP Forwarding enable/disable",
	OptionNonLocalSourceRouting:                      "Non-local Source Routing enable/disable",
	OptionPolicyFilter:                               "Policy Filter",
	OptionMaximumDatagramAssemblySize:                "Maximum Datagram Reassembly Size",
	OptionDefaultIPTTL:                               "Default IP Time-to-live",
	OptionPathMTUAgingTimeout:                        "Path MTU Aging Timeout",
	OptionPathMTUPlateauTable:                        "Path MTU Plateau Table",
	OptionInterfaceMTU:                               "Interface MTU",
	OptionAllSubnetsAreLocal:                         "All Subnets Are Local",
	OptionBroadcastAddress:                           "Broadcast Address",
	OptionPerformMaskDiscovery:                       "Perform Mask Discovery",
	OptionMaskSupplier:                               "Mask Supplier",
	OptionPerformRouterDiscovery:                     "Perform Router Discovery",
	OptionRouterSolicitationAddress:                  "Router Solicitation Address",
	OptionStaticRoutingTable:                         "Static Routing Table",
	OptionTrailerEncapsulation:                       "Trailer Encapsulation",
	OptionArpCacheTimeout:                            "ARP Cache Timeout",
	OptionEthernetEncapsulation:                      "Ethernet Encapsulation",
	OptionDefaulTCPTTL:                               "Default TCP TTL",
	OptionTCPKeepaliveInterval:                       "TCP Keepalive Interval",
	OptionTCPKeepaliveGarbage:                        "TCP Keepalive Garbage",
	OptionNetworkInformationServiceDomain:            "Network Information Service Domain",
	OptionNetworkInformationServers:                  "Network Information Servers",
	OptionNTPServers:                                 "NTP Servers",
	OptionVendorSpecificInformation:                  "Vendor Specific Information",
	OptionNetBIOSOverTCPIPNameServer:                 "NetBIOS over TCP/IP Name Server",
	OptionNetBIOSOverTCPIPDatagramDistributionServer: "NetBIOS over TCP/IP Datagram Distribution Server",
	OptionNetBIOSOverTCPIPNodeType:                   "NetBIOS over TCP/IP Node Type",
	OptionNetBIOSOverTCPIPScope:                      "NetBIOS over TCP/IP Scope",
	OptionXWindowSystemFontServer:                    "X Window System Font Server",
	OptionXWindowSystemDisplayManger:                 "X Window System Display Manager",
	OptionRequestedIPAddress:                         "Requested IP Address",
	OptionIPAddressLeaseTime:                         "IP Addresses Lease Time",
	OptionOptionOverload:                             "Option Overload",
	OptionDHCPMessageType:                            "DHCP Message Type",
	OptionServerIdentifier:                           "Server Identifier",
	OptionParameterRequestList:                       "Parameter Request List",
	OptionMessage:                                    "Message",
	OptionMaximumDHCPMessageSize:                     "Maximum DHCP Message Size",
	OptionRenewTimeValue:                             "Renew Time Value",
	OptionRebindingTimeValue:                         "Rebinding Time Value",
	OptionClassIdentifier:                            "Class Identifier",
	OptionClientIdentifier:                           "Client identifier",
	OptionNetWareIPDomainName:                        "NetWare/IP Domain Name",
	OptionNetWareIPInformation:                       "NetWare/IP Information",
	OptionNetworkInformationServicePlusDomain:        "Network Information Service+ Domain",
	OptionNetworkInformationServicePlusServers:       "Network Information Service+ Servers",
	OptionTFTPServerName:                             "TFTP Server Name",
	OptionBootfileName:                               "Bootfile Name",
	OptionMobileIPHomeAgent:                          "Mobile IP Home Agent",
	OptionSimpleMailTransportProtocolServer:          "SMTP Server",
	OptionPostOfficeProtocolServer:                   "POP Server",
	OptionNetworkNewsTransportProtocolServer:         "NNTP Server",
	OptionDefaultWorldWideWebServer:                  "Default WWW Server",
	OptionDefaultFingerServer:                        "Default Finger Server",
	OptionDefaultInternetRelayChatServer:             "Default IRC Server",
	OptionStreetTalkServer:                           "StreetTalk Server",
	OptionStreetTalkDirectoryAssistanceServer:        "StreetTalk Directory Assistance Server",
	OptionUserClassInformation:                       "User Class Information",
	OptionSLPDirectoryAgent:                          "SLP DIrectory Agent",
	OptionSLPServiceScope:                            "SLP Service Scope",
	OptionRapidCommit:                                "Rapid Commit",
	OptionFQDN:                                       "FQDN",
	OptionRelayAgentInformation:                      "Relay Agent Information",
	OptionInternetStorageNameService:                 "Internet Storage Name Service",
	// Option 84 returned in RFC 3679
	OptionNDSServers:                       "NDS Servers",
	OptionNDSTreeName:                      "NDS Tree Name",
	OptionNDSContext:                       "NDS Context",
	OptionBCMCSControllerDomainNameList:    "BCMCS Controller Domain Name List",
	OptionBCMCSControllerIPv4AddressList:   "BCMCS Controller IPv4 Address List",
	OptionAuthentication:                   "Authentication",
	OptionClientLastTransactionTime:        "Client Last Transaction Time",
	OptionAssociatedIP:                     "Associated IP",
	OptionClientSystemArchitectureType:     "Client System Architecture Type",
	OptionClientNetworkInterfaceIdentifier: "Client Network Interface Identifier",
	OptionLDAP:                             "LDAP",
	// Option 96 returned in RFC 3679
	OptionClientMachineIdentifier:     "Client Machine Identifier",
	OptionOpenGroupUserAuthentication: "OpenGroup's User Authentication",
	OptionGeoConfCivic:                "GEOCONF_CIVIC",
	OptionIEEE10031TZString:           "IEEE 1003.1 TZ String",
	OptionReferenceToTZDatabase:       "Reference to the TZ Database",
	// Options 102-111 returned in RFC 3679
	OptionNetInfoParentServerAddress: "NetInfo Parent Server Address",
	OptionNetInfoParentServerTag:     "NetInfo Parent Server Tag",
	OptionURL:                        "URL",
	// Option 115 returned in RFC 3679
	OptionAutoConfigure:                   "Auto-Configure",
	OptionNameServiceSearch:               "Name Service Search",
	OptionSubnetSelection:                 "Subnet Selection",
	OptionDNSDomainSearchList:             "DNS Domain Search List",
	OptionSIPServers:                      "SIP Servers",
	OptionClasslessStaticRoute:            "Classless Static Route",
	OptionCCC:                             "CCC, CableLabs Client Configuration",
	OptionGeoConf:                         "GeoConf",
	OptionVendorIdentifyingVendorClass:    "Vendor-Identifying Vendor Class",
	OptionVendorIdentifyingVendorSpecific: "Vendor-Identifying Vendor-Specific",
	// Options 126-127 returned in RFC 3679
	OptionTFTPServerIPAddress:                   "TFTP Server IP Address",
	OptionCallServerIPAddress:                   "Call Server IP Address",
	OptionDiscriminationString:                  "Discrimination String",
	OptionRemoteStatisticsServerIPAddress:       "RemoteStatistics Server IP Address",
	Option8021PVLANID:                           "802.1P VLAN ID",
	Option8021QL2Priority:                       "802.1Q L2 Priority",
	OptionDiffservCodePoint:                     "Diffserv Code Point",
	OptionHTTPProxyForPhoneSpecificApplications: "HTTP Proxy for phone-specific applications",
	OptionPANAAuthenticationAgent:               "PANA Authentication Agent",
	OptionLoSTServer:                            "LoST Server",
	OptionCAPWAPAccessControllerAddresses:       "CAPWAP Access Controller Addresses",
	OptionOPTIONIPv4AddressMoS:                  "OPTION-IPv4_Address-MoS",
	OptionOPTIONIPv4FQDNMoS:                     "OPTION-IPv4_FQDN-MoS",
	OptionSIPUAConfigurationServiceDomains:      "SIP UA Configuration Service Domains",
	OptionOPTIONIPv4AddressANDSF:                "OPTION-IPv4_Address-ANDSF",
	OptionOPTIONIPv6AddressANDSF:                "OPTION-IPv6_Address-ANDSF",
	// Options 144-149 returned in RFC 3679
	OptionTFTPServerAddress: "TFTP Server Address",
	OptionStatusCode:        "Status Code",
	OptionBaseTime:          "Base Time",
	OptionStartTimeOfState:  "Start Time of State",
	OptionQueryStartTime:    "Query Start Time",
	OptionQueryEndTime:      "Query End Time",
	OptionDHCPState:         "DHCP Staet",
	OptionDataSource:        "Data Source",
	// Options 158-174 returned in RFC 3679
	OptionEtherboot:                        "Etherboot",
	OptionIPTelephone:                      "IP Telephone",
	OptionEtherbootPacketCableAndCableHome: "Etherboot / PacketCable and CableHome",
	// Options 178-207 returned in RFC 3679
	OptionPXELinuxMagicString:  "PXELinux Magic String",
	OptionPXELinuxConfigFile:   "PXELinux Config File",
	OptionPXELinuxPathPrefix:   "PXELinux Path Prefix",
	OptionPXELinuxRebootTime:   "PXELinux Reboot Time",
	OptionOPTION6RD:            "OPTION_6RD",
	OptionOPTIONv4AccessDomain: "OPTION_V4_ACCESS_DOMAIN",
	// Options 214-219 returned in RFC 3679
	OptionSubnetAllocation:        "Subnet Allocation",
	OptionVirtualSubnetAllocation: "Virtual Subnet Selection",
	// Options 222-223 returned in RFC 3679
	// Options 224-254 are reserved for private use

	OptionEnd: "End",
}
