//go:build 386 || arm
// +build 386 arm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

const (
	ipAdapterWINSServerAddressSize          = 24
	ipAdapterWINSServerAddressNextOffset    = 8
	ipAdapterWINSServerAddressAddressOffset = 12

	ipAdapterGatewayAddressSize          = 24
	ipAdapterGatewayAddressNextOffset    = 8
	ipAdapterGatewayAddressAddressOffset = 12

	ipAdapterDNSSuffixSize         = 516
	ipAdapterDNSSuffixStringOffset = 4

	ipAdapterAddressesSize                         = 376
	ipAdapterAddressesIfIndexOffset                = 4
	ipAdapterAddressesNextOffset                   = 8
	ipAdapterAddressesAdapterNameOffset            = 12
	ipAdapterAddressesFirstUnicastAddressOffset    = 16
	ipAdapterAddressesFirstAnycastAddressOffset    = 20
	ipAdapterAddressesFirstMulticastAddressOffset  = 24
	ipAdapterAddressesFirstDNSServerAddressOffset  = 28
	ipAdapterAddressesDNSSuffixOffset              = 32
	ipAdapterAddressesDescriptionOffset            = 36
	ipAdapterAddressesFriendlyNameOffset           = 40
	ipAdapterAddressesPhysicalAddressOffset        = 44
	ipAdapterAddressesPhysicalAddressLengthOffset  = 52
	ipAdapterAddressesFlagsOffset                  = 56
	ipAdapterAddressesMTUOffset                    = 60
	ipAdapterAddressesIfTypeOffset                 = 64
	ipAdapterAddressesOperStatusOffset             = 68
	ipAdapterAddressesIPv6IfIndexOffset            = 72
	ipAdapterAddressesZoneIndicesOffset            = 76
	ipAdapterAddressesFirstPrefixOffset            = 140
	ipAdapterAddressesTransmitLinkSpeedOffset      = 144
	ipAdapterAddressesReceiveLinkSpeedOffset       = 152
	ipAdapterAddressesFirstWINSServerAddressOffset = 160
	ipAdapterAddressesFirstGatewayAddressOffset    = 164
	ipAdapterAddressesIPv4MetricOffset             = 168
	ipAdapterAddressesIPv6MetricOffset             = 172
	ipAdapterAddressesLUIDOffset                   = 176
	ipAdapterAddressesDHCPv4ServerOffset           = 184
	ipAdapterAddressesCompartmentIDOffset          = 192
	ipAdapterAddressesNetworkGUIDOffset            = 196
	ipAdapterAddressesConnectionTypeOffset         = 212
	ipAdapterAddressesTunnelTypeOffset             = 216
	ipAdapterAddressesDHCPv6ServerOffset           = 220
	ipAdapterAddressesDHCPv6ClientDUIDOffset       = 228
	ipAdapterAddressesDHCPv6ClientDUIDLengthOffset = 360
	ipAdapterAddressesDHCPv6IAIDOffset             = 364
	ipAdapterAddressesFirstDNSSuffixOffset         = 368
)
