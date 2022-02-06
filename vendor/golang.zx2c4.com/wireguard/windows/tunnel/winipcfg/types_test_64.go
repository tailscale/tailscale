//go:build amd64 || arm64
// +build amd64 arm64

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

const (
	ipAdapterWINSServerAddressSize          = 32
	ipAdapterWINSServerAddressNextOffset    = 8
	ipAdapterWINSServerAddressAddressOffset = 16

	ipAdapterGatewayAddressSize          = 32
	ipAdapterGatewayAddressNextOffset    = 8
	ipAdapterGatewayAddressAddressOffset = 16

	ipAdapterDNSSuffixSize         = 520
	ipAdapterDNSSuffixStringOffset = 8

	ipAdapterAddressesSize                         = 448
	ipAdapterAddressesIfIndexOffset                = 4
	ipAdapterAddressesNextOffset                   = 8
	ipAdapterAddressesAdapterNameOffset            = 16
	ipAdapterAddressesFirstUnicastAddressOffset    = 24
	ipAdapterAddressesFirstAnycastAddressOffset    = 32
	ipAdapterAddressesFirstMulticastAddressOffset  = 40
	ipAdapterAddressesFirstDNSServerAddressOffset  = 48
	ipAdapterAddressesDNSSuffixOffset              = 56
	ipAdapterAddressesDescriptionOffset            = 64
	ipAdapterAddressesFriendlyNameOffset           = 72
	ipAdapterAddressesPhysicalAddressOffset        = 80
	ipAdapterAddressesPhysicalAddressLengthOffset  = 88
	ipAdapterAddressesFlagsOffset                  = 92
	ipAdapterAddressesMTUOffset                    = 96
	ipAdapterAddressesIfTypeOffset                 = 100
	ipAdapterAddressesOperStatusOffset             = 104
	ipAdapterAddressesIPv6IfIndexOffset            = 108
	ipAdapterAddressesZoneIndicesOffset            = 112
	ipAdapterAddressesFirstPrefixOffset            = 176
	ipAdapterAddressesTransmitLinkSpeedOffset      = 184
	ipAdapterAddressesReceiveLinkSpeedOffset       = 192
	ipAdapterAddressesFirstWINSServerAddressOffset = 200
	ipAdapterAddressesFirstGatewayAddressOffset    = 208
	ipAdapterAddressesIPv4MetricOffset             = 216
	ipAdapterAddressesIPv6MetricOffset             = 220
	ipAdapterAddressesLUIDOffset                   = 224
	ipAdapterAddressesDHCPv4ServerOffset           = 232
	ipAdapterAddressesCompartmentIDOffset          = 248
	ipAdapterAddressesNetworkGUIDOffset            = 252
	ipAdapterAddressesConnectionTypeOffset         = 268
	ipAdapterAddressesTunnelTypeOffset             = 272
	ipAdapterAddressesDHCPv6ServerOffset           = 280
	ipAdapterAddressesDHCPv6ClientDUIDOffset       = 296
	ipAdapterAddressesDHCPv6ClientDUIDLengthOffset = 428
	ipAdapterAddressesDHCPv6IAIDOffset             = 432
	ipAdapterAddressesFirstDNSSuffixOffset         = 440
)
