// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package header

import "gvisor.dev/gvisor/pkg/tcpip"

// NDPNeighborAdvert is an NDP Neighbor Advertisement message. It will
// only contain the body of an ICMPv6 packet.
//
// See RFC 4861 section 4.4 for more details.
type NDPNeighborAdvert []byte

const (
	// NDPNAMinimumSize is the minimum size of a valid NDP Neighbor
	// Advertisement message (body of an ICMPv6 packet).
	NDPNAMinimumSize = 20

	// ndpNATargetAddressOffset is the start of the Target Address
	// field within an NDPNeighborAdvert.
	ndpNATargetAddressOffset = 4

	// ndpNAOptionsOffset is the start of the NDP options in an
	// NDPNeighborAdvert.
	ndpNAOptionsOffset = ndpNATargetAddressOffset + IPv6AddressSize

	// ndpNAFlagsOffset is the offset of the flags within an
	// NDPNeighborAdvert
	ndpNAFlagsOffset = 0

	// ndpNARouterFlagMask is the mask of the Router Flag field in
	// the flags byte within in an NDPNeighborAdvert.
	ndpNARouterFlagMask = (1 << 7)

	// ndpNASolicitedFlagMask is the mask of the Solicited Flag field in
	// the flags byte within in an NDPNeighborAdvert.
	ndpNASolicitedFlagMask = (1 << 6)

	// ndpNAOverrideFlagMask is the mask of the Override Flag field in
	// the flags byte within in an NDPNeighborAdvert.
	ndpNAOverrideFlagMask = (1 << 5)
)

// TargetAddress returns the value within the Target Address field.
func (b NDPNeighborAdvert) TargetAddress() tcpip.Address {
	return tcpip.Address(b[ndpNATargetAddressOffset:][:IPv6AddressSize])
}

// SetTargetAddress sets the value within the Target Address field.
func (b NDPNeighborAdvert) SetTargetAddress(addr tcpip.Address) {
	copy(b[ndpNATargetAddressOffset:][:IPv6AddressSize], addr)
}

// RouterFlag returns the value of the Router Flag field.
func (b NDPNeighborAdvert) RouterFlag() bool {
	return b[ndpNAFlagsOffset]&ndpNARouterFlagMask != 0
}

// SetRouterFlag sets the value in the Router Flag field.
func (b NDPNeighborAdvert) SetRouterFlag(f bool) {
	if f {
		b[ndpNAFlagsOffset] |= ndpNARouterFlagMask
	} else {
		b[ndpNAFlagsOffset] &^= ndpNARouterFlagMask
	}
}

// SolicitedFlag returns the value of the Solicited Flag field.
func (b NDPNeighborAdvert) SolicitedFlag() bool {
	return b[ndpNAFlagsOffset]&ndpNASolicitedFlagMask != 0
}

// SetSolicitedFlag sets the value in the Solicited Flag field.
func (b NDPNeighborAdvert) SetSolicitedFlag(f bool) {
	if f {
		b[ndpNAFlagsOffset] |= ndpNASolicitedFlagMask
	} else {
		b[ndpNAFlagsOffset] &^= ndpNASolicitedFlagMask
	}
}

// OverrideFlag returns the value of the Override Flag field.
func (b NDPNeighborAdvert) OverrideFlag() bool {
	return b[ndpNAFlagsOffset]&ndpNAOverrideFlagMask != 0
}

// SetOverrideFlag sets the value in the Override Flag field.
func (b NDPNeighborAdvert) SetOverrideFlag(f bool) {
	if f {
		b[ndpNAFlagsOffset] |= ndpNAOverrideFlagMask
	} else {
		b[ndpNAFlagsOffset] &^= ndpNAOverrideFlagMask
	}
}

// Options returns an NDPOptions of the the options body.
func (b NDPNeighborAdvert) Options() NDPOptions {
	return NDPOptions(b[ndpNAOptionsOffset:])
}
