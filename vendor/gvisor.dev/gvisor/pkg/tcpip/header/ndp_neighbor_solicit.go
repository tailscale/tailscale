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

// NDPNeighborSolicit is an NDP Neighbor Solicitation message. It will only
// contain the body of an ICMPv6 packet.
//
// See RFC 4861 section 4.3 for more details.
type NDPNeighborSolicit []byte

const (
	// NDPNSMinimumSize is the minimum size of a valid NDP Neighbor
	// Solicitation message (body of an ICMPv6 packet).
	NDPNSMinimumSize = 20

	// ndpNSTargetAddessOffset is the start of the Target Address
	// field within an NDPNeighborSolicit.
	ndpNSTargetAddessOffset = 4

	// ndpNSOptionsOffset is the start of the NDP options in an
	// NDPNeighborSolicit.
	ndpNSOptionsOffset = ndpNSTargetAddessOffset + IPv6AddressSize
)

// TargetAddress returns the value within the Target Address field.
func (b NDPNeighborSolicit) TargetAddress() tcpip.Address {
	return tcpip.Address(b[ndpNSTargetAddessOffset:][:IPv6AddressSize])
}

// SetTargetAddress sets the value within the Target Address field.
func (b NDPNeighborSolicit) SetTargetAddress(addr tcpip.Address) {
	copy(b[ndpNSTargetAddessOffset:][:IPv6AddressSize], addr)
}

// Options returns an NDPOptions of the the options body.
func (b NDPNeighborSolicit) Options() NDPOptions {
	return NDPOptions(b[ndpNSOptionsOffset:])
}
