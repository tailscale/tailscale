// Copyright 2020 The gVisor Authors.
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

import (
	"encoding/binary"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// MLDMinimumSize is the minimum size for an MLD message.
	MLDMinimumSize = 20

	// MLDHopLimit is the Hop Limit for all IPv6 packets with an MLD message, as
	// per RFC 2710 section 3.
	MLDHopLimit = 1

	// mldMaximumResponseDelayOffset is the offset to the Maximum Response Delay
	// field within MLD.
	mldMaximumResponseDelayOffset = 0

	// mldMulticastAddressOffset is the offset to the Multicast Address field
	// within MLD.
	mldMulticastAddressOffset = 4
)

// MLD is a Multicast Listener Discovery message in an ICMPv6 packet.
//
// MLD will only contain the body of an ICMPv6 packet.
//
// As per RFC 2710 section 3, MLD messages have the following format (MLD only
// holds the bytes after the first four bytes in the diagram below):
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Type      |     Code      |          Checksum             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Maximum Response Delay    |          Reserved             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                       Multicast Address                       +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type MLD []byte

// MaximumResponseDelay returns the Maximum Response Delay.
func (m MLD) MaximumResponseDelay() time.Duration {
	// As per RFC 2710 section 3.4:
	//
	//   The Maximum Response Delay field is meaningful only in Query
	//   messages, and specifies the maximum allowed delay before sending a
	//   responding Report, in units of milliseconds. In all other messages,
	//   it is set to zero by the sender and ignored by receivers.
	return time.Duration(binary.BigEndian.Uint16(m[mldMaximumResponseDelayOffset:])) * time.Millisecond
}

// SetMaximumResponseDelay sets the Maximum Response Delay field.
//
// maxRespDelayMS is the value in milliseconds.
func (m MLD) SetMaximumResponseDelay(maxRespDelayMS uint16) {
	binary.BigEndian.PutUint16(m[mldMaximumResponseDelayOffset:], maxRespDelayMS)
}

// MulticastAddress returns the Multicast Address.
func (m MLD) MulticastAddress() tcpip.Address {
	// As per RFC 2710 section 3.5:
	//
	//   In a Query message, the Multicast Address field is set to zero when
	//   sending a General Query, and set to a specific IPv6 multicast address
	//   when sending a Multicast-Address-Specific Query.
	//
	//   In a Report or Done message, the Multicast Address field holds a
	//   specific IPv6 multicast address to which the message sender is
	//   listening or is ceasing to listen, respectively.
	return tcpip.Address(m[mldMulticastAddressOffset:][:IPv6AddressSize])
}

// SetMulticastAddress sets the Multicast Address field.
func (m MLD) SetMulticastAddress(multicastAddress tcpip.Address) {
	if n := copy(m[mldMulticastAddressOffset:], multicastAddress); n != IPv6AddressSize {
		panic(fmt.Sprintf("copied %d bytes, expected to copy %d bytes", n, IPv6AddressSize))
	}
}
