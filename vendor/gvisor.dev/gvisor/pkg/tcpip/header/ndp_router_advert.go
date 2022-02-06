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

import (
	"encoding/binary"
	"fmt"
	"time"
)

var _ fmt.Stringer = NDPRoutePreference(0)

// NDPRoutePreference is the preference values for default routers or
// more-specific routes.
//
// As per RFC 4191 section 2.1,
//
//   Default router preferences and preferences for more-specific routes
//   are encoded the same way.
//
//   Preference values are encoded as a two-bit signed integer, as
//   follows:
//
//      01      High
//      00      Medium (default)
//      11      Low
//      10      Reserved - MUST NOT be sent
//
//   Note that implementations can treat the value as a two-bit signed
//   integer.
//
//   Having just three values reinforces that they are not metrics and
//   more values do not appear to be necessary for reasonable scenarios.
type NDPRoutePreference uint8

const (
	// HighRoutePreference indicates a high preference, as per
	// RFC 4191 section 2.1.
	HighRoutePreference NDPRoutePreference = 0b01

	// MediumRoutePreference indicates a medium preference, as per
	// RFC 4191 section 2.1.
	//
	// This is the default preference value.
	MediumRoutePreference = 0b00

	// LowRoutePreference indicates a low preference, as per
	// RFC 4191 section 2.1.
	LowRoutePreference = 0b11

	// ReservedRoutePreference is a reserved preference value, as per
	// RFC 4191 section 2.1.
	//
	// It MUST NOT be sent.
	ReservedRoutePreference = 0b10
)

// String implements fmt.Stringer.
func (p NDPRoutePreference) String() string {
	switch p {
	case HighRoutePreference:
		return "HighRoutePreference"
	case MediumRoutePreference:
		return "MediumRoutePreference"
	case LowRoutePreference:
		return "LowRoutePreference"
	case ReservedRoutePreference:
		return "ReservedRoutePreference"
	default:
		return fmt.Sprintf("NDPRoutePreference(%d)", p)
	}
}

// NDPRouterAdvert is an NDP Router Advertisement message. It will only contain
// the body of an ICMPv6 packet.
//
// See RFC 4861 section 4.2 and RFC 4191 section 2.2 for more details.
type NDPRouterAdvert []byte

// As per RFC 4191 section 2.2,
//
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |     Type      |     Code      |          Checksum             |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      | Cur Hop Limit |M|O|H|Prf|Resvd|       Router Lifetime         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                         Reachable Time                        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                          Retrans Timer                        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |   Options ...
//      +-+-+-+-+-+-+-+-+-+-+-+-
const (
	// NDPRAMinimumSize is the minimum size of a valid NDP Router
	// Advertisement message (body of an ICMPv6 packet).
	NDPRAMinimumSize = 12

	// ndpRACurrHopLimitOffset is the byte of the Curr Hop Limit field
	// within an NDPRouterAdvert.
	ndpRACurrHopLimitOffset = 0

	// ndpRAFlagsOffset is the byte with the NDP RA bit-fields/flags
	// within an NDPRouterAdvert.
	ndpRAFlagsOffset = 1

	// ndpRAManagedAddrConfFlagMask is the mask of the Managed Address
	// Configuration flag within the bit-field/flags byte of an
	// NDPRouterAdvert.
	ndpRAManagedAddrConfFlagMask = (1 << 7)

	// ndpRAOtherConfFlagMask is the mask of the Other Configuration flag
	// within the bit-field/flags byte of an NDPRouterAdvert.
	ndpRAOtherConfFlagMask = (1 << 6)

	// ndpDefaultRouterPreferenceShift is the shift of the Prf (Default Router
	// Preference) field within the flags byte of an NDPRouterAdvert.
	ndpDefaultRouterPreferenceShift = 3

	// ndpDefaultRouterPreferenceMask is the mask of the Prf (Default Router
	// Preference) field within the flags byte of an NDPRouterAdvert.
	ndpDefaultRouterPreferenceMask = (0b11 << ndpDefaultRouterPreferenceShift)

	// ndpRARouterLifetimeOffset is the start of the 2-byte Router Lifetime
	// field within an NDPRouterAdvert.
	ndpRARouterLifetimeOffset = 2

	// ndpRAReachableTimeOffset is the start of the 4-byte Reachable Time
	// field within an NDPRouterAdvert.
	ndpRAReachableTimeOffset = 4

	// ndpRARetransTimerOffset is the start of the 4-byte Retrans Timer
	// field within an NDPRouterAdvert.
	ndpRARetransTimerOffset = 8

	// ndpRAOptionsOffset is the start of the NDP options in an
	// NDPRouterAdvert.
	ndpRAOptionsOffset = 12
)

// CurrHopLimit returns the value of the Curr Hop Limit field.
func (b NDPRouterAdvert) CurrHopLimit() uint8 {
	return b[ndpRACurrHopLimitOffset]
}

// ManagedAddrConfFlag returns the value of the Managed Address Configuration
// flag.
func (b NDPRouterAdvert) ManagedAddrConfFlag() bool {
	return b[ndpRAFlagsOffset]&ndpRAManagedAddrConfFlagMask != 0
}

// OtherConfFlag returns the value of the Other Configuration flag.
func (b NDPRouterAdvert) OtherConfFlag() bool {
	return b[ndpRAFlagsOffset]&ndpRAOtherConfFlagMask != 0
}

// DefaultRouterPreference returns the Default Router Preference field.
func (b NDPRouterAdvert) DefaultRouterPreference() NDPRoutePreference {
	return NDPRoutePreference((b[ndpRAFlagsOffset] & ndpDefaultRouterPreferenceMask) >> ndpDefaultRouterPreferenceShift)
}

// RouterLifetime returns the lifetime associated with the default router. A
// value of 0 means the source of the Router Advertisement is not a default
// router and SHOULD NOT appear on the default router list. Note, a value of 0
// only means that the router should not be used as a default router, it does
// not apply to other information contained in the Router Advertisement.
func (b NDPRouterAdvert) RouterLifetime() time.Duration {
	// The field is the time in seconds, as per RFC 4861 section 4.2.
	return time.Second * time.Duration(binary.BigEndian.Uint16(b[ndpRARouterLifetimeOffset:]))
}

// ReachableTime returns the time that a node assumes a neighbor is reachable
// after having received a reachability confirmation. A value of 0 means
// that it is unspecified by the source of the Router Advertisement message.
func (b NDPRouterAdvert) ReachableTime() time.Duration {
	// The field is the time in milliseconds, as per RFC 4861 section 4.2.
	return time.Millisecond * time.Duration(binary.BigEndian.Uint32(b[ndpRAReachableTimeOffset:]))
}

// RetransTimer returns the time between retransmitted Neighbor Solicitation
// messages. A value of 0 means that it is unspecified by the source of the
// Router Advertisement message.
func (b NDPRouterAdvert) RetransTimer() time.Duration {
	// The field is the time in milliseconds, as per RFC 4861 section 4.2.
	return time.Millisecond * time.Duration(binary.BigEndian.Uint32(b[ndpRARetransTimerOffset:]))
}

// Options returns an NDPOptions of the the options body.
func (b NDPRouterAdvert) Options() NDPOptions {
	return NDPOptions(b[ndpRAOptionsOffset:])
}
