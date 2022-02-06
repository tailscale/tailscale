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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// ndpOptionIdentifier is an NDP option type identifier.
type ndpOptionIdentifier uint8

const (
	// ndpSourceLinkLayerAddressOptionType is the type of the Source Link Layer
	// Address option, as per RFC 4861 section 4.6.1.
	ndpSourceLinkLayerAddressOptionType ndpOptionIdentifier = 1

	// ndpTargetLinkLayerAddressOptionType is the type of the Target Link Layer
	// Address option, as per RFC 4861 section 4.6.1.
	ndpTargetLinkLayerAddressOptionType ndpOptionIdentifier = 2

	// ndpPrefixInformationType is the type of the Prefix Information
	// option, as per RFC 4861 section 4.6.2.
	ndpPrefixInformationType ndpOptionIdentifier = 3

	// ndpNonceOptionType is the type of the Nonce option, as per
	// RFC 3971 section 5.3.2.
	ndpNonceOptionType ndpOptionIdentifier = 14

	// ndpRecursiveDNSServerOptionType is the type of the Recursive DNS
	// Server option, as per RFC 8106 section 5.1.
	ndpRecursiveDNSServerOptionType ndpOptionIdentifier = 25

	// ndpDNSSearchListOptionType is the type of the DNS Search List option,
	// as per RFC 8106 section 5.2.
	ndpDNSSearchListOptionType ndpOptionIdentifier = 31
)

const (
	// NDPLinkLayerAddressSize is the size of a Source or Target Link Layer
	// Address option for an Ethernet address.
	NDPLinkLayerAddressSize = 8

	// ndpPrefixInformationLength is the expected length, in bytes, of the
	// body of an NDP Prefix Information option, as per RFC 4861 section
	// 4.6.2 which specifies that the Length field is 4. Given this, the
	// expected length, in bytes, is 30 becuase 4 * lengthByteUnits (8) - 2
	// (Type & Length) = 30.
	ndpPrefixInformationLength = 30

	// ndpPrefixInformationPrefixLengthOffset is the offset of the Prefix
	// Length field within an NDPPrefixInformation.
	ndpPrefixInformationPrefixLengthOffset = 0

	// ndpPrefixInformationFlagsOffset is the offset of the flags byte
	// within an NDPPrefixInformation.
	ndpPrefixInformationFlagsOffset = 1

	// ndpPrefixInformationOnLinkFlagMask is the mask of the On-Link Flag
	// field in the flags byte within an NDPPrefixInformation.
	ndpPrefixInformationOnLinkFlagMask = 1 << 7

	// ndpPrefixInformationAutoAddrConfFlagMask is the mask of the
	// Autonomous Address-Configuration flag field in the flags byte within
	// an NDPPrefixInformation.
	ndpPrefixInformationAutoAddrConfFlagMask = 1 << 6

	// ndpPrefixInformationReserved1FlagsMask is the mask of the Reserved1
	// field in the flags byte within an NDPPrefixInformation.
	ndpPrefixInformationReserved1FlagsMask = 63

	// ndpPrefixInformationValidLifetimeOffset is the start of the 4-byte
	// Valid Lifetime field within an NDPPrefixInformation.
	ndpPrefixInformationValidLifetimeOffset = 2

	// ndpPrefixInformationPreferredLifetimeOffset is the start of the
	// 4-byte Preferred Lifetime field within an NDPPrefixInformation.
	ndpPrefixInformationPreferredLifetimeOffset = 6

	// ndpPrefixInformationReserved2Offset is the start of the 4-byte
	// Reserved2 field within an NDPPrefixInformation.
	ndpPrefixInformationReserved2Offset = 10

	// ndpPrefixInformationReserved2Length is the length of the Reserved2
	// field.
	//
	// It is 4 bytes.
	ndpPrefixInformationReserved2Length = 4

	// ndpPrefixInformationPrefixOffset is the start of the Prefix field
	// within an NDPPrefixInformation.
	ndpPrefixInformationPrefixOffset = 14

	// ndpRecursiveDNSServerLifetimeOffset is the start of the 4-byte
	// Lifetime field within an NDPRecursiveDNSServer.
	ndpRecursiveDNSServerLifetimeOffset = 2

	// ndpRecursiveDNSServerAddressesOffset is the start of the addresses
	// for IPv6 Recursive DNS Servers within an NDPRecursiveDNSServer.
	ndpRecursiveDNSServerAddressesOffset = 6

	// minNDPRecursiveDNSServerLength is the minimum NDP Recursive DNS Server
	// option's body size when it contains at least one IPv6 address, as per
	// RFC 8106 section 5.3.1.
	minNDPRecursiveDNSServerBodySize = 22

	// ndpDNSSearchListLifetimeOffset is the start of the 4-byte
	// Lifetime field within an NDPDNSSearchList.
	ndpDNSSearchListLifetimeOffset = 2

	// ndpDNSSearchListDomainNamesOffset is the start of the DNS search list
	// domain names within an NDPDNSSearchList.
	ndpDNSSearchListDomainNamesOffset = 6

	// minNDPDNSSearchListBodySize is the minimum NDP DNS Search List option's
	// body size when it contains at least one domain name, as per RFC 8106
	// section 5.3.1.
	minNDPDNSSearchListBodySize = 14

	// maxDomainNameLabelLength is the maximum length of a domain name
	// label, as per RFC 1035 section 3.1.
	maxDomainNameLabelLength = 63

	// maxDomainNameLength is the maximum length of a domain name, including
	// label AND label length octet, as per RFC 1035 section 3.1.
	maxDomainNameLength = 255

	// lengthByteUnits is the multiplier factor for the Length field of an
	// NDP option. That is, the length field for NDP options is in units of
	// 8 octets, as per RFC 4861 section 4.6.
	lengthByteUnits = 8

	// NDPInfiniteLifetime is a value that represents infinity for the
	// 4-byte lifetime fields found in various NDP options. Its value is
	// (2^32 - 1)s = 4294967295s.
	NDPInfiniteLifetime = time.Second * math.MaxUint32
)

// NDPOptionIterator is an iterator of NDPOption.
//
// Note, between when an NDPOptionIterator is obtained and last used, no changes
// to the NDPOptions may happen. Doing so may cause undefined and unexpected
// behaviour. It is fine to obtain an NDPOptionIterator, iterate over the first
// few NDPOption then modify the backing NDPOptions so long as the
// NDPOptionIterator obtained before modification is no longer used.
type NDPOptionIterator struct {
	opts *bytes.Buffer
}

// Potential errors when iterating over an NDPOptions.
var (
	ErrNDPOptMalformedBody   = errors.New("NDP option has a malformed body")
	ErrNDPOptMalformedHeader = errors.New("NDP option has a malformed header")
)

// Next returns the next element in the backing NDPOptions, or true if we are
// done, or false if an error occured.
//
// The return can be read as option, done, error. Note, option should only be
// used if done is false and error is nil.
func (i *NDPOptionIterator) Next() (NDPOption, bool, error) {
	for {
		// Do we still have elements to look at?
		if i.opts.Len() == 0 {
			return nil, true, nil
		}

		// Get the Type field.
		temp, err := i.opts.ReadByte()
		if err != nil {
			if err != io.EOF {
				// ReadByte should only ever return nil or io.EOF.
				panic(fmt.Sprintf("unexpected error when reading the option's Type field: %s", err))
			}

			// We use io.ErrUnexpectedEOF as exhausting the buffer is unexpected once
			// we start parsing an option; we expect the buffer to contain enough
			// bytes for the whole option.
			return nil, true, fmt.Errorf("unexpectedly exhausted buffer when reading the option's Type field: %w", io.ErrUnexpectedEOF)
		}
		kind := ndpOptionIdentifier(temp)

		// Get the Length field.
		length, err := i.opts.ReadByte()
		if err != nil {
			if err != io.EOF {
				panic(fmt.Sprintf("unexpected error when reading the option's Length field for %s: %s", kind, err))
			}

			return nil, true, fmt.Errorf("unexpectedly exhausted buffer when reading the option's Length field for %s: %w", kind, io.ErrUnexpectedEOF)
		}

		// This would indicate an erroneous NDP option as the Length field should
		// never be 0.
		if length == 0 {
			return nil, true, fmt.Errorf("zero valued Length field for %s: %w", kind, ErrNDPOptMalformedHeader)
		}

		// Get the body.
		numBytes := int(length) * lengthByteUnits
		numBodyBytes := numBytes - 2
		body := i.opts.Next(numBodyBytes)
		if len(body) < numBodyBytes {
			return nil, true, fmt.Errorf("unexpectedly exhausted buffer when reading the option's Body for %s: %w", kind, io.ErrUnexpectedEOF)
		}

		switch kind {
		case ndpSourceLinkLayerAddressOptionType:
			return NDPSourceLinkLayerAddressOption(body), false, nil

		case ndpTargetLinkLayerAddressOptionType:
			return NDPTargetLinkLayerAddressOption(body), false, nil

		case ndpNonceOptionType:
			return NDPNonceOption(body), false, nil

		case ndpRouteInformationType:
			if numBodyBytes > ndpRouteInformationMaxLength {
				return nil, true, fmt.Errorf("got %d bytes for NDP Route Information option's body, expected at max %d bytes: %w", numBodyBytes, ndpRouteInformationMaxLength, ErrNDPOptMalformedBody)
			}
			opt := NDPRouteInformation(body)
			if err := opt.hasError(); err != nil {
				return nil, true, err
			}

			return opt, false, nil

		case ndpPrefixInformationType:
			// Make sure the length of a Prefix Information option
			// body is ndpPrefixInformationLength, as per RFC 4861
			// section 4.6.2.
			if numBodyBytes != ndpPrefixInformationLength {
				return nil, true, fmt.Errorf("got %d bytes for NDP Prefix Information option's body, expected %d bytes: %w", numBodyBytes, ndpPrefixInformationLength, ErrNDPOptMalformedBody)
			}

			return NDPPrefixInformation(body), false, nil

		case ndpRecursiveDNSServerOptionType:
			opt := NDPRecursiveDNSServer(body)
			if err := opt.checkAddresses(); err != nil {
				return nil, true, err
			}

			return opt, false, nil

		case ndpDNSSearchListOptionType:
			opt := NDPDNSSearchList(body)
			if err := opt.checkDomainNames(); err != nil {
				return nil, true, err
			}

			return opt, false, nil

		default:
			// We do not yet recognize the option, just skip for
			// now. This is okay because RFC 4861 allows us to
			// skip/ignore any unrecognized options. However,
			// we MUST recognized all the options in RFC 4861.
			//
			// TODO(b/141487990): Handle all NDP options as defined
			//                    by RFC 4861.
		}
	}
}

// NDPOptions is a buffer of NDP options as defined by RFC 4861 section 4.6.
type NDPOptions []byte

// Iter returns an iterator of NDPOption.
//
// If check is true, Iter will do an integrity check on the options by iterating
// over it and returning an error if detected.
//
// See NDPOptionIterator for more information.
func (b NDPOptions) Iter(check bool) (NDPOptionIterator, error) {
	it := NDPOptionIterator{
		opts: bytes.NewBuffer(b),
	}

	if check {
		it2 := NDPOptionIterator{
			opts: bytes.NewBuffer(b),
		}

		for {
			if _, done, err := it2.Next(); err != nil || done {
				return it, err
			}
		}
	}

	return it, nil
}

// Serialize serializes the provided list of NDP options into b.
//
// Note, b must be of sufficient size to hold all the options in s. See
// NDPOptionsSerializer.Length for details on the getting the total size
// of a serialized NDPOptionsSerializer.
//
// Serialize may panic if b is not of sufficient size to hold all the options
// in s.
func (b NDPOptions) Serialize(s NDPOptionsSerializer) int {
	done := 0

	for _, o := range s {
		l := paddedLength(o)

		if l == 0 {
			continue
		}

		b[0] = byte(o.kind())

		// We know this safe because paddedLength would have returned
		// 0 if o had an invalid length (> 255 * lengthByteUnits).
		b[1] = uint8(l / lengthByteUnits)

		// Serialize NDP option body.
		used := o.serializeInto(b[2:])

		// Zero out remaining (padding) bytes, if any exists.
		for i := used + 2; i < l; i++ {
			b[i] = 0
		}

		b = b[l:]
		done += l
	}

	return done
}

// NDPOption is the set of functions to be implemented by all NDP option types.
type NDPOption interface {
	fmt.Stringer

	// kind returns the type of the receiver.
	kind() ndpOptionIdentifier

	// length returns the length of the body of the receiver, in bytes.
	length() int

	// serializeInto serializes the receiver into the provided byte
	// buffer.
	//
	// Note, the caller MUST provide a byte buffer with size of at least
	// Length. Implementers of this function may assume that the byte buffer
	// is of sufficient size. serializeInto MAY panic if the provided byte
	// buffer is not of sufficient size.
	//
	// serializeInto will return the number of bytes that was used to
	// serialize the receiver. Implementers must only use the number of
	// bytes required to serialize the receiver. Callers MAY provide a
	// larger buffer than required to serialize into.
	serializeInto([]byte) int
}

// paddedLength returns the length of o, in bytes, with any padding bytes, if
// required.
func paddedLength(o NDPOption) int {
	l := o.length()

	if l == 0 {
		return 0
	}

	// Length excludes the 2 Type and Length bytes.
	l += 2

	// Add extra bytes if needed to make sure the option is
	// lengthByteUnits-byte aligned. We do this by adding lengthByteUnits-1
	// to l and then stripping off the last few LSBits from l. This will
	// make sure that l is rounded up to the nearest unit of
	// lengthByteUnits. This works since lengthByteUnits is a power of 2
	// (= 8).
	mask := lengthByteUnits - 1
	l += mask
	l &^= mask

	if l/lengthByteUnits > 255 {
		// Should never happen because an option can only have a max
		// value of 255 for its Length field, so just return 0 so this
		// option does not get serialized.
		//
		// Returning 0 here will make sure that this option does not get
		// serialized when NDPOptions.Serialize is called with the
		// NDPOptionsSerializer that holds this option, effectively
		// skipping this option during serialization. Also note that
		// a value of zero for the Length field in an NDP option is
		// invalid so this is another sign to the caller that this NDP
		// option is malformed, as per RFC 4861 section 4.6.
		return 0
	}

	return l
}

// NDPOptionsSerializer is a serializer for NDP options.
type NDPOptionsSerializer []NDPOption

// Length returns the total number of bytes required to serialize.
func (b NDPOptionsSerializer) Length() int {
	l := 0

	for _, o := range b {
		l += paddedLength(o)
	}

	return l
}

// NDPNonceOption is the NDP Nonce Option as defined by RFC 3971 section 5.3.2.
//
// It is the first X bytes following the NDP option's Type and Length field
// where X is the value in Length multiplied by lengthByteUnits - 2 bytes.
type NDPNonceOption []byte

// kind implements NDPOption.
func (o NDPNonceOption) kind() ndpOptionIdentifier {
	return ndpNonceOptionType
}

// length implements NDPOption.
func (o NDPNonceOption) length() int {
	return len(o)
}

// serializeInto implements NDPOption.
func (o NDPNonceOption) serializeInto(b []byte) int {
	return copy(b, o)
}

// String implements fmt.Stringer.
func (o NDPNonceOption) String() string {
	return fmt.Sprintf("%T(%x)", o, []byte(o))
}

// Nonce returns the nonce value this option holds.
func (o NDPNonceOption) Nonce() []byte {
	return o
}

// NDPSourceLinkLayerAddressOption is the NDP Source Link Layer Option
// as defined by RFC 4861 section 4.6.1.
//
// It is the first X bytes following the NDP option's Type and Length field
// where X is the value in Length multiplied by lengthByteUnits - 2 bytes.
type NDPSourceLinkLayerAddressOption tcpip.LinkAddress

// kind implements NDPOption.
func (o NDPSourceLinkLayerAddressOption) kind() ndpOptionIdentifier {
	return ndpSourceLinkLayerAddressOptionType
}

// length implements NDPOption.
func (o NDPSourceLinkLayerAddressOption) length() int {
	return len(o)
}

// serializeInto implements NDPOption.
func (o NDPSourceLinkLayerAddressOption) serializeInto(b []byte) int {
	return copy(b, o)
}

// String implements fmt.Stringer.
func (o NDPSourceLinkLayerAddressOption) String() string {
	return fmt.Sprintf("%T(%s)", o, tcpip.LinkAddress(o))
}

// EthernetAddress will return an ethernet (MAC) address if the
// NDPSourceLinkLayerAddressOption's body has at minimum EthernetAddressSize
// bytes. If the body has more than EthernetAddressSize bytes, only the first
// EthernetAddressSize bytes are returned as that is all that is needed for an
// Ethernet address.
func (o NDPSourceLinkLayerAddressOption) EthernetAddress() tcpip.LinkAddress {
	if len(o) >= EthernetAddressSize {
		return tcpip.LinkAddress(o[:EthernetAddressSize])
	}

	return tcpip.LinkAddress([]byte(nil))
}

// NDPTargetLinkLayerAddressOption is the NDP Target Link Layer Option
// as defined by RFC 4861 section 4.6.1.
//
// It is the first X bytes following the NDP option's Type and Length field
// where X is the value in Length multiplied by lengthByteUnits - 2 bytes.
type NDPTargetLinkLayerAddressOption tcpip.LinkAddress

// kind implements NDPOption.
func (o NDPTargetLinkLayerAddressOption) kind() ndpOptionIdentifier {
	return ndpTargetLinkLayerAddressOptionType
}

// length implements NDPOption.
func (o NDPTargetLinkLayerAddressOption) length() int {
	return len(o)
}

// serializeInto implements NDPOption.
func (o NDPTargetLinkLayerAddressOption) serializeInto(b []byte) int {
	return copy(b, o)
}

// String implements fmt.Stringer.
func (o NDPTargetLinkLayerAddressOption) String() string {
	return fmt.Sprintf("%T(%s)", o, tcpip.LinkAddress(o))
}

// EthernetAddress will return an ethernet (MAC) address if the
// NDPTargetLinkLayerAddressOption's body has at minimum EthernetAddressSize
// bytes. If the body has more than EthernetAddressSize bytes, only the first
// EthernetAddressSize bytes are returned as that is all that is needed for an
// Ethernet address.
func (o NDPTargetLinkLayerAddressOption) EthernetAddress() tcpip.LinkAddress {
	if len(o) >= EthernetAddressSize {
		return tcpip.LinkAddress(o[:EthernetAddressSize])
	}

	return tcpip.LinkAddress([]byte(nil))
}

// NDPPrefixInformation is the NDP Prefix Information option as defined by
// RFC 4861 section 4.6.2.
//
// The length, in bytes, of a valid NDP Prefix Information option body MUST be
// ndpPrefixInformationLength bytes.
type NDPPrefixInformation []byte

// kind implements NDPOption.
func (o NDPPrefixInformation) kind() ndpOptionIdentifier {
	return ndpPrefixInformationType
}

// length implements NDPOption.
func (o NDPPrefixInformation) length() int {
	return ndpPrefixInformationLength
}

// serializeInto implements NDPOption.
func (o NDPPrefixInformation) serializeInto(b []byte) int {
	used := copy(b, o)

	// Zero out the Reserved1 field.
	b[ndpPrefixInformationFlagsOffset] &^= ndpPrefixInformationReserved1FlagsMask

	// Zero out the Reserved2 field.
	reserved2 := b[ndpPrefixInformationReserved2Offset:][:ndpPrefixInformationReserved2Length]
	for i := range reserved2 {
		reserved2[i] = 0
	}

	return used
}

// String implements fmt.Stringer.
func (o NDPPrefixInformation) String() string {
	return fmt.Sprintf("%T(O=%t, A=%t, PL=%s, VL=%s, Prefix=%s)",
		o,
		o.OnLinkFlag(),
		o.AutonomousAddressConfigurationFlag(),
		o.PreferredLifetime(),
		o.ValidLifetime(),
		o.Subnet())
}

// PrefixLength returns the value in the number of leading bits in the Prefix
// that are valid.
//
// Valid values are in the range [0, 128], but o may not always contain valid
// values. It is up to the caller to valdiate the Prefix Information option.
func (o NDPPrefixInformation) PrefixLength() uint8 {
	return o[ndpPrefixInformationPrefixLengthOffset]
}

// OnLinkFlag returns true of the prefix is considered on-link. On-link means
// that a forwarding node is not needed to send packets to other nodes on the
// same prefix.
//
// Note, when this function returns false, no statement is made about the
// on-link property of a prefix. That is, if OnLinkFlag returns false, the
// caller MUST NOT conclude that the prefix is off-link and MUST NOT update any
// previously stored state for this prefix about its on-link status.
func (o NDPPrefixInformation) OnLinkFlag() bool {
	return o[ndpPrefixInformationFlagsOffset]&ndpPrefixInformationOnLinkFlagMask != 0
}

// AutonomousAddressConfigurationFlag returns true if the prefix can be used for
// Stateless Address Auto-Configuration (as specified in RFC 4862).
func (o NDPPrefixInformation) AutonomousAddressConfigurationFlag() bool {
	return o[ndpPrefixInformationFlagsOffset]&ndpPrefixInformationAutoAddrConfFlagMask != 0
}

// ValidLifetime returns the length of time that the prefix is valid for the
// purpose of on-link determination. This value is relative to the send time of
// the packet that the Prefix Information option was present in.
//
// Note, a value of 0 implies the prefix should not be considered as on-link,
// and a value of infinity/forever is represented by
// NDPInfiniteLifetime.
func (o NDPPrefixInformation) ValidLifetime() time.Duration {
	// The field is the time in seconds, as per RFC 4861 section 4.6.2.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpPrefixInformationValidLifetimeOffset:]))
}

// PreferredLifetime returns the length of time that an address generated from
// the prefix via Stateless Address Auto-Configuration remains preferred. This
// value is relative to the send time of the packet that the Prefix Information
// option was present in.
//
// Note, a value of 0 implies that addresses generated from the prefix should
// no longer remain preferred, and a value of infinity is represented by
// NDPInfiniteLifetime.
//
// Also note that the value of this field MUST NOT exceed the Valid Lifetime
// field to avoid preferring addresses that are no longer valid, for the
// purpose of Stateless Address Auto-Configuration.
func (o NDPPrefixInformation) PreferredLifetime() time.Duration {
	// The field is the time in seconds, as per RFC 4861 section 4.6.2.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpPrefixInformationPreferredLifetimeOffset:]))
}

// Prefix returns an IPv6 address or a prefix of an IPv6 address. The Prefix
// Length field (see NDPPrefixInformation.PrefixLength) contains the number
// of valid leading bits in the prefix.
//
// Hosts SHOULD ignore an NDP Prefix Information option where the Prefix field
// holds the link-local prefix (fe80::).
func (o NDPPrefixInformation) Prefix() tcpip.Address {
	return tcpip.Address(o[ndpPrefixInformationPrefixOffset:][:IPv6AddressSize])
}

// Subnet returns the Prefix field and Prefix Length field represented in a
// tcpip.Subnet.
func (o NDPPrefixInformation) Subnet() tcpip.Subnet {
	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   o.Prefix(),
		PrefixLen: int(o.PrefixLength()),
	}
	return addrWithPrefix.Subnet()
}

// NDPRecursiveDNSServer is the NDP Recursive DNS Server option, as defined by
// RFC 8106 section 5.1.
//
// To make sure that the option meets its minimum length and does not end in the
// middle of a DNS server's IPv6 address, the length of a valid
// NDPRecursiveDNSServer must meet the following constraint:
//   (Length - ndpRecursiveDNSServerAddressesOffset) % IPv6AddressSize == 0
type NDPRecursiveDNSServer []byte

// Type returns the type of an NDP Recursive DNS Server option.
//
// kind implements NDPOption.
func (NDPRecursiveDNSServer) kind() ndpOptionIdentifier {
	return ndpRecursiveDNSServerOptionType
}

// length implements NDPOption.
func (o NDPRecursiveDNSServer) length() int {
	return len(o)
}

// serializeInto implements NDPOption.
func (o NDPRecursiveDNSServer) serializeInto(b []byte) int {
	used := copy(b, o)

	// Zero out the reserved bytes that are before the Lifetime field.
	for i := 0; i < ndpRecursiveDNSServerLifetimeOffset; i++ {
		b[i] = 0
	}

	return used
}

// String implements fmt.Stringer.
func (o NDPRecursiveDNSServer) String() string {
	lt := o.Lifetime()
	addrs, err := o.Addresses()
	if err != nil {
		return fmt.Sprintf("%T([] valid for %s; err = %s)", o, lt, err)
	}
	return fmt.Sprintf("%T(%s valid for %s)", o, addrs, lt)
}

// Lifetime returns the length of time that the DNS server addresses
// in this option may be used for name resolution.
//
// Note, a value of 0 implies the addresses should no longer be used,
// and a value of infinity/forever is represented by NDPInfiniteLifetime.
//
// Lifetime may panic if o does not have enough bytes to hold the Lifetime
// field.
func (o NDPRecursiveDNSServer) Lifetime() time.Duration {
	// The field is the time in seconds, as per RFC 8106 section 5.1.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpRecursiveDNSServerLifetimeOffset:]))
}

// Addresses returns the recursive DNS server IPv6 addresses that may be
// used for name resolution.
//
// Note, the addresses MAY be link-local addresses.
func (o NDPRecursiveDNSServer) Addresses() ([]tcpip.Address, error) {
	var addrs []tcpip.Address
	return addrs, o.iterAddresses(func(addr tcpip.Address) { addrs = append(addrs, addr) })
}

// checkAddresses iterates over the addresses in an NDP Recursive DNS Server
// option and returns any error it encounters.
func (o NDPRecursiveDNSServer) checkAddresses() error {
	return o.iterAddresses(nil)
}

// iterAddresses iterates over the addresses in an NDP Recursive DNS Server
// option and calls a function with each valid unicast IPv6 address.
//
// Note, the addresses MAY be link-local addresses.
func (o NDPRecursiveDNSServer) iterAddresses(fn func(tcpip.Address)) error {
	if l := len(o); l < minNDPRecursiveDNSServerBodySize {
		return fmt.Errorf("got %d bytes for NDP Recursive DNS Server option's body, expected at least %d bytes: %w", l, minNDPRecursiveDNSServerBodySize, io.ErrUnexpectedEOF)
	}

	o = o[ndpRecursiveDNSServerAddressesOffset:]
	l := len(o)
	if l%IPv6AddressSize != 0 {
		return fmt.Errorf("NDP Recursive DNS Server option's body ends in the middle of an IPv6 address (addresses body size = %d bytes): %w", l, ErrNDPOptMalformedBody)
	}

	for i := 0; len(o) != 0; i++ {
		addr := tcpip.Address(o[:IPv6AddressSize])
		if !IsV6UnicastAddress(addr) {
			return fmt.Errorf("%d-th address (%s) in NDP Recursive DNS Server option is not a valid unicast IPv6 address: %w", i, addr, ErrNDPOptMalformedBody)
		}

		if fn != nil {
			fn(addr)
		}

		o = o[IPv6AddressSize:]
	}

	return nil
}

// NDPDNSSearchList is the NDP DNS Search List option, as defined by
// RFC 8106 section 5.2.
type NDPDNSSearchList []byte

// kind implements NDPOption.
func (o NDPDNSSearchList) kind() ndpOptionIdentifier {
	return ndpDNSSearchListOptionType
}

// length implements NDPOption.
func (o NDPDNSSearchList) length() int {
	return len(o)
}

// serializeInto implements NDPOption.
func (o NDPDNSSearchList) serializeInto(b []byte) int {
	used := copy(b, o)

	// Zero out the reserved bytes that are before the Lifetime field.
	for i := 0; i < ndpDNSSearchListLifetimeOffset; i++ {
		b[i] = 0
	}

	return used
}

// String implements fmt.Stringer.
func (o NDPDNSSearchList) String() string {
	lt := o.Lifetime()
	domainNames, err := o.DomainNames()
	if err != nil {
		return fmt.Sprintf("%T([] valid for %s; err = %s)", o, lt, err)
	}
	return fmt.Sprintf("%T(%s valid for %s)", o, domainNames, lt)
}

// Lifetime returns the length of time that the DNS search list of domain names
// in this option may be used for name resolution.
//
// Note, a value of 0 implies the domain names should no longer be used,
// and a value of infinity/forever is represented by NDPInfiniteLifetime.
func (o NDPDNSSearchList) Lifetime() time.Duration {
	// The field is the time in seconds, as per RFC 8106 section 5.1.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpDNSSearchListLifetimeOffset:]))
}

// DomainNames returns a DNS search list of domain names.
//
// DomainNames will parse the backing buffer as outlined by RFC 1035 section
// 3.1 and return a list of strings, with all domain names in lower case.
func (o NDPDNSSearchList) DomainNames() ([]string, error) {
	var domainNames []string
	return domainNames, o.iterDomainNames(func(domainName string) { domainNames = append(domainNames, domainName) })
}

// checkDomainNames iterates over the domain names in an NDP DNS Search List
// option and returns any error it encounters.
func (o NDPDNSSearchList) checkDomainNames() error {
	return o.iterDomainNames(nil)
}

// iterDomainNames iterates over the domain names in an NDP DNS Search List
// option and calls a function with each valid domain name.
func (o NDPDNSSearchList) iterDomainNames(fn func(string)) error {
	if l := len(o); l < minNDPDNSSearchListBodySize {
		return fmt.Errorf("got %d bytes for NDP DNS Search List  option's body, expected at least %d bytes: %w", l, minNDPDNSSearchListBodySize, io.ErrUnexpectedEOF)
	}

	var searchList bytes.Reader
	searchList.Reset(o[ndpDNSSearchListDomainNamesOffset:])

	var scratch [maxDomainNameLength]byte
	domainName := bytes.NewBuffer(scratch[:])

	// Parse the domain names, as per RFC 1035 section 3.1.
	for searchList.Len() != 0 {
		domainName.Reset()

		// Parse a label within a domain name, as per RFC 1035 section 3.1.
		for {
			// The first byte is the label length.
			labelLenByte, err := searchList.ReadByte()
			if err != nil {
				if err != io.EOF {
					// ReadByte should only ever return nil or io.EOF.
					panic(fmt.Sprintf("unexpected error when reading a label's length: %s", err))
				}

				// We use io.ErrUnexpectedEOF as exhausting the buffer is unexpected
				// once we start parsing a domain name; we expect the buffer to contain
				// enough bytes for the whole domain name.
				return fmt.Errorf("unexpected exhausted buffer while parsing a new label for a domain from NDP Search List option: %w", io.ErrUnexpectedEOF)
			}
			labelLen := int(labelLenByte)

			// A zero-length label implies the end of a domain name.
			if labelLen == 0 {
				// If the domain name is empty or we have no callback function, do
				// nothing further with the current domain name.
				if domainName.Len() == 0 || fn == nil {
					break
				}

				// Ignore the trailing period in the parsed domain name.
				domainName.Truncate(domainName.Len() - 1)
				fn(domainName.String())
				break
			}

			// The label's length must not exceed the maximum length for a label.
			if labelLen > maxDomainNameLabelLength {
				return fmt.Errorf("label length of %d bytes is greater than the max label length of %d bytes for an NDP Search List option: %w", labelLen, maxDomainNameLabelLength, ErrNDPOptMalformedBody)
			}

			// The label (and trailing period) must not make the domain name too long.
			if labelLen+1 > domainName.Cap()-domainName.Len() {
				return fmt.Errorf("label would make an NDP Search List option's domain name longer than the max domain name length of %d bytes: %w", maxDomainNameLength, ErrNDPOptMalformedBody)
			}

			// Copy the label and add a trailing period.
			for i := 0; i < labelLen; i++ {
				b, err := searchList.ReadByte()
				if err != nil {
					if err != io.EOF {
						panic(fmt.Sprintf("unexpected error when reading domain name's label: %s", err))
					}

					return fmt.Errorf("read %d out of %d bytes for a domain name's label from NDP Search List option: %w", i, labelLen, io.ErrUnexpectedEOF)
				}

				// As per RFC 1035 section 2.3.1:
				//  1) the label must only contain ASCII include letters, digits and
				//     hyphens
				//  2) the first character in a label must be a letter
				//  3) the last letter in a label must be a letter or digit

				if !isLetter(b) {
					if i == 0 {
						return fmt.Errorf("first character of a domain name's label in an NDP Search List option must be a letter, got character code = %d: %w", b, ErrNDPOptMalformedBody)
					}

					if b == '-' {
						if i == labelLen-1 {
							return fmt.Errorf("last character of a domain name's label in an NDP Search List option must not be a hyphen (-): %w", ErrNDPOptMalformedBody)
						}
					} else if !isDigit(b) {
						return fmt.Errorf("domain name's label in an NDP Search List option may only contain letters, digits and hyphens, got character code = %d: %w", b, ErrNDPOptMalformedBody)
					}
				}

				// If b is an upper case character, make it lower case.
				if isUpperLetter(b) {
					b = b - 'A' + 'a'
				}

				if err := domainName.WriteByte(b); err != nil {
					panic(fmt.Sprintf("unexpected error writing label to domain name buffer: %s", err))
				}
			}
			if err := domainName.WriteByte('.'); err != nil {
				panic(fmt.Sprintf("unexpected error writing trailing period to domain name buffer: %s", err))
			}
		}
	}

	return nil
}

func isLetter(b byte) bool {
	return b >= 'a' && b <= 'z' || isUpperLetter(b)
}

func isUpperLetter(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// As per RFC 4191 section 2.3,
//
//  2.3.  Route Information Option
//
//      0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |     Type      |    Length     | Prefix Length |Resvd|Prf|Resvd|
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                        Route Lifetime                         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                   Prefix (Variable Length)                    |
//      .                                                               .
//      .                                                               .
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//   Fields:
//
//   Type        24
//
//
//   Length      8-bit unsigned integer.  The length of the option
//               (including the Type and Length fields) in units of 8
//               octets.  The Length field is 1, 2, or 3 depending on the
//               Prefix Length.  If Prefix Length is greater than 64, then
//               Length must be 3.  If Prefix Length is greater than 0,
//               then Length must be 2 or 3.  If Prefix Length is zero,
//               then Length must be 1, 2, or 3.
const (
	ndpRouteInformationType      = ndpOptionIdentifier(24)
	ndpRouteInformationMaxLength = 22

	ndpRouteInformationPrefixLengthIdx  = 0
	ndpRouteInformationFlagsIdx         = 1
	ndpRouteInformationPrfShift         = 3
	ndpRouteInformationPrfMask          = 3 << ndpRouteInformationPrfShift
	ndpRouteInformationRouteLifetimeIdx = 2
	ndpRouteInformationRoutePrefixIdx   = 6
)

// NDPRouteInformation is the NDP Router Information option, as defined by
// RFC 4191 section 2.3.
type NDPRouteInformation []byte

func (NDPRouteInformation) kind() ndpOptionIdentifier {
	return ndpRouteInformationType
}

func (o NDPRouteInformation) length() int {
	return len(o)
}

func (o NDPRouteInformation) serializeInto(b []byte) int {
	return copy(b, o)
}

// String implements fmt.Stringer.
func (o NDPRouteInformation) String() string {
	return fmt.Sprintf("%T", o)
}

// PrefixLength returns the length of the prefix.
func (o NDPRouteInformation) PrefixLength() uint8 {
	return o[ndpRouteInformationPrefixLengthIdx]
}

// RoutePreference returns the preference of the route over other routes to the
// same destination but through a different router.
func (o NDPRouteInformation) RoutePreference() NDPRoutePreference {
	return NDPRoutePreference((o[ndpRouteInformationFlagsIdx] & ndpRouteInformationPrfMask) >> ndpRouteInformationPrfShift)
}

// RouteLifetime returns the lifetime of the route.
//
// Note, a value of 0 implies the route is now invalid and a value of
// infinity/forever is represented by NDPInfiniteLifetime.
func (o NDPRouteInformation) RouteLifetime() time.Duration {
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpRouteInformationRouteLifetimeIdx:]))
}

// Prefix returns the prefix of the destination subnet this route is for.
func (o NDPRouteInformation) Prefix() (tcpip.Subnet, error) {
	prefixLength := int(o.PrefixLength())
	if max := IPv6AddressSize * 8; prefixLength > max {
		return tcpip.Subnet{}, fmt.Errorf("got prefix length = %d, want <= %d", prefixLength, max)
	}

	prefix := o[ndpRouteInformationRoutePrefixIdx:]
	var addrBytes [IPv6AddressSize]byte
	if n := copy(addrBytes[:], prefix); n != len(prefix) {
		panic(fmt.Sprintf("got copy(addrBytes, prefix) = %d, want = %d", n, len(prefix)))
	}

	return tcpip.AddressWithPrefix{
		Address:   tcpip.Address(addrBytes[:]),
		PrefixLen: prefixLength,
	}.Subnet(), nil
}

func (o NDPRouteInformation) hasError() error {
	l := len(o)
	if l < ndpRouteInformationRoutePrefixIdx {
		return fmt.Errorf("%T too small, got = %d bytes: %w", o, l, ErrNDPOptMalformedBody)
	}

	prefixLength := int(o.PrefixLength())
	if max := IPv6AddressSize * 8; prefixLength > max {
		return fmt.Errorf("got prefix length = %d, want <= %d: %w", prefixLength, max, ErrNDPOptMalformedBody)
	}

	//   Length      8-bit unsigned integer.  The length of the option
	//               (including the Type and Length fields) in units of 8
	//               octets.  The Length field is 1, 2, or 3 depending on the
	//               Prefix Length.  If Prefix Length is greater than 64, then
	//               Length must be 3.  If Prefix Length is greater than 0,
	//               then Length must be 2 or 3.  If Prefix Length is zero,
	//               then Length must be 1, 2, or 3.
	l += 2 // Add 2 bytes for the type and length bytes.
	lengthField := l / lengthByteUnits
	if prefixLength > 64 {
		if lengthField != 3 {
			return fmt.Errorf("Length field must be 3 when Prefix Length (%d) is > 64 (got = %d): %w", prefixLength, lengthField, ErrNDPOptMalformedBody)
		}
	} else if prefixLength > 0 {
		if lengthField != 2 && lengthField != 3 {
			return fmt.Errorf("Length field must be 2 or 3 when Prefix Length (%d) is between 0 and 64 (got = %d): %w", prefixLength, lengthField, ErrNDPOptMalformedBody)
		}
	} else if lengthField == 0 || lengthField > 3 {
		return fmt.Errorf("Length field must be 1, 2, or 3 when Prefix Length is zero (got = %d): %w", lengthField, ErrNDPOptMalformedBody)
	}

	return nil
}
