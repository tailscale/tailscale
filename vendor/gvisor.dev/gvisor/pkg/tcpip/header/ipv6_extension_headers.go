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
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// IPv6ExtensionHeaderIdentifier is an IPv6 extension header identifier.
type IPv6ExtensionHeaderIdentifier uint8

const (
	// IPv6HopByHopOptionsExtHdrIdentifier is the header identifier of a Hop by
	// Hop Options extension header, as per RFC 8200 section 4.3.
	IPv6HopByHopOptionsExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 0

	// IPv6RoutingExtHdrIdentifier is the header identifier of a Routing extension
	// header, as per RFC 8200 section 4.4.
	IPv6RoutingExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 43

	// IPv6FragmentExtHdrIdentifier is the header identifier of a Fragment
	// extension header, as per RFC 8200 section 4.5.
	IPv6FragmentExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 44

	// IPv6DestinationOptionsExtHdrIdentifier is the header identifier of a
	// Destination Options extension header, as per RFC 8200 section 4.6.
	IPv6DestinationOptionsExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 60

	// IPv6NoNextHeaderIdentifier is the header identifier used to signify the end
	// of an IPv6 payload, as per RFC 8200 section 4.7.
	IPv6NoNextHeaderIdentifier IPv6ExtensionHeaderIdentifier = 59

	// IPv6UnknownExtHdrIdentifier is reserved by IANA.
	// https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
	// "254	Use for experimentation and testing	[RFC3692][RFC4727]"
	IPv6UnknownExtHdrIdentifier IPv6ExtensionHeaderIdentifier = 254
)

const (
	// ipv6UnknownExtHdrOptionActionMask is the mask of the action to take when
	// a node encounters an unrecognized option.
	ipv6UnknownExtHdrOptionActionMask = 192

	// ipv6UnknownExtHdrOptionActionShift is the least significant bits to discard
	// from the action value for an unrecognized option identifier.
	ipv6UnknownExtHdrOptionActionShift = 6

	// ipv6RoutingExtHdrSegmentsLeftIdx is the index to the Segments Left field
	// within an IPv6RoutingExtHdr.
	ipv6RoutingExtHdrSegmentsLeftIdx = 1

	// IPv6FragmentExtHdrLength is the length of an IPv6 extension header, in
	// bytes.
	IPv6FragmentExtHdrLength = 8

	// ipv6FragmentExtHdrFragmentOffsetOffset is the offset to the start of the
	// Fragment Offset field within an IPv6FragmentExtHdr.
	ipv6FragmentExtHdrFragmentOffsetOffset = 0

	// ipv6FragmentExtHdrFragmentOffsetShift is the bit offset of the Fragment
	// Offset field within an IPv6FragmentExtHdr.
	ipv6FragmentExtHdrFragmentOffsetShift = 3

	// ipv6FragmentExtHdrFlagsIdx is the index to the flags field within an
	// IPv6FragmentExtHdr.
	ipv6FragmentExtHdrFlagsIdx = 1

	// ipv6FragmentExtHdrMFlagMask is the mask of the More (M) flag within the
	// flags field of an IPv6FragmentExtHdr.
	ipv6FragmentExtHdrMFlagMask = 1

	// ipv6FragmentExtHdrIdentificationOffset is the offset to the Identification
	// field within an IPv6FragmentExtHdr.
	ipv6FragmentExtHdrIdentificationOffset = 2

	// ipv6ExtHdrLenBytesPerUnit is the unit size of an extension header's length
	// field. That is, given a Length field of 2, the extension header expects
	// 16 bytes following the first 8 bytes (see ipv6ExtHdrLenBytesExcluded for
	// details about the first 8 bytes' exclusion from the Length field).
	ipv6ExtHdrLenBytesPerUnit = 8

	// ipv6ExtHdrLenBytesExcluded is the number of bytes excluded from an
	// extension header's Length field following the Length field.
	//
	// The Length field excludes the first 8 bytes, but the Next Header and Length
	// field take up the first 2 of the 8 bytes so we expect (at minimum) 6 bytes
	// after the Length field.
	//
	// This ensures that every extension header is at least 8 bytes.
	ipv6ExtHdrLenBytesExcluded = 6

	// IPv6FragmentExtHdrFragmentOffsetBytesPerUnit is the unit size of a Fragment
	// extension header's Fragment Offset field. That is, given a Fragment Offset
	// of 2, the extension header is indiciating that the fragment's payload
	// starts at the 16th byte in the reassembled packet.
	IPv6FragmentExtHdrFragmentOffsetBytesPerUnit = 8
)

// padIPv6OptionsLength returns the total length for IPv6 options of length l
// considering the 8-octet alignment as stated in RFC 8200 Section 4.2.
func padIPv6OptionsLength(length int) int {
	return (length + ipv6ExtHdrLenBytesPerUnit - 1) & ^(ipv6ExtHdrLenBytesPerUnit - 1)
}

// padIPv6Option fills b with the appropriate padding options depending on its
// length.
func padIPv6Option(b []byte) {
	switch len(b) {
	case 0: // No padding needed.
	case 1: // Pad with Pad1.
		b[ipv6ExtHdrOptionTypeOffset] = uint8(ipv6Pad1ExtHdrOptionIdentifier)
	default: // Pad with PadN.
		s := b[ipv6ExtHdrOptionPayloadOffset:]
		for i := range s {
			s[i] = 0
		}
		b[ipv6ExtHdrOptionTypeOffset] = uint8(ipv6PadNExtHdrOptionIdentifier)
		b[ipv6ExtHdrOptionLengthOffset] = uint8(len(s))
	}
}

// ipv6OptionsAlignmentPadding returns the number of padding bytes needed to
// serialize an option at headerOffset with alignment requirements
// [align]n + alignOffset.
func ipv6OptionsAlignmentPadding(headerOffset int, align int, alignOffset int) int {
	padLen := headerOffset - alignOffset
	return ((padLen + align - 1) & ^(align - 1)) - padLen
}

// IPv6PayloadHeader is implemented by the various headers that can be found
// in an IPv6 payload.
//
// These headers include IPv6 extension headers or upper layer data.
type IPv6PayloadHeader interface {
	isIPv6PayloadHeader()
}

// IPv6RawPayloadHeader the remainder of an IPv6 payload after an iterator
// encounters a Next Header field it does not recognize as an IPv6 extension
// header.
type IPv6RawPayloadHeader struct {
	Identifier IPv6ExtensionHeaderIdentifier
	Buf        buffer.VectorisedView
}

// isIPv6PayloadHeader implements IPv6PayloadHeader.isIPv6PayloadHeader.
func (IPv6RawPayloadHeader) isIPv6PayloadHeader() {}

// ipv6OptionsExtHdr is an IPv6 extension header that holds options.
type ipv6OptionsExtHdr []byte

// Iter returns an iterator over the IPv6 extension header options held in b.
func (b ipv6OptionsExtHdr) Iter() IPv6OptionsExtHdrOptionsIterator {
	it := IPv6OptionsExtHdrOptionsIterator{}
	it.reader.Reset(b)
	return it
}

// IPv6OptionsExtHdrOptionsIterator is an iterator over IPv6 extension header
// options.
//
// Note, between when an IPv6OptionsExtHdrOptionsIterator is obtained and last
// used, no changes to the underlying buffer may happen. Doing so may cause
// undefined and unexpected behaviour. It is fine to obtain an
// IPv6OptionsExtHdrOptionsIterator, iterate over the first few options then
// modify the backing payload so long as the IPv6OptionsExtHdrOptionsIterator
// obtained before modification is no longer used.
type IPv6OptionsExtHdrOptionsIterator struct {
	reader bytes.Reader

	// optionOffset is the number of bytes from the first byte of the
	// options field to the beginning of the current option.
	optionOffset uint32

	// nextOptionOffset is the offset of the next option.
	nextOptionOffset uint32
}

// OptionOffset returns the number of bytes parsed while processing the
// option field of the current Extension Header.
func (i *IPv6OptionsExtHdrOptionsIterator) OptionOffset() uint32 {
	return i.optionOffset
}

// IPv6OptionUnknownAction is the action that must be taken if the processing
// IPv6 node does not recognize the option, as outlined in RFC 8200 section 4.2.
type IPv6OptionUnknownAction int

const (
	// IPv6OptionUnknownActionSkip indicates that the unrecognized option must
	// be skipped and the node should continue processing the header.
	IPv6OptionUnknownActionSkip IPv6OptionUnknownAction = 0

	// IPv6OptionUnknownActionDiscard indicates that the packet must be silently
	// discarded.
	IPv6OptionUnknownActionDiscard IPv6OptionUnknownAction = 1

	// IPv6OptionUnknownActionDiscardSendICMP indicates that the packet must be
	// discarded and the node must send an ICMP Parameter Problem, Code 2, message
	// to the packet's source, regardless of whether or not the packet's
	// Destination was a multicast address.
	IPv6OptionUnknownActionDiscardSendICMP IPv6OptionUnknownAction = 2

	// IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest indicates that the
	// packet must be discarded and the node must send an ICMP Parameter Problem,
	// Code 2, message to the packet's source only if the packet's Destination was
	// not a multicast address.
	IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest IPv6OptionUnknownAction = 3
)

// IPv6ExtHdrOption is implemented by the various IPv6 extension header options.
type IPv6ExtHdrOption interface {
	// UnknownAction returns the action to take in response to an unrecognized
	// option.
	UnknownAction() IPv6OptionUnknownAction

	// isIPv6ExtHdrOption is used to "lock" this interface so it is not
	// implemented by other packages.
	isIPv6ExtHdrOption()
}

// IPv6ExtHdrOptionIdentifier is an IPv6 extension header option identifier.
type IPv6ExtHdrOptionIdentifier uint8

const (
	// ipv6Pad1ExtHdrOptionIdentifier is the identifier for a padding option that
	// provides 1 byte padding, as outlined in RFC 8200 section 4.2.
	ipv6Pad1ExtHdrOptionIdentifier IPv6ExtHdrOptionIdentifier = 0

	// ipv6PadBExtHdrOptionIdentifier is the identifier for a padding option that
	// provides variable length byte padding, as outlined in RFC 8200 section 4.2.
	ipv6PadNExtHdrOptionIdentifier IPv6ExtHdrOptionIdentifier = 1

	// ipv6RouterAlertHopByHopOptionIdentifier is the identifier for the Router
	// Alert Hop by Hop option as defined in RFC 2711 section 2.1.
	ipv6RouterAlertHopByHopOptionIdentifier IPv6ExtHdrOptionIdentifier = 5

	// ipv6ExtHdrOptionTypeOffset is the option type offset in an extension header
	// option as defined in RFC 8200 section 4.2.
	ipv6ExtHdrOptionTypeOffset = 0

	// ipv6ExtHdrOptionLengthOffset is the option length offset in an extension
	// header option as defined in RFC 8200 section 4.2.
	ipv6ExtHdrOptionLengthOffset = 1

	// ipv6ExtHdrOptionPayloadOffset is the option payload offset in an extension
	// header option as defined in RFC 8200 section 4.2.
	ipv6ExtHdrOptionPayloadOffset = 2
)

// ipv6UnknownActionFromIdentifier maps an extension header option's
// identifier's high  bits to the action to take when the identifier is unknown.
func ipv6UnknownActionFromIdentifier(id IPv6ExtHdrOptionIdentifier) IPv6OptionUnknownAction {
	return IPv6OptionUnknownAction((id & ipv6UnknownExtHdrOptionActionMask) >> ipv6UnknownExtHdrOptionActionShift)
}

// ErrMalformedIPv6ExtHdrOption indicates that an IPv6 extension header option
// is malformed.
var ErrMalformedIPv6ExtHdrOption = errors.New("malformed IPv6 extension header option")

// IPv6UnknownExtHdrOption holds the identifier and data for an IPv6 extension
// header option that is unknown by the parsing utilities.
type IPv6UnknownExtHdrOption struct {
	Identifier IPv6ExtHdrOptionIdentifier
	Data       []byte
}

// UnknownAction implements IPv6OptionUnknownAction.UnknownAction.
func (o *IPv6UnknownExtHdrOption) UnknownAction() IPv6OptionUnknownAction {
	return ipv6UnknownActionFromIdentifier(o.Identifier)
}

// isIPv6ExtHdrOption implements IPv6ExtHdrOption.isIPv6ExtHdrOption.
func (*IPv6UnknownExtHdrOption) isIPv6ExtHdrOption() {}

// Next returns the next option in the options data.
//
// If the next item is not a known extension header option,
// IPv6UnknownExtHdrOption will be returned with the option identifier and data.
//
// The return is of the format (option, done, error). done will be true when
// Next is unable to return anything because the iterator has reached the end of
// the options data, or an error occured.
func (i *IPv6OptionsExtHdrOptionsIterator) Next() (IPv6ExtHdrOption, bool, error) {
	for {
		i.optionOffset = i.nextOptionOffset
		temp, err := i.reader.ReadByte()
		if err != nil {
			// If we can't read the first byte of a new option, then we know the
			// options buffer has been exhausted and we are done iterating.
			return nil, true, nil
		}
		id := IPv6ExtHdrOptionIdentifier(temp)

		// If the option identifier indicates the option is a Pad1 option, then we
		// know the option does not have Length and Data fields. End processing of
		// the Pad1 option and continue processing the buffer as a new option.
		if id == ipv6Pad1ExtHdrOptionIdentifier {
			i.nextOptionOffset = i.optionOffset + 1
			continue
		}

		length, err := i.reader.ReadByte()
		if err != nil {
			if err != io.EOF {
				// ReadByte should only ever return nil or io.EOF.
				panic(fmt.Sprintf("unexpected error when reading the option's Length field for option with id = %d: %s", id, err))
			}

			// We use io.ErrUnexpectedEOF as exhausting the buffer is unexpected once
			// we start parsing an option; we expect the reader to contain enough
			// bytes for the whole option.
			return nil, true, fmt.Errorf("error when reading the option's Length field for option with id = %d: %w", id, io.ErrUnexpectedEOF)
		}

		// Do we have enough bytes in the reader for the next option?
		if n := i.reader.Len(); n < int(length) {
			// Reset the reader to effectively consume the remaining buffer.
			i.reader.Reset(nil)

			// We return the same error as if we failed to read a non-padding option
			// so consumers of this iterator don't need to differentiate between
			// padding and non-padding options.
			return nil, true, fmt.Errorf("read %d out of %d option data bytes for option with id = %d: %w", n, length, id, io.ErrUnexpectedEOF)
		}

		i.nextOptionOffset = i.optionOffset + uint32(length) + 1 /* option ID */ + 1 /* length byte */

		switch id {
		case ipv6PadNExtHdrOptionIdentifier:
			// Special-case the variable length padding option to avoid a copy.
			if _, err := i.reader.Seek(int64(length), io.SeekCurrent); err != nil {
				panic(fmt.Sprintf("error when skipping PadN (N = %d) option's data bytes: %s", length, err))
			}
			continue
		case ipv6RouterAlertHopByHopOptionIdentifier:
			var routerAlertValue [ipv6RouterAlertPayloadLength]byte
			if n, err := io.ReadFull(&i.reader, routerAlertValue[:]); err != nil {
				switch err {
				case io.EOF, io.ErrUnexpectedEOF:
					return nil, true, fmt.Errorf("got invalid length (%d) for router alert option (want = %d): %w", length, ipv6RouterAlertPayloadLength, ErrMalformedIPv6ExtHdrOption)
				default:
					return nil, true, fmt.Errorf("read %d out of %d option data bytes for router alert option: %w", n, ipv6RouterAlertPayloadLength, err)
				}
			} else if n != int(length) {
				return nil, true, fmt.Errorf("got invalid length (%d) for router alert option (want = %d): %w", length, ipv6RouterAlertPayloadLength, ErrMalformedIPv6ExtHdrOption)
			}
			return &IPv6RouterAlertOption{Value: IPv6RouterAlertValue(binary.BigEndian.Uint16(routerAlertValue[:]))}, false, nil
		default:
			bytes := make([]byte, length)
			if n, err := io.ReadFull(&i.reader, bytes); err != nil {
				// io.ReadFull may return io.EOF if i.reader has been exhausted. We use
				// io.ErrUnexpectedEOF instead as the io.EOF is unexpected given the
				// Length field found in the option.
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}

				return nil, true, fmt.Errorf("read %d out of %d option data bytes for option with id = %d: %w", n, length, id, err)
			}
			return &IPv6UnknownExtHdrOption{Identifier: id, Data: bytes}, false, nil
		}
	}
}

// IPv6HopByHopOptionsExtHdr is a buffer holding the Hop By Hop Options
// extension header.
type IPv6HopByHopOptionsExtHdr struct {
	ipv6OptionsExtHdr
}

// isIPv6PayloadHeader implements IPv6PayloadHeader.isIPv6PayloadHeader.
func (IPv6HopByHopOptionsExtHdr) isIPv6PayloadHeader() {}

// IPv6DestinationOptionsExtHdr is a buffer holding the Destination Options
// extension header.
type IPv6DestinationOptionsExtHdr struct {
	ipv6OptionsExtHdr
}

// isIPv6PayloadHeader implements IPv6PayloadHeader.isIPv6PayloadHeader.
func (IPv6DestinationOptionsExtHdr) isIPv6PayloadHeader() {}

// IPv6RoutingExtHdr is a buffer holding the Routing extension header specific
// data as outlined in RFC 8200 section 4.4.
type IPv6RoutingExtHdr []byte

// isIPv6PayloadHeader implements IPv6PayloadHeader.isIPv6PayloadHeader.
func (IPv6RoutingExtHdr) isIPv6PayloadHeader() {}

// SegmentsLeft returns the Segments Left field.
func (b IPv6RoutingExtHdr) SegmentsLeft() uint8 {
	return b[ipv6RoutingExtHdrSegmentsLeftIdx]
}

// IPv6FragmentExtHdr is a buffer holding the Fragment extension header specific
// data as outlined in RFC 8200 section 4.5.
//
// Note, the buffer does not include the Next Header and Reserved fields.
type IPv6FragmentExtHdr [6]byte

// isIPv6PayloadHeader implements IPv6PayloadHeader.isIPv6PayloadHeader.
func (IPv6FragmentExtHdr) isIPv6PayloadHeader() {}

// FragmentOffset returns the Fragment Offset field.
//
// This value indicates where the buffer following the Fragment extension header
// starts in the target (reassembled) packet.
func (b IPv6FragmentExtHdr) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[ipv6FragmentExtHdrFragmentOffsetOffset:]) >> ipv6FragmentExtHdrFragmentOffsetShift
}

// More returns the More (M) flag.
//
// This indicates whether any fragments are expected to succeed b.
func (b IPv6FragmentExtHdr) More() bool {
	return b[ipv6FragmentExtHdrFlagsIdx]&ipv6FragmentExtHdrMFlagMask != 0
}

// ID returns the Identification field.
//
// This value is used to uniquely identify the packet, between a
// souce and destination.
func (b IPv6FragmentExtHdr) ID() uint32 {
	return binary.BigEndian.Uint32(b[ipv6FragmentExtHdrIdentificationOffset:])
}

// IsAtomic returns whether the fragment header indicates an atomic fragment. An
// atomic fragment is a fragment that contains all the data required to
// reassemble a full packet.
func (b IPv6FragmentExtHdr) IsAtomic() bool {
	return !b.More() && b.FragmentOffset() == 0
}

// IPv6PayloadIterator is an iterator over the contents of an IPv6 payload.
//
// The IPv6 payload may contain IPv6 extension headers before any upper layer
// data.
//
// Note, between when an IPv6PayloadIterator is obtained and last used, no
// changes to the payload may happen. Doing so may cause undefined and
// unexpected behaviour. It is fine to obtain an IPv6PayloadIterator, iterate
// over the first few headers then modify the backing payload so long as the
// IPv6PayloadIterator obtained before modification is no longer used.
type IPv6PayloadIterator struct {
	// The identifier of the next header to parse.
	nextHdrIdentifier IPv6ExtensionHeaderIdentifier

	// reader is an io.Reader over payload.
	reader  bufio.Reader
	payload buffer.VectorisedView

	// Indicates to the iterator that it should return the remaining payload as a
	// raw payload on the next call to Next.
	forceRaw bool

	// headerOffset is the offset of the beginning of the current extension
	// header starting from the beginning of the fixed header.
	headerOffset uint32

	// parseOffset is the byte offset into the current extension header of the
	// field we are currently examining. It can be added to the header offset
	// if the absolute offset within the packet is required.
	parseOffset uint32

	// nextOffset is the offset of the next header.
	nextOffset uint32
}

// HeaderOffset returns the offset to the start of the extension
// header most recently processed.
func (i IPv6PayloadIterator) HeaderOffset() uint32 {
	return i.headerOffset
}

// ParseOffset returns the number of bytes successfully parsed.
func (i IPv6PayloadIterator) ParseOffset() uint32 {
	return i.headerOffset + i.parseOffset
}

// MakeIPv6PayloadIterator returns an iterator over the IPv6 payload containing
// extension headers, or a raw payload if the payload cannot be parsed.
func MakeIPv6PayloadIterator(nextHdrIdentifier IPv6ExtensionHeaderIdentifier, payload buffer.VectorisedView) IPv6PayloadIterator {
	readers := payload.Readers()
	readerPs := make([]io.Reader, 0, len(readers))
	for i := range readers {
		readerPs = append(readerPs, &readers[i])
	}

	return IPv6PayloadIterator{
		nextHdrIdentifier: nextHdrIdentifier,
		payload:           payload.Clone(nil),
		// We need a buffer of size 1 for calls to bufio.Reader.ReadByte.
		reader:     *bufio.NewReaderSize(io.MultiReader(readerPs...), 1),
		nextOffset: IPv6FixedHeaderSize,
	}
}

// AsRawHeader returns the remaining payload of i as a raw header and
// optionally consumes the iterator.
//
// If consume is true, calls to Next after calling AsRawHeader on i will
// indicate that the iterator is done.
func (i *IPv6PayloadIterator) AsRawHeader(consume bool) IPv6RawPayloadHeader {
	identifier := i.nextHdrIdentifier

	var buf buffer.VectorisedView
	if consume {
		// Since we consume the iterator, we return the payload as is.
		buf = i.payload

		// Mark i as done, but keep track of where we were for error reporting.
		*i = IPv6PayloadIterator{
			nextHdrIdentifier: IPv6NoNextHeaderIdentifier,
			headerOffset:      i.headerOffset,
			nextOffset:        i.nextOffset,
		}
	} else {
		buf = i.payload.Clone(nil)
	}

	return IPv6RawPayloadHeader{Identifier: identifier, Buf: buf}
}

// Next returns the next item in the payload.
//
// If the next item is not a known IPv6 extension header, IPv6RawPayloadHeader
// will be returned with the remaining bytes and next header identifier.
//
// The return is of the format (header, done, error). done will be true when
// Next is unable to return anything because the iterator has reached the end of
// the payload, or an error occured.
func (i *IPv6PayloadIterator) Next() (IPv6PayloadHeader, bool, error) {
	i.headerOffset = i.nextOffset
	i.parseOffset = 0
	// We could be forced to return i as a raw header when the previous header was
	// a fragment extension header as the data following the fragment extension
	// header may not be complete.
	if i.forceRaw {
		return i.AsRawHeader(true /* consume */), false, nil
	}

	// Is the header we are parsing a known extension header?
	switch i.nextHdrIdentifier {
	case IPv6HopByHopOptionsExtHdrIdentifier:
		nextHdrIdentifier, bytes, err := i.nextHeaderData(false /* fragmentHdr */, nil)
		if err != nil {
			return nil, true, err
		}

		i.nextHdrIdentifier = nextHdrIdentifier
		return IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr: bytes}, false, nil
	case IPv6RoutingExtHdrIdentifier:
		nextHdrIdentifier, bytes, err := i.nextHeaderData(false /* fragmentHdr */, nil)
		if err != nil {
			return nil, true, err
		}

		i.nextHdrIdentifier = nextHdrIdentifier
		return IPv6RoutingExtHdr(bytes), false, nil
	case IPv6FragmentExtHdrIdentifier:
		var data [6]byte
		// We ignore the returned bytes because we know the fragment extension
		// header specific data will fit in data.
		nextHdrIdentifier, _, err := i.nextHeaderData(true /* fragmentHdr */, data[:])
		if err != nil {
			return nil, true, err
		}

		fragmentExtHdr := IPv6FragmentExtHdr(data)

		// If the packet is not the first fragment, do not attempt to parse anything
		// after the fragment extension header as the payload following the fragment
		// extension header should not contain any headers; the first fragment must
		// hold all the headers up to and including any upper layer headers, as per
		// RFC 8200 section 4.5.
		if fragmentExtHdr.FragmentOffset() != 0 {
			i.forceRaw = true
		}

		i.nextHdrIdentifier = nextHdrIdentifier
		return fragmentExtHdr, false, nil
	case IPv6DestinationOptionsExtHdrIdentifier:
		nextHdrIdentifier, bytes, err := i.nextHeaderData(false /* fragmentHdr */, nil)
		if err != nil {
			return nil, true, err
		}

		i.nextHdrIdentifier = nextHdrIdentifier
		return IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr: bytes}, false, nil
	case IPv6NoNextHeaderIdentifier:
		// This indicates the end of the IPv6 payload.
		return nil, true, nil

	default:
		// The header we are parsing is not a known extension header. Return the
		// raw payload.
		return i.AsRawHeader(true /* consume */), false, nil
	}
}

// nextHeaderData returns the extension header's Next Header field and raw data.
//
// fragmentHdr indicates that the extension header being parsed is the Fragment
// extension header so the Length field should be ignored as it is Reserved
// for the Fragment extension header.
//
// If bytes is not nil, extension header specific data will be read into bytes
// if it has enough capacity. If bytes is provided but does not have enough
// capacity for the data, nextHeaderData will panic.
func (i *IPv6PayloadIterator) nextHeaderData(fragmentHdr bool, bytes []byte) (IPv6ExtensionHeaderIdentifier, []byte, error) {
	// We ignore the number of bytes read because we know we will only ever read
	// at max 1 bytes since rune has a length of 1. If we read 0 bytes, the Read
	// would return io.EOF to indicate that io.Reader has reached the end of the
	// payload.
	nextHdrIdentifier, err := i.reader.ReadByte()
	i.payload.TrimFront(1)
	if err != nil {
		return 0, nil, fmt.Errorf("error when reading the Next Header field for extension header with id = %d: %w", i.nextHdrIdentifier, err)
	}
	i.parseOffset++

	var length uint8
	length, err = i.reader.ReadByte()
	i.payload.TrimFront(1)

	if err != nil {
		if fragmentHdr {
			return 0, nil, fmt.Errorf("error when reading the Length field for extension header with id = %d: %w", i.nextHdrIdentifier, err)
		}

		return 0, nil, fmt.Errorf("error when reading the Reserved field for extension header with id = %d: %w", i.nextHdrIdentifier, err)
	}
	if fragmentHdr {
		length = 0
	}

	// Make parseOffset point to the first byte of the Extension Header
	// specific data.
	i.parseOffset++

	// length is in 8 byte chunks but doesn't include the first one.
	// See RFC 8200 for each header type, sections 4.3-4.6 and the requirement
	// in section 4.8 for new extension headers at the top of page 24.
	//   [ Hdr Ext Len ] ... Length of the Destination Options header in 8-octet
	//   units, not including the first 8 octets.
	i.nextOffset += uint32((length + 1) * ipv6ExtHdrLenBytesPerUnit)

	bytesLen := int(length)*ipv6ExtHdrLenBytesPerUnit + ipv6ExtHdrLenBytesExcluded
	if bytes == nil {
		bytes = make([]byte, bytesLen)
	} else if n := len(bytes); n < bytesLen {
		panic(fmt.Sprintf("bytes only has space for %d bytes but need space for %d bytes (length = %d) for extension header with id = %d", n, bytesLen, length, i.nextHdrIdentifier))
	}

	n, err := io.ReadFull(&i.reader, bytes)
	i.payload.TrimFront(n)
	if err != nil {
		return 0, nil, fmt.Errorf("read %d out of %d extension header data bytes (length = %d) for header with id = %d: %w", n, bytesLen, length, i.nextHdrIdentifier, err)
	}

	return IPv6ExtensionHeaderIdentifier(nextHdrIdentifier), bytes, nil
}

// IPv6SerializableExtHdr provides serialization for IPv6 extension
// headers.
type IPv6SerializableExtHdr interface {
	// identifier returns the assigned IPv6 header identifier for this extension
	// header.
	identifier() IPv6ExtensionHeaderIdentifier

	// length returns the total serialized length in bytes of this extension
	// header, including the common next header and length fields.
	length() int

	// serializeInto serializes the receiver into the provided byte
	// buffer and with the provided nextHeader value.
	//
	// Note, the caller MUST provide a byte buffer with size of at least
	// length. Implementers of this function may assume that the byte buffer
	// is of sufficient size. serializeInto MAY panic if the provided byte
	// buffer is not of sufficient size.
	//
	// serializeInto returns the number of bytes that was used to serialize the
	// receiver. Implementers must only use the number of bytes required to
	// serialize the receiver. Callers MAY provide a larger buffer than required
	// to serialize into.
	serializeInto(nextHeader uint8, b []byte) int
}

var _ IPv6SerializableExtHdr = (*IPv6SerializableHopByHopExtHdr)(nil)

// IPv6SerializableHopByHopExtHdr implements serialization of the Hop by Hop
// options extension header.
type IPv6SerializableHopByHopExtHdr []IPv6SerializableHopByHopOption

const (
	// ipv6HopByHopExtHdrNextHeaderOffset is the offset of the next header field
	// in a hop by hop extension header as defined in RFC 8200 section 4.3.
	ipv6HopByHopExtHdrNextHeaderOffset = 0

	// ipv6HopByHopExtHdrLengthOffset is the offset of the length field in a hop
	// by hop extension header as defined in RFC 8200 section 4.3.
	ipv6HopByHopExtHdrLengthOffset = 1

	// ipv6HopByHopExtHdrPayloadOffset is the offset of the options in a hop by
	// hop extension header as defined in RFC 8200 section 4.3.
	ipv6HopByHopExtHdrOptionsOffset = 2

	// ipv6HopByHopExtHdrUnaccountedLenWords is the implicit number of 8-octet
	// words in a hop by hop extension header's length field, as stated in RFC
	// 8200 section 4.3:
	//   Length of the Hop-by-Hop Options header in 8-octet units,
	//   not including the first 8 octets.
	ipv6HopByHopExtHdrUnaccountedLenWords = 1
)

// identifier implements IPv6SerializableExtHdr.
func (IPv6SerializableHopByHopExtHdr) identifier() IPv6ExtensionHeaderIdentifier {
	return IPv6HopByHopOptionsExtHdrIdentifier
}

// length implements IPv6SerializableExtHdr.
func (h IPv6SerializableHopByHopExtHdr) length() int {
	var total int
	for _, opt := range h {
		align, alignOffset := opt.alignment()
		total += ipv6OptionsAlignmentPadding(total, align, alignOffset)
		total += ipv6ExtHdrOptionPayloadOffset + int(opt.length())
	}
	// Account for next header and total length fields and add padding.
	return padIPv6OptionsLength(ipv6HopByHopExtHdrOptionsOffset + total)
}

// serializeInto implements IPv6SerializableExtHdr.
func (h IPv6SerializableHopByHopExtHdr) serializeInto(nextHeader uint8, b []byte) int {
	optBuffer := b[ipv6HopByHopExtHdrOptionsOffset:]
	totalLength := ipv6HopByHopExtHdrOptionsOffset
	for _, opt := range h {
		// Calculate alignment requirements and pad buffer if necessary.
		align, alignOffset := opt.alignment()
		padLen := ipv6OptionsAlignmentPadding(totalLength, align, alignOffset)
		if padLen != 0 {
			padIPv6Option(optBuffer[:padLen])
			totalLength += padLen
			optBuffer = optBuffer[padLen:]
		}

		l := opt.serializeInto(optBuffer[ipv6ExtHdrOptionPayloadOffset:])
		optBuffer[ipv6ExtHdrOptionTypeOffset] = uint8(opt.identifier())
		optBuffer[ipv6ExtHdrOptionLengthOffset] = l
		l += ipv6ExtHdrOptionPayloadOffset
		totalLength += int(l)
		optBuffer = optBuffer[l:]
	}
	padded := padIPv6OptionsLength(totalLength)
	if padded != totalLength {
		padIPv6Option(optBuffer[:padded-totalLength])
		totalLength = padded
	}
	wordsLen := totalLength/ipv6ExtHdrLenBytesPerUnit - ipv6HopByHopExtHdrUnaccountedLenWords
	if wordsLen > math.MaxUint8 {
		panic(fmt.Sprintf("IPv6 hop by hop options too large: %d+1 64-bit words", wordsLen))
	}
	b[ipv6HopByHopExtHdrNextHeaderOffset] = nextHeader
	b[ipv6HopByHopExtHdrLengthOffset] = uint8(wordsLen)
	return totalLength
}

// IPv6SerializableHopByHopOption provides serialization for hop by hop options.
type IPv6SerializableHopByHopOption interface {
	// identifier returns the option identifier of this Hop by Hop option.
	identifier() IPv6ExtHdrOptionIdentifier

	// length returns the *payload* size of the option (not considering the type
	// and length fields).
	length() uint8

	// alignment returns the alignment requirements from this option.
	//
	// Alignment requirements take the form [align]n + offset as specified in
	// RFC 8200 section 4.2. The alignment requirement is on the offset between
	// the option type byte and the start of the hop by hop header.
	//
	// align must be a power of 2.
	alignment() (align int, offset int)

	// serializeInto serializes the receiver into the provided byte
	// buffer.
	//
	// Note, the caller MUST provide a byte buffer with size of at least
	// length. Implementers of this function may assume that the byte buffer
	// is of sufficient size. serializeInto MAY panic if the provided byte
	// buffer is not of sufficient size.
	//
	// serializeInto will return the number of bytes that was used to
	// serialize the receiver. Implementers must only use the number of
	// bytes required to serialize the receiver. Callers MAY provide a
	// larger buffer than required to serialize into.
	serializeInto([]byte) uint8
}

var _ IPv6SerializableHopByHopOption = (*IPv6RouterAlertOption)(nil)

// IPv6RouterAlertOption is the IPv6 Router alert Hop by Hop option defined in
// RFC 2711 section 2.1.
type IPv6RouterAlertOption struct {
	Value IPv6RouterAlertValue
}

// IPv6RouterAlertValue is the payload of an IPv6 Router Alert option.
type IPv6RouterAlertValue uint16

const (
	// IPv6RouterAlertMLD indicates a datagram containing a Multicast Listener
	// Discovery message as defined in RFC 2711 section 2.1.
	IPv6RouterAlertMLD IPv6RouterAlertValue = 0
	// IPv6RouterAlertRSVP indicates a datagram containing an RSVP message as
	// defined in RFC 2711 section 2.1.
	IPv6RouterAlertRSVP IPv6RouterAlertValue = 1
	// IPv6RouterAlertActiveNetworks indicates a datagram containing an Active
	// Networks message as defined in RFC 2711 section 2.1.
	IPv6RouterAlertActiveNetworks IPv6RouterAlertValue = 2

	// ipv6RouterAlertPayloadLength is the length of the Router Alert payload
	// as defined in RFC 2711.
	ipv6RouterAlertPayloadLength = 2

	// ipv6RouterAlertAlignmentRequirement is the alignment requirement for the
	// Router Alert option defined as 2n+0 in RFC 2711.
	ipv6RouterAlertAlignmentRequirement = 2

	// ipv6RouterAlertAlignmentOffsetRequirement is the alignment offset
	// requirement for the Router Alert option defined as 2n+0 in RFC 2711 section
	// 2.1.
	ipv6RouterAlertAlignmentOffsetRequirement = 0
)

// UnknownAction implements IPv6ExtHdrOption.
func (*IPv6RouterAlertOption) UnknownAction() IPv6OptionUnknownAction {
	return ipv6UnknownActionFromIdentifier(ipv6RouterAlertHopByHopOptionIdentifier)
}

// isIPv6ExtHdrOption implements IPv6ExtHdrOption.
func (*IPv6RouterAlertOption) isIPv6ExtHdrOption() {}

// identifier implements IPv6SerializableHopByHopOption.
func (*IPv6RouterAlertOption) identifier() IPv6ExtHdrOptionIdentifier {
	return ipv6RouterAlertHopByHopOptionIdentifier
}

// length implements IPv6SerializableHopByHopOption.
func (*IPv6RouterAlertOption) length() uint8 {
	return ipv6RouterAlertPayloadLength
}

// alignment implements IPv6SerializableHopByHopOption.
func (*IPv6RouterAlertOption) alignment() (int, int) {
	// From RFC 2711 section 2.1:
	//   Alignment requirement: 2n+0.
	return ipv6RouterAlertAlignmentRequirement, ipv6RouterAlertAlignmentOffsetRequirement
}

// serializeInto implements IPv6SerializableHopByHopOption.
func (o *IPv6RouterAlertOption) serializeInto(b []byte) uint8 {
	binary.BigEndian.PutUint16(b, uint16(o.Value))
	return ipv6RouterAlertPayloadLength
}

// IPv6ExtHdrSerializer provides serialization of IPv6 extension headers.
type IPv6ExtHdrSerializer []IPv6SerializableExtHdr

// Serialize serializes the provided list of IPv6 extension headers into b.
//
// Note, b must be of sufficient size to hold all the headers in s. See
// IPv6ExtHdrSerializer.Length for details on the getting the total size of a
// serialized IPv6ExtHdrSerializer.
//
// Serialize may panic if b is not of sufficient size to hold all the options
// in s.
//
// Serialize takes the transportProtocol value to be used as the last extension
// header's Next Header value and returns the header identifier of the first
// serialized extension header and the total serialized length.
func (s IPv6ExtHdrSerializer) Serialize(transportProtocol tcpip.TransportProtocolNumber, b []byte) (uint8, int) {
	nextHeader := uint8(transportProtocol)
	if len(s) == 0 {
		return nextHeader, 0
	}
	var totalLength int
	for i, h := range s[:len(s)-1] {
		length := h.serializeInto(uint8(s[i+1].identifier()), b)
		b = b[length:]
		totalLength += length
	}
	totalLength += s[len(s)-1].serializeInto(nextHeader, b)
	return uint8(s[0].identifier()), totalLength
}

// Length returns the total number of bytes required to serialize the extension
// headers.
func (s IPv6ExtHdrSerializer) Length() int {
	var totalLength int
	for _, h := range s {
		totalLength += h.length()
	}
	return totalLength
}
