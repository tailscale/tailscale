// go-qrcode
// Copyright 2014 Tom Harwood

package qrcode

import (
	"errors"
	"log"

	bitset "github.com/skip2/go-qrcode/bitset"
)

// Data encoding.
//
// The main data portion of a QR Code consists of one or more segments of data.
// A segment consists of:
//
// - The segment Data Mode: numeric, alphanumeric, or byte.
// - The length of segment in bits.
// - Encoded data.
//
// For example, the string "123ZZ#!#!" may be represented as:
//
// [numeric, 3, "123"] [alphanumeric, 2, "ZZ"] [byte, 4, "#!#!"]
//
// Multiple data modes exist to minimise the size of encoded data. For example,
// 8-bit bytes require 8 bits to encode each, but base 10 numeric data can be
// encoded at a higher density of 3 numbers (e.g. 123) per 10 bits.
//
// Some data can be represented in multiple modes. Numeric data can be
// represented in all three modes, whereas alphanumeric data (e.g. 'A') can be
// represented in alphanumeric and byte mode.
//
// Starting a new segment (to use a different Data Mode) has a cost, the bits to
// state the new segment Data Mode and length. To minimise each QR Code's symbol
// size, an optimisation routine coalesces segment types where possible, to
// reduce the encoded data length.
//
// There are several other data modes available (e.g. Kanji mode) which are not
// implemented here.

// A segment encoding mode.
type dataMode uint8

const (
	// Each dataMode is a subset of the subsequent dataMode:
	// dataModeNone < dataModeNumeric < dataModeAlphanumeric < dataModeByte
	//
	// This ordering is important for determining which data modes a character can
	// be encoded with. E.g. 'E' can be encoded in both dataModeAlphanumeric and
	// dataModeByte.
	dataModeNone dataMode = 1 << iota
	dataModeNumeric
	dataModeAlphanumeric
	dataModeByte
)

// dataModeString returns d as a short printable string.
func dataModeString(d dataMode) string {
	switch d {
	case dataModeNone:
		return "none"
	case dataModeNumeric:
		return "numeric"
	case dataModeAlphanumeric:
		return "alphanumeric"
	case dataModeByte:
		return "byte"
	}

	return "unknown"
}

type dataEncoderType uint8

const (
	dataEncoderType1To9 dataEncoderType = iota
	dataEncoderType10To26
	dataEncoderType27To40
)

// segment is a single segment of data.
type segment struct {
	// Data Mode (e.g. numeric).
	dataMode dataMode

	// segment data (e.g. "abc").
	data []byte
}

// A dataEncoder encodes data for a particular QR Code version.
type dataEncoder struct {
	// Minimum & maximum versions supported.
	minVersion int
	maxVersion int

	// Mode indicator bit sequences.
	numericModeIndicator      *bitset.Bitset
	alphanumericModeIndicator *bitset.Bitset
	byteModeIndicator         *bitset.Bitset

	// Character count lengths.
	numNumericCharCountBits      int
	numAlphanumericCharCountBits int
	numByteCharCountBits         int

	// The raw input data.
	data []byte

	// The data classified into unoptimised segments.
	actual []segment

	// The data classified into optimised segments.
	optimised []segment
}

// newDataEncoder constructs a dataEncoder.
func newDataEncoder(t dataEncoderType) *dataEncoder {
	d := &dataEncoder{}

	switch t {
	case dataEncoderType1To9:
		d = &dataEncoder{
			minVersion:                   1,
			maxVersion:                   9,
			numericModeIndicator:         bitset.New(b0, b0, b0, b1),
			alphanumericModeIndicator:    bitset.New(b0, b0, b1, b0),
			byteModeIndicator:            bitset.New(b0, b1, b0, b0),
			numNumericCharCountBits:      10,
			numAlphanumericCharCountBits: 9,
			numByteCharCountBits:         8,
		}
	case dataEncoderType10To26:
		d = &dataEncoder{
			minVersion:                   10,
			maxVersion:                   26,
			numericModeIndicator:         bitset.New(b0, b0, b0, b1),
			alphanumericModeIndicator:    bitset.New(b0, b0, b1, b0),
			byteModeIndicator:            bitset.New(b0, b1, b0, b0),
			numNumericCharCountBits:      12,
			numAlphanumericCharCountBits: 11,
			numByteCharCountBits:         16,
		}
	case dataEncoderType27To40:
		d = &dataEncoder{
			minVersion:                   27,
			maxVersion:                   40,
			numericModeIndicator:         bitset.New(b0, b0, b0, b1),
			alphanumericModeIndicator:    bitset.New(b0, b0, b1, b0),
			byteModeIndicator:            bitset.New(b0, b1, b0, b0),
			numNumericCharCountBits:      14,
			numAlphanumericCharCountBits: 13,
			numByteCharCountBits:         16,
		}
	default:
		log.Panic("Unknown dataEncoderType")
	}

	return d
}

// encode data as one or more segments and return the encoded data.
//
// The returned data does not include the terminator bit sequence.
func (d *dataEncoder) encode(data []byte) (*bitset.Bitset, error) {
	d.data = data
	d.actual = nil
	d.optimised = nil

	if len(data) == 0 {
		return nil, errors.New("no data to encode")
	}

	// Classify data into unoptimised segments.
	highestRequiredMode := d.classifyDataModes()

	// Optimise segments.
	err := d.optimiseDataModes()
	if err != nil {
		return nil, err
	}

	// Check if a single byte encoded segment would be more efficient.
	optimizedLength := 0
	for _, s := range d.optimised {
		length, err := d.encodedLength(s.dataMode, len(s.data))
		if err != nil {
			return nil, err
		}
		optimizedLength += length
	}

	singleByteSegmentLength, err := d.encodedLength(highestRequiredMode, len(d.data))
	if err != nil {
		return nil, err
	}

	if singleByteSegmentLength <= optimizedLength {
		d.optimised = []segment{segment{dataMode: highestRequiredMode, data: d.data}}
	}

	// Encode data.
	encoded := bitset.New()
	for _, s := range d.optimised {
		d.encodeDataRaw(s.data, s.dataMode, encoded)
	}

	return encoded, nil
}

// classifyDataModes classifies the raw data into unoptimised segments.
// e.g. "123ZZ#!#!" =>
// [numeric, 3, "123"] [alphanumeric, 2, "ZZ"] [byte, 4, "#!#!"].
//
// Returns the highest data mode needed to encode the data. e.g. for a mixed
// numeric/alphanumeric input, the highest is alphanumeric.
//
// dataModeNone < dataModeNumeric < dataModeAlphanumeric < dataModeByte
func (d *dataEncoder) classifyDataModes() dataMode {
	var start int
	mode := dataModeNone
	highestRequiredMode := mode

	for i, v := range d.data {
		newMode := dataModeNone
		switch {
		case v >= 0x30 && v <= 0x39:
			newMode = dataModeNumeric
		case v == 0x20 || v == 0x24 || v == 0x25 || v == 0x2a || v == 0x2b || v ==
			0x2d || v == 0x2e || v == 0x2f || v == 0x3a || (v >= 0x41 && v <= 0x5a):
			newMode = dataModeAlphanumeric
		default:
			newMode = dataModeByte
		}

		if newMode != mode {
			if i > 0 {
				d.actual = append(d.actual, segment{dataMode: mode, data: d.data[start:i]})

				start = i
			}

			mode = newMode
		}

		if newMode > highestRequiredMode {
			highestRequiredMode = newMode
		}
	}

	d.actual = append(d.actual, segment{dataMode: mode, data: d.data[start:len(d.data)]})

	return highestRequiredMode
}

// optimiseDataModes optimises the list of segments to reduce the overall output
// encoded data length.
//
// The algorithm coalesces adjacent segments. segments are only coalesced when
// the Data Modes are compatible, and when the coalesced segment has a shorter
// encoded length than separate segments.
//
// Multiple segments may be coalesced. For example a string of alternating
// alphanumeric/numeric segments ANANANANA can be optimised to just A.
func (d *dataEncoder) optimiseDataModes() error {
	for i := 0; i < len(d.actual); {
		mode := d.actual[i].dataMode
		numChars := len(d.actual[i].data)

		j := i + 1
		for j < len(d.actual) {
			nextNumChars := len(d.actual[j].data)
			nextMode := d.actual[j].dataMode

			if nextMode > mode {
				break
			}

			coalescedLength, err := d.encodedLength(mode, numChars+nextNumChars)

			if err != nil {
				return err
			}

			seperateLength1, err := d.encodedLength(mode, numChars)

			if err != nil {
				return err
			}

			seperateLength2, err := d.encodedLength(nextMode, nextNumChars)

			if err != nil {
				return err
			}

			if coalescedLength < seperateLength1+seperateLength2 {
				j++
				numChars += nextNumChars
			} else {
				break
			}
		}

		optimised := segment{dataMode: mode,
			data: make([]byte, 0, numChars)}

		for k := i; k < j; k++ {
			optimised.data = append(optimised.data, d.actual[k].data...)
		}

		d.optimised = append(d.optimised, optimised)

		i = j
	}

	return nil
}

// encodeDataRaw encodes data in dataMode. The encoded data is appended to
// encoded.
func (d *dataEncoder) encodeDataRaw(data []byte, dataMode dataMode, encoded *bitset.Bitset) {
	modeIndicator := d.modeIndicator(dataMode)
	charCountBits := d.charCountBits(dataMode)

	// Append mode indicator.
	encoded.Append(modeIndicator)

	// Append character count.
	encoded.AppendUint32(uint32(len(data)), charCountBits)

	// Append data.
	switch dataMode {
	case dataModeNumeric:
		for i := 0; i < len(data); i += 3 {
			charsRemaining := len(data) - i

			var value uint32
			bitsUsed := 1

			for j := 0; j < charsRemaining && j < 3; j++ {
				value *= 10
				value += uint32(data[i+j] - 0x30)
				bitsUsed += 3
			}
			encoded.AppendUint32(value, bitsUsed)
		}
	case dataModeAlphanumeric:
		for i := 0; i < len(data); i += 2 {
			charsRemaining := len(data) - i

			var value uint32
			for j := 0; j < charsRemaining && j < 2; j++ {
				value *= 45
				value += encodeAlphanumericCharacter(data[i+j])
			}

			bitsUsed := 6
			if charsRemaining > 1 {
				bitsUsed = 11
			}

			encoded.AppendUint32(value, bitsUsed)
		}
	case dataModeByte:
		for _, b := range data {
			encoded.AppendByte(b, 8)
		}
	}
}

// modeIndicator returns the segment header bits for a segment of type dataMode.
func (d *dataEncoder) modeIndicator(dataMode dataMode) *bitset.Bitset {
	switch dataMode {
	case dataModeNumeric:
		return d.numericModeIndicator
	case dataModeAlphanumeric:
		return d.alphanumericModeIndicator
	case dataModeByte:
		return d.byteModeIndicator
	default:
		log.Panic("Unknown data mode")
	}

	return nil
}

// charCountBits returns the number of bits used to encode the length of a data
// segment of type dataMode.
func (d *dataEncoder) charCountBits(dataMode dataMode) int {
	switch dataMode {
	case dataModeNumeric:
		return d.numNumericCharCountBits
	case dataModeAlphanumeric:
		return d.numAlphanumericCharCountBits
	case dataModeByte:
		return d.numByteCharCountBits
	default:
		log.Panic("Unknown data mode")
	}

	return 0
}

// encodedLength returns the number of bits required to encode n symbols in
// dataMode.
//
// The number of bits required is affected by:
//	- QR code type - Mode Indicator length.
//	- Data mode - number of bits used to represent data length.
//	- Data mode - how the data is encoded.
//	- Number of symbols encoded.
//
// An error is returned if the mode is not supported, or the length requested is
// too long to be represented.
func (d *dataEncoder) encodedLength(dataMode dataMode, n int) (int, error) {
	modeIndicator := d.modeIndicator(dataMode)
	charCountBits := d.charCountBits(dataMode)

	if modeIndicator == nil {
		return 0, errors.New("mode not supported")
	}

	maxLength := (1 << uint8(charCountBits)) - 1

	if n > maxLength {
		return 0, errors.New("length too long to be represented")
	}

	length := modeIndicator.Len() + charCountBits

	switch dataMode {
	case dataModeNumeric:
		length += 10 * (n / 3)

		if n%3 != 0 {
			length += 1 + 3*(n%3)
		}
	case dataModeAlphanumeric:
		length += 11 * (n / 2)
		length += 6 * (n % 2)
	case dataModeByte:
		length += 8 * n
	}

	return length, nil
}

// encodeAlphanumericChar returns the QR Code encoded value of v.
//
// v must be a QR Code defined alphanumeric character: 0-9, A-Z, SP, $%*+-./ or
// :. The characters are mapped to values in the range 0-44 respectively.
func encodeAlphanumericCharacter(v byte) uint32 {
	c := uint32(v)

	switch {
	case c >= '0' && c <= '9':
		// 0-9 encoded as 0-9.
		return c - '0'
	case c >= 'A' && c <= 'Z':
		// A-Z encoded as 10-35.
		return c - 'A' + 10
	case c == ' ':
		return 36
	case c == '$':
		return 37
	case c == '%':
		return 38
	case c == '*':
		return 39
	case c == '+':
		return 40
	case c == '-':
		return 41
	case c == '.':
		return 42
	case c == '/':
		return 43
	case c == ':':
		return 44
	default:
		log.Panicf("encodeAlphanumericCharacter() with non alphanumeric char %v.", v)
	}

	return 0
}
