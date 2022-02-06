package dhcpv4

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/u-root/uio/uio"
)

var (
	// ErrShortByteStream is an error that is thrown any time a short byte stream is
	// detected during option parsing.
	ErrShortByteStream = errors.New("short byte stream")

	// ErrZeroLengthByteStream is an error that is thrown any time a zero-length
	// byte stream is encountered.
	ErrZeroLengthByteStream = errors.New("zero-length byte stream")

	// ErrInvalidOptions is returned when invalid options data is
	// encountered during parsing. The data could report an incorrect
	// length or have trailing bytes which are not part of the option.
	ErrInvalidOptions = errors.New("invalid options data")
)

// OptionValue is an interface that all DHCP v4 options adhere to.
type OptionValue interface {
	ToBytes() []byte
	String() string
}

// Option is a DHCPv4 option and consists of a 1-byte option code and a value
// stream of bytes.
//
// The value is to be interpreted based on the option code.
type Option struct {
	Code  OptionCode
	Value OptionValue
}

// String returns a human-readable version of this option.
func (o Option) String() string {
	v := o.Value.String()
	if strings.Contains(v, "\n") {
		return fmt.Sprintf("%s:\n%s", o.Code, v)
	}
	return fmt.Sprintf("%s: %s", o.Code, v)
}

// Options is a collection of options.
type Options map[uint8][]byte

// OptionsFromList adds all given options to an options map.
func OptionsFromList(o ...Option) Options {
	opts := make(Options)
	for _, opt := range o {
		opts.Update(opt)
	}
	return opts
}

// Get will attempt to get all options that match a DHCPv4 option
// from its OptionCode.  If the option was not found it will return an
// empty list.
//
// According to RFC 3396, options that are specified more than once are
// concatenated, and hence this should always just return one option. This
// currently returns a list to be API compatible.
func (o Options) Get(code OptionCode) []byte {
	return o[code.Code()]
}

// Has checks whether o has the given opcode.
func (o Options) Has(opcode OptionCode) bool {
	_, ok := o[opcode.Code()]
	return ok
}

// Update updates the existing options with the passed option, adding it
// at the end if not present already
func (o Options) Update(option Option) {
	o[option.Code.Code()] = option.Value.ToBytes()
}

// ToBytes makes Options usable as an OptionValue as well.
//
// Used in the case of vendor-specific and relay agent options.
func (o Options) ToBytes() []byte {
	return uio.ToBigEndian(o)
}

// FromBytes parses a sequence of bytes until the end and builds a list of
// options from it.
//
// The sequence should not contain the DHCP magic cookie.
//
// Returns an error if any invalid option or length is found.
func (o Options) FromBytes(data []byte) error {
	return o.fromBytesCheckEnd(data, false)
}

const (
	optPad = 0
	optEnd = 255
)

// FromBytesCheckEnd parses Options from byte sequences using the
// parsing function that is passed in as a paremeter
func (o Options) fromBytesCheckEnd(data []byte, checkEndOption bool) error {
	if len(data) == 0 {
		return nil
	}
	buf := uio.NewBigEndianBuffer(data)

	var end bool
	for buf.Len() >= 1 {
		// 1 byte: option code
		// 1 byte: option length n
		// n bytes: data
		code := buf.Read8()

		if code == optPad {
			continue
		} else if code == optEnd {
			end = true
			break
		}
		length := int(buf.Read8())

		// N bytes: option data
		data := buf.Consume(length)
		if data == nil {
			return fmt.Errorf("error collecting options: %v", buf.Error())
		}
		data = data[:length:length]

		// RFC 2131, Section 4.1 "Options may appear only once, [...].
		// The client concatenates the values of multiple instances of
		// the same option into a single parameter list for
		// configuration."
		//
		// See also RFC 3396 for concatenation order and options longer
		// than 255 bytes.
		o[code] = append(o[code], data...)
	}

	// If we never read the End option, the sender of this packet screwed
	// up.
	if !end && checkEndOption {
		return io.ErrUnexpectedEOF
	}

	// Any bytes left must be padding.
	var pad uint8
	for buf.Len() >= 1 {
		pad = buf.Read8()
		if pad != optPad && pad != optEnd {
			return ErrInvalidOptions
		}
	}
	return nil
}

// sortedKeys returns an ordered slice of option keys from the Options map, for
// use in serializing options to binary.
func (o Options) sortedKeys() []int {
	// Send all values for a given key
	var codes []int
	for k := range o {
		codes = append(codes, int(k))
	}

	sort.Ints(codes)
	return codes
}

// Marshal writes options binary representations to b.
func (o Options) Marshal(b *uio.Lexer) {
	for _, c := range o.sortedKeys() {
		code := uint8(c)
		// Even if the End option is in there, don't marshal it until
		// the end.
		// Don't write padding either, since the options are sorted
		// it would always be written first which isn't useful
		if code == optEnd || code == optPad {
			continue
		}

		data := o[code]

		// Ensure even 0-length options are written out
		if len(data) == 0 {
			b.Write8(code)
			b.Write8(0)
			continue
		}
		// RFC 3396: If more than 256 bytes of data are given, the
		// option is simply listed multiple times.
		for len(data) > 0 {
			// 1 byte: option code
			b.Write8(code)

			n := len(data)
			if n > math.MaxUint8 {
				n = math.MaxUint8
			}

			// 1 byte: option length
			b.Write8(uint8(n))

			// N bytes: option data
			b.WriteBytes(data[:n])
			data = data[n:]
		}
	}
}

// String prints options using DHCP-specified option codes.
func (o Options) String() string {
	return o.ToString(dhcpHumanizer)
}

// Summary prints options in human-readable values.
//
// Summary uses vendorParser to interpret the OptionVendorSpecificInformation option.
func (o Options) Summary(vendorDecoder OptionDecoder) string {
	return o.ToString(OptionHumanizer{
		ValueHumanizer: parserFor(vendorDecoder),
		CodeHumanizer: func(c uint8) OptionCode {
			return optionCode(c)
		},
	})
}

// OptionParser gives a human-legible interpretation of data for the given option code.
type OptionParser func(code OptionCode, data []byte) fmt.Stringer

// OptionHumanizer is used to interpret a set of Options for their option code
// name and values.
//
// There should be separate OptionHumanizers for each Option "space": DHCP,
// BSDP, Relay Agent Info, and others.
type OptionHumanizer struct {
	ValueHumanizer OptionParser
	CodeHumanizer  func(code uint8) OptionCode
}

// Stringify returns a human-readable interpretation of the option code and its
// associated data.
func (oh OptionHumanizer) Stringify(code uint8, data []byte) string {
	c := oh.CodeHumanizer(code)
	val := oh.ValueHumanizer(c, data)
	return fmt.Sprintf("%s: %s", c, val)
}

// dhcpHumanizer humanizes the set of DHCP option codes.
var dhcpHumanizer = OptionHumanizer{
	ValueHumanizer: parseOption,
	CodeHumanizer: func(c uint8) OptionCode {
		return optionCode(c)
	},
}

// ToString uses parse to parse options into human-readable values.
func (o Options) ToString(humanizer OptionHumanizer) string {
	var ret string
	for _, c := range o.sortedKeys() {
		code := uint8(c)
		v := o[code]
		optString := humanizer.Stringify(code, v)
		// If this option has sub structures, offset them accordingly.
		if strings.Contains(optString, "\n") {
			optString = strings.Replace(optString, "\n  ", "\n      ", -1)
		}
		ret += fmt.Sprintf("    %v\n", optString)
	}
	return ret
}

func parseOption(code OptionCode, data []byte) fmt.Stringer {
	return parserFor(nil)(code, data)
}

func parserFor(vendorParser OptionDecoder) OptionParser {
	return func(code OptionCode, data []byte) fmt.Stringer {
		return getOption(code, data, vendorParser)
	}
}

// OptionDecoder can decode a byte stream into a human-readable option.
type OptionDecoder interface {
	fmt.Stringer
	FromBytes([]byte) error
}

func getOption(code OptionCode, data []byte, vendorDecoder OptionDecoder) fmt.Stringer {
	var d OptionDecoder
	switch code {
	case OptionRouter, OptionDomainNameServer, OptionNTPServers, OptionServerIdentifier:
		d = &IPs{}

	case OptionBroadcastAddress, OptionRequestedIPAddress:
		d = &IP{}

	case OptionClientSystemArchitectureType:
		d = &iana.Archs{}

	case OptionSubnetMask:
		d = &IPMask{}

	case OptionDHCPMessageType:
		var mt MessageType
		d = &mt

	case OptionParameterRequestList:
		d = &OptionCodeList{}

	case OptionHostName, OptionDomainName, OptionRootPath,
		OptionClassIdentifier, OptionTFTPServerName, OptionBootfileName:
		var s String
		d = &s

	case OptionRelayAgentInformation:
		d = &RelayOptions{}

	case OptionDNSDomainSearchList:
		d = &rfc1035label.Labels{}

	case OptionIPAddressLeaseTime:
		var dur Duration
		d = &dur

	case OptionMaximumDHCPMessageSize:
		var u Uint16
		d = &u

	case OptionUserClassInformation:
		var s Strings
		d = &s
		if s.FromBytes(data) != nil {
			var s String
			d = &s
		}

	case OptionVendorIdentifyingVendorClass:
		d = &VIVCIdentifiers{}

	case OptionVendorSpecificInformation:
		d = vendorDecoder

	case OptionClasslessStaticRoute:
		d = &Routes{}
	}
	if d != nil && d.FromBytes(data) == nil {
		return d
	}
	return OptionGeneric{data}
}
