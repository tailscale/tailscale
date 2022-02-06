package dhcpv4

import (
	"sort"
	"strings"

	"github.com/u-root/uio/uio"
)

// OptionCodeList is a list of DHCP option codes.
type OptionCodeList []OptionCode

// Has returns whether c is in the list.
func (ol OptionCodeList) Has(c OptionCode) bool {
	for _, code := range ol {
		if code == c {
			return true
		}
	}
	return false
}

// Add adds option codes in cs to ol.
func (ol *OptionCodeList) Add(cs ...OptionCode) {
	for _, c := range cs {
		if !ol.Has(c) {
			*ol = append(*ol, c)
		}
	}
}

func (ol OptionCodeList) sort() {
	sort.Slice(ol, func(i, j int) bool { return ol[i].Code() < ol[j].Code() })
}

// String returns a human-readable string for the option names.
func (ol OptionCodeList) String() string {
	var names []string
	ol.sort()
	for _, code := range ol {
		names = append(names, code.String())
	}
	return strings.Join(names, ", ")
}

// ToBytes returns a serialized stream of bytes for this option as defined by
// RFC 2132, Section 9.8.
func (ol OptionCodeList) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	for _, req := range ol {
		buf.Write8(req.Code())
	}
	return buf.Data()
}

// FromBytes parses a byte stream for this option as described by RFC 2132,
// Section 9.8.
func (ol *OptionCodeList) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	*ol = make(OptionCodeList, 0, buf.Len())
	for buf.Has(1) {
		*ol = append(*ol, optionCode(buf.Read8()))
	}
	return buf.FinError()
}

// OptParameterRequestList returns a new DHCPv4 Parameter Request List.
//
// The parameter request list option is described by RFC 2132, Section 9.8.
func OptParameterRequestList(codes ...OptionCode) Option {
	return Option{Code: OptionParameterRequestList, Value: OptionCodeList(codes)}
}
