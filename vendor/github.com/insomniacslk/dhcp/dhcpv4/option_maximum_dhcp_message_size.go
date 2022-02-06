package dhcpv4

import (
	"fmt"

	"github.com/u-root/uio/uio"
)

// Uint16 implements encoding and decoding functions for a uint16 as used in
// RFC 2132, Section 9.10.
type Uint16 uint16

// ToBytes returns a serialized stream of bytes for this option.
func (o Uint16) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	buf.Write16(uint16(o))
	return buf.Data()
}

// String returns a human-readable string for this option.
func (o Uint16) String() string {
	return fmt.Sprintf("%d", uint16(o))
}

// FromBytes decodes data into o as per RFC 2132, Section 9.10.
func (o *Uint16) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	*o = Uint16(buf.Read16())
	return buf.FinError()
}

// GetUint16 parses a uint16 from code in o.
func GetUint16(code OptionCode, o Options) (uint16, error) {
	v := o.Get(code)
	if v == nil {
		return 0, fmt.Errorf("option not present")
	}
	var u Uint16
	if err := u.FromBytes(v); err != nil {
		return 0, err
	}
	return uint16(u), nil
}

// OptMaxMessageSize returns a new DHCP Maximum Message Size option.
//
// The Maximum DHCP Message Size option is described by RFC 2132, Section 9.10.
func OptMaxMessageSize(size uint16) Option {
	return Option{Code: OptionMaximumDHCPMessageSize, Value: Uint16(size)}
}
