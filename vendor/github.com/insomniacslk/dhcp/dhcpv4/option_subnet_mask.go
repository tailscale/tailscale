package dhcpv4

import (
	"net"

	"github.com/u-root/uio/uio"
)

// IPMask represents an option encapsulating the subnet mask.
//
// This option implements the subnet mask option in RFC 2132, Section 3.3.
type IPMask net.IPMask

// ToBytes returns a serialized stream of bytes for this option.
func (im IPMask) ToBytes() []byte {
	if len(im) > net.IPv4len {
		return im[:net.IPv4len]
	}
	return im
}

// String returns a human-readable string.
func (im IPMask) String() string {
	return net.IPMask(im).String()
}

// FromBytes parses im from data per RFC 2132.
func (im *IPMask) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	*im = IPMask(buf.CopyN(net.IPv4len))
	return buf.FinError()
}

// OptSubnetMask returns a new DHCPv4 SubnetMask option per RFC 2132, Section 3.3.
func OptSubnetMask(mask net.IPMask) Option {
	return Option{
		Code:  OptionSubnetMask,
		Value: IPMask(mask),
	}
}
