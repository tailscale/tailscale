package dhcpv4

import (
	"net"

	"github.com/u-root/uio/uio"
)

// IP implements DHCPv4 IP option marshaling and unmarshaling as described by
// RFC 2132, Sections 5.3, 9.1, 9.7, and others.
type IP net.IP

// FromBytes parses an IP from data in binary form.
func (i *IP) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	*i = IP(buf.CopyN(net.IPv4len))
	return buf.FinError()
}

// ToBytes returns a serialized stream of bytes for this option.
func (i IP) ToBytes() []byte {
	return []byte(net.IP(i).To4())
}

// String returns a human-readable IP.
func (i IP) String() string {
	return net.IP(i).String()
}

// GetIP returns code out of o parsed as an IP.
func GetIP(code OptionCode, o Options) net.IP {
	v := o.Get(code)
	if v == nil {
		return nil
	}
	var ip IP
	if err := ip.FromBytes(v); err != nil {
		return nil
	}
	return net.IP(ip)
}

// OptBroadcastAddress returns a new DHCPv4 Broadcast Address option.
//
// The broadcast address option is described in RFC 2132, Section 5.3.
func OptBroadcastAddress(ip net.IP) Option {
	return Option{Code: OptionBroadcastAddress, Value: IP(ip)}
}

// OptRequestedIPAddress returns a new DHCPv4 Requested IP Address option.
//
// The requested IP address option is described by RFC 2132, Section 9.1.
func OptRequestedIPAddress(ip net.IP) Option {
	return Option{Code: OptionRequestedIPAddress, Value: IP(ip)}
}

// OptServerIdentifier returns a new DHCPv4 Server Identifier option.
//
// The server identifier option is described by RFC 2132, Section 9.7.
func OptServerIdentifier(ip net.IP) Option {
	return Option{Code: OptionServerIdentifier, Value: IP(ip)}
}
