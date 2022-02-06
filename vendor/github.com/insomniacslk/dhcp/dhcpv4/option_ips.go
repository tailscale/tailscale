package dhcpv4

import (
	"fmt"
	"net"
	"strings"

	"github.com/u-root/uio/uio"
)

// IPs are IPv4 addresses from a DHCP packet as used and specified by options
// in RFC 2132, Sections 3.5 through 3.13, 8.2, 8.3, 8.5, 8.6, 8.9, and 8.10.
//
// IPs implements the OptionValue type.
type IPs []net.IP

// FromBytes parses an IPv4 address from a DHCP packet as used and specified by
// options in RFC 2132, Sections 3.5 through 3.13, 8.2, 8.3, 8.5, 8.6, 8.9, and
// 8.10.
func (i *IPs) FromBytes(data []byte) error {
	buf := uio.NewBigEndianBuffer(data)
	if buf.Len() == 0 {
		return fmt.Errorf("IP DHCP options must always list at least one IP")
	}

	*i = make(IPs, 0, buf.Len()/net.IPv4len)
	for buf.Has(net.IPv4len) {
		*i = append(*i, net.IP(buf.CopyN(net.IPv4len)))
	}
	return buf.FinError()
}

// ToBytes marshals IPv4 addresses to a DHCP packet as specified by RFC 2132,
// Section 3.5 et al.
func (i IPs) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	for _, ip := range i {
		buf.WriteBytes(ip.To4())
	}
	return buf.Data()
}

// String returns a human-readable representation of a list of IPs.
func (i IPs) String() string {
	s := make([]string, 0, len(i))
	for _, ip := range i {
		s = append(s, ip.String())
	}
	return strings.Join(s, ", ")
}

// GetIPs parses a list of IPs from code in o.
func GetIPs(code OptionCode, o Options) []net.IP {
	v := o.Get(code)
	if v == nil {
		return nil
	}
	var ips IPs
	if err := ips.FromBytes(v); err != nil {
		return nil
	}
	return []net.IP(ips)
}

// OptRouter returns a new DHCPv4 Router option.
//
// The Router option is described by RFC 2132, Section 3.5.
func OptRouter(routers ...net.IP) Option {
	return Option{
		Code:  OptionRouter,
		Value: IPs(routers),
	}
}

// WithRouter updates a packet with the DHCPv4 Router option.
func WithRouter(routers ...net.IP) Modifier {
	return WithOption(OptRouter(routers...))
}

// OptNTPServers returns a new DHCPv4 NTP Server option.
//
// The NTP servers option is described by RFC 2132, Section 8.3.
func OptNTPServers(ntpServers ...net.IP) Option {
	return Option{
		Code:  OptionNTPServers,
		Value: IPs(ntpServers),
	}
}

// OptDNS returns a new DHCPv4 Domain Name Server option.
//
// The DNS server option is described by RFC 2132, Section 3.8.
func OptDNS(servers ...net.IP) Option {
	return Option{
		Code:  OptionDomainNameServer,
		Value: IPs(servers),
	}
}

// WithDNS modifies a packet with the DHCPv4 Domain Name Server option.
func WithDNS(servers ...net.IP) Modifier {
	return WithOption(OptDNS(servers...))
}
