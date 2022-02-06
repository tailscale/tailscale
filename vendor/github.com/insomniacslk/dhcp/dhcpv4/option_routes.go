package dhcpv4

import (
	"fmt"
	"net"
	"strings"

	"github.com/u-root/uio/uio"
)

// Route is a classless static route as per RFC 3442.
type Route struct {
	// Dest is the destination network.
	Dest *net.IPNet

	// Router is the router to use for the given destination network.
	Router net.IP
}

// Marshal implements uio.Marshaler.
//
// Format described in RFC 3442:
//
// <size of mask in number of bits>
// <destination address, omitting octets that must be zero per mask>
// <route IP>
func (r Route) Marshal(buf *uio.Lexer) {
	ones, _ := r.Dest.Mask.Size()
	buf.Write8(uint8(ones))

	// Only write the non-zero octets.
	dstLen := (ones + 7) / 8
	buf.WriteBytes(r.Dest.IP.To4()[:dstLen])

	buf.WriteBytes(r.Router.To4())
}

// Unmarshal implements uio.Unmarshaler.
func (r *Route) Unmarshal(buf *uio.Lexer) error {
	maskSize := buf.Read8()
	if maskSize > 32 {
		return fmt.Errorf("invalid mask length %d in route option", maskSize)
	}
	r.Dest = &net.IPNet{
		IP:   make([]byte, net.IPv4len),
		Mask: net.CIDRMask(int(maskSize), 32),
	}

	dstLen := (maskSize + 7) / 8
	buf.ReadBytes(r.Dest.IP[:dstLen])

	r.Router = buf.CopyN(net.IPv4len)
	return buf.Error()
}

// String prints the destination network and router IP.
func (r *Route) String() string {
	return fmt.Sprintf("route to %s via %s", r.Dest, r.Router)
}

// Routes is a collection of network routes.
type Routes []*Route

// FromBytes parses routes from a set of bytes as described by RFC 3442.
func (r *Routes) FromBytes(p []byte) error {
	buf := uio.NewBigEndianBuffer(p)
	for buf.Has(1) {
		var route Route
		if err := route.Unmarshal(buf); err != nil {
			return err
		}
		*r = append(*r, &route)
	}
	return buf.FinError()
}

// ToBytes marshals a set of routes as described by RFC 3442.
func (r Routes) ToBytes() []byte {
	buf := uio.NewBigEndianBuffer(nil)
	for _, route := range r {
		route.Marshal(buf)
	}
	return buf.Data()
}

// String prints all routes.
func (r Routes) String() string {
	s := make([]string, 0, len(r))
	for _, route := range r {
		s = append(s, route.String())
	}
	return strings.Join(s, "; ")
}

// OptClasslessStaticRoute returns a new DHCPv4 Classless Static Route
// option.
//
// The Classless Static Route option is described by RFC 3442.
func OptClasslessStaticRoute(routes ...*Route) Option {
	return Option{
		Code:  OptionClasslessStaticRoute,
		Value: Routes(routes),
	}
}
