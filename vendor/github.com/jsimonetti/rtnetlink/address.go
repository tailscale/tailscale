package rtnetlink

import (
	"errors"
	"fmt"
	"net"

	"github.com/jsimonetti/rtnetlink/internal/unix"

	"github.com/mdlayher/netlink"
)

var (
	// errInvalidaddressMessage is returned when a AddressMessage is malformed.
	errInvalidAddressMessage = errors.New("rtnetlink AddressMessage is invalid or too short")
)

var _ Message = &AddressMessage{}

// A AddressMessage is a route netlink address message.
type AddressMessage struct {
	// Address family (current unix.AF_INET or unix.AF_INET6)
	Family uint8

	// Prefix length
	PrefixLength uint8

	// Contains address flags
	Flags uint8

	// Address Scope
	Scope uint8

	// Interface index
	Index uint32

	// Optional attributes which are appended when not nil.
	Attributes *AddressAttributes
}

// MarshalBinary marshals a AddressMessage into a byte slice.
func (m *AddressMessage) MarshalBinary() ([]byte, error) {
	b := make([]byte, unix.SizeofIfAddrmsg)

	b[0] = m.Family
	b[1] = m.PrefixLength
	b[2] = m.Flags
	b[3] = m.Scope
	nativeEndian.PutUint32(b[4:8], m.Index)

	if m.Attributes == nil {
		// No attributes to encode.
		return b, nil
	}

	ae := netlink.NewAttributeEncoder()
	err := m.Attributes.encode(ae)
	if err != nil {
		return nil, err
	}

	a, err := ae.Encode()
	if err != nil {
		return nil, err
	}

	return append(b, a...), nil
}

// UnmarshalBinary unmarshals the contents of a byte slice into a AddressMessage.
func (m *AddressMessage) UnmarshalBinary(b []byte) error {
	l := len(b)
	if l < unix.SizeofIfAddrmsg {
		return errInvalidAddressMessage
	}

	m.Family = uint8(b[0])
	m.PrefixLength = uint8(b[1])
	m.Flags = uint8(b[2])
	m.Scope = uint8(b[3])
	m.Index = nativeEndian.Uint32(b[4:8])

	if l > unix.SizeofIfAddrmsg {
		ad, err := netlink.NewAttributeDecoder(b[unix.SizeofIfAddrmsg:])
		if err != nil {
			return err
		}

		var aa AddressAttributes
		if err := aa.decode(ad); err != nil {
			return err
		}

		// Must consume errors from decoder before returning.
		if err := ad.Err(); err != nil {
			return fmt.Errorf("invalid address message attributes: %v", err)
		}
		m.Attributes = &aa
	}

	return nil
}

// rtMessage is an empty method to sattisfy the Message interface.
func (*AddressMessage) rtMessage() {}

// AddressService is used to retrieve rtnetlink family information.
type AddressService struct {
	c *Conn
}

// New creates a new address using the AddressMessage information.
func (a *AddressService) New(req *AddressMessage) error {
	flags := netlink.Request | netlink.Create | netlink.Acknowledge | netlink.Excl
	_, err := a.c.Execute(req, unix.RTM_NEWADDR, flags)
	if err != nil {
		return err
	}

	return nil
}

// Delete removes an address using the AddressMessage information.
func (a *AddressService) Delete(req *AddressMessage) error {
	flags := netlink.Request | netlink.Acknowledge
	_, err := a.c.Execute(req, unix.RTM_DELADDR, flags)
	if err != nil {
		return err
	}

	return nil
}

// List retrieves all addresses.
func (a *AddressService) List() ([]AddressMessage, error) {
	req := AddressMessage{}

	flags := netlink.Request | netlink.Dump
	msgs, err := a.c.Execute(&req, unix.RTM_GETADDR, flags)
	if err != nil {
		return nil, err
	}

	addresses := make([]AddressMessage, len(msgs))
	for i := range msgs {
		addresses[i] = *msgs[i].(*AddressMessage)
	}
	return addresses, nil
}

// AddressAttributes contains all attributes for an interface.
type AddressAttributes struct {
	Address   net.IP // Interface Ip address
	Local     net.IP // Local Ip address
	Label     string
	Broadcast net.IP    // Broadcast Ip address
	Anycast   net.IP    // Anycast Ip address
	CacheInfo CacheInfo // Address information
	Multicast net.IP    // Multicast Ip address
	Flags     uint32    // Address flags
}

func (a *AddressAttributes) decode(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ad.Type() {
		case unix.IFA_UNSPEC:
			// unused attribute
		case unix.IFA_ADDRESS:
			ad.Do(decodeIP(&a.Address))
		case unix.IFA_LOCAL:
			ad.Do(decodeIP(&a.Local))
		case unix.IFA_LABEL:
			a.Label = ad.String()
		case unix.IFA_BROADCAST:
			ad.Do(decodeIP(&a.Broadcast))
		case unix.IFA_ANYCAST:
			ad.Do(decodeIP(&a.Anycast))
		case unix.IFA_CACHEINFO:
			ad.Do(a.CacheInfo.decode)
		case unix.IFA_MULTICAST:
			ad.Do(decodeIP(&a.Multicast))
		case unix.IFA_FLAGS:
			a.Flags = ad.Uint32()
		}
	}

	return nil
}

func (a *AddressAttributes) encode(ae *netlink.AttributeEncoder) error {
	ae.Uint16(unix.IFA_UNSPEC, 0)
	ae.Do(unix.IFA_ADDRESS, encodeIP(a.Address))
	if a.Local != nil {
		ae.Do(unix.IFA_LOCAL, encodeIP(a.Local))
	}
	if a.Broadcast != nil {
		ae.Do(unix.IFA_BROADCAST, encodeIP(a.Broadcast))
	}
	if a.Anycast != nil {
		ae.Do(unix.IFA_ANYCAST, encodeIP(a.Anycast))
	}
	if a.Multicast != nil {
		ae.Do(unix.IFA_MULTICAST, encodeIP(a.Multicast))
	}
	ae.Uint32(unix.IFA_FLAGS, a.Flags)

	return nil
}

// CacheInfo contains address information
type CacheInfo struct {
	Prefered uint32
	Valid    uint32
	Created  uint32
	Updated  uint32
}

// decode decodes raw bytes into a CacheInfo's fields.
func (c *CacheInfo) decode(b []byte) error {
	if len(b) != 16 {
		return fmt.Errorf("rtnetlink: incorrect CacheInfo size, want: 16, got: %d", len(b))
	}

	c.Prefered = nativeEndian.Uint32(b[0:4])
	c.Valid = nativeEndian.Uint32(b[4:8])
	c.Created = nativeEndian.Uint32(b[8:12])
	c.Updated = nativeEndian.Uint32(b[12:16])

	return nil
}

// encodeIP is a helper for validating and encoding IPv4 and IPv6 addresses as
// appropriate for the specified netlink attribute type. It should be used
// with (*netlink.AttributeEncoder).Do.
func encodeIP(ip net.IP) func() ([]byte, error) {
	return func() ([]byte, error) {
		// Don't allow nil or non 4/16-byte addresses.
		if ip == nil || ip.To16() == nil {
			return nil, fmt.Errorf("rtnetlink: cannot encode invalid IP address: %s", ip)
		}

		if ip4 := ip.To4(); ip4 != nil {
			// IPv4 address.
			return ip4, nil
		}

		// IPv6 address.
		return ip, nil
	}
}

// decodeIP is a helper for validating and decoding IPv4 and IPv6 addresses as
// appropriate for the specified netlink attribute type. It should be used with
// (*netlink.AttributeDecoder).Do.
func decodeIP(ip *net.IP) func(b []byte) error {
	return func(b []byte) error {
		if l := len(b); l != 4 && l != 16 {
			return fmt.Errorf("rtnetlink: invalid IP address length: %d", l)
		}

		// We cannot retain b outside the closure, so make a copy into ip.
		*ip = make(net.IP, len(b))
		copy(*ip, b)
		return nil
	}
}
