package rtnetlink

import (
	"errors"
	"fmt"
	"net"

	"github.com/jsimonetti/rtnetlink/internal/unix"

	"github.com/mdlayher/netlink"
)

var (
	// errInvalidNeighMessage is returned when a LinkMessage is malformed.
	errInvalidNeighMessage = errors.New("rtnetlink NeighMessage is invalid or too short")

	// errInvalidNeighMessageAttr is returned when neigh attributes are malformed.
	errInvalidNeighMessageAttr = errors.New("rtnetlink NeighMessage has a wrong attribute data length")
)

var _ Message = &NeighMessage{}

// A NeighMessage is a route netlink neighbor message.
type NeighMessage struct {
	// Always set to AF_UNSPEC (0)
	Family uint16

	// Unique interface index
	Index uint32

	// Neighbor State is a bitmask of neighbor states (see rtnetlink(7))
	State uint16

	// Neighbor flags
	Flags uint8

	// Neighbor type
	Type uint8

	// Attributes List
	Attributes *NeighAttributes
}

// MarshalBinary marshals a NeighMessage into a byte slice.
func (m *NeighMessage) MarshalBinary() ([]byte, error) {
	b := make([]byte, unix.SizeofNdMsg)

	nativeEndian.PutUint16(b[0:2], m.Family)
	// bytes 3 and 4 are padding
	nativeEndian.PutUint32(b[4:8], m.Index)
	nativeEndian.PutUint16(b[8:10], m.State)
	b[10] = m.Flags
	b[11] = m.Type

	if m.Attributes != nil {
		ae := netlink.NewAttributeEncoder()
		ae.ByteOrder = nativeEndian
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
	return b, nil
}

// UnmarshalBinary unmarshals the contents of a byte slice into a NeighMessage.
func (m *NeighMessage) UnmarshalBinary(b []byte) error {
	l := len(b)
	if l < unix.SizeofNdMsg {
		return errInvalidNeighMessage
	}

	m.Family = nativeEndian.Uint16(b[0:2])
	m.Index = nativeEndian.Uint32(b[4:8])
	m.State = nativeEndian.Uint16(b[8:10])
	m.Flags = b[10]
	m.Type = b[11]

	if l > unix.SizeofNdMsg {
		m.Attributes = &NeighAttributes{}
		ad, err := netlink.NewAttributeDecoder(b[unix.SizeofNdMsg:])
		if err != nil {
			return err
		}
		ad.ByteOrder = nativeEndian
		err = m.Attributes.decode(ad)
		if err != nil {
			return err
		}
	}

	return nil
}

// rtMessage is an empty method to sattisfy the Message interface.
func (*NeighMessage) rtMessage() {}

// NeighService is used to retrieve rtnetlink family information.
type NeighService struct {
	c *Conn
}

// New creates a new interface using the LinkMessage information.
func (l *NeighService) New(req *NeighMessage) error {
	flags := netlink.Request | netlink.Create | netlink.Acknowledge | netlink.Excl
	_, err := l.c.Execute(req, unix.RTM_NEWNEIGH, flags)
	if err != nil {
		return err
	}

	return nil
}

// Delete removes an neighbor entry by index.
func (l *NeighService) Delete(index uint32) error {
	req := &NeighMessage{}

	flags := netlink.Request | netlink.Acknowledge
	_, err := l.c.Execute(req, unix.RTM_DELNEIGH, flags)
	if err != nil {
		return err
	}

	return nil
}

// List retrieves all neighbors.
func (l *NeighService) List() ([]NeighMessage, error) {
	req := NeighMessage{}

	flags := netlink.Request | netlink.Dump
	msgs, err := l.c.Execute(&req, unix.RTM_GETNEIGH, flags)
	if err != nil {
		return nil, err
	}

	neighs := make([]NeighMessage, len(msgs))
	for i := range msgs {
		neighs[i] = *msgs[i].(*NeighMessage)
	}

	return neighs, nil
}

// NeighCacheInfo contains neigh information
type NeighCacheInfo struct {
	Confirmed uint32
	Used      uint32
	Updated   uint32
	RefCount  uint32
}

// UnmarshalBinary unmarshals the contents of a byte slice into a NeighMessage.
func (n *NeighCacheInfo) unmarshalBinary(b []byte) error {
	if len(b) != 16 {
		return fmt.Errorf("incorrect size, want: 16, got: %d", len(b))
	}

	n.Confirmed = nativeEndian.Uint32(b[0:4])
	n.Used = nativeEndian.Uint32(b[4:8])
	n.Updated = nativeEndian.Uint32(b[8:12])
	n.RefCount = nativeEndian.Uint32(b[12:16])

	return nil
}

// NeighAttributes contains all attributes for a neighbor.
type NeighAttributes struct {
	Address   net.IP           // a neighbor cache n/w layer destination address
	LLAddress net.HardwareAddr // a neighbor cache link layer address
	CacheInfo *NeighCacheInfo  // cache statistics
	IfIndex   uint32
}

func (a *NeighAttributes) decode(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ad.Type() {
		case unix.NDA_UNSPEC:
			// unused attribute
		case unix.NDA_DST:
			l := len(ad.Bytes())
			if l != 4 && l != 16 {
				return errInvalidNeighMessageAttr
			}
			a.Address = ad.Bytes()
		case unix.NDA_LLADDR:
			if len(ad.Bytes()) != 6 {
				return errInvalidNeighMessageAttr
			}
			a.LLAddress = ad.Bytes()
		case unix.NDA_CACHEINFO:
			a.CacheInfo = &NeighCacheInfo{}
			err := a.CacheInfo.unmarshalBinary(ad.Bytes())
			if err != nil {
				return err
			}
		case unix.NDA_IFINDEX:
			a.IfIndex = ad.Uint32()
		}
	}

	return nil
}

func (a *NeighAttributes) encode(ae *netlink.AttributeEncoder) error {
	ae.Uint16(unix.NDA_UNSPEC, 0)
	ae.Bytes(unix.NDA_DST, a.Address)
	ae.Bytes(unix.NDA_LLADDR, a.LLAddress)
	ae.Uint32(unix.NDA_IFINDEX, a.IfIndex)

	return nil
}
