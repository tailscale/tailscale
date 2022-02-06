package rtnetlink

import (
	"errors"
	"fmt"
	"net"

	"github.com/jsimonetti/rtnetlink/internal/unix"

	"github.com/mdlayher/netlink"
)

var (
	// errInvalidLinkMessage is returned when a LinkMessage is malformed.
	errInvalidLinkMessage = errors.New("rtnetlink LinkMessage is invalid or too short")

	// errInvalidLinkMessageAttr is returned when link attributes are malformed.
	errInvalidLinkMessageAttr = errors.New("rtnetlink LinkMessage has a wrong attribute data length")
)

var _ Message = &LinkMessage{}

// A LinkMessage is a route netlink link message.
type LinkMessage struct {
	// Always set to AF_UNSPEC (0)
	Family uint16

	// Device Type
	Type uint16

	// Unique interface index, using a nonzero value with
	// NewLink will instruct the kernel to create a
	// device with the given index (kernel 3.7+ required)
	Index uint32

	// Contains device flags, see netdevice(7)
	Flags uint32

	// Change Flags, specifies which flags will be affected by the Flags field
	Change uint32

	// Attributes List
	Attributes *LinkAttributes
}

// MarshalBinary marshals a LinkMessage into a byte slice.
func (m *LinkMessage) MarshalBinary() ([]byte, error) {
	b := make([]byte, unix.SizeofIfInfomsg)

	b[0] = 0 // Family
	b[1] = 0 // reserved
	nativeEndian.PutUint16(b[2:4], m.Type)
	nativeEndian.PutUint32(b[4:8], m.Index)
	nativeEndian.PutUint32(b[8:12], m.Flags)
	nativeEndian.PutUint32(b[12:16], m.Change)

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

// UnmarshalBinary unmarshals the contents of a byte slice into a LinkMessage.
func (m *LinkMessage) UnmarshalBinary(b []byte) error {
	l := len(b)
	if l < unix.SizeofIfInfomsg {
		return errInvalidLinkMessage
	}

	m.Family = nativeEndian.Uint16(b[0:2])
	m.Type = nativeEndian.Uint16(b[2:4])
	m.Index = nativeEndian.Uint32(b[4:8])
	m.Flags = nativeEndian.Uint32(b[8:12])
	m.Change = nativeEndian.Uint32(b[12:16])

	if l > unix.SizeofIfInfomsg {
		m.Attributes = &LinkAttributes{}
		ad, err := netlink.NewAttributeDecoder(b[16:])
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
func (*LinkMessage) rtMessage() {}

// LinkService is used to retrieve rtnetlink family information.
type LinkService struct {
	c *Conn
}

// execute executes the request and returns the messages as a LinkMessage slice
func (l *LinkService) execute(m Message, family uint16, flags netlink.HeaderFlags) ([]LinkMessage, error) {
	msgs, err := l.c.Execute(m, family, flags)

	links := make([]LinkMessage, len(msgs))
	for i := range msgs {
		links[i] = *msgs[i].(*LinkMessage)
	}

	return links, err
}

// New creates a new interface using the LinkMessage information.
func (l *LinkService) New(req *LinkMessage) error {
	flags := netlink.Request | netlink.Create | netlink.Acknowledge | netlink.Excl
	_, err := l.execute(req, unix.RTM_NEWLINK, flags)

	return err
}

// Delete removes an interface by index.
func (l *LinkService) Delete(index uint32) error {
	req := &LinkMessage{
		Index: index,
	}

	flags := netlink.Request | netlink.Acknowledge
	_, err := l.c.Execute(req, unix.RTM_DELLINK, flags)

	return err
}

// Get retrieves interface information by index.
func (l *LinkService) Get(index uint32) (LinkMessage, error) {
	req := &LinkMessage{
		Index: index,
	}

	flags := netlink.Request | netlink.DumpFiltered
	links, err := l.execute(req, unix.RTM_GETLINK, flags)

	if len(links) != 1 {
		return LinkMessage{}, fmt.Errorf("too many/little matches, expected 1, actual %d", len(links))
	}

	return links[0], err
}

// Set sets interface attributes according to the LinkMessage information.
//
// ref: https://lwn.net/Articles/236919/
// We explicitly use RTM_NEWLINK to set link attributes instead of
// RTM_SETLINK because:
// - using RTM_SETLINK is actually an old rtnetlink API, not supporting most
//   attributes common today
// - using RTM_NEWLINK is the prefered way to create AND update links
// - RTM_NEWLINK is backward compatible to RTM_SETLINK
func (l *LinkService) Set(req *LinkMessage) error {
	flags := netlink.Request | netlink.Acknowledge
	_, err := l.c.Execute(req, unix.RTM_NEWLINK, flags)

	return err
}

func (l *LinkService) list(kind string) ([]LinkMessage, error) {
	req := &LinkMessage{}
	if kind != "" {
		req.Attributes = &LinkAttributes{
			Info: &LinkInfo{Kind: kind},
		}
	}

	flags := netlink.Request | netlink.Dump
	return l.execute(req, unix.RTM_GETLINK, flags)
}

// ListByKind retrieves all interfaces of a specific kind.
func (l *LinkService) ListByKind(kind string) ([]LinkMessage, error) {
	return l.list(kind)
}

// List retrieves all interfaces.
func (l *LinkService) List() ([]LinkMessage, error) {
	return l.list("")
}

// LinkAttributes contains all attributes for an interface.
type LinkAttributes struct {
	Address          net.HardwareAddr // Interface L2 address
	Broadcast        net.HardwareAddr // L2 broadcast address
	Name             string           // Device name
	MTU              uint32           // MTU of the device
	Type             uint32           // Link type
	QueueDisc        string           // Queueing discipline
	Master           *uint32          // Master device index (0 value un-enslaves)
	OperationalState OperationalState // Interface operation state
	Stats            *LinkStats       // Interface Statistics
	Stats64          *LinkStats64     // Interface Statistics (64 bits version)
	Info             *LinkInfo        // Detailed Interface Information
	XDP              *LinkXDP         // Express Data Patch Information
}

// OperationalState represents an interface's operational state.
type OperationalState uint8

// Constants that represent operational state of an interface
//
// Adapted from https://elixir.bootlin.com/linux/v4.19.2/source/include/uapi/linux/if.h#L166
const (
	OperStateUnknown        OperationalState = iota // status could not be determined
	OperStateNotPresent                             // down, due to some missing component (typically hardware)
	OperStateDown                                   // down, either administratively or due to a fault
	OperStateLowerLayerDown                         // down, due to lower-layer interfaces
	OperStateTesting                                // operationally down, in some test mode
	OperStateDormant                                // down, waiting for some external event
	OperStateUp                                     // interface is in a state to send and receive packets
)

// unmarshalBinary unmarshals the contents of a byte slice into a LinkMessage.
func (a *LinkAttributes) decode(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ad.Type() {
		case unix.IFLA_UNSPEC:
			// unused attribute
		case unix.IFLA_ADDRESS:
			l := len(ad.Bytes())
			if l < 4 || l > 32 {
				return errInvalidLinkMessageAttr
			}
			a.Address = ad.Bytes()
		case unix.IFLA_BROADCAST:
			l := len(ad.Bytes())
			if l < 4 || l > 32 {
				return errInvalidLinkMessageAttr
			}
			a.Broadcast = ad.Bytes()
		case unix.IFLA_IFNAME:
			a.Name = ad.String()
		case unix.IFLA_MTU:
			a.MTU = ad.Uint32()
		case unix.IFLA_LINK:
			a.Type = ad.Uint32()
		case unix.IFLA_QDISC:
			a.QueueDisc = ad.String()
		case unix.IFLA_OPERSTATE:
			a.OperationalState = OperationalState(ad.Uint8())
		case unix.IFLA_STATS:
			a.Stats = &LinkStats{}
			err := a.Stats.unmarshalBinary(ad.Bytes())
			if err != nil {
				return err
			}
		case unix.IFLA_STATS64:
			a.Stats64 = &LinkStats64{}
			err := a.Stats64.unmarshalBinary(ad.Bytes())
			if err != nil {
				return err
			}
		case unix.IFLA_LINKINFO:
			a.Info = &LinkInfo{}
			ad.Nested(a.Info.decode)
		case unix.IFLA_MASTER:
			v := ad.Uint32()
			a.Master = &v
		case unix.IFLA_XDP:
			a.XDP = &LinkXDP{}
			ad.Nested(a.XDP.decode)
		}
	}

	return nil
}

// MarshalBinary marshals a LinkAttributes into a byte slice.
func (a *LinkAttributes) encode(ae *netlink.AttributeEncoder) error {
	ae.Uint16(unix.IFLA_UNSPEC, 0)
	ae.String(unix.IFLA_IFNAME, a.Name)
	ae.Uint32(unix.IFLA_LINK, a.Type)
	ae.String(unix.IFLA_QDISC, a.QueueDisc)

	if a.MTU != 0 {
		ae.Uint32(unix.IFLA_MTU, a.MTU)
	}

	if len(a.Address) != 0 {
		ae.Bytes(unix.IFLA_ADDRESS, a.Address)
	}

	if len(a.Broadcast) != 0 {
		ae.Bytes(unix.IFLA_BROADCAST, a.Broadcast)
	}

	if a.OperationalState != OperStateUnknown {
		ae.Uint8(unix.IFLA_OPERSTATE, uint8(a.OperationalState))
	}

	if a.Info != nil {
		nae := netlink.NewAttributeEncoder()
		nae.ByteOrder = ae.ByteOrder

		err := a.Info.encode(nae)
		if err != nil {
			return err
		}
		b, err := nae.Encode()
		if err != nil {
			return err
		}
		ae.Bytes(unix.IFLA_LINKINFO, b)
	}

	if a.XDP != nil {
		nae := netlink.NewAttributeEncoder()
		nae.ByteOrder = ae.ByteOrder

		err := a.XDP.encode(nae)
		if err != nil {
			return err
		}
		b, err := nae.Encode()
		if err != nil {
			return err
		}

		ae.Bytes(unix.IFLA_XDP, b)
	}

	if a.Master != nil {
		ae.Uint32(unix.IFLA_MASTER, *a.Master)
	}

	return nil
}

// LinkStats contains packet statistics
type LinkStats struct {
	RXPackets  uint32 // total packets received
	TXPackets  uint32 // total packets transmitted
	RXBytes    uint32 // total bytes received
	TXBytes    uint32 // total bytes transmitted
	RXErrors   uint32 // bad packets received
	TXErrors   uint32 // packet transmit problems
	RXDropped  uint32 // no space in linux buffers
	TXDropped  uint32 // no space available in linux
	Multicast  uint32 // multicast packets received
	Collisions uint32

	// detailed rx_errors:
	RXLengthErrors uint32
	RXOverErrors   uint32 // receiver ring buff overflow
	RXCRCErrors    uint32 // recved pkt with crc error
	RXFrameErrors  uint32 // recv'd frame alignment error
	RXFIFOErrors   uint32 // recv'r fifo overrun
	RXMissedErrors uint32 // receiver missed packet

	// detailed tx_errors
	TXAbortedErrors   uint32
	TXCarrierErrors   uint32
	TXFIFOErrors      uint32
	TXHeartbeatErrors uint32
	TXWindowErrors    uint32

	// for cslip etc
	RXCompressed uint32
	TXCompressed uint32

	RXNoHandler uint32 // dropped, no handler found
}

// unmarshalBinary unmarshals the contents of a byte slice into a LinkMessage.
func (a *LinkStats) unmarshalBinary(b []byte) error {
	l := len(b)
	if l != 92 && l != 96 {
		return fmt.Errorf("incorrect size, want: 92 or 96")
	}

	a.RXPackets = nativeEndian.Uint32(b[0:4])
	a.TXPackets = nativeEndian.Uint32(b[4:8])
	a.RXBytes = nativeEndian.Uint32(b[8:12])
	a.TXBytes = nativeEndian.Uint32(b[12:16])
	a.RXErrors = nativeEndian.Uint32(b[16:20])
	a.TXErrors = nativeEndian.Uint32(b[20:24])
	a.RXDropped = nativeEndian.Uint32(b[24:28])
	a.TXDropped = nativeEndian.Uint32(b[28:32])
	a.Multicast = nativeEndian.Uint32(b[32:36])
	a.Collisions = nativeEndian.Uint32(b[36:40])

	a.RXLengthErrors = nativeEndian.Uint32(b[40:44])
	a.RXOverErrors = nativeEndian.Uint32(b[44:48])
	a.RXCRCErrors = nativeEndian.Uint32(b[48:52])
	a.RXFrameErrors = nativeEndian.Uint32(b[52:56])
	a.RXFIFOErrors = nativeEndian.Uint32(b[56:60])
	a.RXMissedErrors = nativeEndian.Uint32(b[60:64])

	a.TXAbortedErrors = nativeEndian.Uint32(b[64:68])
	a.TXCarrierErrors = nativeEndian.Uint32(b[68:72])
	a.TXFIFOErrors = nativeEndian.Uint32(b[72:76])
	a.TXHeartbeatErrors = nativeEndian.Uint32(b[76:80])
	a.TXWindowErrors = nativeEndian.Uint32(b[80:84])

	a.RXCompressed = nativeEndian.Uint32(b[84:88])
	a.TXCompressed = nativeEndian.Uint32(b[88:92])

	if l == 96 {
		a.RXNoHandler = nativeEndian.Uint32(b[92:96])
	}

	return nil
}

// LinkStats64 contains packet statistics
type LinkStats64 struct {
	RXPackets  uint64 // total packets received
	TXPackets  uint64 // total packets transmitted
	RXBytes    uint64 // total bytes received
	TXBytes    uint64 // total bytes transmitted
	RXErrors   uint64 // bad packets received
	TXErrors   uint64 // packet transmit problems
	RXDropped  uint64 // no space in linux buffers
	TXDropped  uint64 // no space available in linux
	Multicast  uint64 // multicast packets received
	Collisions uint64

	// detailed rx_errors:
	RXLengthErrors uint64
	RXOverErrors   uint64 // receiver ring buff overflow
	RXCRCErrors    uint64 // recved pkt with crc error
	RXFrameErrors  uint64 // recv'd frame alignment error
	RXFIFOErrors   uint64 // recv'r fifo overrun
	RXMissedErrors uint64 // receiver missed packet

	// detailed tx_errors
	TXAbortedErrors   uint64
	TXCarrierErrors   uint64
	TXFIFOErrors      uint64
	TXHeartbeatErrors uint64
	TXWindowErrors    uint64

	// for cslip etc
	RXCompressed uint64
	TXCompressed uint64

	RXNoHandler uint64 // dropped, no handler found
}

// unmarshalBinary unmarshals the contents of a byte slice into a LinkMessage.
func (a *LinkStats64) unmarshalBinary(b []byte) error {
	l := len(b)
	if l != 184 && l != 192 {
		return fmt.Errorf("incorrect size, want: 184 or 192")
	}

	a.RXPackets = nativeEndian.Uint64(b[0:8])
	a.TXPackets = nativeEndian.Uint64(b[8:16])
	a.RXBytes = nativeEndian.Uint64(b[16:24])
	a.TXBytes = nativeEndian.Uint64(b[24:32])
	a.RXErrors = nativeEndian.Uint64(b[32:40])
	a.TXErrors = nativeEndian.Uint64(b[40:48])
	a.RXDropped = nativeEndian.Uint64(b[48:56])
	a.TXDropped = nativeEndian.Uint64(b[56:64])
	a.Multicast = nativeEndian.Uint64(b[64:72])
	a.Collisions = nativeEndian.Uint64(b[72:80])

	a.RXLengthErrors = nativeEndian.Uint64(b[80:88])
	a.RXOverErrors = nativeEndian.Uint64(b[88:96])
	a.RXCRCErrors = nativeEndian.Uint64(b[96:104])
	a.RXFrameErrors = nativeEndian.Uint64(b[104:112])
	a.RXFIFOErrors = nativeEndian.Uint64(b[112:120])
	a.RXMissedErrors = nativeEndian.Uint64(b[120:128])

	a.TXAbortedErrors = nativeEndian.Uint64(b[128:136])
	a.TXCarrierErrors = nativeEndian.Uint64(b[136:144])
	a.TXFIFOErrors = nativeEndian.Uint64(b[144:152])
	a.TXHeartbeatErrors = nativeEndian.Uint64(b[152:160])
	a.TXWindowErrors = nativeEndian.Uint64(b[160:168])

	a.RXCompressed = nativeEndian.Uint64(b[168:176])
	a.TXCompressed = nativeEndian.Uint64(b[176:184])

	if l == 192 {
		a.RXNoHandler = nativeEndian.Uint64(b[184:192])
	}

	return nil
}

// LinkInfo contains data for specific network types
type LinkInfo struct {
	Kind      string // Driver name
	Data      []byte // Driver specific configuration stored as nested Netlink messages
	SlaveKind string // Slave driver name
	SlaveData []byte // Slave driver specific configuration
}

func (i *LinkInfo) decode(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ad.Type() {
		case unix.IFLA_INFO_KIND:
			i.Kind = ad.String()
		case unix.IFLA_INFO_SLAVE_KIND:
			i.SlaveKind = ad.String()
		case unix.IFLA_INFO_DATA:
			i.Data = ad.Bytes()
		case unix.IFLA_INFO_SLAVE_DATA:
			i.SlaveData = ad.Bytes()
		}
	}

	return nil
}

func (i *LinkInfo) encode(ae *netlink.AttributeEncoder) error {
	ae.String(unix.IFLA_INFO_KIND, i.Kind)
	ae.Bytes(unix.IFLA_INFO_DATA, i.Data)

	if len(i.SlaveData) > 0 {
		ae.String(unix.IFLA_INFO_SLAVE_KIND, i.SlaveKind)
		ae.Bytes(unix.IFLA_INFO_SLAVE_DATA, i.SlaveData)
	}

	return nil
}

// LinkXDP holds Express Data Path specific information
type LinkXDP struct {
	FD         int32
	ExpectedFD int32
	Attached   uint8
	Flags      uint32
	ProgID     uint32
}

func (xdp *LinkXDP) decode(ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ad.Type() {
		case unix.IFLA_XDP_FD:
			xdp.FD = ad.Int32()
		case unix.IFLA_XDP_EXPECTED_FD:
			xdp.ExpectedFD = ad.Int32()
		case unix.IFLA_XDP_ATTACHED:
			xdp.Attached = ad.Uint8()
		case unix.IFLA_XDP_FLAGS:
			xdp.Flags = ad.Uint32()
		case unix.IFLA_XDP_PROG_ID:
			xdp.ProgID = ad.Uint32()
		}
	}
	return nil
}

func (xdp *LinkXDP) encode(ae *netlink.AttributeEncoder) error {
	ae.Int32(unix.IFLA_XDP_FD, xdp.FD)
	ae.Int32(unix.IFLA_XDP_EXPECTED_FD, xdp.ExpectedFD)
	ae.Uint32(unix.IFLA_XDP_FLAGS, xdp.Flags)
	// XDP_ATtACHED and XDP_PROG_ID are things that only can return from the kernel,
	// not be send, so we don't encode them.
	// source: https://elixir.bootlin.com/linux/v5.10.15/source/net/core/rtnetlink.c#L2894
	return nil
}
