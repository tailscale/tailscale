package rtnetlink

import (
	"encoding"
	"time"

	"github.com/jsimonetti/rtnetlink/internal/unix"

	"github.com/mdlayher/netlink"
)

// A Conn is a route netlink connection. A Conn can be used to send and
// receive route netlink messages to and from netlink.
type Conn struct {
	c       conn
	Link    *LinkService
	Address *AddressService
	Route   *RouteService
	Neigh   *NeighService
}

var _ conn = &netlink.Conn{}

// A conn is a netlink connection, which can be swapped for tests.
type conn interface {
	Close() error
	Send(m netlink.Message) (netlink.Message, error)
	Receive() ([]netlink.Message, error)
	Execute(m netlink.Message) ([]netlink.Message, error)
	SetOption(option netlink.ConnOption, enable bool) error
	SetReadDeadline(t time.Time) error
}

// Dial dials a route netlink connection.  Config specifies optional
// configuration for the underlying netlink connection.  If config is
// nil, a default configuration will be used.
func Dial(config *netlink.Config) (*Conn, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, config)
	if err != nil {
		return nil, err
	}

	return newConn(c), nil
}

// newConn creates a Conn that wraps an existing *netlink.Conn for
// rtnetlink communications. It is used for testing.
func newConn(c conn) *Conn {
	rtc := &Conn{
		c: c,
	}

	rtc.Link = &LinkService{c: rtc}
	rtc.Address = &AddressService{c: rtc}
	rtc.Route = &RouteService{c: rtc}
	rtc.Neigh = &NeighService{c: rtc}

	return rtc
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.c.Close()
}

// SetOption enables or disables a netlink socket option for the Conn.
func (c *Conn) SetOption(option netlink.ConnOption, enable bool) error {
	return c.c.SetOption(option, enable)
}

// SetReadDeadline sets the read deadline associated with the connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

// Send sends a single Message to netlink, wrapping it in a netlink.Message
// using the specified generic netlink family and flags.  On success, Send
// returns a copy of the netlink.Message with all parameters populated, for
// later validation.
func (c *Conn) Send(m Message, family uint16, flags netlink.HeaderFlags) (netlink.Message, error) {
	nm := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(family),
			Flags: flags,
		},
	}

	mb, err := m.MarshalBinary()
	if err != nil {
		return netlink.Message{}, err
	}
	nm.Data = mb
	reqnm, err := c.c.Send(nm)
	if err != nil {
		return netlink.Message{}, err
	}

	return reqnm, nil
}

// Receive receives one or more Messages from netlink.  The netlink.Messages
// used to wrap each Message are available for later validation.
func (c *Conn) Receive() ([]Message, []netlink.Message, error) {
	msgs, err := c.c.Receive()
	if err != nil {
		return nil, nil, err
	}

	rtmsgs, err := unpackMessages(msgs)
	if err != nil {
		return nil, nil, err
	}

	return rtmsgs, msgs, nil
}

// Execute sends a single Message to netlink using Send, receives one or more
// replies using Receive, and then checks the validity of the replies against
// the request using netlink.Validate.
//
// Execute acquires a lock for the duration of the function call which blocks
// concurrent calls to Send and Receive, in order to ensure consistency between
// generic netlink request/reply messages.
//
// See the documentation of Send, Receive, and netlink.Validate for details
// about each function.
func (c *Conn) Execute(m Message, family uint16, flags netlink.HeaderFlags) ([]Message, error) {
	nm, err := packMessage(m, family, flags)
	if err != nil {
		return nil, err
	}

	msgs, err := c.c.Execute(nm)
	if err != nil {
		return nil, err
	}

	return unpackMessages(msgs)
}

// Message is the interface used for passing around different kinds of rtnetlink messages
type Message interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	rtMessage()
}

// packMessage packs a rtnetlink Message into a netlink.Message with the
// appropriate rtnetlink family and netlink flags.
func packMessage(m Message, family uint16, flags netlink.HeaderFlags) (netlink.Message, error) {
	nm := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(family),
			Flags: flags,
		},
	}

	mb, err := m.MarshalBinary()
	if err != nil {
		return netlink.Message{}, err
	}
	nm.Data = mb

	return nm, nil
}

// unpackMessages unpacks rtnetlink Messages from a slice of netlink.Messages.
func unpackMessages(msgs []netlink.Message) ([]Message, error) {
	lmsgs := make([]Message, 0, len(msgs))

	for _, nm := range msgs {
		var m Message
		switch nm.Header.Type {
		case unix.RTM_GETLINK, unix.RTM_NEWLINK, unix.RTM_DELLINK:
			m = &LinkMessage{}
		case unix.RTM_GETADDR, unix.RTM_NEWADDR, unix.RTM_DELADDR:
			m = &AddressMessage{}
		case unix.RTM_GETROUTE, unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
			m = &RouteMessage{}
		case unix.RTM_GETNEIGH, unix.RTM_NEWNEIGH, unix.RTM_DELNEIGH:
			m = &NeighMessage{}
		default:
			continue
		}

		if err := (m).UnmarshalBinary(nm.Data); err != nil {
			return nil, err
		}
		lmsgs = append(lmsgs, m)
	}

	return lmsgs, nil
}
