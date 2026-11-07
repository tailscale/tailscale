// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tswg

import (
	"fmt"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"go4.org/mem"
	"tailscale.com/types/key"
)

// Constants for tswg's peer events, from its uapi header.
const (
	cmdPeerEvent = 64
	mcgrpEvents  = "events"

	eventAIfindex   = 1
	eventAPublicKey = 2
	eventAFlags     = 3

	eventFlagSession = 1
	eventFlagTX      = 2
	eventFlagRX      = 4
)

// EventConn receives peer events from all tswg devices in the current
// network namespace.
type EventConn struct {
	c *genetlink.Conn
}

// OpenEvents opens an EventConn. It fails if the tswg module isn't loaded
// or doesn't support events.
func OpenEvents() (*EventConn, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	fam, err := c.GetFamily(FamilyName)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("tswg: getting genetlink family %q (is tswg.ko loaded?): %w", FamilyName, err)
	}
	for _, g := range fam.Groups {
		if g.Name == mcgrpEvents {
			if err := c.JoinGroup(g.ID); err != nil {
				c.Close()
				return nil, fmt.Errorf("tswg: joining %q group: %w", mcgrpEvents, err)
			}
			return &EventConn{c: c}, nil
		}
	}
	c.Close()
	return nil, fmt.Errorf("tswg: module has no %q multicast group; too old?", mcgrpEvents)
}

// Close closes the EventConn, unblocking any Receive.
func (c *EventConn) Close() error {
	return c.c.Close()
}

// Receive blocks until it receives some events, and returns them.
//
// If the kernel had to drop events because they weren't read fast
// enough, it returns an error wrapping ENOBUFS; the EventConn remains
// usable.
func (c *EventConn) Receive() ([]Event, error) {
	msgs, _, err := c.c.Receive()
	if err != nil {
		return nil, err
	}
	var evs []Event
	for _, m := range msgs {
		if m.Header.Command != cmdPeerEvent {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data)
		if err != nil {
			continue
		}
		var ev Event
		for ad.Next() {
			switch ad.Type() {
			case eventAIfindex:
				ev.IfIndex = int(ad.Uint32())
			case eventAPublicKey:
				if b := ad.Bytes(); len(b) == 32 {
					ev.PublicKey = key.NodePublicFromRaw32(mem.B(b))
				}
			case eventAFlags:
				f := ad.Uint32()
				ev.Session = f&eventFlagSession != 0
				ev.TX = f&eventFlagTX != 0
				ev.RX = f&eventFlagRX != 0
			}
		}
		if ad.Err() == nil && !ev.PublicKey.IsZero() {
			evs = append(evs, ev)
		}
	}
	return evs, nil
}
