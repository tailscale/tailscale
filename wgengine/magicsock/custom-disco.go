// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_customdisco

package magicsock

import (
	"errors"
	"fmt"
	"net/netip"

	"tailscale.com/disco"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// customDiscoRegistry is the type of Conn.customDisco when custom disco
// support is compiled in.
type customDiscoRegistry map[disco.MessageType]*CustomDiscoMessage

// CustomDiscoMessage defines a custom disco message type for use with
// AddCustomDiscoMessage. This is an experimental interface for extending the
// disco protocol; as of 2026-03-10 it is not yet a guaranteed stable API.
type CustomDiscoMessage struct {
	// MessageType is the disco message type byte. It must be >=
	// disco.MinCustomMessageType (0x80); AddCustomDiscoMessage panics
	// otherwise. Values below 0x80 are reserved for the Tailscale
	// disco protocol.
	MessageType disco.MessageType

	// Parse parses the raw message payload (after the type and version
	// header bytes) into a disco.Message. If it returns (nil, nil) the
	// message is treated as an unknown type.
	Parse disco.ParseHookFunc

	// AcceptUnknownPeers, if true, causes disco messages to be
	// accepted even from peers not present in the netmap.
	AcceptUnknownPeers bool

	// HandleMessage, if non-nil, is called after a received disco message is
	// parsed.
	HandleMessage func(dm disco.Message, sender key.DiscoPublic, derpNodeSrc key.NodePublic)
}

// AddCustomDiscoMessage registers a custom disco message type on the Conn.
// See CustomDiscoMessage for field documentation.
//
// It panics if m.MessageType < disco.MinCustomMessageType (0x80) or if a
// handler for the same MessageType has already been registered.
func (c *Conn) AddCustomDiscoMessage(m *CustomDiscoMessage) {
	if m.MessageType < disco.MinCustomMessageType {
		panic(fmt.Sprintf("disco message type 0x%02x is in the reserved range (must be >= 0x%02x)", byte(m.MessageType), byte(disco.MinCustomMessageType)))
	}
	if _, dup := c.customDisco[m.MessageType]; dup {
		panic(fmt.Sprintf("duplicate registration for disco message type 0x%02x", byte(m.MessageType)))
	}
	if c.customDisco == nil {
		c.customDisco = make(customDiscoRegistry)
	}
	c.customDisco[m.MessageType] = m
}

// customDiscoAcceptsUnknownPeers reports whether any registered custom disco
// message type has AcceptUnknownPeers set.
func (c *Conn) customDiscoAcceptsUnknownPeers() bool {
	for _, cd := range c.customDisco {
		if cd.AcceptUnknownPeers {
			return true
		}
	}
	return false
}

// customDiscoParseHook dispatches to the Parse hook of the registered custom
// disco message type matching msgType.
func (c *Conn) customDiscoParseHook(msgType disco.MessageType, ver uint8, p []byte) (disco.Message, error) {
	if cd, ok := c.customDisco[msgType]; ok && cd.Parse != nil {
		return cd.Parse(msgType, ver, p)
	}
	return nil, nil
}

// handleMessage dispatches a parsed disco message to the registered handler
// for the given message type.
func (r customDiscoRegistry) handleMessage(msgType disco.MessageType, dm disco.Message, sender key.DiscoPublic, derpNodeSrc key.NodePublic) {
	if cd, ok := r[msgType]; ok && cd.HandleMessage != nil {
		cd.HandleMessage(dm, sender, derpNodeSrc)
	}
}

// SendCustomDiscoOverDERP sends a disco message to a peer identified by
// its disco and node public keys via the specified DERP region.
//
// It returns an error if the message's type byte (the first byte of its
// marshaled form) has not been registered via AddCustomDiscoMessage.
func (c *Conn) SendCustomDiscoOverDERP(dstDisco key.DiscoPublic, dstNode key.NodePublic, derpRegion int, m disco.Message) (sent bool, err error) {
	payload := m.AppendMarshal(nil)
	if len(payload) == 0 {
		return false, errors.New("empty disco message")
	}
	msgType := disco.MessageType(payload[0])
	if _, ok := c.customDisco[msgType]; !ok {
		return false, fmt.Errorf("unregistered custom disco message type 0x%02x", byte(msgType))
	}

	dstAddr := netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, uint16(derpRegion))

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false, errConnClosed
	}
	pkt := make([]byte, 0, 512)
	pkt = append(pkt, disco.Magic...)
	pkt = c.discoAtomic.Public().AppendTo(pkt)
	di := c.discoInfoForKnownPeerLocked(dstDisco)
	c.mu.Unlock()

	box := di.sharedKey.Seal(payload)
	pkt = append(pkt, box...)
	const isDisco = true
	const isGeneveEncap = false
	return c.sendAddr(dstAddr, dstNode, pkt, isDisco, isGeneveEncap)
}
