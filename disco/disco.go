// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package disco contains the discovery message types.
//
// A discovery message is:
//
// Header:
//     magic          [6]byte  // “TS💬” (0x54 53 f0 9f 92 ac)
//     senderDiscoPub [32]byte // nacl public key
//     nonce          [24]byte
//
// The recipient then decrypts the bytes following (the nacl secretbox)
// and then the inner payload structure is:
//
//     messageType    byte  (the MessageType constants below)
//     messageVersion byte  (0 for now; but always ignore bytes at the end)
//     message-paylod [...]byte
package disco

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"inet.af/netaddr"
)

// Magic is the 6 byte header of all discovery messages.
const Magic = "TS💬" // 6 bytes: 0x54 53 f0 9f 92 ac

// NonceLen is the length of the nonces used by nacl secretboxes.
const NonceLen = 24

type MessageType byte

const (
	TypePing        = MessageType(0x01)
	TypePong        = MessageType(0x02)
	TypeCallMeMaybe = MessageType(0x03)
)

const v0 = byte(0)

var errShort = errors.New("short message")

// Parse parses the encrypted part of the message from inside the
// nacl secretbox.
func Parse(p []byte) (Message, error) {
	if len(p) < 2 {
		return nil, errShort
	}
	t, ver, p := MessageType(p[0]), p[1], p[2:]
	switch t {
	case TypePing:
		return parsePing(ver, p)
	case TypePong:
		return parsePong(ver, p)
	case TypeCallMeMaybe:
		return CallMeMaybe{}, nil
	default:
		return nil, fmt.Errorf("unknown message type 0x%02x", byte(t))
	}
}

// Message a discovery message.
type Message interface {
	// AppendMarshal appends the message's marshaled representation.
	AppendMarshal([]byte) []byte
}

// appendMsgHeader appends two bytes (for t and ver) and then also
// dataLen bytes to b, returning the appended slice in all. The
// returned data slice is a subslice of all with just dataLen bytes of
// where the caller will fill in the data.
func appendMsgHeader(b []byte, t MessageType, ver uint8, dataLen int) (all, data []byte) {
	// TODO: optimize this?
	all = append(b, make([]byte, dataLen+2)...)
	all[len(b)] = byte(t)
	all[len(b)+1] = ver
	data = all[len(b)+2:]
	return
}

type Ping struct {
	TxID [12]byte
}

func (m *Ping) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypePing, v0, 12)
	copy(d, m.TxID[:])
	return ret
}

func parsePing(ver uint8, p []byte) (m *Ping, err error) {
	if len(p) < 12 {
		return nil, errShort
	}
	m = new(Ping)
	copy(m.TxID[:], p)
	return m, nil
}

// CallMeMaybe is a message sent only over DERP to request that the recipient try
// to open up a magicsock path back to the sender.
//
// The sender should've already sent UDP packets to the peer to open
// up the stateful firewall mappings inbound.
//
// The recipient may choose to not open a path back, if it's already
// happy with its path. But usually it will.
type CallMeMaybe struct{}

func (CallMeMaybe) AppendMarshal(b []byte) []byte {
	ret, _ := appendMsgHeader(b, TypeCallMeMaybe, v0, 0)
	return ret
}

// Pong is a response a Ping.
//
// It includes the sender's source IP + port, so it's effectively a
// STUN response.
type Pong struct {
	TxID [12]byte
	Src  netaddr.IPPort // 18 bytes (16+2) on the wire; v4-mapped ipv6 for IPv4
}

const pongLen = 12 + 16 + 2

func (m *Pong) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypePong, v0, pongLen)
	d = d[copy(d, m.TxID[:]):]
	ip16 := m.Src.IP.As16()
	d = d[copy(d, ip16[:]):]
	binary.BigEndian.PutUint16(d, m.Src.Port)
	return ret
}

func parsePong(ver uint8, p []byte) (m *Pong, err error) {
	if len(p) < pongLen {
		return nil, errShort
	}
	m = new(Pong)
	copy(m.TxID[:], p)
	p = p[12:]

	m.Src.IP, _ = netaddr.FromStdIP(net.IP(p[:16]))
	p = p[16:]

	m.Src.Port = binary.BigEndian.Uint16(p)
	return m, nil
}

// MessageSummary returns a short summary of m for logging purposes.
func MessageSummary(m Message) string {
	switch m := m.(type) {
	case *Ping:
		return fmt.Sprintf("ping tx=%x", m.TxID[:6])
	case *Pong:
		return fmt.Sprintf("pong tx=%x", m.TxID[:6])
	case CallMeMaybe:
		return "call-me-maybe"
	default:
		return fmt.Sprintf("%#v", m)
	}
}
