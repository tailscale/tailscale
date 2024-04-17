// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package disco contains the discovery message types.
//
// A discovery message is:
//
// Header:
//
//	magic          [6]byte  // “TS💬” (0x54 53 f0 9f 92 ac)
//	senderDiscoPub [32]byte // nacl public key
//	nonce          [24]byte
//
// The recipient then decrypts the bytes following (the nacl box)
// and then the inner payload structure is:
//
//	messageType     byte  (the MessageType constants below)
//	messageVersion  byte  (0 for now; but always ignore bytes at the end)
//	message-payload [...]byte
package disco

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"go4.org/mem"
	"tailscale.com/types/key"
)

// Magic is the 6 byte header of all discovery messages.
const Magic = "TS💬" // 6 bytes: 0x54 53 f0 9f 92 ac

const keyLen = 32

// NonceLen is the length of the nonces used by nacl box.
const NonceLen = 24

type MessageType byte

const (
	TypePing        = MessageType(0x01)
	TypePong        = MessageType(0x02)
	TypeCallMeMaybe = MessageType(0x03)
)

const v0 = byte(0)

var errShort = errors.New("short message")

// LooksLikeDiscoWrapper reports whether p looks like it's a packet
// containing an encrypted disco message.
func LooksLikeDiscoWrapper(p []byte) bool {
	if len(p) < len(Magic)+keyLen+NonceLen {
		return false
	}
	return string(p[:len(Magic)]) == Magic
}

// Source returns the slice of p that represents the
// disco public key source, and whether p looks like
// a disco message.
func Source(p []byte) (src []byte, ok bool) {
	if !LooksLikeDiscoWrapper(p) {
		return nil, false
	}
	return p[len(Magic):][:keyLen], true
}

// Parse parses the encrypted part of the message from inside the
// nacl box.
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
		return parseCallMeMaybe(ver, p)
	default:
		return nil, fmt.Errorf("unknown message type 0x%02x", byte(t))
	}
}

// Message a discovery message.
type Message interface {
	// AppendMarshal appends the message's marshaled representation.
	AppendMarshal([]byte) []byte
}

// MessageHeaderLen is the length of a message header, 2 bytes for type and version.
const MessageHeaderLen = 2

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
	// TxID is a random client-generated per-ping transaction ID.
	TxID [12]byte

	// NodeKey is allegedly the ping sender's wireguard public key.
	// Old clients (~1.16.0 and earlier) don't send this field.
	// It shouldn't be trusted by itself, but can be combined with
	// netmap data to reduce the discokey:nodekey relation from 1:N to
	// 1:1.
	NodeKey key.NodePublic

	// Padding is the number of 0 bytes at the end of the
	// message. (It's used to probe path MTU.)
	Padding int
}

// PingLen is the length of a marshalled ping message, without the message
// header or padding.
const PingLen = 12 + key.NodePublicRawLen

func (m *Ping) AppendMarshal(b []byte) []byte {
	dataLen := 12
	hasKey := !m.NodeKey.IsZero()
	if hasKey {
		dataLen += key.NodePublicRawLen
	}

	ret, d := appendMsgHeader(b, TypePing, v0, dataLen+m.Padding)
	n := copy(d, m.TxID[:])
	if hasKey {
		m.NodeKey.AppendTo(d[:n])
	}
	return ret
}

func parsePing(ver uint8, p []byte) (m *Ping, err error) {
	if len(p) < 12 {
		return nil, errShort
	}
	m = new(Ping)
	m.Padding = len(p)
	p = p[copy(m.TxID[:], p):]
	m.Padding -= 12
	// Deliberately lax on longer-than-expected messages, for future
	// compatibility.
	if len(p) >= key.NodePublicRawLen {
		m.NodeKey = key.NodePublicFromRaw32(mem.B(p[:key.NodePublicRawLen]))
		m.Padding -= key.NodePublicRawLen
	}
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
type CallMeMaybe struct {
	// MyNumber is what the peer believes its endpoints are.
	//
	// Prior to Tailscale 1.4, the endpoints were exchanged purely
	// between nodes and the control server.
	//
	// Starting with Tailscale 1.4, clients advertise their endpoints.
	// Older clients won't use this, but newer clients should
	// use any endpoints in here that aren't included from control.
	//
	// Control might have sent stale endpoints if the client was idle
	// before contacting us. In that case, the client likely did a STUN
	// request immediately before sending the CallMeMaybe to recreate
	// their NAT port mapping, and that new good endpoint is included
	// in this field, but might not yet be in control's endpoints.
	// (And in the future, control will stop distributing endpoints
	// when clients are suitably new.)
	MyNumber []netip.AddrPort
}

const epLength = 16 + 2 // 16 byte IP address + 2 byte port

func (m *CallMeMaybe) AppendMarshal(b []byte) []byte {
	ret, p := appendMsgHeader(b, TypeCallMeMaybe, v0, epLength*len(m.MyNumber))
	for _, ipp := range m.MyNumber {
		a := ipp.Addr().As16()
		copy(p[:], a[:])
		binary.BigEndian.PutUint16(p[16:], ipp.Port())
		p = p[epLength:]
	}
	return ret
}

func parseCallMeMaybe(ver uint8, p []byte) (m *CallMeMaybe, err error) {
	m = new(CallMeMaybe)
	if len(p)%epLength != 0 || ver != 0 || len(p) == 0 {
		return m, nil
	}
	m.MyNumber = make([]netip.AddrPort, 0, len(p)/epLength)
	for len(p) > 0 {
		var a [16]byte
		copy(a[:], p)
		m.MyNumber = append(m.MyNumber, netip.AddrPortFrom(
			netip.AddrFrom16(a).Unmap(),
			binary.BigEndian.Uint16(p[16:18])))
		p = p[epLength:]
	}
	return m, nil
}

// Pong is a response a Ping.
//
// It includes the sender's source IP + port, so it's effectively a
// STUN response.
type Pong struct {
	TxID [12]byte
	Src  netip.AddrPort // 18 bytes (16+2) on the wire; v4-mapped ipv6 for IPv4
}

// pongLen is the length of a marshalled pong message, without the message
// header or padding.
const pongLen = 12 + 16 + 2

func (m *Pong) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypePong, v0, pongLen)
	d = d[copy(d, m.TxID[:]):]
	ip16 := m.Src.Addr().As16()
	d = d[copy(d, ip16[:]):]
	binary.BigEndian.PutUint16(d, m.Src.Port())
	return ret
}

func parsePong(ver uint8, p []byte) (m *Pong, err error) {
	if len(p) < pongLen {
		return nil, errShort
	}
	m = new(Pong)
	copy(m.TxID[:], p)
	p = p[12:]

	srcIP, _ := netip.AddrFromSlice(net.IP(p[:16]))
	p = p[16:]
	port := binary.BigEndian.Uint16(p)
	m.Src = netip.AddrPortFrom(srcIP.Unmap(), port)
	return m, nil
}

// MessageSummary returns a short summary of m for logging purposes.
func MessageSummary(m Message) string {
	switch m := m.(type) {
	case *Ping:
		return fmt.Sprintf("ping tx=%x padding=%v", m.TxID[:6], m.Padding)
	case *Pong:
		return fmt.Sprintf("pong tx=%x", m.TxID[:6])
	case *CallMeMaybe:
		return "call-me-maybe"
	default:
		return fmt.Sprintf("%#v", m)
	}
}
