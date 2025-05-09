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
	"time"

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
	TypePing                          = MessageType(0x01)
	TypePong                          = MessageType(0x02)
	TypeCallMeMaybe                   = MessageType(0x03)
	TypeBindUDPRelayEndpoint          = MessageType(0x04)
	TypeBindUDPRelayEndpointChallenge = MessageType(0x05)
	TypeBindUDPRelayEndpointAnswer    = MessageType(0x06)
	TypeCallMeMaybeVia                = MessageType(0x07)
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
	// TODO(jwhited): consider using a signature matching encoding.BinaryUnmarshaler
	case TypePing:
		return parsePing(ver, p)
	case TypePong:
		return parsePong(ver, p)
	case TypeCallMeMaybe:
		return parseCallMeMaybe(ver, p)
	case TypeBindUDPRelayEndpoint:
		return parseBindUDPRelayEndpoint(ver, p)
	case TypeBindUDPRelayEndpointChallenge:
		return parseBindUDPRelayEndpointChallenge(ver, p)
	case TypeBindUDPRelayEndpointAnswer:
		return parseBindUDPRelayEndpointAnswer(ver, p)
	case TypeCallMeMaybeVia:
		return parseCallMeMaybeVia(ver, p)
	default:
		return nil, fmt.Errorf("unknown message type 0x%02x", byte(t))
	}
}

// Message a discovery message.
type Message interface {
	// AppendMarshal appends the message's marshaled representation.
	// TODO(jwhited): consider using a signature matching encoding.BinaryAppender
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
	case *BindUDPRelayEndpoint:
		return "bind-udp-relay-endpoint"
	case *BindUDPRelayEndpointChallenge:
		return "bind-udp-relay-endpoint-challenge"
	case *BindUDPRelayEndpointAnswer:
		return "bind-udp-relay-endpoint-answer"
	default:
		return fmt.Sprintf("%#v", m)
	}
}

// BindUDPRelayHandshakeState represents the state of the 3-way bind handshake
// between UDP relay client and UDP relay server. Its potential values include
// those for both participants, UDP relay client and UDP relay server. A UDP
// relay server implementation can be found in net/udprelay. This is currently
// considered experimental.
type BindUDPRelayHandshakeState int

const (
	// BindUDPRelayHandshakeStateInit represents the initial state prior to any
	// message being transmitted.
	BindUDPRelayHandshakeStateInit BindUDPRelayHandshakeState = iota
	// BindUDPRelayHandshakeStateBindSent is the first client state after
	// transmitting a BindUDPRelayEndpoint message to a UDP relay server.
	BindUDPRelayHandshakeStateBindSent
	// BindUDPRelayHandshakeStateChallengeSent is the first server state after
	// receiving a BindUDPRelayEndpoint message from a UDP relay client and
	// replying with a BindUDPRelayEndpointChallenge.
	BindUDPRelayHandshakeStateChallengeSent
	// BindUDPRelayHandshakeStateAnswerSent is a client state that is entered
	// after transmitting a BindUDPRelayEndpointAnswer message towards a UDP
	// relay server in response to a BindUDPRelayEndpointChallenge message.
	BindUDPRelayHandshakeStateAnswerSent
	// BindUDPRelayHandshakeStateAnswerReceived is a server state that is
	// entered after it has received a correct BindUDPRelayEndpointAnswer
	// message from a UDP relay client in response to a
	// BindUDPRelayEndpointChallenge message.
	BindUDPRelayHandshakeStateAnswerReceived
)

// bindUDPRelayEndpointLen is the length of a marshalled BindUDPRelayEndpoint
// message, without the message header.
const bindUDPRelayEndpointLen = BindUDPRelayEndpointChallengeLen

// BindUDPRelayEndpoint is the first messaged transmitted from UDP relay client
// towards UDP relay server as part of the 3-way bind handshake. It is padded to
// match the length of BindUDPRelayEndpointChallenge. This message type is
// currently considered experimental and is not yet tied to a
// tailcfg.CapabilityVersion.
type BindUDPRelayEndpoint struct {
}

func (m *BindUDPRelayEndpoint) AppendMarshal(b []byte) []byte {
	ret, _ := appendMsgHeader(b, TypeBindUDPRelayEndpoint, v0, bindUDPRelayEndpointLen)
	return ret
}

func parseBindUDPRelayEndpoint(ver uint8, p []byte) (m *BindUDPRelayEndpoint, err error) {
	m = new(BindUDPRelayEndpoint)
	return m, nil
}

// BindUDPRelayEndpointChallengeLen is the length of a marshalled
// BindUDPRelayEndpointChallenge message, without the message header.
const BindUDPRelayEndpointChallengeLen = 32

// BindUDPRelayEndpointChallenge is transmitted from UDP relay server towards
// UDP relay client in response to a BindUDPRelayEndpoint message as part of the
// 3-way bind handshake. This message type is currently considered experimental
// and is not yet tied to a tailcfg.CapabilityVersion.
type BindUDPRelayEndpointChallenge struct {
	Challenge [BindUDPRelayEndpointChallengeLen]byte
}

func (m *BindUDPRelayEndpointChallenge) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypeBindUDPRelayEndpointChallenge, v0, BindUDPRelayEndpointChallengeLen)
	copy(d, m.Challenge[:])
	return ret
}

func parseBindUDPRelayEndpointChallenge(ver uint8, p []byte) (m *BindUDPRelayEndpointChallenge, err error) {
	if len(p) < BindUDPRelayEndpointChallengeLen {
		return nil, errShort
	}
	m = new(BindUDPRelayEndpointChallenge)
	copy(m.Challenge[:], p[:])
	return m, nil
}

// bindUDPRelayEndpointAnswerLen is the length of a marshalled
// BindUDPRelayEndpointAnswer message, without the message header.
const bindUDPRelayEndpointAnswerLen = BindUDPRelayEndpointChallengeLen

// BindUDPRelayEndpointAnswer is transmitted from UDP relay client to UDP relay
// server in response to a BindUDPRelayEndpointChallenge message. This message
// type is currently considered experimental and is not yet tied to a
// tailcfg.CapabilityVersion.
type BindUDPRelayEndpointAnswer struct {
	Answer [bindUDPRelayEndpointAnswerLen]byte
}

func (m *BindUDPRelayEndpointAnswer) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypeBindUDPRelayEndpointAnswer, v0, bindUDPRelayEndpointAnswerLen)
	copy(d, m.Answer[:])
	return ret
}

func parseBindUDPRelayEndpointAnswer(ver uint8, p []byte) (m *BindUDPRelayEndpointAnswer, err error) {
	if len(p) < bindUDPRelayEndpointAnswerLen {
		return nil, errShort
	}
	m = new(BindUDPRelayEndpointAnswer)
	copy(m.Answer[:], p[:])
	return m, nil
}

// CallMeMaybeVia is a message sent only over DERP to request that the recipient
// try to open up a magicsock path back to the sender. The 'Via' in
// CallMeMaybeVia highlights that candidate paths are served through an
// intermediate relay, likely a [tailscale.com/net/udprelay.Server].
//
// Usage of the candidate paths in magicsock requires a 3-way handshake
// involving [BindUDPRelayEndpoint], [BindUDPRelayEndpointChallenge], and
// [BindUDPRelayEndpointAnswer].
//
// CallMeMaybeVia mirrors [tailscale.com/net/udprelay/endpoint.ServerEndpoint],
// which contains field documentation.
//
// The recipient may choose to not open a path back if it's already happy with
// its path. Direct connections, e.g. [CallMeMaybe]-signaled, take priority over
// CallMeMaybeVia paths.
//
// This message type is currently considered experimental and is not yet tied to
// a [tailscale.com/tailcfg.CapabilityVersion].
type CallMeMaybeVia struct {
	// ServerDisco is [tailscale.com/net/udprelay/endpoint.ServerEndpoint.ServerDisco]
	ServerDisco key.DiscoPublic
	// LamportID is [tailscale.com/net/udprelay/endpoint.ServerEndpoint.LamportID]
	LamportID uint64
	// VNI is [tailscale.com/net/udprelay/endpoint.ServerEndpoint.VNI]
	VNI uint32
	// BindLifetime is [tailscale.com/net/udprelay/endpoint.ServerEndpoint.BindLifetime]
	BindLifetime time.Duration
	// SteadyStateLifetime is [tailscale.com/net/udprelay/endpoint.ServerEndpoint.SteadyStateLifetime]
	SteadyStateLifetime time.Duration
	// AddrPorts is [tailscale.com/net/udprelay/endpoint.ServerEndpoint.AddrPorts]
	AddrPorts []netip.AddrPort
}

const cmmvDataLenMinusEndpoints = key.DiscoPublicRawLen + // ServerDisco
	8 + // LamportID
	4 + // VNI
	8 + // BindLifetime
	8 // SteadyStateLifetime

func (m *CallMeMaybeVia) AppendMarshal(b []byte) []byte {
	endpointsLen := epLength * len(m.AddrPorts)
	ret, p := appendMsgHeader(b, TypeCallMeMaybeVia, v0, cmmvDataLenMinusEndpoints+endpointsLen)
	disco := m.ServerDisco.AppendTo(nil)
	copy(p, disco)
	p = p[key.DiscoPublicRawLen:]
	binary.BigEndian.PutUint64(p[:8], m.LamportID)
	p = p[8:]
	binary.BigEndian.PutUint32(p[:4], m.VNI)
	p = p[4:]
	binary.BigEndian.PutUint64(p[:8], uint64(m.BindLifetime))
	p = p[8:]
	binary.BigEndian.PutUint64(p[:8], uint64(m.SteadyStateLifetime))
	p = p[8:]
	for _, ipp := range m.AddrPorts {
		a := ipp.Addr().As16()
		copy(p, a[:])
		binary.BigEndian.PutUint16(p[16:18], ipp.Port())
		p = p[epLength:]
	}
	return ret
}

func parseCallMeMaybeVia(ver uint8, p []byte) (m *CallMeMaybeVia, err error) {
	m = new(CallMeMaybeVia)
	if len(p) < cmmvDataLenMinusEndpoints+epLength ||
		(len(p)-cmmvDataLenMinusEndpoints)%epLength != 0 ||
		ver != 0 {
		return m, nil
	}
	m.ServerDisco = key.DiscoPublicFromRaw32(mem.B(p[:key.DiscoPublicRawLen]))
	p = p[key.DiscoPublicRawLen:]
	m.LamportID = binary.BigEndian.Uint64(p[:8])
	p = p[8:]
	m.VNI = binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	m.BindLifetime = time.Duration(binary.BigEndian.Uint64(p[:8]))
	p = p[8:]
	m.SteadyStateLifetime = time.Duration(binary.BigEndian.Uint64(p[:8]))
	p = p[8:]
	m.AddrPorts = make([]netip.AddrPort, 0, len(p)-cmmvDataLenMinusEndpoints/epLength)
	for len(p) > 0 {
		var a [16]byte
		copy(a[:], p)
		m.AddrPorts = append(m.AddrPorts, netip.AddrPortFrom(
			netip.AddrFrom16(a).Unmap(),
			binary.BigEndian.Uint16(p[16:18])))
		p = p[epLength:]
	}
	return m, nil
}
