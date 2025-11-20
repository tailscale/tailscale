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
	TypePing                             = MessageType(0x01)
	TypePong                             = MessageType(0x02)
	TypeCallMeMaybe                      = MessageType(0x03)
	TypeBindUDPRelayEndpoint             = MessageType(0x04)
	TypeBindUDPRelayEndpointChallenge    = MessageType(0x05)
	TypeBindUDPRelayEndpointAnswer       = MessageType(0x06)
	TypeCallMeMaybeVia                   = MessageType(0x07)
	TypeAllocateUDPRelayEndpointRequest  = MessageType(0x08)
	TypeAllocateUDPRelayEndpointResponse = MessageType(0x09)
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
	case TypeAllocateUDPRelayEndpointRequest:
		return parseAllocateUDPRelayEndpointRequest(ver, p)
	case TypeAllocateUDPRelayEndpointResponse:
		return parseAllocateUDPRelayEndpointResponse(ver, p)
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
	case *CallMeMaybeVia:
		return "call-me-maybe-via"
	case *BindUDPRelayEndpoint:
		return "bind-udp-relay-endpoint"
	case *BindUDPRelayEndpointChallenge:
		return "bind-udp-relay-endpoint-challenge"
	case *BindUDPRelayEndpointAnswer:
		return "bind-udp-relay-endpoint-answer"
	case *AllocateUDPRelayEndpointRequest:
		return "allocate-udp-relay-endpoint-request"
	case *AllocateUDPRelayEndpointResponse:
		return "allocate-udp-relay-endpoint-response"
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

// bindUDPRelayEndpointCommonLen is the length of a marshalled
// [BindUDPRelayEndpointCommon], without the message header.
const bindUDPRelayEndpointCommonLen = 72

// BindUDPRelayChallengeLen is the length of the Challenge field carried in
// [BindUDPRelayEndpointChallenge] & [BindUDPRelayEndpointAnswer] messages.
const BindUDPRelayChallengeLen = 32

// BindUDPRelayEndpointCommon contains fields that are common across all 3
// UDP relay handshake message types. All 4 field values are expected to be
// consistent for the lifetime of a handshake besides Challenge, which is
// irrelevant in a [BindUDPRelayEndpoint] message.
type BindUDPRelayEndpointCommon struct {
	// VNI is the Geneve header Virtual Network Identifier field value, which
	// must match this disco-sealed value upon reception. If they are
	// non-matching it indicates the cleartext Geneve header was tampered with
	// and/or mangled.
	VNI uint32
	// Generation represents the handshake generation. Clients must set a new,
	// nonzero value at the start of every handshake.
	Generation uint32
	// RemoteKey is the disco key of the remote peer participating over this
	// relay endpoint.
	RemoteKey key.DiscoPublic
	// Challenge is set by the server in a [BindUDPRelayEndpointChallenge]
	// message, and expected to be echoed back by the client in a
	// [BindUDPRelayEndpointAnswer] message. Its value is irrelevant in a
	// [BindUDPRelayEndpoint] message, where it simply serves a padding purpose
	// ensuring all handshake messages are equal in size.
	Challenge [BindUDPRelayChallengeLen]byte
}

// encode encodes m in b. b must be at least bindUDPRelayEndpointCommonLen bytes
// long.
func (m *BindUDPRelayEndpointCommon) encode(b []byte) {
	binary.BigEndian.PutUint32(b, m.VNI)
	b = b[4:]
	binary.BigEndian.PutUint32(b, m.Generation)
	b = b[4:]
	m.RemoteKey.AppendTo(b[:0])
	b = b[key.DiscoPublicRawLen:]
	copy(b, m.Challenge[:])
}

// decode decodes m from b.
func (m *BindUDPRelayEndpointCommon) decode(b []byte) error {
	if len(b) < bindUDPRelayEndpointCommonLen {
		return errShort
	}
	m.VNI = binary.BigEndian.Uint32(b)
	b = b[4:]
	m.Generation = binary.BigEndian.Uint32(b)
	b = b[4:]
	m.RemoteKey = key.DiscoPublicFromRaw32(mem.B(b[:key.DiscoPublicRawLen]))
	b = b[key.DiscoPublicRawLen:]
	copy(m.Challenge[:], b[:BindUDPRelayChallengeLen])
	return nil
}

// BindUDPRelayEndpoint is the first messaged transmitted from UDP relay client
// towards UDP relay server as part of the 3-way bind handshake.
type BindUDPRelayEndpoint struct {
	BindUDPRelayEndpointCommon
}

func (m *BindUDPRelayEndpoint) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypeBindUDPRelayEndpoint, v0, bindUDPRelayEndpointCommonLen)
	m.BindUDPRelayEndpointCommon.encode(d)
	return ret
}

func parseBindUDPRelayEndpoint(ver uint8, p []byte) (m *BindUDPRelayEndpoint, err error) {
	m = new(BindUDPRelayEndpoint)
	err = m.BindUDPRelayEndpointCommon.decode(p)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// BindUDPRelayEndpointChallenge is transmitted from UDP relay server towards
// UDP relay client in response to a BindUDPRelayEndpoint message as part of the
// 3-way bind handshake.
type BindUDPRelayEndpointChallenge struct {
	BindUDPRelayEndpointCommon
}

func (m *BindUDPRelayEndpointChallenge) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypeBindUDPRelayEndpointChallenge, v0, bindUDPRelayEndpointCommonLen)
	m.BindUDPRelayEndpointCommon.encode(d)
	return ret
}

func parseBindUDPRelayEndpointChallenge(ver uint8, p []byte) (m *BindUDPRelayEndpointChallenge, err error) {
	m = new(BindUDPRelayEndpointChallenge)
	err = m.BindUDPRelayEndpointCommon.decode(p)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// BindUDPRelayEndpointAnswer is transmitted from UDP relay client to UDP relay
// server in response to a BindUDPRelayEndpointChallenge message.
type BindUDPRelayEndpointAnswer struct {
	BindUDPRelayEndpointCommon
}

func (m *BindUDPRelayEndpointAnswer) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypeBindUDPRelayEndpointAnswer, v0, bindUDPRelayEndpointCommonLen)
	m.BindUDPRelayEndpointCommon.encode(d)
	return ret
}

func parseBindUDPRelayEndpointAnswer(ver uint8, p []byte) (m *BindUDPRelayEndpointAnswer, err error) {
	m = new(BindUDPRelayEndpointAnswer)
	err = m.BindUDPRelayEndpointCommon.decode(p)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// AllocateUDPRelayEndpointRequest is a message sent only over DERP to request
// allocation of a relay endpoint on a [tailscale.com/net/udprelay.Server]
type AllocateUDPRelayEndpointRequest struct {
	// ClientDisco are the Disco public keys of the clients that should be
	// permitted to handshake with the endpoint.
	ClientDisco [2]key.DiscoPublic
	// Generation represents the allocation request generation. The server must
	// echo it back in the [AllocateUDPRelayEndpointResponse] to enable request
	// and response alignment client-side.
	Generation uint32
}

// allocateUDPRelayEndpointRequestLen is the length of a marshaled
// [AllocateUDPRelayEndpointRequest] message without the message header.
const allocateUDPRelayEndpointRequestLen = key.DiscoPublicRawLen*2 + // ClientDisco
	4 // Generation

func (m *AllocateUDPRelayEndpointRequest) AppendMarshal(b []byte) []byte {
	ret, p := appendMsgHeader(b, TypeAllocateUDPRelayEndpointRequest, v0, allocateUDPRelayEndpointRequestLen)
	for i := 0; i < len(m.ClientDisco); i++ {
		disco := m.ClientDisco[i].AppendTo(nil)
		copy(p, disco)
		p = p[key.DiscoPublicRawLen:]
	}
	binary.BigEndian.PutUint32(p, m.Generation)
	return ret
}

func parseAllocateUDPRelayEndpointRequest(ver uint8, p []byte) (m *AllocateUDPRelayEndpointRequest, err error) {
	m = new(AllocateUDPRelayEndpointRequest)
	if ver != 0 {
		return
	}
	if len(p) < allocateUDPRelayEndpointRequestLen {
		return m, errShort
	}
	for i := 0; i < len(m.ClientDisco); i++ {
		m.ClientDisco[i] = key.DiscoPublicFromRaw32(mem.B(p[:key.DiscoPublicRawLen]))
		p = p[key.DiscoPublicRawLen:]
	}
	m.Generation = binary.BigEndian.Uint32(p)
	return m, nil
}

// AllocateUDPRelayEndpointResponse is a message sent only over DERP in response
// to a [AllocateUDPRelayEndpointRequest].
type AllocateUDPRelayEndpointResponse struct {
	// Generation represents the allocation request generation. The server must
	// echo back the [AllocateUDPRelayEndpointRequest.Generation] here to enable
	// request and response alignment client-side.
	Generation uint32
	UDPRelayEndpoint
}

func (m *AllocateUDPRelayEndpointResponse) AppendMarshal(b []byte) []byte {
	endpointsLen := epLength * len(m.AddrPorts)
	generationLen := 4
	ret, d := appendMsgHeader(b, TypeAllocateUDPRelayEndpointResponse, v0, generationLen+udpRelayEndpointLenMinusAddrPorts+endpointsLen)
	binary.BigEndian.PutUint32(d, m.Generation)
	m.encode(d[4:])
	return ret
}

func parseAllocateUDPRelayEndpointResponse(ver uint8, p []byte) (m *AllocateUDPRelayEndpointResponse, err error) {
	m = new(AllocateUDPRelayEndpointResponse)
	if ver != 0 {
		return m, nil
	}
	if len(p) < 4 {
		return m, errShort
	}
	m.Generation = binary.BigEndian.Uint32(p)
	err = m.decode(p[4:])
	return m, err
}

const udpRelayEndpointLenMinusAddrPorts = key.DiscoPublicRawLen + // ServerDisco
	(key.DiscoPublicRawLen * 2) + // ClientDisco
	8 + // LamportID
	4 + // VNI
	8 + // BindLifetime
	8 // SteadyStateLifetime

// UDPRelayEndpoint is a mirror of [tailscale.com/net/udprelay/endpoint.ServerEndpoint],
// refer to it for field documentation. [UDPRelayEndpoint] is carried in both
// [CallMeMaybeVia] and [AllocateUDPRelayEndpointResponse] messages.
type UDPRelayEndpoint struct {
	// ServerDisco is [tailscale.com/net/udprelay/endpoint.ServerEndpoint.ServerDisco]
	ServerDisco key.DiscoPublic
	// ClientDisco is [tailscale.com/net/udprelay/endpoint.ServerEndpoint.ClientDisco]
	ClientDisco [2]key.DiscoPublic
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

// encode encodes m in b. b must be at least [udpRelayEndpointLenMinusAddrPorts]
// + [epLength] * len(m.AddrPorts) bytes long.
func (m *UDPRelayEndpoint) encode(b []byte) {
	disco := m.ServerDisco.AppendTo(nil)
	copy(b, disco)
	b = b[key.DiscoPublicRawLen:]
	for i := 0; i < len(m.ClientDisco); i++ {
		disco = m.ClientDisco[i].AppendTo(nil)
		copy(b, disco)
		b = b[key.DiscoPublicRawLen:]
	}
	binary.BigEndian.PutUint64(b[:8], m.LamportID)
	b = b[8:]
	binary.BigEndian.PutUint32(b[:4], m.VNI)
	b = b[4:]
	binary.BigEndian.PutUint64(b[:8], uint64(m.BindLifetime))
	b = b[8:]
	binary.BigEndian.PutUint64(b[:8], uint64(m.SteadyStateLifetime))
	b = b[8:]
	for _, ipp := range m.AddrPorts {
		a := ipp.Addr().As16()
		copy(b, a[:])
		binary.BigEndian.PutUint16(b[16:18], ipp.Port())
		b = b[epLength:]
	}
}

// decode decodes m from b.
func (m *UDPRelayEndpoint) decode(b []byte) error {
	if len(b) < udpRelayEndpointLenMinusAddrPorts+epLength ||
		(len(b)-udpRelayEndpointLenMinusAddrPorts)%epLength != 0 {
		return errShort
	}
	m.ServerDisco = key.DiscoPublicFromRaw32(mem.B(b[:key.DiscoPublicRawLen]))
	b = b[key.DiscoPublicRawLen:]
	for i := 0; i < len(m.ClientDisco); i++ {
		m.ClientDisco[i] = key.DiscoPublicFromRaw32(mem.B(b[:key.DiscoPublicRawLen]))
		b = b[key.DiscoPublicRawLen:]
	}
	m.LamportID = binary.BigEndian.Uint64(b[:8])
	b = b[8:]
	m.VNI = binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	m.BindLifetime = time.Duration(binary.BigEndian.Uint64(b[:8]))
	b = b[8:]
	m.SteadyStateLifetime = time.Duration(binary.BigEndian.Uint64(b[:8]))
	b = b[8:]
	m.AddrPorts = make([]netip.AddrPort, 0, len(b)-udpRelayEndpointLenMinusAddrPorts/epLength)
	for len(b) > 0 {
		var a [16]byte
		copy(a[:], b)
		m.AddrPorts = append(m.AddrPorts, netip.AddrPortFrom(
			netip.AddrFrom16(a).Unmap(),
			binary.BigEndian.Uint16(b[16:18])))
		b = b[epLength:]
	}
	return nil
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
type CallMeMaybeVia struct {
	UDPRelayEndpoint
}

func (m *CallMeMaybeVia) AppendMarshal(b []byte) []byte {
	endpointsLen := epLength * len(m.AddrPorts)
	ret, p := appendMsgHeader(b, TypeCallMeMaybeVia, v0, udpRelayEndpointLenMinusAddrPorts+endpointsLen)
	m.encode(p)
	return ret
}

func parseCallMeMaybeVia(ver uint8, p []byte) (m *CallMeMaybeVia, err error) {
	m = new(CallMeMaybeVia)
	if ver != 0 {
		return m, nil
	}
	err = m.decode(p)
	return m, err
}
