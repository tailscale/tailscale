// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlbase

import "encoding/binary"

const (
	// msgTypeInitiation frames carry a Noise IK handshake initiation message.
	msgTypeInitiation = 1
	// msgTypeResponse frames carry a Noise IK handshake response message.
	msgTypeResponse = 2
	// msgTypeError frames carry an unauthenticated human-readable
	// error message.
	//
	// Errors reported in this message type must be treated as public
	// hints only. They are not encrypted or authenticated, and so can
	// be seen and tampered with on the wire.
	msgTypeError = 3
	// msgTypeRecord frames carry session data bytes.
	msgTypeRecord = 4

	// headerLen is the size of the header on all messages except msgTypeInitiation.
	headerLen = 3
	// initiationHeaderLen is the size of the header on all msgTypeInitiation messages.
	initiationHeaderLen = 5
)

// initiationMessage is the protocol message sent from a client
// machine to a control server.
//
// 2b: protocol version
// 1b: message type (0x01)
// 2b: payload length (96)
// 5b: header (see headerLen for fields)
// 32b: client ephemeral public key (cleartext)
// 48b: client machine public key (encrypted)
// 16b: message tag (authenticates the whole message)
type initiationMessage [101]byte

func mkInitiationMessage(protocolVersion uint16) initiationMessage {
	var ret initiationMessage
	binary.BigEndian.PutUint16(ret[:2], protocolVersion)
	ret[2] = msgTypeInitiation
	binary.BigEndian.PutUint16(ret[3:5], uint16(len(ret.Payload())))
	return ret
}

func (m *initiationMessage) Header() []byte  { return m[:initiationHeaderLen] }
func (m *initiationMessage) Payload() []byte { return m[initiationHeaderLen:] }

func (m *initiationMessage) Version() uint16 { return binary.BigEndian.Uint16(m[:2]) }
func (m *initiationMessage) Type() byte      { return m[2] }
func (m *initiationMessage) Length() int     { return int(binary.BigEndian.Uint16(m[3:5])) }

func (m *initiationMessage) EphemeralPub() []byte {
	return m[initiationHeaderLen : initiationHeaderLen+32]
}
func (m *initiationMessage) MachinePub() []byte {
	return m[initiationHeaderLen+32 : initiationHeaderLen+32+48]
}
func (m *initiationMessage) Tag() []byte { return m[initiationHeaderLen+32+48:] }

// responseMessage is the protocol message sent from a control server
// to a client machine.
//
// 1b: message type (0x02)
// 2b: payload length (48)
// 32b: control ephemeral public key (cleartext)
// 16b: message tag (authenticates the whole message)
type responseMessage [51]byte

func mkResponseMessage() responseMessage {
	var ret responseMessage
	ret[0] = msgTypeResponse
	binary.BigEndian.PutUint16(ret[1:], uint16(len(ret.Payload())))
	return ret
}

func (m *responseMessage) Header() []byte  { return m[:headerLen] }
func (m *responseMessage) Payload() []byte { return m[headerLen:] }

func (m *responseMessage) Type() byte  { return m[0] }
func (m *responseMessage) Length() int { return int(binary.BigEndian.Uint16(m[1:3])) }

func (m *responseMessage) EphemeralPub() []byte { return m[headerLen : headerLen+32] }
func (m *responseMessage) Tag() []byte          { return m[headerLen+32:] }
