// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlbase

import (
	"crypto/mlkem"
	"encoding/binary"
)

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

	initiationPayloadLen   = 32 + 48 + 16
	responsePayloadLen     = 32 + 16
	pqInitiationPayloadLen = 32 + mlkem.EncapsulationKeySize768 + 48 + 16
	pqResponsePayloadLen   = 32 + mlkem.CiphertextSize768 + 16
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
type initiationMessage [initiationHeaderLen + initiationPayloadLen]byte

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

// pqInitiationMessage is the ML-KEM-augmented protocol message sent from a
// client machine to a control server.
//
// 2b: protocol version
// 1b: message type (0x01)
// 2b: payload length (1280)
// 32b: client ephemeral public key (cleartext)
// 1184b: client ML-KEM-768 encapsulation key (cleartext)
// 48b: client machine public key (encrypted)
// 16b: message tag (authenticates the whole message)
type pqInitiationMessage [initiationHeaderLen + pqInitiationPayloadLen]byte

func mkPQInitiationMessage(protocolVersion uint16) pqInitiationMessage {
	var ret pqInitiationMessage
	binary.BigEndian.PutUint16(ret[:2], protocolVersion)
	ret[2] = msgTypeInitiation
	binary.BigEndian.PutUint16(ret[3:5], uint16(len(ret.Payload())))
	return ret
}

func (m *pqInitiationMessage) Header() []byte  { return m[:initiationHeaderLen] }
func (m *pqInitiationMessage) Payload() []byte { return m[initiationHeaderLen:] }

func (m *pqInitiationMessage) Version() uint16 { return binary.BigEndian.Uint16(m[:2]) }
func (m *pqInitiationMessage) Type() byte      { return m[2] }
func (m *pqInitiationMessage) Length() int     { return int(binary.BigEndian.Uint16(m[3:5])) }

func (m *pqInitiationMessage) EphemeralPub() []byte {
	return m[initiationHeaderLen : initiationHeaderLen+32]
}
func (m *pqInitiationMessage) MLKEMEncapsulationKey() []byte {
	return m[initiationHeaderLen+32 : initiationHeaderLen+32+mlkem.EncapsulationKeySize768]
}
func (m *pqInitiationMessage) MachinePub() []byte {
	return m[initiationHeaderLen+32+mlkem.EncapsulationKeySize768 : initiationHeaderLen+32+mlkem.EncapsulationKeySize768+48]
}
func (m *pqInitiationMessage) Tag() []byte {
	return m[initiationHeaderLen+32+mlkem.EncapsulationKeySize768+48:]
}

// responseMessage is the protocol message sent from a control server
// to a client machine.
//
// 1b: message type (0x02)
// 2b: payload length (48)
// 32b: control ephemeral public key (cleartext)
// 16b: message tag (authenticates the whole message)
type responseMessage [headerLen + responsePayloadLen]byte

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

// pqResponseMessage is the ML-KEM-augmented protocol message sent from a
// control server to a client machine.
//
// 1b: message type (0x02)
// 2b: payload length (1136)
// 32b: control ephemeral public key (cleartext)
// 1088b: ML-KEM-768 ciphertext (cleartext)
// 16b: message tag (authenticates the whole message)
type pqResponseMessage [headerLen + pqResponsePayloadLen]byte

func mkPQResponseMessage() pqResponseMessage {
	var ret pqResponseMessage
	ret[0] = msgTypeResponse
	binary.BigEndian.PutUint16(ret[1:], uint16(len(ret.Payload())))
	return ret
}

func (m *pqResponseMessage) Header() []byte  { return m[:headerLen] }
func (m *pqResponseMessage) Payload() []byte { return m[headerLen:] }

func (m *pqResponseMessage) Type() byte  { return m[0] }
func (m *pqResponseMessage) Length() int { return int(binary.BigEndian.Uint16(m[1:3])) }

func (m *pqResponseMessage) EphemeralPub() []byte { return m[headerLen : headerLen+32] }
func (m *pqResponseMessage) MLKEMCiphertext() []byte {
	return m[headerLen+32 : headerLen+32+mlkem.CiphertextSize768]
}
func (m *pqResponseMessage) Tag() []byte { return m[headerLen+32+mlkem.CiphertextSize768:] }
