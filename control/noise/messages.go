// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noise

import "encoding/binary"

// The transport protocol is mostly Noise messages encapsulated in a
// small header describing the payload's type and length. The one
// place we deviate from pure Noise+header is that we also support
// sending an unauthenticated plaintext error as payload, to provide
// an explanation for a connection error that happens before the
// handshake completes.
//
// All frames in our protocol have a 5-byte header:
//
// +------+------+------+------+------+
// |   version   | type |   length    |
// +------+------+------+------+------+
//
// 2b: protocol version
// 1b: message type
// 2b: payload length (not including the header)
//
// Multibyte values are all big-endian on the wire, as is traditional
// for network protocols.
//
// The protocol version is 2 bytes in order to encourage frequent
// revving of the protocol as needed, without fear of running out of
// version numbers. At minimum, the version number must change
// whenever any particulars of the Noise handshake change
// (e.g. switching from Noise IK to Noise IKpsk1 or Noise XX), and
// when security-critical aspects of the "uppper" protocol within the
// Noise frames change (e.g. how further authentication data is bound
// to the underlying Noise session).

// headerLen is the size of the header that gets prepended to Noise
// messages.
const headerLen = 5

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
	// msgTypeRecord frames carry a Noise transport message (i.e. "user data").
	msgTypeRecord = 4
)

func setHeader(bs []byte, version uint16, msgType byte, length int) {
	binary.LittleEndian.PutUint16(bs[:2], uint16(version))
	bs[2] = msgType
	binary.LittleEndian.PutUint16(bs[3:5], uint16(length))
}
func hdrVersion(bs []byte) uint16 { return binary.LittleEndian.Uint16(bs[:2]) }
func hdrType(bs []byte) byte      { return bs[2] }
func hdrLen(bs []byte) int        { return int(binary.LittleEndian.Uint16(bs[3:5])) }

// initiationMessage is the Noise protocol message sent from a client
// machine to a control server. Aside from the message header, the
// values are as specified in the Noise specification for the IK
// handshake pattern.
//
// 5b: header (see headerLen for fields)
// 32b: client ephemeral public key (cleartext)
// 48b: client machine public key (encrypted)
// 16b: message tag (authenticates the whole message)
type initiationMessage [101]byte

func mkInitiationMessage() initiationMessage {
	var ret initiationMessage
	setHeader(ret[:], protocolVersion, msgTypeInitiation, len(ret.Payload()))
	return ret
}

func (m *initiationMessage) Header() []byte  { return m[:headerLen] }
func (m *initiationMessage) Payload() []byte { return m[headerLen:] }

func (m *initiationMessage) Version() uint16 { return hdrVersion(m.Header()) }
func (m *initiationMessage) Type() byte      { return hdrType(m.Header()) }
func (m *initiationMessage) Length() int     { return hdrLen(m.Header()) }

func (m *initiationMessage) EphemeralPub() []byte { return m[headerLen : headerLen+32] }
func (m *initiationMessage) MachinePub() []byte   { return m[headerLen+32 : headerLen+32+48] }
func (m *initiationMessage) Tag() []byte          { return m[headerLen+32+48:] }

// responseMessage is the Noise protocol message sent from a control
// server to a client machine. Aside from the message header, the
// values are as specified in the Noise specification for the IK
// handshake pattern.
//
// 5b: header (see headerLen for fields)
// 32b: control ephemeral public key (cleartext)
// 16b: message tag (authenticates the whole message)
type responseMessage [53]byte

func mkResponseMessage() responseMessage {
	var ret responseMessage
	setHeader(ret[:], protocolVersion, msgTypeResponse, len(ret.Payload()))
	return ret
}

func (m *responseMessage) Header() []byte  { return m[:headerLen] }
func (m *responseMessage) Payload() []byte { return m[headerLen:] }

func (m *responseMessage) Version() uint16 { return hdrVersion(m.Header()) }
func (m *responseMessage) Type() byte      { return hdrType(m.Header()) }
func (m *responseMessage) Length() int     { return hdrLen(m.Header()) }

func (m *responseMessage) EphemeralPub() []byte { return m[headerLen : headerLen+32] }
func (m *responseMessage) Tag() []byte          { return m[headerLen+32:] }
