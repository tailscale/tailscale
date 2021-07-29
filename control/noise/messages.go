// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noise

import "encoding/binary"

const (
	msgTypeInitiation = 1
	msgTypeResponse   = 2
	msgTypeError      = 3
	msgTypeRecord     = 4
)

// headerLen is the size of the cleartext message header that gets
// prepended to Noise messages.
//
// 2b: protocol version
// 1b: message type
// 2b: payload length (not including this header)
const headerLen = 5

func setHeader(bs []byte, version int, msgType byte, length int) {
	binary.LittleEndian.PutUint16(bs[:2], uint16(version))
	bs[2] = msgType
	binary.LittleEndian.PutUint16(bs[3:5], uint16(length))
}
func hdrVersion(bs []byte) int { return int(binary.LittleEndian.Uint16(bs[:2])) }
func hdrType(bs []byte) byte   { return bs[2] }
func hdrLen(bs []byte) int     { return int(binary.LittleEndian.Uint16(bs[3:5])) }

// initiationMessage is the Noise protocol message sent from a client
// machine to a control server.
//
// 5b: header (see headerLen for fields)
// 32b: client ephemeral public key (cleartext)
// 48b: client machine public key (encrypted)
// 16b: message tag (authenticates the whole message)
type initiationMessage [101]byte

func mkInitiationMessage() initiationMessage {
	var ret initiationMessage
	binary.LittleEndian.PutUint16(ret[:2], protocolVersion)
	ret[2] = msgTypeInitiation
	binary.LittleEndian.PutUint16(ret[3:5], 96)
	return ret
}

func (m *initiationMessage) Header() []byte  { return m[:5] }
func (m *initiationMessage) Payload() []byte { return m[5:] }

func (m *initiationMessage) Version() int { return hdrVersion(m.Header()) }
func (m *initiationMessage) Type() byte   { return hdrType(m.Header()) }
func (m *initiationMessage) Length() int  { return hdrLen(m.Header()) }

func (m *initiationMessage) EphemeralPub() []byte { return m[5:37] }
func (m *initiationMessage) MachinePub() []byte   { return m[37:85] }
func (m *initiationMessage) Tag() []byte          { return m[85:] }

// responseMessage is the Noise protocol message sent from a control
// server to a client machine.
//
// 2b: little-endian protocol version
// 1b: message type
// 2b: little-endian size of message (not including this header)
// 32b: control ephemeral public key (cleartext)
// 16b: message tag (authenticates the whole message)
type responseMessage [53]byte

func mkResponseMessage() responseMessage {
	var ret responseMessage
	binary.LittleEndian.PutUint16(ret[:2], protocolVersion)
	ret[2] = msgTypeResponse
	binary.LittleEndian.PutUint16(ret[3:5], 48)
	return ret
}

func (m *responseMessage) Header() []byte  { return m[:5] }
func (m *responseMessage) Payload() []byte { return m[5:] }

func (m *responseMessage) Version() int { return hdrVersion(m.Header()) }
func (m *responseMessage) Type() byte   { return hdrType(m.Header()) }
func (m *responseMessage) Length() int  { return hdrLen(m.Header()) }

func (m *responseMessage) EphemeralPub() []byte { return m[5:37] }
func (m *responseMessage) Tag() []byte          { return m[37:] }
