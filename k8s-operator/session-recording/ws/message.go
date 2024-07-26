// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package ws

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	noOpcode      messageType = 0 // continuation frame for fragmented messages
	binaryMessage messageType = 2
)

// messageType is the type of a websocket data or control message as defined by opcode.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
// Known types of control messages are close, ping and pong.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.5
// The only data message type supported by Kubernetes is binary message
// https://github.com/kubernetes/client-go/blob/v0.30.0-rc.1/tools/remotecommand/websocket.go#L281
type messageType int

// message is a parsed Websocket Message.
type message struct {
	// payload is the contents of the so far parsed Websocket
	// data Message payload, potentially from multiple fragments written by
	// multiple invocations of Parse. As per RFC 6455 We can assume that the
	// fragments will always arrive in order and data messages will not be
	// interleaved.
	payload []byte

	// isFinalized is set to true if msgPayload contains full contents of
	// the message (the final fragment has been received).
	isFinalized bool

	// streamID is the stream to which the message belongs, i.e stdin, stout
	// etc. It is one of the stream IDs defined in
	// https://github.com/kubernetes/apimachinery/commit/73d12d09c5be8703587b5127416eb83dc3b7e182#diff-291f96e8632d04d2d20f5fb00f6b323492670570d65434e8eac90c7a442d13bdR23-R36
	streamID atomic.Uint32

	// typ is the type of a WebsocketMessage as defined by its opcode
	// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
	typ messageType
	raw []byte
}

// Parse accepts a websocket message fragment as a byte slice and parses its contents.
// The fragment can be:
// - a fragment that consists of a whole message
// - an initial fragment for a message for which we expect more fragments
// - a subsequent fragment for a message that we are currently parsing and whose so-far parsed contents are stored in msg.
// It is not expected that the byte slice would contain an incomplete fragment or fragment for a different message than the one currently being parsed (if any).
// Message fragment structure:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+
// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
//
// Fragmentation rules:
// An unfragmented message consists of a single frame with the FIN
// bit set (Section 5.2) and an opcode other than 0.
// A fragmented message consists of a single frame with the FIN bit
// clear and an opcode other than 0, followed by zero or more frames
// with the FIN bit clear and the opcode set to 0, and terminated by
// a single frame with the FIN bit set and an opcode of 0.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.4
func (msg *message) Parse(b []byte, log *zap.SugaredLogger) (bool, error) {
	if msg.typ != binaryMessage {
		return false, fmt.Errorf("[unexpected] internal error: attempted to parse a message with type %d", msg.typ)
	}

	msg.isFinalized = isFinalFragment(b)

	maskSet := isMasked(b)

	payloadLength, payloadOffset, maskOffset, err := fragmentDimensions(b, maskSet)
	if err != nil {
		return false, fmt.Errorf("error determining payload length: %w", err)
	}
	log.Debugf("parse: parsing a message with payload length: %d payload offset: %d maskOffset: %d mask set: %t, is finalized: %t", payloadLength, payloadOffset, maskOffset, maskSet, msg.isFinalized)

	if len(b) < int(payloadOffset)+int(payloadLength) { // incomplete fragment
		return false, nil
	}
	msg.raw = make([]byte, int(payloadOffset)+int(payloadLength))
	copy(msg.raw, b[:payloadOffset+payloadLength])

	// Extract the payload.
	msgPayload := b[payloadOffset : payloadOffset+payloadLength]

	// Unmask the payload if needed.
	if maskSet {
		m := b[maskOffset:payloadOffset]
		var mask [4]byte
		copy(mask[:], m)
		maskBytes(mask, msgPayload)
	}

	// Determine what stream the message is for. Stream ID of a Kubernetes
	// streaming session is a 32bit integer, stored in the first byte of the
	// message payload.
	// https://github.com/kubernetes/apimachinery/commit/73d12d09c5be8703587b5127416eb83dc3b7e182#diff-291f96e8632d04d2d20f5fb00f6b323492670570d65434e8eac90c7a442d13bdR23-R36
	if len(msgPayload) == 0 {
		return false, errors.New("[unexpected] received a message fragment with no stream ID")
	}

	streamId := uint32(msgPayload[0])
	if msg.streamID.Load() != 0 && msg.streamID.Load() != streamId {
		return false, fmt.Errorf("[unexpected] received message fragments with mismatched streamIDs %d and %d", msg.streamID.Load(), streamId)
	}
	msg.streamID.Store(streamId)

	// This is normal, Kubernetes seem to send a couple data messages with
	// no payloads at the start.
	if len(msgPayload) < 2 {
		return true, nil
	}
	msgPayload = msgPayload[1:] // remove the stream ID byte
	msg.payload = append(msg.payload, msgPayload...)
	return true, nil
}

// maskBytes applies mask to bytes in place.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.3
func maskBytes(key [4]byte, b []byte) {
	for i := range b {
		b[i] = b[i] ^ key[i%4]
	}
}

// isControlMessage returns true if the message type is one of the know control
// frame message types.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.5
func isControlMessage(t messageType) bool {
	const (
		closeMessage messageType = 8
		pingMessage  messageType = 9
		pongMessage  messageType = 10
	)
	return t == closeMessage || t == pingMessage || t == pongMessage
}

// isFinalFragment can be called with  websocket message fragment and returns true if
// the fragment is the final fragment of a websocket message.
func isFinalFragment(b []byte) bool {
	// Extract FIN bit. FIN bit is the first bit of a message fragment.
	const finBitMask byte = 1 << 7
	finBit := b[0] & finBitMask
	return finBit != 0
}

// isMasked can be called with a websocket message fragment and returns true if
// the payload of the message is masked. It uses the mask bit to determine if
// the payload is masked.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.3
func isMasked(b []byte) bool {
	return extractFirstBit(b[1]) != 0
}

// extractFirstBit extracts first bit of a byte by zeroing out all the other
// bits.
func extractFirstBit(b byte) byte {
	const mask byte = 1 << 7
	return b & mask
}

// zeroFirstBit returns the provided byte with the first bit set to 0.
func zeroFirstBit(b byte) byte {
	const revMask byte = 1 << 7
	return b & (^revMask)
}

// fragmentDimensions returns payload length as well as payload offset and mask offset.
func fragmentDimensions(b []byte, maskSet bool) (payloadLength, payloadOffset, maskOffset int64, _ error) {

	// payload length can be stored either in bits [9-15] or in bytes 2, 3
	// or in bytes 2, 3, 4, 5, 6, 7.
	// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
	// 0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-------+-+-------------+-------------------------------+
	// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
	// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
	// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
	// | |1|2|3|       |K|             |                               |
	// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	// |     Extended payload length continued, if payload len == 127  |
	// + - - - - - - - - - - - - - - - +-------------------------------+
	payloadLengthIndicator := zeroFirstBit(b[1])
	var lengthOffset int64
	switch {
	case payloadLengthIndicator < 126:
		lengthOffset = 1
		maskOffset = 2
		payloadLength = int64(payloadLengthIndicator)
	case payloadLengthIndicator == 126:
		maskOffset = 4
		lengthOffset = 2
		payloadLength = extractInt64(b, lengthOffset, 2)
	case payloadLengthIndicator == 127:
		maskOffset = 10
		lengthOffset = 2
		payloadLength = extractInt64(b, lengthOffset, 6)
	default:
		return -1, -1, -1, fmt.Errorf("unexpected payload length indicator value: %v", payloadLengthIndicator)
	}

	// Masking key can take up 0 or 4 bytes- we need to take that into
	// account when determining payload offset.
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// ....
	// + - - - - - - - - - - - - - - - +-------------------------------+
	// |                               |Masking-key, if MASK set to 1  |
	// +-------------------------------+-------------------------------+
	// | Masking-key (continued)       |          Payload Data         |
	// + - - - - - - - - - - - - - - - +-------------------------------+
	// ...
	if maskSet {
		payloadOffset = maskOffset + 4
	} else {
		payloadOffset = maskOffset
	}
	return
}

func extractInt64(b []byte, offset, length int64) int64 {
	payloadLengthBytes := b[offset : offset+length]
	payloadLengthBytesPadded := append(make([]byte, 8-len(payloadLengthBytes)), payloadLengthBytes...)

	return int64(binary.BigEndian.Uint64(payloadLengthBytesPadded))
}
