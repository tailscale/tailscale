// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package derp implements the Designated Encrypted Relay for Packets (DERP)
// protocol.
//
// DERP routes packets to clients using curve25519 keys as addresses.
//
// DERP is used by Tailscale nodes to proxy encrypted WireGuard
// packets through the Tailscale cloud servers when a direct path
// cannot be found or opened. DERP is a last resort. Both sides
// between very aggressive NATs, firewalls, no IPv6, etc? Well, DERP.
package derp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// MaxPacketSize is the maximum size of a packet sent over DERP.
// (This only includes the data bytes visible to magicsock, not
// including its on-wire framing overhead)
const MaxPacketSize = 64 << 10

// magic is the DERP magic number, sent in the frameServerKey frame
// upon initial connection.
const magic = "DERP🔑" // 8 bytes: 0x44 45 52 50 f0 9f 94 91

const (
	nonceLen       = 24
	frameHeaderLen = 1 + 4 // frameType byte + 4 byte length
	keyLen         = 32
	maxInfoLen     = 1 << 20
	keepAlive      = 60 * time.Second
)

// ProtocolVersion is bumped whenever there's a wire-incompatible change.
//   - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
//   - version 2: received packets have src addrs in frameRecvPacket at beginning
const ProtocolVersion = 2

// frameType is the one byte frame type at the beginning of the frame
// header.  The second field is a big-endian uint32 describing the
// length of the remaining frame (not including the initial 5 bytes).
type frameType byte

/*
Protocol flow:

Login:
* client connects
* server sends frameServerKey
* client sends frameClientInfo
* server sends frameServerInfo

Steady state:
* server occasionally sends frameKeepAlive (or framePing)
* client responds to any framePing with a framePong
* client sends frameSendPacket
* server then sends frameRecvPacket to recipient
*/
const (
	frameServerKey     = frameType(0x01) // 8B magic + 32B public key + (0+ bytes future use)
	frameClientInfo    = frameType(0x02) // 32B pub key + 24B nonce + naclbox(json)
	frameServerInfo    = frameType(0x03) // 24B nonce + naclbox(json)
	frameSendPacket    = frameType(0x04) // 32B dest pub key + packet bytes
	frameForwardPacket = frameType(0x0a) // 32B src pub key + 32B dst pub key + packet bytes
	frameRecvPacket    = frameType(0x05) // v0/1: packet bytes, v2: 32B src pub key + packet bytes
	frameKeepAlive     = frameType(0x06) // no payload, no-op (to be replaced with ping/pong)
	frameNotePreferred = frameType(0x07) // 1 byte payload: 0x01 or 0x00 for whether this is client's home node

	// framePeerGone is sent from server to client to signal that
	// a previous sender is no longer connected. That is, if A
	// sent to B, and then if A disconnects, the server sends
	// framePeerGone to B so B can forget that a reverse path
	// exists on that connection to get back to A. It is also sent
	// if A tries to send a CallMeMaybe to B and the server has no
	// record of B (which currently would only happen if there was
	// a bug).
	framePeerGone = frameType(0x08) // 32B pub key of peer that's gone + 1 byte reason

	// framePeerPresent is like framePeerGone, but for other members of the DERP
	// region when they're meshed up together.
	//
	// The message is at least 32 bytes (the public key of the peer that's
	// connected). If there are at least 18 bytes remaining after that, it's the
	// 16 byte IP + 2 byte BE uint16 port of the client. If there's another byte
	// remaining after that, it's a PeerPresentFlags byte.
	// While current servers send 41 bytes, old servers will send fewer, and newer
	// servers might send more.
	framePeerPresent = frameType(0x09)

	// frameWatchConns is how one DERP node in a regional mesh
	// subscribes to the others in the region.
	// There's no payload. If the sender doesn't have permission, the connection
	// is closed. Otherwise, the client is initially flooded with
	// framePeerPresent for all connected nodes, and then a stream of
	// framePeerPresent & framePeerGone has peers connect and disconnect.
	frameWatchConns = frameType(0x10)

	// frameClosePeer is a privileged frame type (requires the
	// mesh key for now) that closes the provided peer's
	// connection. (To be used for cluster load balancing
	// purposes, when clients end up on a non-ideal node)
	frameClosePeer = frameType(0x11) // 32B pub key of peer to close.

	framePing = frameType(0x12) // 8 byte ping payload, to be echoed back in framePong
	framePong = frameType(0x13) // 8 byte payload, the contents of the ping being replied to

	// frameHealth is sent from server to client to tell the client
	// if their connection is unhealthy somehow. Currently the only unhealthy state
	// is whether the connection is detected as a duplicate.
	// The entire frame body is the text of the error message. An empty message
	// clears the error state.
	frameHealth = frameType(0x14)

	// frameRestarting is sent from server to client for the
	// server to declare that it's restarting. Payload is two big
	// endian uint32 durations in milliseconds: when to reconnect,
	// and how long to try total. See ServerRestartingMessage docs for
	// more details on how the client should interpret them.
	frameRestarting = frameType(0x15)
)

// PeerGoneReasonType is a one byte reason code explaining why a
// server does not have a path to the requested destination.
type PeerGoneReasonType byte

const (
	PeerGoneReasonDisconnected  = PeerGoneReasonType(0x00) // peer disconnected from this server
	PeerGoneReasonNotHere       = PeerGoneReasonType(0x01) // server doesn't know about this peer, unexpected
	PeerGoneReasonMeshConnBroke = PeerGoneReasonType(0xf0) // invented by Client.RunWatchConnectionLoop on disconnect; not sent on the wire
)

// PeerPresentFlags is an optional byte of bit flags sent after a framePeerPresent message.
//
// For a modern server, the value should always be non-zero. If the value is zero,
// that means the server doesn't support this field.
type PeerPresentFlags byte

// PeerPresentFlags bits.
const (
	PeerPresentIsRegular  = 1 << 0
	PeerPresentIsMeshPeer = 1 << 1
	PeerPresentIsProber   = 1 << 2
	PeerPresentNotIdeal   = 1 << 3 // client said derp server is not its Region.Nodes[0] ideal node
)

var bin = binary.BigEndian

func writeUint32(bw *bufio.Writer, v uint32) error {
	var b [4]byte
	bin.PutUint32(b[:], v)
	// Writing a byte at a time is a bit silly,
	// but it causes b not to escape,
	// which more than pays for the silliness.
	for _, c := range &b {
		err := bw.WriteByte(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func readUint32(br *bufio.Reader) (uint32, error) {
	var b [4]byte
	// Reading a byte at a time is a bit silly,
	// but it causes b not to escape,
	// which more than pays for the silliness.
	for i := range &b {
		c, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		b[i] = c
	}
	return bin.Uint32(b[:]), nil
}

func readFrameTypeHeader(br *bufio.Reader, wantType frameType) (frameLen uint32, err error) {
	gotType, frameLen, err := readFrameHeader(br)
	if err == nil && wantType != gotType {
		err = fmt.Errorf("bad frame type 0x%X, want 0x%X", gotType, wantType)
	}
	return frameLen, err
}

func readFrameHeader(br *bufio.Reader) (t frameType, frameLen uint32, err error) {
	tb, err := br.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	frameLen, err = readUint32(br)
	if err != nil {
		return 0, 0, err
	}
	return frameType(tb), frameLen, nil
}

// readFrame reads a frame header and then reads its payload into
// b[:frameLen].
//
// If the frame header length is greater than maxSize, readFrame returns
// an error after reading the frame header.
//
// If the frame is less than maxSize but greater than len(b), len(b)
// bytes are read, err will be io.ErrShortBuffer, and frameLen and t
// will both be set. That is, callers need to explicitly handle when
// they get more data than expected.
func readFrame(br *bufio.Reader, maxSize uint32, b []byte) (t frameType, frameLen uint32, err error) {
	t, frameLen, err = readFrameHeader(br)
	if err != nil {
		return 0, 0, err
	}
	if frameLen > maxSize {
		return 0, 0, fmt.Errorf("frame header size %d exceeds reader limit of %d", frameLen, maxSize)
	}

	n, err := io.ReadFull(br, b[:min(frameLen, uint32(len(b)))])
	if err != nil {
		return 0, 0, err
	}
	remain := frameLen - uint32(n)
	if remain > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(remain)); err != nil {
			return 0, 0, err
		}
		err = io.ErrShortBuffer
	}
	return t, frameLen, err
}

func writeFrameHeader(bw *bufio.Writer, t frameType, frameLen uint32) error {
	if err := bw.WriteByte(byte(t)); err != nil {
		return err
	}
	return writeUint32(bw, frameLen)
}

// writeFrame writes a complete frame & flushes it.
func writeFrame(bw *bufio.Writer, t frameType, b []byte) error {
	if len(b) > 10<<20 {
		return errors.New("unreasonably large frame write")
	}
	if err := writeFrameHeader(bw, t, uint32(len(b))); err != nil {
		return err
	}
	if _, err := bw.Write(b); err != nil {
		return err
	}
	return bw.Flush()
}
