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
	"net"
	"time"
)

// MaxPacketSize is the maximum size of a packet sent over DERP.
// (This only includes the data bytes visible to magicsock, not
// including its on-wire framing overhead)
const MaxPacketSize = 64 << 10

// Magic is the DERP Magic number, sent in the frameServerKey frame
// upon initial connection.
const Magic = "DERP🔑" // 8 bytes: 0x44 45 52 50 f0 9f 94 91

const (
	NonceLen       = 24
	FrameHeaderLen = 1 + 4 // frameType byte + 4 byte length
	KeyLen         = 32
	MaxInfoLen     = 1 << 20
)

// KeepAlive is the minimum frequency at which the DERP server sends
// keep alive frames. The server adds some jitter, so this timing is not
// exact, but 2x this value can be considered a missed keep alive.
const KeepAlive = 60 * time.Second

// ProtocolVersion is bumped whenever there's a wire-incompatible change.
//   - version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
//   - version 2: received packets have src addrs in frameRecvPacket at beginning
const ProtocolVersion = 2

// FrameType is the one byte frame type at the beginning of the frame
// header.  The second field is a big-endian uint32 describing the
// length of the remaining frame (not including the initial 5 bytes).
type FrameType byte

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
	FrameServerKey     = FrameType(0x01) // 8B magic + 32B public key + (0+ bytes future use)
	FrameClientInfo    = FrameType(0x02) // 32B pub key + 24B nonce + naclbox(json)
	FrameServerInfo    = FrameType(0x03) // 24B nonce + naclbox(json)
	FrameSendPacket    = FrameType(0x04) // 32B dest pub key + packet bytes
	FrameForwardPacket = FrameType(0x0a) // 32B src pub key + 32B dst pub key + packet bytes
	FrameRecvPacket    = FrameType(0x05) // v0/1: packet bytes, v2: 32B src pub key + packet bytes
	FrameKeepAlive     = FrameType(0x06) // no payload, no-op (to be replaced with ping/pong)
	FrameNotePreferred = FrameType(0x07) // 1 byte payload: 0x01 or 0x00 for whether this is client's home node

	// framePeerGone is sent from server to client to signal that
	// a previous sender is no longer connected. That is, if A
	// sent to B, and then if A disconnects, the server sends
	// framePeerGone to B so B can forget that a reverse path
	// exists on that connection to get back to A. It is also sent
	// if A tries to send a CallMeMaybe to B and the server has no
	// record of B
	FramePeerGone = FrameType(0x08) // 32B pub key of peer that's gone + 1 byte reason

	// framePeerPresent is like framePeerGone, but for other members of the DERP
	// region when they're meshed up together.
	//
	// The message is at least 32 bytes (the public key of the peer that's
	// connected). If there are at least 18 bytes remaining after that, it's the
	// 16 byte IP + 2 byte BE uint16 port of the client. If there's another byte
	// remaining after that, it's a PeerPresentFlags byte.
	// While current servers send 41 bytes, old servers will send fewer, and newer
	// servers might send more.
	FramePeerPresent = FrameType(0x09)

	// frameWatchConns is how one DERP node in a regional mesh
	// subscribes to the others in the region.
	// There's no payload. If the sender doesn't have permission, the connection
	// is closed. Otherwise, the client is initially flooded with
	// framePeerPresent for all connected nodes, and then a stream of
	// framePeerPresent & framePeerGone has peers connect and disconnect.
	FrameWatchConns = FrameType(0x10)

	// frameClosePeer is a privileged frame type (requires the
	// mesh key for now) that closes the provided peer's
	// connection. (To be used for cluster load balancing
	// purposes, when clients end up on a non-ideal node)
	FrameClosePeer = FrameType(0x11) // 32B pub key of peer to close.

	FramePing = FrameType(0x12) // 8 byte ping payload, to be echoed back in framePong
	FramePong = FrameType(0x13) // 8 byte payload, the contents of the ping being replied to

	// frameHealth is sent from server to client to tell the client
	// if their connection is unhealthy somehow. Currently the only unhealthy state
	// is whether the connection is detected as a duplicate.
	// The entire frame body is the text of the error message. An empty message
	// clears the error state.
	FrameHealth = FrameType(0x14)

	// frameRestarting is sent from server to client for the
	// server to declare that it's restarting. Payload is two big
	// endian uint32 durations in milliseconds: when to reconnect,
	// and how long to try total. See ServerRestartingMessage docs for
	// more details on how the client should interpret them.
	FrameRestarting = FrameType(0x15)
)

// PeerGoneReasonType is a one byte reason code explaining why a
// server does not have a path to the requested destination.
type PeerGoneReasonType byte

const (
	PeerGoneReasonDisconnected  = PeerGoneReasonType(0x00) // is only sent when a peer disconnects from this server
	PeerGoneReasonNotHere       = PeerGoneReasonType(0x01) // server doesn't know about this peer
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

// IdealNodeHeader is the HTTP request header sent on DERP HTTP client requests
// to indicate that they're connecting to their ideal (Region.Nodes[0]) node.
// The HTTP header value is the name of the node they wish they were connected
// to. This is an optional header.
const IdealNodeHeader = "Ideal-Node"

// FastStartHeader is the header (with value "1") that signals to the HTTP
// server that the DERP HTTP client does not want the HTTP 101 response
// headers and it will begin writing & reading the DERP protocol immediately
// following its HTTP request.
const FastStartHeader = "Derp-Fast-Start"

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

// ReadFrameTypeHeader reads a frame header from br and
// verifies that the frame type matches wantType.
//
// If it does, it returns the frame length (not including
// the 5 byte header) and a nil error.
//
// If it doesn't, it returns an error and a zero length.
func ReadFrameTypeHeader(br *bufio.Reader, wantType FrameType) (frameLen uint32, err error) {
	gotType, frameLen, err := ReadFrameHeader(br)
	if err == nil && wantType != gotType {
		err = fmt.Errorf("bad frame type 0x%X, want 0x%X", gotType, wantType)
	}
	return frameLen, err
}

// ReadFrameHeader reads the header of a DERP frame,
// reading 5 bytes from br.
func ReadFrameHeader(br *bufio.Reader) (t FrameType, frameLen uint32, err error) {
	tb, err := br.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	frameLen, err = readUint32(br)
	if err != nil {
		return 0, 0, err
	}
	return FrameType(tb), frameLen, nil
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
func readFrame(br *bufio.Reader, maxSize uint32, b []byte) (t FrameType, frameLen uint32, err error) {
	t, frameLen, err = ReadFrameHeader(br)
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

// WriteFrameHeader writes a frame header to bw.
//
// The frame header is 5 bytes: a one byte frame type
// followed by a big-endian uint32 length of the
// remaining frame (not including the 5 byte header).
//
// It does not flush bw.
func WriteFrameHeader(bw *bufio.Writer, t FrameType, frameLen uint32) error {
	if err := bw.WriteByte(byte(t)); err != nil {
		return err
	}
	return writeUint32(bw, frameLen)
}

// WriteFrame writes a complete frame & flushes it.
func WriteFrame(bw *bufio.Writer, t FrameType, b []byte) error {
	if len(b) > 10<<20 {
		return errors.New("unreasonably large frame write")
	}
	if err := WriteFrameHeader(bw, t, uint32(len(b))); err != nil {
		return err
	}
	if _, err := bw.Write(b); err != nil {
		return err
	}
	return bw.Flush()
}

// Conn is the subset of the underlying net.Conn the DERP Server needs.
// It is a defined type so that non-net connections can be used.
type Conn interface {
	io.WriteCloser
	LocalAddr() net.Addr
	// The *Deadline methods follow the semantics of net.Conn.
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// ServerInfo is the message sent from the server to clients during
// the connection setup.
type ServerInfo struct {
	Version int `json:"version,omitempty"`

	TokenBucketBytesPerSecond int `json:",omitempty"`
	TokenBucketBytesBurst     int `json:",omitempty"`
}
