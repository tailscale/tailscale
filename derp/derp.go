// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derp implements DERP, the Detour Encrypted Routing Protocol.
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
	"fmt"
	"io"
	"time"
)

// magic is the derp magic number, sent on the wire as a uint32.
// It's "DERP" with a non-ASCII high-bit.
const magic = 0x44c55250

// frameType is the one byte frame type header in frame headers.
type frameType byte

const (
	typeServerKey  = frameType(0x01)
	typeServerInfo = frameType(0x02)
	typeSendPacket = frameType(0x03)
	typeRecvPacket = frameType(0x04)
	typeKeepAlive  = frameType(0x05)
)

func (b frameType) Write(w io.ByteWriter) error {
	return w.WriteByte(byte(b))
}

const keepAlive = 60 * time.Second

var bin = binary.BigEndian

const oneMB = 1 << 20

func readType(r *bufio.Reader, t frameType) error {
	packetType, err := r.ReadByte()
	if err != nil {
		return err
	}
	if frameType(packetType) != t {
		return fmt.Errorf("bad packet type 0x%X, want 0x%X", packetType, t)
	}
	return nil
}

func putUint32(w io.Writer, v uint32) error {
	var b [4]byte
	bin.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func readUint32(r io.Reader, maxVal uint32) (uint32, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	val := bin.Uint32(b)
	if val > maxVal {
		return 0, fmt.Errorf("uint32 %d exceeds limit %d", val, maxVal)
	}
	return val, nil
}
