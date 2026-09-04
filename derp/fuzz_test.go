// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"

	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func FuzzReadFrameHeader(f *testing.F) {
	f.Add([]byte{byte(FramePing), 0, 1, 2, 3})
	// A complete ping frame header: type + big-endian length of 8
	f.Add([]byte{byte(FramePing), 0, 0, 0, 8})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ReadFrameHeader(bufio.NewReader(bytes.NewReader(data)))
	})
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{byte(FramePing), 0, 1, 2, 3})
	// A complete ping frame: header plus its 8-byte payload
	f.Add(append([]byte{byte(FramePing), 0, 0, 0, 8}, 1, 2, 3, 4, 5, 6, 7, 8))
	// A frame longer than the 40-byte scratch buffer (exercises ErrShortBuffer)
	f.Add(append([]byte{byte(FramePing), 0, 0, 0, 50}, make([]byte, 50)...))

	const maxSize = 1 << 10

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readFrame(bufio.NewReader(bytes.NewReader(data)), maxSize, make([]byte, 40))
	})
}

func FuzzRecvTimeout(f *testing.F) {
	// A minimal valid frame stream: a keep-alive followed by EOF
	f.Add([]byte{byte(FrameKeepAlive), 0, 1, 2, 3})
	// A valid keep-alive (zero-length frame)
	f.Add([]byte{byte(FrameKeepAlive), 0, 0, 0, 0})
	// A valid ping frame with its 8-byte payload
	f.Add(append([]byte{byte(FramePing), 0, 0, 0, 8}, 1, 2, 3, 4, 5, 6, 7, 8))
	// A FramePeerGone with a 32-byte peer key and reason byte
	f.Add(append(append([]byte{byte(FramePeerGone), 0, 0, 0, 33}, make([]byte, 32)...), 0))
	// A FrameRecvPacket with a 32-byte source key plus packet payload
	f.Add(append(append([]byte{byte(FrameRecvPacket), 0, 0, 0, 36}, make([]byte, 32)...), 1, 2, 3, 4))
	// A FrameRestarting with the two big-endian duration payloads
	f.Add([]byte{byte(FrameRestarting), 0, 0, 0, 8, 0, 0, 0x0e, 0x10, 0, 0, 0x3a, 0x98})
	// A keep-alive followed by a ping frame (multi-frame stream)
	f.Add([]byte{byte(FrameKeepAlive), 0, 0, 0, 0, byte(FramePing), 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	// A valid pong frame with its 8-byte payload
	f.Add(append([]byte{byte(FramePong), 0, 0, 0, 8}, 1, 2, 3, 4, 5, 6, 7, 8))
	// A health-problem frame with a text payload
	f.Add(append([]byte{byte(FrameHealth), 0, 0, 0, 4}, 'd', 'e', 'r', 'p'))
	// A PeerPresent frame: 32-byte key + IPv6 addr/port + flags + app name
	f.Add(append(append([]byte{byte(FramePeerPresent), 0, 0, 0, 0x34}, make([]byte, 32)...),
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90,
		0x00, 0x04, 't', 'a', 'i', 'l'))

	f.Fuzz(func(t *testing.T, data []byte) {
		priv := key.NewNode()
		c := &Client{
			privateKey: priv,
			serverKey:  priv.Public(),
			logf:       logger.Discard,
			nc:         dummyNetConn{},
			br:         bufio.NewReader(bytes.NewReader(data)),
		}
		_, _ = c.recvTimeout(0)
	})
}

func FuzzRecvServerKey(f *testing.F) {
	f.Add([]byte{byte(FrameServerKey), 1, 2, 3, 4})
	// A valid server greeting: type, big-endian length 40, magic, 32-byte key
	var greeting [5 + 8 + 32]byte
	greeting[0] = byte(FrameServerKey)
	binary.BigEndian.PutUint32(greeting[1:5], 40)
	copy(greeting[5:13], Magic)
	f.Add(greeting[:])
	// Right length but bad magic
	f.Add(append(append([]byte{byte(FrameServerKey), 0, 0, 0, 40},
		0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58), make([]byte, 32)...))
	// A greeting shorter than 40 bytes
	f.Add(append([]byte{byte(FrameServerKey), 0, 0, 0, 39}, make([]byte, 39)...))
	// Zero-length greeting
	f.Add([]byte{byte(FrameServerKey), 0, 0, 0, 0})
	// Wrong frame type with an otherwise-valid body
	f.Add(append(append([]byte{byte(FrameKeepAlive), 0, 0, 0, 40}, Magic...), make([]byte, 32)...))
	// Length over the 1KiB readFrame limit
	f.Add([]byte{byte(FrameServerKey), 0, 0, 0x04, 0x01})
	// Truncated payload after the header
	f.Add(append([]byte{byte(FrameServerKey), 0, 0, 0, 40}, Magic...))
	// A future-proof long greeting (50 bytes): ErrShortBuffer tolerated
	f.Add(append(append(append([]byte{byte(FrameServerKey), 0, 0, 0, 50}, Magic...),
		make([]byte, 32)...), make([]byte, 10)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := &Client{
			logf: logger.Discard,
			br:   bufio.NewReader(bytes.NewReader(data)),
		}
		_ = c.recvServerKey()
	})
}
