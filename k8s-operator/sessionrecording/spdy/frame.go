// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package spdy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sync"

	"go.uber.org/zap"
)

const (
	SYN_STREAM ControlFrameType = 1 // https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.1
	SYN_REPLY  ControlFrameType = 2 // https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.2
	SYN_PING   ControlFrameType = 6 // https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.5
)

// spdyFrame is a parsed SPDY frame as defined in
// https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt
// A SPDY frame can be either a control frame or a data frame.
type spdyFrame struct {
	Raw []byte // full frame as raw bytes

	// Common frame fields:
	Ctrl    bool   // true if this is a SPDY control frame
	Payload []byte // payload as raw bytes

	// Control frame fields:
	Version uint16 // SPDY protocol version
	Type    ControlFrameType

	// Data frame fields:
	// StreamID is the id of the steam to which this data frame belongs.
	// SPDY allows transmitting multiple data streams concurrently.
	StreamID uint32
}

// Type of an SPDY control frame.
type ControlFrameType uint16

// Parse parses bytes into spdyFrame.
// If the bytes don't contain a full frame, return false.
//
// Control frame structure:
//
//	 +----------------------------------+
//	|C| Version(15bits) | Type(16bits) |
//	+----------------------------------+
//	| Flags (8)  |  Length (24 bits)   |
//	+----------------------------------+
//	|               Data               |
//	+----------------------------------+
//
// Data frame structure:
//
//	+----------------------------------+
//	|C|       Stream-ID (31bits)       |
//	+----------------------------------+
//	| Flags (8)  |  Length (24 bits)   |
//	+----------------------------------+
//	|               Data               |
//	+----------------------------------+
//
// https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt
func (sf *spdyFrame) Parse(b []byte, log *zap.SugaredLogger) (ok bool, _ error) {
	const (
		spdyHeaderLength = 8
	)
	have := len(b)
	if have < spdyHeaderLength { // input does not contain full frame
		return false, nil
	}

	if !isSPDYFrameHeader(b) {
		return false, fmt.Errorf("bytes %v do not seem to contain SPDY frames. Ensure that you are using a SPDY based client to 'kubectl exec'.", b)
	}

	payloadLength := readInt24(b[5:8])
	frameLength := payloadLength + spdyHeaderLength
	if have < frameLength { // input does not contain full frame
		return false, nil
	}

	frame := b[:frameLength:frameLength] // enforce frameLength capacity

	sf.Raw = frame
	sf.Payload = frame[spdyHeaderLength:frameLength]

	sf.Ctrl = hasControlBitSet(frame)

	if !sf.Ctrl { // data frame
		sf.StreamID = dataFrameStreamID(frame)
		return true, nil
	}

	sf.Version = controlFrameVersion(frame)
	sf.Type = controlFrameType(frame)
	return true, nil
}

// parseHeaders retrieves any headers from this spdyFrame.
func (sf *spdyFrame) parseHeaders(z *zlibReader, log *zap.SugaredLogger) (http.Header, error) {
	if !sf.Ctrl {
		return nil, fmt.Errorf("[unexpected] parseHeaders called for a frame that is not a control frame")
	}
	const (
		// +------------------------------------+
		// |X|           Stream-ID (31bits)     |
		// +------------------------------------+
		// |X| Associated-To-Stream-ID (31bits) |
		// +------------------------------------+
		// | Pri|Unused | Slot |                |
		// +-------------------+                |
		synStreamPayloadLengthBeforeHeaders = 10

		// +------------------------------------+
		// |X|           Stream-ID (31bits)     |
		//+------------------------------------+
		synReplyPayloadLengthBeforeHeaders = 4

		// +----------------------------------|
		// |            32-bit ID             |
		// +----------------------------------+
		pingPayloadLength = 4
	)

	switch sf.Type {
	case SYN_STREAM:
		if len(sf.Payload) < synStreamPayloadLengthBeforeHeaders {
			return nil, fmt.Errorf("SYN_STREAM frame too short: %v", len(sf.Payload))
		}
		z.Set(sf.Payload[synStreamPayloadLengthBeforeHeaders:])
		return parseHeaders(z, log)
	case SYN_REPLY:
		if len(sf.Payload) < synReplyPayloadLengthBeforeHeaders {
			return nil, fmt.Errorf("SYN_REPLY frame too short: %v", len(sf.Payload))
		}
		if len(sf.Payload) == synReplyPayloadLengthBeforeHeaders {
			return nil, nil // no headers
		}
		z.Set(sf.Payload[synReplyPayloadLengthBeforeHeaders:])
		return parseHeaders(z, log)
	case SYN_PING:
		if len(sf.Payload) != pingPayloadLength {
			return nil, fmt.Errorf("PING frame with unexpected length %v", len(sf.Payload))
		}
		return nil, nil // ping frame has no headers

	default:
		log.Infof("[unexpected] unknown control frame type %v", sf.Type)
	}
	return nil, nil
}

// parseHeaders expects to be passed a reader that contains a compressed SPDY control
// frame Name/Value Header Block with 0 or more headers:
//
// | Number of Name/Value pairs (int32) |   <+
// +------------------------------------+    |
// |     Length of name (int32)         |    | This section is the "Name/Value
// +------------------------------------+    | Header Block", and is compressed.
// |           Name (string)            |    |
// +------------------------------------+    |
// |     Length of value  (int32)       |    |
// +------------------------------------+    |
// |          Value   (string)          |    |
// +------------------------------------+    |
// |           (repeats)                |   <+
//
// It extracts the headers and returns them as http.Header. By doing that it
// also advances the provided reader past the headers block.
// See also https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.10
func parseHeaders(decompressor io.Reader, log *zap.SugaredLogger) (http.Header, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	buf.Reset()

	// readUint32 reads the next 4 decompressed bytes from the decompressor
	// as a uint32.
	readUint32 := func() (uint32, error) {
		const uint32Length = 4
		if _, err := io.CopyN(buf, decompressor, uint32Length); err != nil { // decompress
			return 0, fmt.Errorf("error decompressing bytes: %w", err)
		}
		return binary.BigEndian.Uint32(buf.Next(uint32Length)), nil // return as uint32
	}

	// readLenBytes decompresses and returns as bytes the next 'Name' or 'Value'
	// field from SPDY Name/Value header block. decompressor must be at
	// 'Length of name'/'Length of value' field.
	readLenBytes := func() ([]byte, error) {
		xLen, err := readUint32() // length of field to read
		if err != nil {
			return nil, err
		}
		if _, err := io.CopyN(buf, decompressor, int64(xLen)); err != nil { // decompress
			return nil, err
		}
		return buf.Next(int(xLen)), nil
	}

	numHeaders, err := readUint32()
	if err != nil {
		return nil, fmt.Errorf("error determining num headers: %v", err)
	}
	h := make(http.Header, numHeaders)
	for i := uint32(0); i < numHeaders; i++ {
		name, err := readLenBytes()
		if err != nil {
			return nil, err
		}
		ns := string(name)
		if _, ok := h[ns]; ok {
			return nil, fmt.Errorf("invalid data: duplicate header %q", ns)
		}
		val, err := readLenBytes()
		if err != nil {
			return nil, fmt.Errorf("error reading header data: %w", err)
		}
		for _, v := range bytes.Split(val, headerSep) {
			h.Add(ns, string(v))
		}
	}
	return h, nil
}

// isSPDYFrame validates that the input bytes start with a valid SPDY frame
// header.
func isSPDYFrameHeader(f []byte) bool {
	if hasControlBitSet(f) {
		// If this is a control frame, version and type must be set.
		return controlFrameVersion(f) != uint16(0) && uint16(controlFrameType(f)) != uint16(0)
	}
	// If this is a data frame, stream ID must be set.
	return dataFrameStreamID(f) != uint32(0)
}

// spdyDataFrameStreamID returns stream ID for an SPDY data frame passed as the
// input data slice. StreaID is contained within bits [0-31) of a data frame
// header.
func dataFrameStreamID(frame []byte) uint32 {
	return binary.BigEndian.Uint32(frame[0:4]) & 0x7f
}

// controlFrameType returns the type of a SPDY control frame.
// See https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6
func controlFrameType(f []byte) ControlFrameType {
	return ControlFrameType(binary.BigEndian.Uint16(f[2:4]))
}

// spdyControlFrameVersion returns SPDY version extracted from input bytes that
// must be a SPDY control frame.
func controlFrameVersion(frame []byte) uint16 {
	bs := binary.BigEndian.Uint16(frame[0:2]) // first 16 bits
	return bs & 0x7f                          // discard control bit
}

// hasControlBitSet returns true if the passsed bytes have SPDY control bit set.
// SPDY frames can be either control frames or data frames. A control frame has
// control bit set to 1 and a data frame has it set to 0.
func hasControlBitSet(frame []byte) bool {
	return frame[0]&0x80 == 128 // 0x80
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// Headers in SPDY header name/value block are separated by a 0 byte.
// https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.10
var headerSep = []byte{0}

func readInt24(b []byte) int {
	_ = b[2] // bounds check hint to compiler; see golang.org/issue/14808
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}
