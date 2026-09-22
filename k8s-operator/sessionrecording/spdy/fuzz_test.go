// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package spdy

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"net/http"
	"slices"
	"strings"
	"testing"

	"go.uber.org/zap"
	"tailscale.com/k8s-operator/sessionrecording/fakes"
	"tailscale.com/k8s-operator/sessionrecording/tsrecorder"
	"tailscale.com/tstest"
)

// fuzzLog is a discarding logger, needed for fuzz speed.
var fuzzLog = zap.NewNop().Sugar()

const (
	fuzzStdoutStreamID uint32 = 1
	fuzzStderrStreamID uint32 = 2
	fuzzResizeStreamID uint32 = 3
)

// fuzzCtrlFrame returns a SPDY control frame carrying payload. version is the 15 bit protocol
// version, so seeds can set bits that controlFrameVersion drops.
func fuzzCtrlFrame(version uint16, typ ControlFrameType, payload []byte) []byte {
	f := make([]byte, 8+len(payload))
	v := version & 0x7fff // bit 15 is the control bit
	f[0] = 0x80 | byte(v>>8)
	f[1] = byte(v)
	binary.BigEndian.PutUint16(f[2:4], uint16(typ))
	writeFuzzLen24(f[5:8], len(payload))
	copy(f[8:], payload)
	return f
}

// fuzzDataFrame returns a SPDY data frame for streamID carrying payload.
func fuzzDataFrame(streamID uint32, payload []byte) []byte {
	f := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(f[0:4], streamID&0x7fffffff) // bit 31 is the control bit
	writeFuzzLen24(f[5:8], len(payload))
	copy(f[8:], payload)
	return f
}

// writeFuzzLen24 writes n as SPDY's 24 bit frame length field.
func writeFuzzLen24(b []byte, n int) {
	b[0] = byte(n >> 16)
	b[1] = byte(n >> 8)
	b[2] = byte(n)
}

// fuzzBlock returns a decompressed Name/Value header block declaring count pairs
// followed by the given entries.
func fuzzBlock(count uint32, pairs ...[2]string) []byte {
	b := binary.BigEndian.AppendUint32(nil, count)
	for _, p := range pairs {
		b = append(b, fuzzKV(p[0], p[1])...)
	}
	return b
}

// fuzzKV returns one decompressed entry of a Name/Value header block.
// Writes length followed by the value for the key then the value.
func fuzzKV(name, value string) []byte {
	b := make([]byte, 8+len(name)+len(value))
	binary.BigEndian.PutUint32(b[0:4], uint32(len(name)))
	copy(b[4:], name)
	binary.BigEndian.PutUint32(b[4+len(name):8+len(name)], uint32(len(value)))
	copy(b[8+len(name):], value)
	return b
}

// fuzzCompress zlib-compresses b with the SPDY header dictionary, mirroring a client
// compressing a Name/Value header block.
func fuzzCompress(b []byte) []byte {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevelDict(&buf, zlib.BestSpeed, spdyTxtDictionary)
	if err != nil {
		panic(err)
	} else if _, err := w.Write(b); err != nil {
		panic(err)
	} else if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// fuzzName returns a distinct three letter name for i, so one block can declare many pairs.
func fuzzName(i int) string {
	return string([]byte{byte('a' + i/676%26), byte('a' + i/26%26), byte('a' + i%26)})
}

// fuzzSynStream returns a SYN_STREAM payload: the 10 bytes that precede the
// header block (stream ID, priority, slot) plus the compressed block for pairs.
func fuzzSynStream(streamID uint32, pairs ...[2]string) []byte {
	p := make([]byte, 10)
	binary.BigEndian.PutUint32(p[0:4], streamID)
	if len(pairs) > 0 {
		p = append(p, fuzzCompress(fuzzBlock(uint32(len(pairs)), pairs...))...)
	}
	return p
}

// fuzzSynStreamBlock returns a SYN_STREAM payload: the 10 byte prefix plus an arbitrary
// decompressed block, compressed. Lets a seed declare counts that pairs cannot express.
func fuzzSynStreamBlock(streamID uint32, block []byte) []byte {
	p := make([]byte, 10)
	binary.BigEndian.PutUint32(p[0:4], streamID)
	return append(p, fuzzCompress(block)...)
}

// fuzzSynReply returns a SYN_REPLY payload: the 4 byte stream ID plus the
// compressed header block for pairs.
func fuzzSynReply(streamID uint32, pairs ...[2]string) []byte {
	p := make([]byte, 4)
	binary.BigEndian.PutUint32(p[0:4], streamID)
	if len(pairs) > 0 {
		p = append(p, fuzzCompress(fuzzBlock(uint32(len(pairs)), pairs...))...)
	}
	return p
}

func FuzzSpdyFrameParse(f *testing.F) {
	// Complete frames
	synStream := fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(fuzzStdoutStreamID, [2]string{"streamtype", "stdout"}))
	f.Add(synStream)
	f.Add(fuzzCtrlFrame(3, SYN_REPLY, fuzzSynReply(0, [2]string{"status", "200"})))
	f.Add(fuzzCtrlFrame(3, SYN_PING, []byte{0, 0, 0, 1}))
	f.Add(fuzzDataFrame(fuzzStdoutStreamID, []byte("hello")))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte(`{"width":80,"height":24}`)))
	// Header only frames, length field is zero
	f.Add([]byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0})
	f.Add([]byte{0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0})
	// A complete frame followed by the first bytes of the next one
	f.Add(append(slices.Clone(synStream), 0x80, 0x3))
	// Two whole frames in one buffer: only the first may be consumed
	f.Add(slices.Concat(synStream, fuzzDataFrame(fuzzStdoutStreamID, []byte("x"))))
	// Flags byte all set, sitting between version/type and the length field
	f.Add([]byte{0x80, 0x3, 0x0, 0x1, 0xff, 0x0, 0x0, 0x0})
	f.Add([]byte{0x0, 0x0, 0x0, 0x1, 0xff, 0x0, 0x0, 0x0}) // data frame variant
	// Version bits above bit 7: controlFrameVersion masks with 0x7f so this reads
	// as version 35 instead of the 15 bit value 291
	f.Add([]byte{0x81, 0x23, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0})
	// A version whose set bits are all above bit 7: the mask hides them so the
	// frame is rejected as non-SPDY
	f.Add([]byte{0x81, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0})
	// Control frames rejected for a zero version or type
	f.Add([]byte{0x80, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0})
	f.Add([]byte{0x80, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
	// Data frame rejected for a zero stream ID
	f.Add([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0})
	// Stream IDs above 7 bits: dataFrameStreamID masks with 0x7f so ID 300 and
	// ID 44 parse to the same value, putting two streams on one recording
	f.Add(fuzzDataFrame(300, []byte("stream 300")))
	f.Add(fuzzDataFrame(44, []byte("stream 44")))
	f.Add(fuzzDataFrame(0x7fffffff, []byte("max stream id, masked to 127")))
	// Truncated headers, one per boundary Parse checks
	for _, n := range []int{0, 1, 4, 7} {
		f.Add(slices.Clone(synStream[:n]))
	}
	f.Add(synStream[:len(synStream)-1]) // last payload byte missing
	// Length claims more bytes than are present, up to the 16MiB field maximum
	f.Add([]byte{0x80, 0x3, 0x0, 0x1, 0x0, 0xff, 0xff, 0xff})
	f.Add([]byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2})
	// Declared length above 64KiB: the first complete frame whose size needs all
	// three length bytes, so a wrong use of them shows up as a size mismatch
	f.Add(fuzzDataFrame(1, make([]byte, 65536)))
	// Control bit boundary in the first byte
	f.Add([]byte{0x7f, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0})
	f.Add([]byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0})

	f.Fuzz(func(t *testing.T, data []byte) {
		var sf spdyFrame
		ok, err := sf.Parse(data, fuzzLog)
		switch {
		case err != nil:
			return // input rejected as not SPDY
		case !ok:
			if len(data) < 8 {
				return // header cut off before the length field, nothing to size
			} else if want := 8 + readInt24(data[5:8]); len(data) >= want {
				t.Fatalf("Parse called a %d byte frame incomplete with %d bytes available", want, len(data))
			}
			return
		}
		n := 8 + readInt24(data[5:8])
		if len(sf.Raw) != n {
			t.Fatalf("Raw length %d, want %d", len(sf.Raw), n)
		} else if cap(sf.Raw) != n {
			t.Fatalf("Raw capacity %d, want %d: frame bytes can alias later input", cap(sf.Raw), n)
		} else if len(sf.Payload) != n-8 {
			t.Fatalf("Payload length %d, want %d", len(sf.Payload), n-8)
		} else if sf.Ctrl != hasControlBitSet(data) {
			t.Fatalf("Ctrl = %v, control bit says %v", sf.Ctrl, hasControlBitSet(data))
		} else if !sf.Ctrl && (sf.Version != 0 || sf.Type != 0) {
			t.Fatalf("data frame parsed out version %d and type %d", sf.Version, sf.Type)
		} else if sf.Ctrl && sf.StreamID != 0 {
			t.Fatalf("control frame parsed out stream id %d", sf.StreamID)
		} else if !sf.Ctrl && (sf.StreamID == 0 || sf.StreamID&^0x7f != 0) {
			// A data frame only parses with a nonzero ID, and dataFrameStreamID keeps 7 bits
			t.Fatalf("data frame stream id %d, want nonzero within its mask", sf.StreamID)
		}
	})
}

// fuzzFrameCopy returns a deep copy of the provided spdyFrame.
func fuzzFrameCopy(sf spdyFrame) spdyFrame {
	sf.Raw = slices.Clone(sf.Raw)
	sf.Payload = sf.Raw[len(sf.Raw)-len(sf.Payload):]
	return sf
}

func FuzzSpdyFrameParseHeaders(f *testing.F) {
	// SYN_STREAM: 10 bytes ahead of the header block, then a zlib block
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(fuzzStdoutStreamID, [2]string{"streamtype", "stdout"})))
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(fuzzResizeStreamID, [2]string{"streamtype", "resize"})))
	// SYN_STREAM with exactly the 10 byte prefix: nothing to decompress
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, make([]byte, 10)))
	// SYN_REPLY: headers start at offset 4 and may be absent entirely
	f.Add(fuzzCtrlFrame(3, SYN_REPLY, fuzzSynReply(0, [2]string{"status", "200"})))
	f.Add(fuzzCtrlFrame(3, SYN_REPLY, []byte{0, 0, 0, 1}))
	// SYN_PING: payload must be exactly 4 bytes long
	f.Add(fuzzCtrlFrame(3, SYN_PING, []byte{0, 0, 0, 7}))
	f.Add(fuzzCtrlFrame(3, SYN_PING, []byte{0, 0, 0}))
	f.Add(fuzzCtrlFrame(3, SYN_PING, []byte{0, 0, 0, 7, 8}))
	// Prefixes one byte short of what each type requires
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, make([]byte, 9)))
	f.Add(fuzzCtrlFrame(3, SYN_REPLY, make([]byte, 3)))
	// Where a header block is expected: zlib garbage, then a stream cut off mid deflate block
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, append(make([]byte, 10), 0x78, 0x9c, 0xff, 0xfe, 0xfd)))
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevelDict(&buf, zlib.BestSpeed, spdyTxtDictionary)
	if err != nil {
		f.Fatalf("Failed to create zlib writer: %v", err)
	} else if _, err := w.Write(fuzzBlock(1, [2]string{"streamtype", "stdout"})); err != nil {
		f.Fatalf("Failed to write block: %v", err)
	} else if err := w.Flush(); err != nil { // sync flush makes 'a' decodable here
		f.Fatalf("Failed to flush: %v", err)
	}
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, append(make([]byte, 10), buf.Bytes()[:buf.Len()/2]...)))
	// A well formed zlib stream whose declared pair count is wrong by two
	f.Add(fuzzCtrlFrame(3, SYN_REPLY, append([]byte{0, 0, 0, 0}, fuzzCompress(fuzzBlock(3, [2]string{"a", "b"}))...)))
	// Control types that are not handled: headers must be skipped without error
	for _, typ := range []ControlFrameType{0, 3, 4, 5, 7, 8, 9, 0xffff} {
		f.Add(fuzzCtrlFrame(3, typ, fuzzSynStream(2, [2]string{"streamtype", "stdin"})))
	}
	// A data frame: parseHeaders must refuse it
	f.Add(fuzzDataFrame(fuzzStdoutStreamID, []byte("not a control frame")))

	f.Fuzz(func(t *testing.T, data []byte) {
		var parsed spdyFrame
		ok, err := parsed.Parse(data, fuzzLog)
		if !ok || err != nil {
			return
		}
		// If parsed without error, the same bytes as a data frame must be rejected without panic.
		// Reading headers out of a data frame would advance the shared decompression context.
		sf := fuzzFrameCopy(parsed)
		sf.Ctrl = false
		var zr zlibReader
		if _, err := sf.parseHeaders(&zr, fuzzLog); err == nil {
			t.Fatal("parseHeaders accepted a frame that is not a control frame")
		}
		// Errors are expected below, but no panics from different control types
		for _, typ := range []ControlFrameType{SYN_STREAM, SYN_REPLY, SYN_PING, 0, 3, 4, 5, 7, 8, 9, 0xffff} {
			sf := fuzzFrameCopy(parsed)
			sf.Ctrl = true
			sf.Type = typ
			var zr zlibReader
			_, _ = sf.parseHeaders(&zr, fuzzLog) // errors expected, but not panics
		}
	})
}

func FuzzParseHeaders(f *testing.F) {
	// One header pair, as sent when a stream is opened
	f.Add(fuzzBlock(1, [2]string{"streamtype", "stdout"}))
	f.Add(fuzzBlock(1, [2]string{"streamtype", "resize"}))
	f.Add(fuzzBlock(3,
		[2]string{":method", "GET"},
		[2]string{":path", "/api/v1/namespaces/default/pods/x/exec"},
		[2]string{"user-agent", "kubectl/v1.30.0"},
	))
	// A block declaring no headers is valid
	f.Add(binary.BigEndian.AppendUint32(nil, 0))
	// Headers with 0 byte separation inside the name and values
	f.Add(fuzzBlock(1, [2]string{"set-cookie", "a=1\x00b=2\x00c=3"}))
	f.Add(fuzzBlock(1, [2]string{"n\x00ame", "v"}))
	// Declared count does not match the entries that follow
	f.Add(append(binary.BigEndian.AppendUint32(nil, 2), fuzzKV("a", "b")...)) // one pair fewer than declared
	f.Add(fuzzBlock(1))                                                       // no pairs after a count of 1
	f.Add(fuzzBlock(1, [2]string{"a", "b"}, [2]string{"c", "d"}))             // one pair more than declared
	f.Add([]byte{0, 0, 0})                                                    // truncated count field
	// Duplicate names are rejected when looked up exactly
	f.Add(fuzzBlock(2, [2]string{"dup", "1"}, [2]string{"dup", "2"}))
	// Case difference so both values land on one header
	f.Add(fuzzBlock(2, [2]string{"Foo", "1"}, [2]string{"foo", "2"}))
	// Empty names and values still carry length fields
	f.Add(fuzzBlock(1, [2]string{"", ""}))
	f.Add(fuzzBlock(2, [2]string{"", "v"}, [2]string{"n", ""}))
	// Length fields running past the end of the block
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 8, 'a', 'b'})                  // name claims 8 bytes, 2 present
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 2, 'a', 'b', 0, 0})            // value length cut in half
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 2, 'a', 'b', 0, 0, 0, 9, 'x'}) // value claims 9 bytes, 1 present
	// Zero length fields followed by unrelated bytes
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 'z', 'z'})
	// Names that are not HTTP tokens and text that is not valid UTF-8
	f.Add(fuzzBlock(1, [2]string{"foo bar", "v"}))
	f.Add(fuzzBlock(1, [2]string{"foo\x00bar\nbaz", "a\nb"}))
	f.Add(fuzzBlock(1, [2]string{"\xff\xfe", "\xc3\x28"}))
	// Long but legal name and value
	f.Add(fuzzBlock(1, [2]string{strings.Repeat("a", 4096), "v"}))
	f.Add(fuzzBlock(1, [2]string{"n", strings.Repeat("v", 4096)}))
	// A count with the high bit set, ensure limits are enforced on header counts
	f.Add(binary.BigEndian.AppendUint32(nil, 0xffff_ffff))
	// Exceed max header count
	var atCap [][2]string
	for i := range maxHeaderCount + 1 {
		atCap = append(atCap, [2]string{fuzzName(i), "v"})
	}
	f.Add(fuzzBlock(maxHeaderCount+1, atCap...))
	// A value made only of separators, attempting to produce many values in parser
	f.Add(fuzzBlock(1, [2]string{"n", strings.Repeat("\x00", 64<<10)}))
	// A decompression bomb: a name length past maxHeaderBlockSize backed by zeros
	f.Add(slices.Concat(
		binary.BigEndian.AppendUint32(nil, 1),     // one pair
		binary.BigEndian.AppendUint32(nil, 4<<20), // name claims 4MiB
		make([]byte, 4<<20),                       // backed by compressible zeros
	))

	f.Fuzz(func(t *testing.T, data []byte) {
		var z zlibReader
		z.Set(fuzzCompress(data))
		h, err := parseHeaders(&z, fuzzLog)
		if err != nil {
			return
		}
		var total int
		for name, vals := range h {
			total += len(name)
			if len(vals) == 0 {
				t.Fatalf("header %q present with no values", name)
			} else if c := http.CanonicalHeaderKey(name); c != name {
				t.Fatalf("header name %q is not canonicalized by Add, got %q", name, c)
			}
			for _, v := range vals {
				total += len(v)
				if strings.ContainsRune(v, 0) {
					t.Fatalf("header %q value %q still holds a 0 byte separator", name, v)
				}
			}
		}
		if total > maxHeaderBlockSize {
			t.Fatalf("parsed %d bytes of headers out of one block, maximum is %d", total, maxHeaderBlockSize)
		}
	})
}

// fuzzChunks splits the bytes into roughly equal parts, mimicking frames arriving across several reads.
func fuzzChunks(b []byte, n int) [][]byte {
	if n <= 1 || len(b) == 0 {
		return [][]byte{b}
	}
	step := max(1, (len(b)+n-1)/n)
	out := make([][]byte, 0, n)
	for i := 0; i < len(b); i += step {
		out = append(out, b[i:min(i+step, len(b))])
	}
	return out
}

// fuzzConn returns a conn over tc that records to a throwaway recorder. The stored
// stream IDs match the seeds so mutated frames still land on streams we care about.
func fuzzConn(t *testing.T, tc *fakes.TestConn, hasTerm bool) *conn {
	t.Helper()

	cl := tstest.NewClock(tstest.ClockOpts{})
	c := &conn{
		Conn:                  tc,
		ctx:                   t.Context(),
		rec:                   tsrecorder.New(&fakes.TestSessionRecorder{}, cl, cl.Now(), true, fuzzLog),
		log:                   fuzzLog,
		hasTerm:               hasTerm,
		initialCastHeaderSent: make(chan struct{}),
	}
	c.stdoutStreamID.Store(fuzzStdoutStreamID)
	c.stderrStreamID.Store(fuzzStderrStreamID)
	c.resizeStreamID.Store(fuzzResizeStreamID)
	return c
}

func FuzzConnRead(f *testing.F) {
	resize := fuzzDataFrame(fuzzResizeStreamID, []byte(`{"width":80,"height":24}`))
	synStdout := fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(fuzzStdoutStreamID, [2]string{"streamtype", "stdout"}))
	synResize := fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(fuzzResizeStreamID, [2]string{"streamtype", "resize"}))

	// A resize message on the resize stream: sets terminal size and sends the
	// CastHeader on a session with a TTY attached
	f.Add(resize, true, uint8(1))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte(`{"height":24,"width":80}`)), false, uint8(1))
	// Malformed resize payloads: JSON that is not an object, wrong value types and
	// numbers out of int range
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte("")), true, uint8(1))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte("{")), true, uint8(1))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte("null")), true, uint8(1))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte("[0,0]")), true, uint8(1))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte(`{"width":"wide","height":null}`)), true, uint8(1))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte(`{"width":-1,"height":-1}`)), true, uint8(1))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte(`{"width":9223372036854775808}`)), true, uint8(1))
	// A resize frame whose JSON payload is cut off mid object
	f.Add(append(slices.Clone(resize[:len(resize)-1]), '{'), true, uint8(1))
	// Stream opening frames: stdout, stderr and resize IDs get stored
	f.Add(synStdout, true, uint8(1))
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(fuzzStderrStreamID, [2]string{"streamtype", "stderr"})), true, uint8(1))
	f.Add(synResize, true, uint8(1))
	// Stream types that are not recorded must still be parsed
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(7, [2]string{"streamtype", "stdin"})), true, uint8(1))
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(8, [2]string{"streamtype", "\x00"})), true, uint8(1))
	// storeStreamID keeps all 32 bits of the ID from a SYN_STREAM payload while
	// dataFrameStreamID keeps 7. Output on a stdout stream opened above ID 127 is
	// therefore never matched: the stored ID is 300 while the frame masks to 44.
	f.Add(slices.Concat(
		fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(300, [2]string{"streamtype", "stdout"})),
		fuzzDataFrame(300, []byte("output on the stored ID"))), true, uint8(1))
	// A frame on stream 259: masked to 3, the resize stream, so its payload gets
	// parsed as a resize message even though it belongs to another stream
	f.Add(fuzzDataFrame(259, []byte(`{"width":1,"height":1}`)), true, uint8(1))
	// A session opening: SYN_REPLY plus stream setup plus output and resize frames,
	// sharing one decompression context across reads
	f.Add(slices.Concat(
		fuzzCtrlFrame(3, SYN_REPLY, fuzzSynReply(fuzzStdoutStreamID, [2]string{"status", "200"})),
		synStdout, synResize, fuzzDataFrame(fuzzStdoutStreamID, []byte("hello")), resize), true, uint8(3))
	f.Add(slices.Concat(synResize, resize, resize), true, uint8(2))
	// The same session without a TTY: resize messages are not parsed
	f.Add(slices.Concat(synResize, resize), false, uint8(4))
	// A SYN_STREAM whose header block is a bomb: the pair count and the name length claim far
	// more than maxHeaderBlockSize, backed by zeros. conn parses headers for every control
	// frame, so this must fail or stay bounded rather than expand.
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStreamBlock(fuzzStdoutStreamID, slices.Concat(
		binary.BigEndian.AppendUint32(nil, maxHeaderCount+1),
		make([]byte, 4<<20),
	))), true, uint8(1))
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStreamBlock(fuzzStdoutStreamID, slices.Concat(
		binary.BigEndian.AppendUint32(nil, 1),
		binary.BigEndian.AppendUint32(nil, 1<<20),
		make([]byte, 1<<20),
	))), true, uint8(1))
	// A SYN_REPLY whose block declares a count with the high bit set
	f.Add(fuzzCtrlFrame(3, SYN_REPLY, slices.Concat(
		[]byte{0, 0, 0, 1}, fuzzCompress(binary.BigEndian.AppendUint32(nil, 0x8000_0000)))), true, uint8(1))
	// A SYN_STREAM whose compressed header block is cut off mid stream
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, append(make([]byte, 10), 0x78, 0x9c, 0x63)), true, uint8(2))
	// Non-SPDY bytes on a hijacked connection: a TLS record header masks to a
	// zero stream ID so Read reports it, while plain HTTP parses as a data frame
	// header with a huge claimed length and is buffered as incomplete
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, true, uint8(1))
	f.Add([]byte("HTTP/1.1 200 OK\r\n\r\n"), true, uint8(1))

	f.Fuzz(func(t *testing.T, data []byte, hasTerm bool, parts uint8) {
		tc := &fakes.TestConn{}
		c := fuzzConn(t, tc, hasTerm)
		for _, chunk := range fuzzChunks(data, int(parts)%4+1) {
			if err := tc.WriteReadBufBytes(chunk); err != nil {
				t.Fatalf("writing bytes to test conn: %v", err)
			}

			if n, err := c.Read(make([]byte, len(chunk))); err != nil {
				continue // unparseable frames and truncated resize messages are fine
			} else if n != len(chunk) {
				t.Fatalf("Read returned %d bytes, want %d", n, len(chunk))
			}
		}
	})
}

func FuzzConnWrite(f *testing.F) {
	out := fuzzDataFrame(fuzzStdoutStreamID, []byte("hello"))
	errF := fuzzDataFrame(fuzzStderrStreamID, []byte("boom"))

	// Output on the recorded streams, including empty payloads
	f.Add(out, uint8(1))
	f.Add(errF, uint8(1))
	f.Add(fuzzDataFrame(fuzzStdoutStreamID, nil), uint8(1))
	f.Add(fuzzDataFrame(fuzzResizeStreamID, []byte(`{"width":80,"height":24}`)), uint8(1)) // not a recorded stream
	// Data frames whose ID only matches a recorded stream after truncation.
	// stdout is stored as ID 1 and dataFrameStreamID keeps 7 bits, so these
	// land on the stdout recording together with the real stream 1 output.
	f.Add(fuzzDataFrame(129, []byte("aliased onto stdout")), uint8(1))
	f.Add(fuzzDataFrame(0x1000001, []byte("also aliased onto stdout")), uint8(1))
	// Control frames carry no output but must be forwarded whole
	f.Add(fuzzCtrlFrame(3, SYN_STREAM, fuzzSynStream(fuzzStdoutStreamID, [2]string{"streamtype", "stdout"})), uint8(1))
	f.Add(fuzzCtrlFrame(3, SYN_REPLY, fuzzSynReply(0, [2]string{"status", "200"})), uint8(1))
	f.Add(fuzzCtrlFrame(3, SYN_PING, []byte{0, 0, 0, 7}), uint8(1))
	// Payload bytes that are invalid UTF-8
	f.Add(fuzzDataFrame(fuzzStdoutStreamID, []byte("\xff\xfe\x00\x01\n\r\"\\")), uint8(1))
	// A frame whose length field lies about the payload present
	f.Add([]byte{0x00, 0x00, 0x00, 1, 0x00, 0xff, 0xff, 0xff}, uint8(1))
	// Incomplete header
	f.Add(out[:4], uint8(1))
	// Partial payload
	f.Add(out[:len(out)-2], uint8(1))
	// Several frames that must be forwarded whole and in order across writes
	f.Add(slices.Concat(out, errF, out), uint8(4))
	// Plain HTTP parses as a data frame header with a huge claimed length
	f.Add([]byte("GET / HTTP/1.1\r\n"), uint8(1))

	f.Fuzz(func(t *testing.T, data []byte, parts uint8) {
		tc := &fakes.TestConn{}
		c := fuzzConn(t, tc, false)
		// Output can only be recorded once the CastHeader is out.
		// Leaving it open would park every stdout frame on ctx.
		c.writeCastHeaderOnce.Do(func() { close(c.initialCastHeaderSent) })

		for _, chunk := range fuzzChunks(data, int(parts)%4+1) {
			if n, err := c.Write(chunk); err != nil {
				return
			} else if n != len(chunk) {
				t.Fatalf("Write returned %d, want %d", n, len(chunk))
			}
		}
	})
}
