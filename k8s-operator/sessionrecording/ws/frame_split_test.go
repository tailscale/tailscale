// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package ws

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
	"tailscale.com/k8s-operator/sessionrecording/fakes"
	"tailscale.com/k8s-operator/sessionrecording/tsrecorder"
	"tailscale.com/sessionrecording"
	"tailscale.com/tstest"
)

// segConn is a net.Conn whose Read returns pre-scripted segments, simulating
// arbitrary TCP segmentation of the client-to-server byte stream. Writes are
// collected in wb.
type segConn struct {
	net.Conn
	segs [][]byte
	wb   bytes.Buffer
}

func (sc *segConn) Read(b []byte) (int, error) {
	if len(sc.segs) == 0 {
		return 0, io.EOF
	}
	seg := sc.segs[0]
	n := copy(b, seg)
	if n < len(seg) {
		sc.segs[0] = seg[n:]
	} else {
		sc.segs = sc.segs[1:]
	}
	return n, nil
}

func (sc *segConn) Write(b []byte) (int, error) { return sc.wb.Write(b) }
func (sc *segConn) Close() error                { return nil }

// writeTestFrame appends a single WebSocket frame with the given opcode and
// payload to out. Client-to-server frames are masked; server-to-client
// frames are not.
func writeTestFrame(out *bytes.Buffer, opcode byte, payload []byte, masked bool, rng *rand.Rand) {
	out.WriteByte(0x80 | opcode) // FIN set
	var maskBit byte
	if masked {
		maskBit = 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		out.WriteByte(maskBit | byte(n))
	case n <= 0xffff:
		out.WriteByte(maskBit | 126)
		binary.Write(out, binary.BigEndian, uint16(n))
	default:
		out.WriteByte(maskBit | 127)
		binary.Write(out, binary.BigEndian, uint64(n))
	}
	if masked {
		var mask [4]byte
		rng.Read(mask[:])
		out.Write(mask[:])
		p := bytes.Clone(payload)
		maskBytes(mask, p)
		out.Write(p)
		return
	}
	out.Write(payload)
}

// buildStdinStream frames data the way kubectl sends exec stdin over
// WebSocket: masked binary messages on stream 0, one frame per message, with
// pings sprinkled in and a half-close message plus a CLOSE frame at the end.
func buildStdinStream(data []byte, frameSize int, rng *rand.Rand) []byte {
	var out bytes.Buffer
	frames := 0
	for off := 0; off < len(data); off += frameSize {
		end := min(off+frameSize, len(data))
		writeTestFrame(&out, 0x2, append([]byte{0x00}, data[off:end]...), true, rng) // stream 0 = stdin
		frames++
		if frames%100 == 0 {
			writeTestFrame(&out, 0x9, nil, true, rng) // ping
		}
	}
	writeTestFrame(&out, 0x2, []byte{255, 0}, true, rng) // v5 half-close of stream 0
	writeTestFrame(&out, 0x8, []byte{0x03, 0xe8}, true, rng)
	return out.Bytes()
}

// segment splits stream into random-sized segments in [1, maxSeg].
func segment(stream []byte, maxSeg int, rng *rand.Rand) [][]byte {
	var segs [][]byte
	for off := 0; off < len(stream); {
		n := min(1+rng.Intn(maxSeg), len(stream)-off)
		segs = append(segs, stream[off:off+n])
		off += n
	}
	return segs
}

func newTestWSConn(t *testing.T, segs [][]byte) *conn {
	t.Helper()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	sr := &fakes.TestSessionRecorder{}
	rec := tsrecorder.New(sr, cl, cl.Now(), true, zl.Sugar())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	c, err := New(ctx, &segConn{segs: segs}, rec, sessionrecording.CastHeader{Width: 80, Height: 24}, false, zl.Sugar())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c.(*conn)
}

// readAll drains the wrapped conn like the hijacker's io.Copy would and
// returns everything read.
func readAll(t *testing.T, c net.Conn, streamLen int) []byte {
	t.Helper()
	var got bytes.Buffer
	buf := make([]byte, 32*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
		if err == io.EOF {
			return got.Bytes()
		}
		if err != nil {
			t.Fatalf("Read failed after %d of %d stream bytes: %v", got.Len(), streamLen, err)
		}
	}
}

// splits2and3 returns all ways to split stream into two or three non-empty
// segments with all cut points within the first maxCut bytes, plus the
// unsplit stream itself.
func splits2and3(stream []byte, maxCut int) [][][]byte {
	segsList := [][][]byte{{stream}}
	maxCut = min(maxCut, len(stream)-1)
	for cut1 := 1; cut1 <= maxCut; cut1++ {
		segsList = append(segsList, [][]byte{stream[:cut1], stream[cut1:]})
		for cut2 := cut1 + 1; cut2 <= maxCut; cut2++ {
			segsList = append(segsList, [][]byte{stream[:cut1], stream[cut1:cut2], stream[cut2:]})
		}
	}
	return segsList
}

// frameCases returns single frames covering all header encodings: short,
// 16-bit and 64-bit extended payload lengths, for both data and control
// frames.
func frameCases(masked bool, rng *rand.Rand) map[string][]byte {
	mkPayload := func(n int) []byte {
		return append([]byte{0x00}, bytes.Repeat([]byte{0xab}, n)...) // stream 0 = stdin
	}
	cases := map[string][]byte{}
	for name, payloadLen := range map[string]int{"short_len": 100, "extended_len_16bit": 300, "extended_len_64bit": 70000} {
		var out bytes.Buffer
		writeTestFrame(&out, 0x2, mkPayload(payloadLen), masked, rng)
		cases[name] = out.Bytes()
	}
	var out bytes.Buffer
	writeTestFrame(&out, 0x9, []byte{0x01, 0x02}, masked, rng) // ping with a tiny payload
	cases["control_ping"] = out.Bytes()
	return cases
}

// TestReadSplitFrameHeader exercises client-to-server frames split across
// reads at every possible boundary within and just past the frame header,
// in both two and three segments. The parser must buffer and wait for the
// rest of the frame rather than erroring out.
func TestReadSplitFrameHeader(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	// The longest header is 2 + 8 (64-bit length) + 4 (mask) = 14 bytes;
	// cutting a few bytes into the payload too costs little extra.
	const maxCut = 18
	for name, stream := range frameCases(true, rng) {
		t.Run(name, func(t *testing.T) {
			for i, segs := range splits2and3(stream, maxCut) {
				got := readAll(t, newTestWSConn(t, segs), len(stream))
				if !bytes.Equal(got, stream) {
					t.Fatalf("split %d: passthrough corrupted: got %d bytes, want %d", i, len(got), len(stream))
				}
			}
		})
	}
}

// TestWriteSplitFrameHeader is the server-to-client (unmasked) counterpart
// of TestReadSplitFrameHeader: frames arrive via Write in segments split at
// every boundary within and just past the frame header, and the parser must
// forward exactly the original bytes to the underlying connection.
func TestWriteSplitFrameHeader(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	const maxCut = 14 // longest unmasked header is 2 + 8 bytes
	for name, stream := range frameCases(false, rng) {
		t.Run(name, func(t *testing.T) {
			for i, segs := range splits2and3(stream, maxCut) {
				c := newTestWSConn(t, nil)
				for _, seg := range segs {
					if _, err := c.Write(seg); err != nil {
						t.Fatalf("split %d: Write: %v", i, err)
					}
				}
				got := c.Conn.(*segConn).wb.Bytes()
				if !bytes.Equal(got, stream) {
					t.Fatalf("split %d: passthrough corrupted: got %d bytes, want %d", i, len(got), len(stream))
				}
			}
		})
	}
}

func runStdinThroughParser(t *testing.T, data []byte, frameSize, maxSeg int, seed int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	stream := buildStdinStream(data, frameSize, rng)
	got := readAll(t, newTestWSConn(t, segment(stream, maxSeg, rng)), len(stream))
	if !bytes.Equal(got, stream) {
		t.Errorf("passthrough corrupted: got %d bytes, want %d", len(got), len(stream))
	}
}

// TestBulkStdinPassthrough streams several MB of stdin through the parser
// under a variety of frame sizes and TCP segmentations, as 'kubectl exec'
// piping a large file does.
func TestBulkStdinPassthrough(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	data := make([]byte, 8<<20)
	rng.Read(data)
	for _, frameSize := range []int{4 << 10, 32 << 10} {
		for _, maxSeg := range []int{1460, 16 << 10} {
			for seed := int64(0); seed < 3; seed++ {
				t.Run(fmt.Sprintf("frame%d_seg%d_seed%d", frameSize, maxSeg, seed), func(t *testing.T) {
					runStdinThroughParser(t, data, frameSize, maxSeg, seed)
				})
			}
		}
	}
}

// TestBulkStdinPassthroughFile replays an arbitrary local file as exec
// stdin. Set BULK_STDIN_FILE to reproduce a failure with specific data.
func TestBulkStdinPassthroughFile(t *testing.T) {
	path := os.Getenv("BULK_STDIN_FILE")
	if path == "" {
		t.Skip("BULK_STDIN_FILE not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, maxSeg := range []int{1460, 16 << 10, 64 << 10} {
		for seed := int64(0); seed < 3; seed++ {
			t.Run(fmt.Sprintf("seg%d_seed%d", maxSeg, seed), func(t *testing.T) {
				runStdinThroughParser(t, data, 32<<10, maxSeg, seed)
			})
		}
	}
}
