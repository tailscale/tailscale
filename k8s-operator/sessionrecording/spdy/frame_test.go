// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package spdy

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"math/rand"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
)

func Test_limitHeaderReader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     []byte // underlying stream, never nil in practice
		remain   int64  // starting budget
		readSize int    // bytes to request per Read
		wantData []byte // total bytes expected before the terminal error
		wantErr  error  // terminal error; nil means clean EOF
	}{
		{
			name:     "under_limit",
			body:     []byte("hello"),
			remain:   16,
			readSize: 16,
			wantData: []byte("hello"),
		},
		{
			// Budget spent with the last bytes: parsing succeeded but any
			// further read, including the ended() check, errors.
			name:     "exactly_at_limit",
			body:     []byte("hello"),
			remain:   5,
			readSize: 5,
			wantData: []byte("hello"),
			wantErr:  errHeaderBlockTooLarge,
		},
		{
			name:     "budget_spent_mid_stream",
			body:     []byte("hello world"),
			remain:   5,
			readSize: 2,
			wantData: []byte("hello"),
			wantErr:  errHeaderBlockTooLarge,
		},
		{
			name:     "budget_spent_mid_stream_single_reads",
			body:     []byte("hello world"),
			remain:   5,
			readSize: 1,
			wantData: []byte("hello"),
			wantErr:  errHeaderBlockTooLarge,
		},
		{
			// Every read after the budget is spent keeps reporting the
			// sentinel while data remains.
			name:     "error_persists_after_trip",
			body:     []byte("hello world"),
			remain:   5,
			readSize: 5,
			wantData: []byte("hello"),
			wantErr:  errHeaderBlockTooLarge,
		},
		{
			name:     "empty_read_no_hang",
			body:     []byte("hello"),
			remain:   5,
			readSize: 0, // zero length read must not spin the budget away
			wantData: nil,
		},
		{
			name:     "eof_mid_block",
			body:     []byte("hi"),
			remain:   5,
			readSize: 1,
			wantData: []byte("hi"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lr := &limitHeaderReader{r: bytes.NewReader(tt.body), remain: tt.remain}
			var got []byte
			var lastErr error
			for range 10 { // bounded loop: a bug here must not hang the test
				p := make([]byte, tt.readSize)
				n, err := lr.Read(p)
				got = append(got, p[:n]...)
				if err != nil {
					lastErr = err
					break
				}
			}
			if tt.wantErr != nil && lastErr == nil {
				t.Errorf("limitHeaderReader.Read() got no error after %v bytes, want %v", len(got), tt.wantErr)
			}
			if tt.wantErr == nil {
				// No error expected: the stream must end in a clean EOF, not
				// the sentinel or a loop that returned (0, nil) until the cap.
				if lastErr != nil && !errors.Is(lastErr, io.EOF) {
					t.Errorf("limitHeaderReader.Read() error = %v, want clean EOF", lastErr)
				}
			} else if !errors.Is(lastErr, tt.wantErr) {
				t.Errorf("limitHeaderReader.Read() error = %v, want %v", lastErr, tt.wantErr)
			}
			if !bytes.Equal(got, tt.wantData) {
				t.Errorf("limitHeaderReader.Read() data = %q, want %q", got, tt.wantData)
			}
			if tt.wantErr == nil {
				return
			}
		})
	}
}

func Test_limitHeaderReader_ended(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    []byte
		remain  int64
		read    int64 // bytes to consume before calling ended
		wantErr error
	}{
		{
			name:   "clean_end",
			body:   []byte("hello"),
			remain: 16,
			read:   5,
		},
		{
			name:    "trailing_data",
			body:    []byte("hello!"),
			remain:  16,
			read:    5,
			wantErr: errHeaderBlockTooLarge,
		},
		{
			name:    "cap_exceeded",
			body:    []byte("hello world"),
			remain:  5,
			read:    5,
			wantErr: errHeaderBlockTooLarge,
		},
		{
			name:    "under_read",
			body:    []byte("hello"),
			remain:  16,
			read:    2,
			wantErr: errHeaderBlockTooLarge, // 'llo' remains unconsumed
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lr := &limitHeaderReader{r: bytes.NewReader(tt.body), remain: tt.remain}
			if _, err := io.CopyN(io.Discard, lr, tt.read); err != nil {
				t.Fatalf("consuming %d bytes: %v", tt.read, err)
			}
			err := lr.ended()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("limitHeaderReader.ended() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseHeaders_oversizeBlock(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	const synStreamPrefix = 10 // stream ID, priority, slot before the header block

	// A block declaring one name of maxHeaderBlockSize+1 bytes, backed by
	// zeros so it compresses far below the 1MiB wire limit.
	block := slices.Concat(
		binary.BigEndian.AppendUint32(nil, 1),                    // one pair
		binary.BigEndian.AppendUint32(nil, maxHeaderBlockSize+1), // name length
		make([]byte, maxHeaderBlockSize+1),                       // name bytes
	)
	sf := &spdyFrame{
		Ctrl:    true,
		Type:    SYN_STREAM,
		Payload: append(make([]byte, synStreamPrefix), fuzzCompress(block)...),
	}
	var zr zlibReader
	zr.Set(sf.Payload[synStreamPrefix:])
	_, err = parseHeaders(&zr, zl.Sugar())
	if !errors.Is(err, errHeaderBlockTooLarge) {
		t.Errorf("parseHeaders() error = %v, want errHeaderBlockTooLarge", err)
	}

	// A block of exactly maxHeaderBlockSize parses its headers but then errors
	nameLen := uint32(maxHeaderBlockSize - 12) // minus the pair count, name and value length fields
	block = slices.Concat(
		binary.BigEndian.AppendUint32(nil, 1),       // one pair
		binary.BigEndian.AppendUint32(nil, nameLen), // name length
		make([]byte, nameLen),                       // name bytes
		binary.BigEndian.AppendUint32(nil, 0),       // value length
	)
	sf = &spdyFrame{
		Ctrl:    true,
		Type:    SYN_STREAM,
		Payload: append(make([]byte, synStreamPrefix), fuzzCompress(block)...),
	}
	var zr2 zlibReader
	zr2.Set(sf.Payload[synStreamPrefix:])
	_, err = parseHeaders(&zr2, zl.Sugar())
	if !errors.Is(err, errHeaderBlockTooLarge) {
		t.Errorf("parseHeaders() error = %v, want errHeaderBlockTooLarge for a block of exactly maxHeaderBlockSize", err)
	}
}

func Test_spdyFrame_Parse(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		gotBytes  []byte
		wantFrame spdyFrame
		wantOk    bool
		wantErr   bool
	}{
		{
			name:     "control_frame_syn_stream",
			gotBytes: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
			wantFrame: spdyFrame{
				Version: 3,
				Type:    SYN_STREAM,
				Ctrl:    true,
				Raw:     []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
				Payload: []byte{},
			},
			wantOk: true,
		},
		{
			name:     "control_frame_syn_reply",
			gotBytes: []byte{0x80, 0x3, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0},
			wantFrame: spdyFrame{
				Ctrl:    true,
				Version: 3,
				Type:    SYN_REPLY,
				Raw:     []byte{0x80, 0x3, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0},
				Payload: []byte{},
			},
			wantOk: true,
		},
		{
			name:     "control_frame_headers",
			gotBytes: []byte{0x80, 0x3, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0},
			wantFrame: spdyFrame{
				Ctrl:    true,
				Version: 3,
				Type:    8,
				Raw:     []byte{0x80, 0x3, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0},
				Payload: []byte{},
			},
			wantOk: true,
		},
		{
			name:     "data_frame_stream_id_5",
			gotBytes: []byte{0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0},
			wantFrame: spdyFrame{
				Payload:  []byte{},
				StreamID: 5,
				Raw:      []byte{0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0},
			},
			wantOk: true,
		},
		{
			name:     "frame_with_incomplete_header",
			gotBytes: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			name:     "frame_with_incomplete_payload",
			gotBytes: []byte{0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x2}, // header specifies payload length of 2
		},
		{
			name:     "control_bit_set_not_spdy_frame",
			gotBytes: []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, // header specifies payload length of 2
			wantErr:  true,
		},
		{
			name:     "control_bit_not_set_not_spdy_frame",
			gotBytes: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, // header specifies payload length of 2
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sf := &spdyFrame{}
			gotOk, err := sf.Parse(tt.gotBytes, zl.Sugar())
			if (err != nil) != tt.wantErr {
				t.Errorf("spdyFrame.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOk != tt.wantOk {
				t.Errorf("spdyFrame.Parse() = %v, want %v", gotOk, tt.wantOk)
			}
			if diff := cmp.Diff(*sf, tt.wantFrame); diff != "" {
				t.Errorf("Unexpected SPDY frame (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_spdyFrame_parseHeaders(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		isCtrl     bool
		payload    []byte
		typ        ControlFrameType
		wantHeader http.Header
		wantErr    bool
	}{
		{
			name:       "syn_stream_with_header",
			payload:    payload(t, map[string]string{"Streamtype": "stdin"}, SYN_STREAM, 1),
			typ:        SYN_STREAM,
			isCtrl:     true,
			wantHeader: header(map[string]string{"Streamtype": "stdin"}),
		},
		{
			name:    "syn_ping",
			payload: payload(t, nil, SYN_PING, 0),
			typ:     SYN_PING,
			isCtrl:  true,
		},
		{
			name:       "syn_reply_headers",
			payload:    payload(t, map[string]string{"foo": "bar", "bar": "baz"}, SYN_REPLY, 0),
			typ:        SYN_REPLY,
			isCtrl:     true,
			wantHeader: header(map[string]string{"foo": "bar", "bar": "baz"}),
		},
		{
			name:    "syn_reply_no_headers",
			payload: payload(t, nil, SYN_REPLY, 0),
			typ:     SYN_REPLY,
			isCtrl:  true,
		},
		{
			name:    "syn_stream_too_short_payload",
			payload: []byte{0, 1, 2, 3, 4},
			typ:     SYN_STREAM,
			isCtrl:  true,
			wantErr: true,
		},
		{
			name:    "syn_reply_too_short_payload",
			payload: []byte{0, 1, 2},
			typ:     SYN_REPLY,
			isCtrl:  true,
			wantErr: true,
		},
		{
			name:    "syn_ping_too_short_payload",
			payload: []byte{0, 1, 2},
			typ:     SYN_PING,
			isCtrl:  true,
			wantErr: true,
		},
		{
			name:    "not_a_control_frame",
			payload: []byte{0, 1, 2, 3},
			typ:     SYN_PING,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		var reader zlibReader
		t.Run(tt.name, func(t *testing.T) {
			sf := &spdyFrame{
				Ctrl:    tt.isCtrl,
				Type:    tt.typ,
				Payload: tt.payload,
			}
			gotHeader, err := sf.parseHeaders(&reader, zl.Sugar())
			if (err != nil) != tt.wantErr {
				t.Errorf("spdyFrame.parseHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(gotHeader, tt.wantHeader) {
				t.Errorf("spdyFrame.parseHeaders() = %v, want %v", gotHeader, tt.wantHeader)
			}
		})
	}
}

// Test_spdyFrame_ParseRand calls spdyFrame.Parse with randomly generated bytes
// to test that it doesn't panic.
func Test_spdyFrame_ParseRand(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range 100 {
		n := r.Intn(4096)
		b := make([]byte, n)
		_, err := r.Read(b)
		if err != nil {
			t.Fatalf("error generating random byte slice: %v", err)
		}
		sf := &spdyFrame{}
		f := func() {
			sf.Parse(b, zl.Sugar())
		}
		testPanic(t, f, fmt.Sprintf("[%d] Parse panicked running with byte slice of length %d: %v", i, n, r))
	}
}

// payload takes a control frame type and a map with 0 or more header keys and
// values and returns a SPDY control frame payload with the header as SPDY zlib
// compressed header name/value block. The payload is padded with arbitrary
// bytes to ensure the header name/value block is in the correct position for
// the frame type.
func payload(t *testing.T, headerM map[string]string, typ ControlFrameType, streamID int) []byte {
	t.Helper()

	buf := bytes.NewBuffer([]byte{})
	writeControlFramePayloadBeforeHeaders(t, buf, typ, streamID)
	if len(headerM) == 0 {
		return buf.Bytes()
	}

	w, err := zlib.NewWriterLevelDict(buf, zlib.BestCompression, spdyTxtDictionary)
	if err != nil {
		t.Fatalf("error creating new zlib writer: %v", err)
	}
	if len(headerM) != 0 {
		writeHeaderValueBlock(t, w, headerM)
	}
	if err != nil {
		t.Fatalf("error writing headers: %v", err)
	}
	w.Flush()
	return buf.Bytes()
}

// writeControlFramePayloadBeforeHeaders writes to w N bytes, N being the number
// of bytes that control frame payload for that control frame is required to
// contain before the name/value header block.
func writeControlFramePayloadBeforeHeaders(t *testing.T, w io.Writer, typ ControlFrameType, streamID int) {
	t.Helper()
	switch typ {
	case SYN_STREAM:
		// needs 10 bytes in payload before any headers
		if err := binary.Write(w, binary.BigEndian, uint32(streamID)); err != nil {
			t.Fatalf("writing streamID: %v", err)
		}
		if err := binary.Write(w, binary.BigEndian, [6]byte{0}); err != nil {
			t.Fatalf("writing payload: %v", err)
		}
	case SYN_REPLY:
		// needs 4 bytes in payload before any headers
		if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
			t.Fatalf("writing payload: %v", err)
		}
	case SYN_PING:
		// needs 4 bytes in payload
		if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
			t.Fatalf("writing payload: %v", err)
		}
	default:
		t.Fatalf("unexpected frame type: %v", typ)
	}
}

// writeHeaderValue block takes http.Header and zlib writer, writes the headers
// as SPDY zlib compressed bytes to the writer.
// Adopted from https://github.com/moby/spdystream/blob/v0.2.0/spdy/write.go#L171-L198 (which is also what Kubernetes uses).
func writeHeaderValueBlock(t *testing.T, w io.Writer, headerM map[string]string) {
	t.Helper()
	h := header(headerM)
	if err := binary.Write(w, binary.BigEndian, uint32(len(h))); err != nil {
		t.Fatalf("error writing header block length: %v", err)
	}
	for name, values := range h {
		if err := binary.Write(w, binary.BigEndian, uint32(len(name))); err != nil {
			t.Fatalf("error writing name length for name %q: %v", name, err)
		}
		name = strings.ToLower(name)
		if _, err := io.WriteString(w, name); err != nil {
			t.Fatalf("error writing name %q: %v", name, err)
		}
		v := strings.Join(values, string(headerSep))
		if err := binary.Write(w, binary.BigEndian, uint32(len(v))); err != nil {
			t.Fatalf("error writing value length for value %q: %v", v, err)
		}
		if _, err := io.WriteString(w, v); err != nil {
			t.Fatalf("error writing value %q: %v", v, err)
		}
	}
}

func header(hs map[string]string) http.Header {
	h := make(http.Header, len(hs))
	for key, val := range hs {
		h.Add(key, val)
	}
	return h
}

func testPanic(t *testing.T, f func(), msg string) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatal(msg, r)
		}
	}()
	f()
}
