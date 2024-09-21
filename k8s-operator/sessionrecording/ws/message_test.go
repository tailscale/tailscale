// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package ws

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
	"time"

	"math/rand"

	"go.uber.org/zap"
	"golang.org/x/net/websocket"
)

func Test_msg_Parse(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("error creating a test logger: %v", err)
	}
	testMask := [4]byte{1, 2, 3, 4}
	bs126, bs126Len := bytesSlice2ByteLen(t)
	bs127, bs127Len := byteSlice8ByteLen(t)
	tests := []struct {
		name            string
		b               []byte
		initialPayload  []byte
		wantPayload     []byte
		wantIsFinalized bool
		wantStreamID    uint32
		wantErr         bool
	}{
		{
			name:            "single_fragment_stdout_stream_no_payload_no_mask",
			b:               []byte{0x82, 0x1, 0x1},
			wantPayload:     nil,
			wantIsFinalized: true,
			wantStreamID:    1,
		},
		{
			name:            "single_fragment_stderr_steam_no_payload_has_mask",
			b:               append([]byte{0x82, 0x81, 0x1, 0x2, 0x3, 0x4}, maskedBytes(testMask, []byte{0x2})...),
			wantPayload:     nil,
			wantIsFinalized: true,
			wantStreamID:    2,
		},
		{
			name:            "single_fragment_stdout_stream_no_mask_has_payload",
			b:               []byte{0x82, 0x3, 0x1, 0x7, 0x8},
			wantPayload:     []byte{0x7, 0x8},
			wantIsFinalized: true,
			wantStreamID:    1,
		},
		{
			name:            "single_fragment_stdout_stream_has_mask_has_payload",
			b:               append([]byte{0x82, 0x83, 0x1, 0x2, 0x3, 0x4}, maskedBytes(testMask, []byte{0x1, 0x7, 0x8})...),
			wantPayload:     []byte{0x7, 0x8},
			wantIsFinalized: true,
			wantStreamID:    1,
		},
		{
			name:         "initial_fragment_stdout_stream_no_mask_has_payload",
			b:            []byte{0x2, 0x3, 0x1, 0x7, 0x8},
			wantPayload:  []byte{0x7, 0x8},
			wantStreamID: 1,
		},
		{
			name:         "initial_fragment_stdout_stream_has_mask_has_payload",
			b:            append([]byte{0x2, 0x83, 0x1, 0x2, 0x3, 0x4}, maskedBytes(testMask, []byte{0x1, 0x7, 0x8})...),
			wantPayload:  []byte{0x7, 0x8},
			wantStreamID: 1,
		},
		{
			name:           "subsequent_fragment_stdout_stream_no_mask_has_payload",
			b:              []byte{0x0, 0x3, 0x1, 0x7, 0x8},
			initialPayload: []byte{0x1, 0x2, 0x3},
			wantPayload:    []byte{0x1, 0x2, 0x3, 0x7, 0x8},
			wantStreamID:   1,
		},
		{
			name:           "subsequent_fragment_stdout_stream_has_mask_has_payload",
			b:              append([]byte{0x0, 0x83, 0x1, 0x2, 0x3, 0x4}, maskedBytes(testMask, []byte{0x1, 0x7, 0x8})...),
			initialPayload: []byte{0x1, 0x2, 0x3},
			wantPayload:    []byte{0x1, 0x2, 0x3, 0x7, 0x8},
			wantStreamID:   1,
		},
		{
			name:            "final_fragment_stdout_stream_no_mask_has_payload",
			b:               []byte{0x80, 0x3, 0x1, 0x7, 0x8},
			initialPayload:  []byte{0x1, 0x2, 0x3},
			wantIsFinalized: true,
			wantPayload:     []byte{0x1, 0x2, 0x3, 0x7, 0x8},
			wantStreamID:    1,
		},
		{
			name:            "final_fragment_stdout_stream_has_mask_has_payload",
			b:               append([]byte{0x80, 0x83, 0x1, 0x2, 0x3, 0x4}, maskedBytes(testMask, []byte{0x1, 0x7, 0x8})...),
			initialPayload:  []byte{0x1, 0x2, 0x3},
			wantIsFinalized: true,
			wantPayload:     []byte{0x1, 0x2, 0x3, 0x7, 0x8},
			wantStreamID:    1,
		},
		{
			name:            "single_large_fragment_no_mask_length_hint_126",
			b:               append(append([]byte{0x80, 0x7e}, bs126Len...), append([]byte{0x1}, bs126...)...),
			wantIsFinalized: true,
			wantPayload:     bs126,
			wantStreamID:    1,
		},
		{
			name:            "single_large_fragment_no_mask_length_hint_127",
			b:               append(append([]byte{0x80, 0x7f}, bs127Len...), append([]byte{0x1}, bs127...)...),
			wantIsFinalized: true,
			wantPayload:     bs127,
			wantStreamID:    1,
		},
		{
			name:    "zero_length_bytes",
			b:       []byte{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &message{
				typ:     binaryMessage,
				payload: tt.initialPayload,
			}
			if _, err := msg.Parse(tt.b, zl.Sugar()); (err != nil) != tt.wantErr {
				t.Errorf("msg.Parse() = %v, wantsErr: %t", err, tt.wantErr)
			}
			if msg.isFinalized != tt.wantIsFinalized {
				t.Errorf("wants message to be finalized: %t, got: %t", tt.wantIsFinalized, msg.isFinalized)
			}
			if msg.streamID.Load() != tt.wantStreamID {
				t.Errorf("wants stream ID: %d, got: %d", tt.wantStreamID, msg.streamID.Load())
			}
			if !reflect.DeepEqual(msg.payload, tt.wantPayload) {
				t.Errorf("unexpected message payload after Parse, wants %b got %b", tt.wantPayload, msg.payload)
			}
		})
	}
}

// Test_msg_Parse_Rand calls Parse with a randomly generated input to verify
// that it doesn't panic.
func Test_msg_Parse_Rand(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("error creating a test logger: %v", err)
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range 100 {
		n := r.Intn(4096)
		b := make([]byte, n)
		_, err := r.Read(b)
		if err != nil {
			t.Fatalf("error generating random byte slice: %v", err)
		}
		msg := message{typ: binaryMessage}
		f := func() {
			msg.Parse(b, zl.Sugar())
		}
		testPanic(t, f, fmt.Sprintf("[%d] Parse panicked running with byte slice of length %d: %v", i, n, r))
	}
}

// byteSlice2ByteLen generates a number that represents websocket message fragment length and is stored in an 8 byte slice.
// Returns the byte slice with the length as well as a slice of arbitrary bytes of the given length.
// This is used to generate test input representing websocket message with payload length hint 126.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
func bytesSlice2ByteLen(t *testing.T) ([]byte, []byte) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var n uint16
	n = uint16(rand.Intn(65535 - 1)) // space for and additional 1 byte stream ID
	b := make([]byte, n)
	_, err := r.Read(b)
	if err != nil {
		t.Fatalf("error generating random byte slice: %v ", err)
	}
	bb := make([]byte, 2)
	binary.BigEndian.PutUint16(bb, n+1) // + stream ID
	return b, bb
}

// byteSlice8ByteLen generates a number that represents websocket message fragment length and is stored in an 8 byte slice.
// Returns the byte slice with the length as well as a slice of arbitrary bytes of the given length.
// This is used to generate test input representing websocket message with payload length hint 127.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
func byteSlice8ByteLen(t *testing.T) ([]byte, []byte) {
	nanos := time.Now().UnixNano()
	t.Logf("Creating random source with seed %v", nanos)
	r := rand.New(rand.NewSource(nanos))
	var n uint64
	n = uint64(rand.Intn(websocket.DefaultMaxPayloadBytes - 1)) // space for and additional 1 byte stream ID
	t.Logf("byteSlice8ByteLen: generating message payload of length %d", n)
	b := make([]byte, n)
	_, err := r.Read(b)
	if err != nil {
		t.Fatalf("error generating random byte slice: %v ", err)
	}
	bb := make([]byte, 8)
	binary.BigEndian.PutUint64(bb, n+1) // + stream ID
	return b, bb
}

func maskedBytes(mask [4]byte, b []byte) []byte {
	maskBytes(mask, b)
	return b
}
