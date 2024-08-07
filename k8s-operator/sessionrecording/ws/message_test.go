// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package ws

import (
	"reflect"
	"testing"

	"go.uber.org/zap"
)

func Test_msg_Parse(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("error creating a test logger: %v", err)
	}
	testMask := [4]byte{1, 2, 3, 4}
	tests := []struct {
		name            string
		b               []byte
		initialPayload  []byte
		wantPayload     []byte
		wantIsFinalized bool
		wantStreamID    uint32
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &message{
				typ:     binaryMessage,
				payload: tt.initialPayload,
			}
			if _, err := msg.Parse(tt.b, zl.Sugar()); err != nil {
				t.Errorf("msg.Parse() errored %v", err)
			}
			if msg.isFinalized != tt.wantIsFinalized {
				t.Errorf("wants message to be finalized: %t, got: %t", tt.wantIsFinalized, msg.isFinalized)
			}
			if msg.streamID.Load() != tt.wantStreamID {
				t.Errorf("wants stream ID: %d, got: %d", tt.wantStreamID, msg.streamID.Load())
			}
			if !reflect.DeepEqual(msg.payload, tt.wantPayload) {
				t.Errorf("unexpected message payload after Parse, wants %b, got %b", tt.wantPayload, msg.payload)
			}
		})
	}
}

func maskedBytes(mask [4]byte, b []byte) []byte {
	maskBytes(mask, b)
	return b
}
