// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package spdy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"go.uber.org/zap"
	"tailscale.com/k8s-operator/sessionrecording/fakes"
	"tailscale.com/k8s-operator/sessionrecording/tsrecorder"
	"tailscale.com/sessionrecording"
	"tailscale.com/tstest"
)

// Test_Writes tests that 1 or more Write calls to spdyRemoteConnRecorder
// results in the expected data being forwarded to the original destination and
// the session recorder.
func Test_Writes(t *testing.T) {
	var stdoutStreamID, stderrStreamID uint32 = 1, 2
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	tests := []struct {
		name              string
		inputs            [][]byte
		wantForwarded     []byte
		wantRecorded      []byte
		firstWrite        bool
		width             int
		height            int
		sendInitialResize bool
		hasTerm           bool
	}{
		{
			name:          "single_write_control_frame_with_payload",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5},
		},
		{
			name:          "two_writes_control_frame_with_leftover",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1}, {0x0, 0x0, 0x0, 0x1, 0x5, 0x80, 0x3}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5},
		},
		{
			name:          "single_write_stdout_data_frame",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
		},
		{
			name:          "single_write_stdout_data_frame_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  fakes.CastLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
		{
			name:          "single_write_stderr_data_frame_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  fakes.CastLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
		{
			name:          "single_data_frame_unknow_stream_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
		},
		{
			name:          "control_frame_and_data_frame_split_across_two_writes",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, {0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  fakes.CastLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
		{
			name:              "single_first_write_stdout_data_frame_with_payload_sess_has_terminal",
			inputs:            [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded:     []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:      append(fakes.AsciinemaResizeMsg(t, 10, 20), fakes.CastLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl)...),
			width:             10,
			height:            20,
			hasTerm:           true,
			firstWrite:        true,
			sendInitialResize: true,
		},
		{
			name:          "single_first_write_stdout_data_frame_with_payload_sess_does_not_have_terminal",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  append(fakes.AsciinemaResizeMsg(t, 10, 20), fakes.CastLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl)...),
			width:         10,
			height:        20,
			firstWrite:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &fakes.TestConn{}
			sr := &fakes.TestSessionRecorder{}
			rec := tsrecorder.New(sr, cl, cl.Now(), true, zl.Sugar())

			c := &conn{
				Conn: tc,
				log:  zl.Sugar(),
				rec:  rec,
				ch: sessionrecording.CastHeader{
					Width:  tt.width,
					Height: tt.height,
				},
				initialTermSizeSet: make(chan struct{}),
				hasTerm:            tt.hasTerm,
			}
			if !tt.firstWrite {
				// this test case does not intend to test that cast header gets written once
				c.writeCastHeaderOnce.Do(func() {})
			}
			if tt.sendInitialResize {
				close(c.initialTermSizeSet)
			}

			c.stdoutStreamID.Store(stdoutStreamID)
			c.stderrStreamID.Store(stderrStreamID)
			for i, input := range tt.inputs {
				c.hasTerm = tt.hasTerm
				if _, err := c.Write(input); err != nil {
					t.Errorf("[%d] spdyRemoteConnRecorder.Write() unexpected error %v", i, err)
				}
			}

			// Assert that the expected bytes have been forwarded to the original destination.
			gotForwarded := tc.WriteBufBytes()
			if !reflect.DeepEqual(gotForwarded, tt.wantForwarded) {
				t.Errorf("expected bytes not forwarded, wants\n%v\ngot\n%v", tt.wantForwarded, gotForwarded)
			}

			// Assert that the expected bytes have been forwarded to the session recorder.
			gotRecorded := sr.Bytes()
			if !reflect.DeepEqual(gotRecorded, tt.wantRecorded) {
				t.Errorf("expected bytes not recorded, wants\n%v\ngot\n%v", tt.wantRecorded, gotRecorded)
			}
		})
	}
}

// Test_Reads tests that 1 or more Read calls to spdyRemoteConnRecorder results
// in the expected data being forwarded to the original destination and the
// session recorder.
func Test_Reads(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	var reader zlibReader
	resizeMsg := resizeMsgBytes(t, 10, 20)
	synStreamStdoutPayload := payload(t, map[string]string{"Streamtype": "stdout"}, SYN_STREAM, 1)
	synStreamStderrPayload := payload(t, map[string]string{"Streamtype": "stderr"}, SYN_STREAM, 2)
	synStreamResizePayload := payload(t, map[string]string{"Streamtype": "resize"}, SYN_STREAM, 3)
	syn_stream_ctrl_header := []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, uint8(len(synStreamStdoutPayload))}

	tests := []struct {
		name                     string
		inputs                   [][]byte
		wantStdoutStreamID       uint32
		wantStderrStreamID       uint32
		wantResizeStreamID       uint32
		wantWidth                int
		wantHeight               int
		resizeStreamIDBeforeRead uint32
	}{
		{
			name:                     "resize_data_frame_single_read",
			inputs:                   [][]byte{append([]byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, uint8(len(resizeMsg))}, resizeMsg...)},
			resizeStreamIDBeforeRead: 1,
			wantWidth:                10,
			wantHeight:               20,
		},
		{
			name:                     "resize_data_frame_two_reads",
			inputs:                   [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, uint8(len(resizeMsg))}, resizeMsg},
			resizeStreamIDBeforeRead: 1,
			wantWidth:                10,
			wantHeight:               20,
		},
		{
			name:               "syn_stream_ctrl_frame_stdout_single_read",
			inputs:             [][]byte{append(syn_stream_ctrl_header, synStreamStdoutPayload...)},
			wantStdoutStreamID: 1,
		},
		{
			name:               "syn_stream_ctrl_frame_stderr_single_read",
			inputs:             [][]byte{append(syn_stream_ctrl_header, synStreamStderrPayload...)},
			wantStderrStreamID: 2,
		},
		{
			name:               "syn_stream_ctrl_frame_resize_single_read",
			inputs:             [][]byte{append(syn_stream_ctrl_header, synStreamResizePayload...)},
			wantResizeStreamID: 3,
		},
		{
			name:               "syn_stream_ctrl_frame_resize_four_reads_with_leftover",
			inputs:             [][]byte{syn_stream_ctrl_header, append(synStreamResizePayload, syn_stream_ctrl_header...), append(synStreamStderrPayload, syn_stream_ctrl_header...), append(synStreamStdoutPayload, 0x0, 0x3)},
			wantStdoutStreamID: 1,
			wantStderrStreamID: 2,
			wantResizeStreamID: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &fakes.TestConn{}
			sr := &fakes.TestSessionRecorder{}
			rec := tsrecorder.New(sr, cl, cl.Now(), true, zl.Sugar())
			c := &conn{
				Conn:               tc,
				log:                zl.Sugar(),
				rec:                rec,
				initialTermSizeSet: make(chan struct{}),
			}
			c.resizeStreamID.Store(tt.resizeStreamIDBeforeRead)

			for i, input := range tt.inputs {
				c.zlibReqReader = reader
				tc.ResetReadBuf()
				if err := tc.WriteReadBufBytes(input); err != nil {
					t.Fatalf("writing bytes to test conn: %v", err)
				}
				_, err = c.Read(make([]byte, len(input)))
				if err != nil {
					t.Errorf("[%d] spdyRemoteConnRecorder.Read() resulted in an unexpected error: %v", i, err)
				}
			}
			if id := c.resizeStreamID.Load(); id != tt.wantResizeStreamID && id != tt.resizeStreamIDBeforeRead {
				t.Errorf("wants resizeStreamID: %d, got %d", tt.wantResizeStreamID, id)
			}
			if id := c.stderrStreamID.Load(); id != tt.wantStderrStreamID {
				t.Errorf("wants stderrStreamID: %d, got %d", tt.wantStderrStreamID, id)
			}
			if id := c.stdoutStreamID.Load(); id != tt.wantStdoutStreamID {
				t.Errorf("wants stdoutStreamID: %d, got %d", tt.wantStdoutStreamID, id)
			}
			if tt.wantHeight != 0 || tt.wantWidth != 0 {
				if tt.wantWidth != c.ch.Width {
					t.Errorf("wants width: %v, got %v", tt.wantWidth, c.ch.Width)
				}
				if tt.wantHeight != c.ch.Height {
					t.Errorf("want height: %v, got %v", tt.wantHeight, c.ch.Height)
				}
			}
		})
	}
}

// Test_conn_ReadRand tests reading arbitrarily generated byte slices from conn to
// test that we don't panic when parsing input from a broken or malicious
// client.
func Test_conn_ReadRand(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("error creating a test logger: %v", err)
	}
	for i := range 1000 {
		tc := &fakes.TestConn{}
		tc.ResetReadBuf()
		c := &conn{
			Conn: tc,
			log:  zl.Sugar(),
		}
		bb := fakes.RandomBytes(t)
		for j, input := range bb {
			if err := tc.WriteReadBufBytes(input); err != nil {
				t.Fatalf("[%d] writing bytes to test conn: %v", i, err)
			}
			f := func() {
				c.Read(make([]byte, len(input)))
			}
			testPanic(t, f, fmt.Sprintf("[%d %d] Read panic parsing input of length %d", i, j, len(input)))
		}
	}
}

// Test_conn_WriteRand calls conn.Write with an arbitrary input to validate that
// it does not panic.
func Test_conn_WriteRand(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("error creating a test logger: %v", err)
	}
	for i := range 100 {
		tc := &fakes.TestConn{}
		c := &conn{
			Conn: tc,
			log:  zl.Sugar(),
		}
		bb := fakes.RandomBytes(t)
		for j, input := range bb {
			f := func() {
				c.Write(input)
			}
			testPanic(t, f, fmt.Sprintf("[%d %d] Write: panic parsing input of length %d", i, j, len(input)))
		}
	}
}

func resizeMsgBytes(t *testing.T, width, height int) []byte {
	t.Helper()
	bs, err := json.Marshal(spdyResizeMsg{Width: width, Height: height})
	if err != nil {
		t.Fatalf("error marshalling resizeMsg: %v", err)
	}
	return bs
}
