// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package ws

import (
	"fmt"
	"reflect"
	"testing"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/remotecommand"
	"tailscale.com/k8s-operator/sessionrecording/fakes"
	"tailscale.com/k8s-operator/sessionrecording/tsrecorder"
	"tailscale.com/sessionrecording"
	"tailscale.com/tstest"
)

func Test_conn_Read(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	// Resize stream ID + {"width": 10, "height": 20}
	testResizeMsg := []byte{byte(remotecommand.StreamResize), 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x3a, 0x31, 0x30, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x32, 0x30, 0x7d}
	lenResizeMsgPayload := byte(len(testResizeMsg))

	tests := []struct {
		name       string
		inputs     [][]byte
		wantWidth  int
		wantHeight int
	}{
		{
			name:   "single_read_control_message",
			inputs: [][]byte{{0x88, 0x0}},
		},
		{
			name:       "single_read_resize_message",
			inputs:     [][]byte{append([]byte{0x82, lenResizeMsgPayload}, testResizeMsg...)},
			wantWidth:  10,
			wantHeight: 20,
		},
		{
			name:       "two_reads_resize_message",
			inputs:     [][]byte{{0x2, 0x9, 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22}, {0x80, 0x11, 0x4, 0x3a, 0x31, 0x30, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3a, 0x32, 0x30, 0x7d}},
			wantWidth:  10,
			wantHeight: 20,
		},
		{
			name:       "three_reads_resize_message_with_split_fragment",
			inputs:     [][]byte{{0x2, 0x9, 0x4, 0x7b, 0x22, 0x77, 0x69, 0x64, 0x74, 0x68, 0x22}, {0x80, 0x11, 0x4, 0x3a, 0x31, 0x30, 0x2c, 0x22, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74}, {0x22, 0x3a, 0x32, 0x30, 0x7d}},
			wantWidth:  10,
			wantHeight: 20,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &fakes.TestConn{}
			tc.ResetReadBuf()
			c := &conn{
				Conn: tc,
				log:  zl.Sugar(),
			}
			for i, input := range tt.inputs {
				if err := tc.WriteReadBufBytes(input); err != nil {
					t.Fatalf("writing bytes to test conn: %v", err)
				}
				_, err := c.Read(make([]byte, len(input)))
				if err != nil {
					t.Errorf("[%d] conn.Read() errored %v", i, err)
					return
				}
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

func Test_conn_Write(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	tests := []struct {
		name          string
		inputs        [][]byte
		wantForwarded []byte
		wantRecorded  []byte
		firstWrite    bool
		width         int
		height        int
	}{
		{
			name:          "single_write_control_frame",
			inputs:        [][]byte{{0x88, 0x0}},
			wantForwarded: []byte{0x88, 0x0},
		},
		{
			name:          "single_write_stdout_data_message",
			inputs:        [][]byte{{0x82, 0x3, 0x1, 0x7, 0x8}},
			wantForwarded: []byte{0x82, 0x3, 0x1, 0x7, 0x8},
			wantRecorded:  fakes.CastLine(t, []byte{0x7, 0x8}, cl),
		},
		{
			name:          "single_write_stderr_data_message",
			inputs:        [][]byte{{0x82, 0x3, 0x2, 0x7, 0x8}},
			wantForwarded: []byte{0x82, 0x3, 0x2, 0x7, 0x8},
			wantRecorded:  fakes.CastLine(t, []byte{0x7, 0x8}, cl),
		},
		{
			name:          "single_write_stdin_data_message",
			inputs:        [][]byte{{0x82, 0x3, 0x0, 0x7, 0x8}},
			wantForwarded: []byte{0x82, 0x3, 0x0, 0x7, 0x8},
		},
		{
			name:          "single_write_stdout_data_message_with_cast_header",
			inputs:        [][]byte{{0x82, 0x3, 0x1, 0x7, 0x8}},
			wantForwarded: []byte{0x82, 0x3, 0x1, 0x7, 0x8},
			wantRecorded:  append(fakes.AsciinemaResizeMsg(t, 10, 20), fakes.CastLine(t, []byte{0x7, 0x8}, cl)...),
			width:         10,
			height:        20,
			firstWrite:    true,
		},
		{
			name:          "two_writes_stdout_data_message",
			inputs:        [][]byte{{0x2, 0x3, 0x1, 0x7, 0x8}, {0x80, 0x6, 0x1, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x2, 0x3, 0x1, 0x7, 0x8, 0x80, 0x6, 0x1, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  fakes.CastLine(t, []byte{0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
		{
			name:          "three_writes_stdout_data_message_with_split_fragment",
			inputs:        [][]byte{{0x2, 0x3, 0x1, 0x7, 0x8}, {0x80, 0x6, 0x1, 0x1, 0x2, 0x3}, {0x4, 0x5}},
			wantForwarded: []byte{0x2, 0x3, 0x1, 0x7, 0x8, 0x80, 0x6, 0x1, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  fakes.CastLine(t, []byte{0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &fakes.TestConn{}
			sr := &fakes.TestSessionRecorder{}
			rec := tsrecorder.New(sr, cl, cl.Now(), true)
			c := &conn{
				Conn: tc,
				log:  zl.Sugar(),
				ch: sessionrecording.CastHeader{
					Width:  tt.width,
					Height: tt.height,
				},
				rec: rec,
			}
			if !tt.firstWrite {
				// This test case does not intend to test that cast header gets written once.
				c.writeCastHeaderOnce.Do(func() {})
			}
			for i, input := range tt.inputs {
				_, err := c.Write(input)
				if err != nil {
					t.Fatalf("[%d] conn.Write() errored: %v", i, err)
				}
			}
			// Assert that the expected bytes have been forwarded to the original destination.
			gotForwarded := tc.WriteBufBytes()
			if !reflect.DeepEqual(gotForwarded, tt.wantForwarded) {
				t.Errorf("expected bytes not forwarded, wants\n%x\ngot\n%x", tt.wantForwarded, gotForwarded)
			}

			// Assert that the expected bytes have been forwarded to the session recorder.
			gotRecorded := sr.Bytes()
			if !reflect.DeepEqual(gotRecorded, tt.wantRecorded) {
				t.Errorf("expected bytes not recorded, wants\n%b\ngot\n%b", tt.wantRecorded, gotRecorded)
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
	for i := range 100 {
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
			testPanic(t, f, fmt.Sprintf("[%d %d] Read panic parsing input of length %d first bytes: %v, current read message: %+#v", i, j, len(input), firstBytes(input), c.currentReadMsg))
		}
	}
}

// Test_conn_WriteRand calls conn.Write with an arbitrary input to validate that it does not
// panic.
func Test_conn_WriteRand(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("error creating a test logger: %v", err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	sr := &fakes.TestSessionRecorder{}
	rec := tsrecorder.New(sr, cl, cl.Now(), true)
	for i := range 100 {
		tc := &fakes.TestConn{}
		c := &conn{
			Conn: tc,
			log:  zl.Sugar(),
			rec:  rec,
		}
		bb := fakes.RandomBytes(t)
		for j, input := range bb {
			f := func() {
				c.Write(input)
			}
			testPanic(t, f, fmt.Sprintf("[%d %d] Write: panic parsing input of length %d first bytes %b current write message %+#v", i, j, len(input), firstBytes(input), c.currentWriteMsg))
		}
	}
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

func firstBytes(b []byte) []byte {
	if len(b) < 10 {
		return b
	}
	return b[:10]
}
