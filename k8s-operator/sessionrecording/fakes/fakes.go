// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package fakes contains mocks used for testing 'kubectl exec' session
// recording functionality.
package fakes

import (
	"bytes"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"math/rand"

	"tailscale.com/sessionrecording"
	"tailscale.com/tstime"
)

func New(conn net.Conn, wb bytes.Buffer, rb bytes.Buffer, closed bool) net.Conn {
	return &TestConn{
		Conn:     conn,
		writeBuf: wb,
		readBuf:  rb,
		closed:   closed,
	}
}

type TestConn struct {
	net.Conn
	// writeBuf contains whatever was send to the conn via Write.
	writeBuf bytes.Buffer
	// readBuf contains whatever was sent to the conn via Read.
	readBuf      bytes.Buffer
	sync.RWMutex // protects the following
	closed       bool
}

var _ net.Conn = &TestConn{}

func (tc *TestConn) Read(b []byte) (int, error) {
	return tc.readBuf.Read(b)
}

func (tc *TestConn) Write(b []byte) (int, error) {
	return tc.writeBuf.Write(b)
}

func (tc *TestConn) Close() error {
	tc.Lock()
	defer tc.Unlock()
	tc.closed = true
	return nil
}

func (tc *TestConn) IsClosed() bool {
	tc.Lock()
	defer tc.Unlock()
	return tc.closed
}

func (tc *TestConn) WriteBufBytes() []byte {
	return tc.writeBuf.Bytes()
}

func (tc *TestConn) ResetReadBuf() {
	tc.readBuf.Reset()
}

func (tc *TestConn) WriteReadBufBytes(b []byte) error {
	_, err := tc.readBuf.Write(b)
	return err
}

type TestSessionRecorder struct {
	// buf holds data that was sent to the session recorder.
	buf bytes.Buffer
}

func (t *TestSessionRecorder) Write(b []byte) (int, error) {
	return t.buf.Write(b)
}

func (t *TestSessionRecorder) Close() error {
	t.buf.Reset()
	return nil
}

func (t *TestSessionRecorder) Bytes() []byte {
	return t.buf.Bytes()
}

func CastLine(t *testing.T, p []byte, clock tstime.Clock) []byte {
	t.Helper()
	j, err := json.Marshal([]any{
		clock.Now().Sub(clock.Now()).Seconds(),
		"o",
		string(p),
	})
	if err != nil {
		t.Fatalf("error marshalling cast line: %v", err)
	}
	return append(j, '\n')
}

func AsciinemaResizeMsg(t *testing.T, width, height int) []byte {
	t.Helper()
	ch := sessionrecording.CastHeader{
		Width:  width,
		Height: height,
	}
	bs, err := json.Marshal(ch)
	if err != nil {
		t.Fatalf("error marshalling CastHeader: %v", err)
	}
	return append(bs, '\n')
}

func RandomBytes(t *testing.T) [][]byte {
	t.Helper()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	n := r.Intn(4096)
	b := make([]byte, n)
	t.Logf("RandomBytes: generating byte slice of length %d", n)
	_, err := r.Read(b)
	if err != nil {
		t.Fatalf("error generating random byte slice: %v", err)
	}
	if len(b) < 2 {
		return [][]byte{b}
	}
	split := r.Intn(len(b) - 1)
	return [][]byte{b[:split], b[split:]}
}
