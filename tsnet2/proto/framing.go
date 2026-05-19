// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package proto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// FrameReader reads JSON-RPC frames terminated by '\n' from an
// io.Reader. It is safe to use from a single goroutine.
type FrameReader struct {
	br *bufio.Reader
}

// NewFrameReader returns a new FrameReader reading from r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{br: bufio.NewReader(r)}
}

// Next reads and decodes the next frame from the stream.
func (fr *FrameReader) Next() (*Frame, error) {
	// We read a length-prefixed line so we can accept arbitrarily
	// large frames (control RPC params can be modestly large).
	line, err := fr.br.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	var f Frame
	if err := json.Unmarshal(line[:len(line)-1], &f); err != nil {
		return nil, fmt.Errorf("proto: bad frame %q: %w", line, err)
	}
	return &f, nil
}

// FrameWriter writes JSON-RPC frames terminated by '\n' to an
// io.Writer. Writes are serialised through a mutex so multiple
// goroutines can share one FrameWriter.
type FrameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewFrameWriter returns a new FrameWriter writing to w.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// Write encodes and emits a single frame.
func (fw *FrameWriter) Write(f *Frame) error {
	buf, err := json.Marshal(f)
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	fw.mu.Lock()
	defer fw.mu.Unlock()
	_, err = fw.w.Write(buf)
	return err
}

// MarshalParams is a small helper that marshals v to JSON and stuffs
// the bytes into a Frame.Params field (which is []byte holding raw
// JSON).
func MarshalParams(v any) ([]byte, error) {
	return json.Marshal(v)
}

// UnmarshalParams decodes raw JSON params into v.
func UnmarshalParams(raw []byte, v any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}
