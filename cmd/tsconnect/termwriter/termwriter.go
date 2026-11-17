// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package termwriter provides a Writer that adapts byte output for a
// terminal emulator that takes strings, such as xterm.js.
package termwriter

import (
	"bytes"
	"unicode/utf8"
)

// Writer is an io.Writer that converts "\n" to "\n\r" and holds incomplete
// UTF-8 sequences until the next Write, preventing malformed output from being
// sent to the JS side.
type Writer struct {
	write   func(string)
	pending []byte
}

// New returns a Writer that passes its output to write.
func New(write func(string)) *Writer {
	return &Writer{write: write}
}

func (w *Writer) Write(p []byte) (n int, err error) {
	buf := p
	if len(w.pending) > 0 {
		buf = append(w.pending, p...)
	}
	end := len(buf)

	// Chunks ending with incomplete UTF-8 sequences need to save the bytes for
	// the next chunk to avoid sending malformed output to the JS side.
	for i := len(buf) - 1; i >= 0 && i >= len(buf)-utf8.UTFMax; i-- {
		if utf8.RuneStart(buf[i]) {
			if !utf8.FullRune(buf[i:]) {
				end = i
			}
			break
		}
	}

	w.pending = bytes.Clone(buf[end:])
	if end > 0 {
		r := bytes.Replace(buf[:end], []byte("\n"), []byte("\n\r"), -1)
		w.write(string(r))
	}
	return len(p), nil
}
