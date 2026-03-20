// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package bufiox provides extensions to the standard bufio package.
package bufiox

import "io"

// BufferedReader is an interface for readers that support peeking
// into an internal buffer, like [bufio.Reader].
type BufferedReader interface {
	Peek(n int) ([]byte, error)
	Discard(n int) (discarded int, err error)
}

// ReadFull reads exactly len(buf) bytes from r into buf, like
// [io.ReadFull], but without heap allocations. It uses Peek to
// access the buffered data directly, copies it into buf, then
// discards the consumed bytes. If an error occurs,
// discard is not called and the buffer is left unchanged.
func ReadFull(r BufferedReader, buf []byte) (int, error) {
	b, err := r.Peek(len(buf))
	if err != nil {
		if len(b) > 0 && err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	defer r.Discard(len(buf))
	return copy(buf, b), nil
}
