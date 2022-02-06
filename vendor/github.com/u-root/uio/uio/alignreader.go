// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uio

import (
	"io"
)

// AlignReader keeps track of how many bytes were read so the reader can be
// aligned at a future time.
type AlignReader struct {
	R io.Reader
	N int
}

// Read reads from the underlying io.Reader.
func (r *AlignReader) Read(b []byte) (int, error) {
	n, err := r.R.Read(b)
	r.N += n
	return n, err
}

// ReadByte reads one byte from the underlying io.Reader.
func (r *AlignReader) ReadByte() (byte, error) {
	b := make([]byte, 1)
	_, err := io.ReadFull(r, b)
	return b[0], err
}

// Align aligns the reader to the given number of bytes and returns the
// bytes read to pad it.
func (r *AlignReader) Align(n int) ([]byte, error) {
	if r.N%n == 0 {
		return []byte{}, nil
	}
	pad := make([]byte, n-r.N%n)
	m, err := io.ReadFull(r, pad)
	return pad[:m], err
}
