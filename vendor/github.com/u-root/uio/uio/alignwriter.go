// Copyright 2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uio

import (
	"bytes"
	"io"
)

// AlignWriter keeps track of how many bytes were written so the writer can be
// aligned at a future time.
type AlignWriter struct {
	W io.Writer
	N int
}

// Write writes to the underlying io.Writew.
func (w *AlignWriter) Write(b []byte) (int, error) {
	n, err := w.W.Write(b)
	w.N += n
	return n, err
}

// Align aligns the writer to the given number of bytes using the given pad
// value.
func (w *AlignWriter) Align(n int, pad byte) error {
	if w.N%n == 0 {
		return nil
	}
	_, err := w.Write(bytes.Repeat([]byte{pad}, n-w.N%n))
	return err
}
