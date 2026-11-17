// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derp

import (
	"bytes"
	"io"
)

// LoanedBytes is a packet payload lent to a callee for the duration of
// a call. The lender reuses the memory once the call returns, so the
// callee must not retain it; Clone gives it a copy to keep.
//
// It deliberately has no accessor for the underlying slice.
type LoanedBytes struct {
	bs []byte
}

// LoanBytes lends b for the duration of the call it's passed to.
func LoanBytes(b []byte) LoanedBytes { return LoanedBytes{bs: b} }

// Len returns the number of bytes.
func (b LoanedBytes) Len() int { return len(b.bs) }

// WriteTo writes the bytes to w.
func (b LoanedBytes) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(b.bs)
	return int64(n), err
}

// Clone returns a copy of the bytes that the caller owns.
func (b LoanedBytes) Clone() []byte { return bytes.Clone(b.bs) }
