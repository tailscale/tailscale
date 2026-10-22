// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || wasip1 || wasm

package neterror

import (
	"errors"
	"io"
	"io/fs"
)

// ReadWasAborted returns false on js/wasm/wasip1; it is a no-op here so that
// callers on other platforms can use it freely. See neterror_posix.go for
// the real implementation and its rationale.
func ReadWasAborted(err error) bool {
	return false
}

// Reports whether err resulted from reading or writing to a closed or broken pipe.
func IsClosedPipeError(err error) bool {
	// Libraries may also return root errors like fs.ErrClosed/io.ErrClosedPipe
	// due to a closed socket.
	return errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe)
}
