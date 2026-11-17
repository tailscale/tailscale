// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || wasip1 || wasm

package neterror

import (
	"errors"
	"io"
	"io/fs"
)

// Reports whether err resulted from reading or writing to a closed or broken pipe.
func IsClosedPipeError(err error) bool {
	// Libraries may also return root errors like fs.ErrClosed/io.ErrClosedPipe
	// due to a closed socket.
	return errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe)
}
