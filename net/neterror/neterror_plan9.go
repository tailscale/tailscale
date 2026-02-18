// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build plan9

package neterror

import (
	"errors"
	"io"
	"io/fs"
	"strings"
)

// Reports whether err resulted from reading or writing to a closed or broken pipe.
func IsClosedPipeError(err error) bool {
	// Libraries may also return root errors like fs.ErrClosed/io.ErrClosedPipe
	// due to a closed socket.
	// For a raw syscall error, check for error string containing "closed pipe",
	// per the note set by the system: https://9p.io/magic/man2html/2/pipe
	return errors.Is(err, fs.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) ||
		strings.Contains(err.Error(), "closed pipe")
}
