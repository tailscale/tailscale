// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_colorable

package cli

import (
	"io"
	"os"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
)

// colorableOutput returns a colorable writer if stdout is a terminal (not, say,
// redirected to a file or pipe), the Stdout writer is os.Stdout (we're not
// embedding the CLI in wasm or a mobile app), and NO_COLOR is not set (see
// https://no-color.org/). If any of those is not the case, ok is false
// and w is Stdout.
func colorableOutput() (w io.Writer, ok bool) {
	if Stdout != os.Stdout ||
		os.Getenv("NO_COLOR") != "" ||
		!isatty.IsTerminal(os.Stdout.Fd()) {
		return Stdout, false
	}
	return colorable.NewColorableStdout(), true
}
