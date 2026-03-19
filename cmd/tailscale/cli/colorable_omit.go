// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_colorable

package cli

import "io"

func colorableOutput() (w io.Writer, ok bool) {
	return Stdout, false
}
