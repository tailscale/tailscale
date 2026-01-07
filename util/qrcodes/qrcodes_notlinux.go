// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !ts_omit_qrcodes

package qrcodes

import "io"

func detectFormat(w io.Writer, inverse bool) (Format, error) {
	// Assume all terminals can support the full set of UTF-8 block
	// characters: (█, ▀, ▄). See tailscale/tailscale#12935.
	return FormatSmall, nil
}
