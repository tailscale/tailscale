// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_qrcodes

package qrcodes

import "io"

func Fprintln(w io.Writer, format Format, s string) (n int, err error) {
	panic("omitted")
}

func EncodePNG(s string, size int) ([]byte, error) {
	panic("omitted")
}
