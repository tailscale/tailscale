// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_qrcodes

// Package qrcodes provides functions to render or format QR codes.
package qrcodes

import (
	"fmt"
	"io"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// Fprintln formats s according to [Format] and writes a QR code to w, along
// with a newline. It returns the number of bytes written and any write error
// encountered.
func Fprintln(w io.Writer, format Format, s string) (n int, err error) {
	const inverse = false // Modern scanners can read QR codes of any colour.

	q, err := qrcode.New(s, qrcode.Medium)
	if err != nil {
		return 0, fmt.Errorf("QR code error: %w", err)
	}

	if format == FormatAuto {
		format, err = detectFormat(w, inverse)
		if err != nil {
			return 0, fmt.Errorf("QR code error: %w", err)
		}
	}

	var out string
	switch format {
	case FormatASCII:
		out = q.ToString(inverse)
		out = strings.ReplaceAll(out, "█", "#")
	case FormatLarge:
		out = q.ToString(inverse)
	case FormatSmall:
		out = q.ToSmallString(inverse)
	default:
		return 0, fmt.Errorf("unknown QR code format: %q", format)
	}

	return fmt.Fprintln(w, out)
}

// EncodePNG renders a QR code for s as a PNG, with a width and height of size
// pixels.
func EncodePNG(s string, size int) ([]byte, error) {
	q, err := qrcode.New(s, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	return q.PNG(size)
}
