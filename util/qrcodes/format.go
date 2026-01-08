// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package qrcodes

// Format selects the text representation used to print QR codes.
type Format string

const (
	// FormatAuto will format QR codes to best fit the capabilities of the
	// [io.Writer].
	FormatAuto Format = "auto"

	// FormatASCII will format QR codes with only ASCII characters.
	FormatASCII Format = "ascii"

	// FormatLarge will format QR codes with full block characters.
	FormatLarge Format = "large"

	// FormatSmall will format QR codes with full and half block characters.
	FormatSmall Format = "small"
)
