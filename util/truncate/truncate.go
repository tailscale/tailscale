// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package truncate provides a utility function for safely truncating UTF-8
// strings to a fixed length, respecting multi-byte codepoints.
package truncate

// String returns a prefix of a UTF-8 string s, having length no greater than n
// bytes. If s exceeds this length, it is truncated at a point ≤ n so that the
// result does not end in a partial UTF-8 encoding.  If s is less than or equal
// to this length, it is returned unmodified.
func String[String ~string | ~[]byte](s String, n int) String {
	if n >= len(s) {
		return s
	}

	// Back up until we find the beginning of a UTF-8 encoding.
	for n > 0 && s[n-1]&0xc0 == 0x80 { // 0x10... is a continuation byte
		n--
	}

	// If we're at the beginning of a multi-byte encoding, back up one more to
	// skip it. It's possible the value was already complete, but it's simpler
	// if we only have to check in one direction.
	//
	// Otherwise, we have a single-byte code (0x00... or 0x01...).
	if n > 0 && s[n-1]&0xc0 == 0xc0 { // 0x11... starts a multibyte encoding
		n--
	}
	return s[:n]
}
