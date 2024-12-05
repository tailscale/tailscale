// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

// This code is only used in Windows builds, but is in an
// OS-independent file so tests can run all the time.

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// maybeUnUTF16 tries to detect whether bs contains UTF-16, and if so
// translates it to regular UTF-8.
//
// Some of wsl.exe's output get printed as UTF-16, which breaks a
// bunch of things. Try to detect this by looking for a zero byte in
// the first few bytes of output (which will appear if any of those
// codepoints are basic ASCII - very likely). From that we can infer
// that UTF-16 is being printed, and the byte order in use, and we
// decode that back to UTF-8.
//
// https://github.com/microsoft/WSL/issues/4607
func maybeUnUTF16(bs []byte) []byte {
	if len(bs)%2 != 0 {
		// Can't be complete UTF-16.
		return bs
	}
	checkLen := 20
	if len(bs) < checkLen {
		checkLen = len(bs)
	}
	zeroOff := bytes.IndexByte(bs[:checkLen], 0)
	if zeroOff == -1 {
		return bs
	}

	// We assume wsl.exe is trying to print an ASCII codepoint,
	// meaning the zero byte is in the upper 8 bits of the
	// codepoint. That means we can use the zero's byte offset to
	// work out if we're seeing little-endian or big-endian
	// UTF-16.
	var endian binary.ByteOrder = binary.LittleEndian
	if zeroOff%2 == 0 {
		endian = binary.BigEndian
	}

	var u16 []uint16
	for i := 0; i < len(bs); i += 2 {
		u16 = append(u16, endian.Uint16(bs[i:]))
	}
	return []byte(string(utf16.Decode(u16)))
}
