// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"tailscale.com/util/slicesx"
)

func formatMaybePrintable(b []byte) string {
	// Remove a single trailing null, if any.
	if slicesx.LastEqual(b, 0) {
		b = b[:len(b)-1]
	}

	nonprintable := strings.IndexFunc(string(b), func(r rune) bool {
		return r > unicode.MaxASCII || !unicode.IsPrint(r)
	})
	if nonprintable >= 0 {
		return "<hex>" + hex.EncodeToString(b)
	}
	return string(b)
}

func formatPortRange(r [2]uint16) string {
	if r == [2]uint16{0, 65535} {
		return fmt.Sprintf(`any`)
	} else if r[0] == r[1] {
		return fmt.Sprintf(`%d`, r[0])
	}
	return fmt.Sprintf(`%d-%d`, r[0], r[1])
}
