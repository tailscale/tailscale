// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tailcfg

import "strings"

var separators = map[byte]bool{
	' ': true,
	'.': true,
	'@': true,
	'_': true,
}

func islower(c byte) bool {
	return 'a' <= c && c <= 'z'
}

func isupper(c byte) bool {
	return 'A' <= c && c <= 'Z'
}

func isalpha(c byte) bool {
	return islower(c) || isupper(c)
}

func isalphanum(c byte) bool {
	return isalpha(c) || ('0' <= c && c <= '9')
}

func isdnschar(c byte) bool {
	return isalphanum(c) || c == '-'
}

func tolower(c byte) byte {
	if isupper(c) {
		return c + 'a' - 'A'
	} else {
		return c
	}
}

// maxLabelLength is the maximal length of a label permitted by RFC 1035.
const maxLabelLength = 63

// SanitizeNameLabel takes a string intended to be a DNS name label
// and turns it into a valid name label according to RFC 1035.
func SanitizeNameLabel(label string) string {
	var sb strings.Builder
	start, end := 0, len(label)

	// This is technically stricter than necessary as some characters may be dropped,
	// but labels have no business being anywhere near this long in any case.
	if end > maxLabelLength {
		end = maxLabelLength
	}

	// A label must start with a letter...
	for ; start < end; start++ {
		if isalpha(label[start]) {
			break
		}
	}

	// ...and end with a letter or number.
	for ; start < end; end-- {
		// This is safe because (start < end) implies (end >= 1).
		if isalphanum(label[end-1]) {
			break
		}
	}

	for i := start; i < end; i++ {
		// Consume a separator only if we are not at a boundary:
		// then we can turn it into a hypen without breaking the rules.
		boundary := (i == start) || (i == end-1)
		if !boundary && separators[label[i]] {
			sb.WriteByte('-')
		} else if isdnschar(label[i]) {
			sb.WriteByte(tolower(label[i]))
		}
	}

	return sb.String()
}

// SanitizeName takes a string intended to be a DNS name
// and turns it into a valid name according to RFC 1035.
//
// All dots in the string are preserved, defining its division into labels,
// unless the string represents an email address,
// in which case the local part of the address is treated as a single label.
func SanitizeName(name string) string {
	// The local part may be a quoted string containing @, so we split on the last @.
	if idx := strings.LastIndexByte(name, '@'); idx != -1 {
		localPart := SanitizeNameLabel(name[:idx])
		domain := SanitizeName(name[idx+1:])
		return localPart + "." + domain
	}

	labels := strings.Split(name, ".")
	for i, label := range labels {
		labels[i] = SanitizeNameLabel(label)
	}

	return strings.Join(labels, ".")
}
