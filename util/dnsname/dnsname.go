// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnsname contains string functions for working with DNS names.
package dnsname

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

// SanitizeLabel takes a string intended to be a DNS name label
// and turns it into a valid name label according to RFC 1035.
func SanitizeLabel(label string) string {
	var sb strings.Builder // TODO: don't allocate in common case where label is already fine
	start, end := 0, len(label)

	// This is technically stricter than necessary as some characters may be dropped,
	// but labels have no business being anywhere near this long in any case.
	if end > maxLabelLength {
		end = maxLabelLength
	}

	// A label must start with a letter or number...
	for ; start < end; start++ {
		if isalphanum(label[start]) {
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
		// then we can turn it into a hyphen without breaking the rules.
		boundary := (i == start) || (i == end-1)
		if !boundary && separators[label[i]] {
			sb.WriteByte('-')
		} else if isdnschar(label[i]) {
			sb.WriteByte(tolower(label[i]))
		}
	}

	return sb.String()
}

// HasSuffix reports whether the provided name ends with the
// component(s) in suffix, ignoring any trailing or leading dots.
//
// If suffix is the empty string, HasSuffix always reports false.
func HasSuffix(name, suffix string) bool {
	name = strings.TrimSuffix(name, ".")
	suffix = strings.TrimSuffix(suffix, ".")
	suffix = strings.TrimPrefix(suffix, ".")
	nameBase := strings.TrimSuffix(name, suffix)
	return len(nameBase) < len(name) && strings.HasSuffix(nameBase, ".")
}

// TrimSuffix trims any trailing dots from a name and removes the
// suffix ending if present. The name will never be returned with
// a trailing dot, even after trimming.
func TrimSuffix(name, suffix string) string {
	if HasSuffix(name, suffix) {
		name = strings.TrimSuffix(name, ".")
		suffix = strings.Trim(suffix, ".")
		name = strings.TrimSuffix(name, suffix)
	}
	return strings.TrimSuffix(name, ".")
}

// TrimCommonSuffixes returns hostname with some common suffixes removed.
func TrimCommonSuffixes(hostname string) string {
	hostname = strings.TrimSuffix(hostname, ".local")
	hostname = strings.TrimSuffix(hostname, ".localdomain")
	hostname = strings.TrimSuffix(hostname, ".lan")
	return hostname
}

// SanitizeHostname turns hostname into a valid name label according
// to RFC 1035.
func SanitizeHostname(hostname string) string {
	hostname = TrimCommonSuffixes(hostname)
	return SanitizeLabel(hostname)
}

// NumLabels returns the number of DNS labels in hostname.
// If hostname is empty or the top-level name ".", returns 0.
func NumLabels(hostname string) int {
	if hostname == "" || hostname == "." {
		return 0
	}
	return strings.Count(hostname, ".")
}
