// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package dnsname contains string functions for working with DNS names.
package dnsname

import (
	"strings"

	"tailscale.com/util/vizerror"
)

const (
	// maxLabelLength is the maximum length of a label permitted by RFC 1035.
	maxLabelLength = 63
	// maxNameLength is the maximum length of a DNS name.
	maxNameLength = 254
)

// A FQDN is a fully-qualified DNS name or name suffix.
type FQDN string

func ToFQDN(s string) (FQDN, error) {
	if len(s) == 0 || s == "." {
		return FQDN("."), nil
	}

	if s[0] == '.' {
		s = s[1:]
	}
	raw := s
	totalLen := len(s)
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	} else {
		totalLen += 1 // account for missing dot
	}
	if totalLen > maxNameLength {
		return "", vizerror.Errorf("%q is too long to be a DNS name", s)
	}

	st := 0
	for i := range len(s) {
		if s[i] != '.' {
			continue
		}
		label := s[st:i]
		// You might be tempted to do further validation of the
		// contents of labels here, based on the hostname rules in RFC
		// 1123. However, DNS labels are not always subject to
		// hostname rules. In general, they can contain any non-zero
		// byte sequence, even though in practice a more restricted
		// set is used.
		//
		// See https://github.com/tailscale/tailscale/issues/2024 for more.
		if len(label) == 0 || len(label) > maxLabelLength {
			return "", vizerror.Errorf("%q is not a valid DNS label", label)
		}
		st = i + 1
	}

	if raw[len(raw)-1] != '.' {
		raw = raw + "."
	}
	return FQDN(raw), nil
}

// WithTrailingDot returns f as a string, with a trailing dot.
func (f FQDN) WithTrailingDot() string {
	return string(f)
}

// WithoutTrailingDot returns f as a string, with the trailing dot
// removed.
func (f FQDN) WithoutTrailingDot() string {
	return string(f[:len(f)-1])
}

func (f FQDN) NumLabels() int {
	if f == "." {
		return 0
	}
	return strings.Count(f.WithTrailingDot(), ".")
}

func (f FQDN) Contains(other FQDN) bool {
	if f == other {
		return true
	}
	cmp := f.WithTrailingDot()
	if cmp != "." {
		cmp = "." + cmp
	}
	return strings.HasSuffix(other.WithTrailingDot(), cmp)
}

// ValidLabel reports whether label is a valid DNS label. All errors are
// [vizerror.Error].
func ValidLabel(label string) error {
	if len(label) == 0 {
		return vizerror.New("empty DNS label")
	}
	if len(label) > maxLabelLength {
		return vizerror.Errorf("%q is too long, max length is %d bytes", label, maxLabelLength)
	}
	if !isalphanum(label[0]) {
		return vizerror.Errorf("%q is not a valid DNS label: must start with a letter or number", label)
	}
	if !isalphanum(label[len(label)-1]) {
		return vizerror.Errorf("%q is not a valid DNS label: must end with a letter or number", label)
	}
	if len(label) < 2 {
		return nil
	}
	for i := 1; i < len(label)-1; i++ {
		if !isdnschar(label[i]) {
			return vizerror.Errorf("%q is not a valid DNS label: contains invalid character %q", label, label[i])
		}
	}
	return nil
}

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

// FirstLabel returns the first DNS label of hostname.
func FirstLabel(hostname string) string {
	first, _, _ := strings.Cut(hostname, ".")
	return first
}

// ValidHostname checks if a string is a valid hostname.
func ValidHostname(hostname string) error {
	fqdn, err := ToFQDN(hostname)
	if err != nil {
		return err
	}

	for _, label := range strings.Split(fqdn.WithoutTrailingDot(), ".") {
		if err := ValidLabel(label); err != nil {
			return err
		}
	}
	return nil
}

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
