// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package httphdr implements functionality for parsing and formatting
// standard HTTP headers.
package httphdr

import (
	"bytes"
	"strconv"
	"strings"
)

// Range is a range of bytes within some content.
type Range struct {
	// Start is the starting offset.
	// It is zero if Length is negative; it must not be negative.
	Start int64
	// Length is the length of the content.
	// It is zero if the length extends to the end of the content.
	// It is negative if the length is relative to the end (e.g., last 5 bytes).
	Length int64
}

// ows is optional whitespace.
const ows = " \t" // per RFC 7230, section 3.2.3

// ParseRange parses a "Range" header per RFC 7233, section 3.
// It only handles "Range" headers where the units is "bytes".
// The "Range" header is usually only specified in GET requests.
func ParseRange(hdr string) (ranges []Range, ok bool) {
	// Grammar per RFC 7233, appendix D:
	//	Range = byte-ranges-specifier | other-ranges-specifier
	//	byte-ranges-specifier = bytes-unit "=" byte-range-set
	//	bytes-unit = "bytes"
	//	byte-range-set =
	//		*("," OWS)
	//		(byte-range-spec | suffix-byte-range-spec)
	//		*(OWS "," [OWS ( byte-range-spec | suffix-byte-range-spec )])
	//	byte-range-spec = first-byte-pos "-" [last-byte-pos]
	//	suffix-byte-range-spec = "-" suffix-length
	// We do not support other-ranges-specifier.
	// All other identifiers are 1*DIGIT.
	hdr = strings.Trim(hdr, ows) // per RFC 7230, section 3.2
	units, elems, hasUnits := strings.Cut(hdr, "=")
	elems = strings.TrimLeft(elems, ","+ows)
	for _, elem := range strings.Split(elems, ",") {
		elem = strings.Trim(elem, ows) // per RFC 7230, section 7
		switch {
		case strings.HasPrefix(elem, "-"): // i.e., "-" suffix-length
			n, ok := parseNumber(strings.TrimPrefix(elem, "-"))
			if !ok {
				return ranges, false
			}
			ranges = append(ranges, Range{0, -n})
		case strings.HasSuffix(elem, "-"): // i.e., first-byte-pos "-"
			n, ok := parseNumber(strings.TrimSuffix(elem, "-"))
			if !ok {
				return ranges, false
			}
			ranges = append(ranges, Range{n, 0})
		default: // i.e., first-byte-pos "-" last-byte-pos
			prefix, suffix, hasDash := strings.Cut(elem, "-")
			n, ok2 := parseNumber(prefix)
			m, ok3 := parseNumber(suffix)
			if !hasDash || !ok2 || !ok3 || m < n {
				return ranges, false
			}
			ranges = append(ranges, Range{n, m - n + 1})
		}
	}
	return ranges, units == "bytes" && hasUnits && len(ranges) > 0 // must see at least one element per RFC 7233, section 2.1
}

// FormatRange formats a "Range" header per RFC 7233, section 3.
// It only handles "Range" headers where the units is "bytes".
// The "Range" header is usually only specified in GET requests.
func FormatRange(ranges []Range) (hdr string, ok bool) {
	b := []byte("bytes=")
	for _, r := range ranges {
		switch {
		case r.Length > 0: // i.e., first-byte-pos "-" last-byte-pos
			if r.Start < 0 {
				return string(b), false
			}
			b = strconv.AppendUint(b, uint64(r.Start), 10)
			b = append(b, '-')
			b = strconv.AppendUint(b, uint64(r.Start+r.Length-1), 10)
			b = append(b, ',')
		case r.Length == 0: // i.e., first-byte-pos "-"
			if r.Start < 0 {
				return string(b), false
			}
			b = strconv.AppendUint(b, uint64(r.Start), 10)
			b = append(b, '-')
			b = append(b, ',')
		case r.Length < 0: // i.e., "-" suffix-length
			if r.Start != 0 {
				return string(b), false
			}
			b = append(b, '-')
			b = strconv.AppendUint(b, uint64(-r.Length), 10)
			b = append(b, ',')
		default:
			return string(b), false
		}
	}
	return string(bytes.TrimRight(b, ",")), len(ranges) > 0
}

// ParseContentRange parses a "Content-Range" header per RFC 7233, section 4.2.
// It only handles "Content-Range" headers where the units is "bytes".
// The "Content-Range" header is usually only specified in HTTP responses.
//
// If only the completeLength is specified, then start and length are both zero.
//
// Otherwise, the parses the start and length and the optional completeLength,
// which is -1 if unspecified. The start is non-negative and the length is positive.
func ParseContentRange(hdr string) (start, length, completeLength int64, ok bool) {
	// Grammar per RFC 7233, appendix D:
	//	Content-Range = byte-content-range | other-content-range
	//	byte-content-range = bytes-unit SP (byte-range-resp | unsatisfied-range)
	//	bytes-unit = "bytes"
	//	byte-range-resp = byte-range "/" (complete-length | "*")
	//	unsatisfied-range = "*/" complete-length
	//	byte-range = first-byte-pos "-" last-byte-pos
	// We do not support other-content-range.
	// All other identifiers are 1*DIGIT.
	hdr = strings.Trim(hdr, ows) // per RFC 7230, section 3.2
	suffix, hasUnits := strings.CutPrefix(hdr, "bytes ")
	suffix, unsatisfied := strings.CutPrefix(suffix, "*/")
	if unsatisfied { // i.e., unsatisfied-range
		n, ok := parseNumber(suffix)
		if !ok {
			return start, length, completeLength, false
		}
		completeLength = n
	} else { // i.e., byte-range "/" (complete-length | "*")
		prefix, suffix, hasDash := strings.Cut(suffix, "-")
		middle, suffix, hasSlash := strings.Cut(suffix, "/")
		n, ok0 := parseNumber(prefix)
		m, ok1 := parseNumber(middle)
		o, ok2 := parseNumber(suffix)
		if suffix == "*" {
			o, ok2 = -1, true
		}
		if !hasDash || !hasSlash || !ok0 || !ok1 || !ok2 || m < n || (o >= 0 && o <= m) {
			return start, length, completeLength, false
		}
		start = n
		length = m - n + 1
		completeLength = o
	}
	return start, length, completeLength, hasUnits
}

// FormatContentRange parses a "Content-Range" header per RFC 7233, section 4.2.
// It only handles "Content-Range" headers where the units is "bytes".
// The "Content-Range" header is usually only specified in HTTP responses.
//
// If start and length are non-positive, then it encodes just the completeLength,
// which must be a non-negative value.
//
// Otherwise, it encodes the start and length as a byte-range,
// and optionally emits the complete length if it is non-negative.
// The length must be positive (as RFC 7233 uses inclusive end offsets).
func FormatContentRange(start, length, completeLength int64) (hdr string, ok bool) {
	b := []byte("bytes ")
	switch {
	case start <= 0 && length <= 0 && completeLength >= 0: // i.e., unsatisfied-range
		b = append(b, "*/"...)
		b = strconv.AppendUint(b, uint64(completeLength), 10)
		ok = true
	case start >= 0 && length > 0: // i.e., byte-range "/" (complete-length | "*")
		b = strconv.AppendUint(b, uint64(start), 10)
		b = append(b, '-')
		b = strconv.AppendUint(b, uint64(start+length-1), 10)
		b = append(b, '/')
		if completeLength >= 0 {
			b = strconv.AppendUint(b, uint64(completeLength), 10)
			ok = completeLength >= start+length && start+length > 0
		} else {
			b = append(b, '*')
			ok = true
		}
	}
	return string(b), ok
}

// parseNumber parses s as an unsigned decimal integer.
// It parses according to the 1*DIGIT grammar, which allows leading zeros.
func parseNumber(s string) (int64, bool) {
	suffix := strings.TrimLeft(s, "0123456789")
	prefix := s[:len(s)-len(suffix)]
	n, err := strconv.ParseInt(prefix, 10, 64)
	return n, suffix == "" && err == nil
}
