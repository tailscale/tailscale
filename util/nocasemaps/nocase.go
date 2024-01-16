// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// nocasemaps provides efficient functions to set and get entries in Go maps
// keyed by a string, where the string is always lower-case.
package nocasemaps

import (
	"unicode"
	"unicode/utf8"
)

// TODO(https://github.com/golang/go/discussions/54245):
// Define a generic Map type instead. The main reason to avoid that is because
// there is currently no convenient API for iteration.
// An opaque Map type would force callers to interact with the map through
// the methods, preventing accidental interactions with the underlying map
// without using functions in this package.

const stackArraySize = 32

// Get is equivalent to:
//
//	v := m[strings.ToLower(k)]
func Get[K ~string, V any](m map[K]V, k K) V {
	if isLowerASCII(string(k)) {
		return m[k]
	}
	var a [stackArraySize]byte
	return m[K(appendToLower(a[:0], string(k)))]
}

// GetOk is equivalent to:
//
//	v, ok := m[strings.ToLower(k)]
func GetOk[K ~string, V any](m map[K]V, k K) (V, bool) {
	if isLowerASCII(string(k)) {
		v, ok := m[k]
		return v, ok
	}
	var a [stackArraySize]byte
	v, ok := m[K(appendToLower(a[:0], string(k)))]
	return v, ok
}

// Set is equivalent to:
//
//	m[strings.ToLower(k)] = v
func Set[K ~string, V any](m map[K]V, k K, v V) {
	if isLowerASCII(string(k)) {
		m[k] = v
		return
	}
	// TODO(https://go.dev/issues/55930): This currently always allocates.
	// An optimization to the compiler and runtime could make this allocate-free
	// in the event that we are overwriting a map entry.
	//
	// Alternatively, we could use string interning.
	// See an example intern data structure, see:
	//	https://github.com/go-json-experiment/json/blob/master/intern.go
	var a [stackArraySize]byte
	m[K(appendToLower(a[:0], string(k)))] = v
}

// Delete is equivalent to:
//
//	delete(m, strings.ToLower(k))
func Delete[K ~string, V any](m map[K]V, k K) {
	if isLowerASCII(string(k)) {
		delete(m, k)
		return
	}
	var a [stackArraySize]byte
	delete(m, K(appendToLower(a[:0], string(k))))
}

// AppendSliceElem is equivalent to:
//
//	append(m[strings.ToLower(k)], v)
func AppendSliceElem[K ~string, S []E, E any](m map[K]S, k K, vs ...E) {
	// if the key is already lowercased
	if isLowerASCII(string(k)) {
		m[k] = append(m[k], vs...)
		return
	}

	// if key needs to become lowercase, uses appendToLower
	var a [stackArraySize]byte
	s := appendToLower(a[:0], string(k))
	m[K(s)] = append(m[K(s)], vs...)
}

func isLowerASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= utf8.RuneSelf || ('A' <= c && c <= 'Z') {
			return false
		}
	}
	return true
}

func appendToLower(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'A' <= c && c <= 'Z':
			b = append(b, c+('a'-'A'))
		case c < utf8.RuneSelf:
			b = append(b, c)
		default:
			r, n := utf8.DecodeRuneInString(s[i:])
			b = utf8.AppendRune(b, unicode.ToLower(r))
			i += n - 1 // -1 to compensate for i++ in loop advancement
		}
	}
	return b
}
