// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hujson

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

func lineColumn(b []byte, n int) (line, column int) {
	line = 1 + bytes.Count(b[:n], []byte("\n"))
	column = 1 + n - (bytes.LastIndexByte(b[:n], '\n') + len("\n"))
	return line, column
}

// Parse parses a HuJSON value as a Value.
// Extra and Literal values in v will alias the provided input buffer.
func Parse(b []byte) (Value, error) {
	v, n, err := parseNext(0, b)
	if err == nil && n < len(b) {
		err = fmt.Errorf("invalid character %q after top-level value", b[n])
	}
	if err != nil {
		line, column := lineColumn(b, n)
		err = fmt.Errorf("hujson: line %d, column %d: %w", line, column, err)
		return v, err
	}
	return v, nil
}

// parseNext parses the next value with surrounding whitespace and comments.
func parseNext(n int, b []byte) (v Value, _ int, err error) {
	n0 := n

	// Consume leading whitespace and comments.
	if n, err = consumeExtra(n, b); err != nil {
		return v, n, err
	}
	if n > n0 {
		v.BeforeExtra = b[n0:n:n]
	}

	// Parse the next value.
	v.StartOffset = n
	if v.Value, n, err = parseNextTrimmed(n, b); err != nil {
		return v, n, err
	}
	v.EndOffset = n

	// Consume trailing whitespace and comments.
	if n, err = consumeExtra(n, b); err != nil {
		return v, n, err
	}
	if n > v.EndOffset {
		v.AfterExtra = b[v.EndOffset:n:n]
	}

	return v, n, nil
}

var (
	errInvalidObjectEnd = errors.New("invalid character '}' at start of value")
	errInvalidArrayEnd  = errors.New("invalid character ']' at start of value")
)

// parseNextTrimmed parses the next value without surrounding whitespace and comments.
func parseNextTrimmed(n int, b []byte) (ValueTrimmed, int, error) {
	if len(b) == n {
		return nil, n, fmt.Errorf("parsing value: %w", io.ErrUnexpectedEOF)
	}
	switch b[n] {
	// Parse objects.
	case '{':
		n++
		var obj Object
		for {
			var vk, vv Value
			var err error

			// Parse the name.
			if vk, n, err = parseNext(n, b); err != nil {
				if err == errInvalidObjectEnd && vk.Value == nil {
					setTrailingComma(&obj, len(obj.Members) > 0)
					obj.AfterExtra = vk.BeforeExtra
					return &obj, n + len(`}`), nil
				}
				return &obj, n, err
			}
			if vk.Value.Kind() != '"' {
				return &obj, vk.StartOffset, fmt.Errorf("invalid character %q at start of object name", b[vk.StartOffset])
			}

			// Parse the colon.
			switch {
			case len(b) == n:
				return &obj, n, fmt.Errorf("parsing object after name: %w", io.ErrUnexpectedEOF)
			case b[n] != ':':
				return &obj, n, fmt.Errorf("invalid character %q after object name", b[n])
			}
			n++

			// Parse the value.
			if vv, n, err = parseNext(n, b); err != nil {
				return &obj, n, err
			}

			obj.Members = append(obj.Members, ObjectMember{vk, vv})
			switch {
			case len(b) == n:
				return &obj, n, fmt.Errorf("parsing object after value: %w", io.ErrUnexpectedEOF)
			case b[n] == ',':
				n++
			case b[n] == '}':
				// Move AfterExtra from last value to AfterExtra of the object.
				obj.AfterExtra = obj.Members[len(obj.Members)-1].Value.AfterExtra
				obj.Members[len(obj.Members)-1].Value.AfterExtra = nil
				return &obj, n + len(`}`), nil
			default:
				return &obj, n, fmt.Errorf("invalid character %q after object value (expecting ',' or '}')", b[n])
			}
		}
	case '}':
		return nil, n, errInvalidObjectEnd

	// Parse arrays.
	case '[':
		n++
		var arr Array
		for {
			var v Value
			var err error
			if v, n, err = parseNext(n, b); err != nil {
				if err == errInvalidArrayEnd && v.Value == nil {
					setTrailingComma(&arr, len(arr.Elements) > 0)
					arr.AfterExtra = v.BeforeExtra
					return &arr, n + len(`]`), nil
				}
				return &arr, n, err
			}
			arr.Elements = append(arr.Elements, v)
			switch {
			case len(b) == n:
				return &arr, n, fmt.Errorf("parsing array after value: %w", io.ErrUnexpectedEOF)
			case b[n] == ',':
				n++
			case b[n] == ']':
				// Move AfterExtra from last value to AfterExtra of the array.
				arr.AfterExtra = arr.Elements[len(arr.Elements)-1].AfterExtra
				arr.Elements[len(arr.Elements)-1].AfterExtra = nil
				return &arr, n + len(`]`), nil
			default:
				return &arr, n, fmt.Errorf("invalid character %q after array value (expecting ',' or ']')", b[n])
			}
		}
	case ']':
		return nil, n, errInvalidArrayEnd

	// Parse strings.
	case '"':
		n0 := n
		n++
		var inEscape bool
		for {
			switch {
			case len(b) == n:
				return nil, n, fmt.Errorf("parsing string: %w", io.ErrUnexpectedEOF)
			case inEscape:
				inEscape = false
			case b[n] == '\\':
				inEscape = true
			case b[n] == '"':
				n++
				lit := Literal(b[n0:n:n])
				if !lit.IsValid() {
					return nil, n0, fmt.Errorf("invalid literal: %s", lit)
				}
				return lit, n, nil
			}
			n++
		}

	// Parse null, booleans, and numbers.
	default:
		n0 := n
		for len(b) > n && (b[n] == '-' || b[n] == '+' || b[n] == '.' ||
			('a' <= b[n] && b[n] <= 'z') ||
			('A' <= b[n] && b[n] <= 'Z') ||
			('0' <= b[n] && b[n] <= '9')) {
			n++
		}
		switch lit := Literal(b[n0:n:n]); {
		case len(lit) == 0:
			return nil, n0, fmt.Errorf("invalid character %q at start of value", b[n0])
		case !lit.IsValid():
			return nil, n0, fmt.Errorf("invalid literal: %s", lit)
		default:
			return lit, n, nil
		}
	}
}

var (
	lineCommentStart  = []byte("//")
	lineCommentEnd    = []byte("\n")
	blockCommentStart = []byte("/*")
	blockCommentEnd   = []byte("*/")
)

// consumeExtra consumes leading whitespace and comments.
func consumeExtra(n int, b []byte) (int, error) {
	for len(b) > n {
		switch b[n] {
		// Skip past whitespace.
		case ' ', '\t', '\r', '\n':
			n += consumeWhitespace(b[n:])
		// Skip past comments.
		case '/':
			switch nc := consumeComment(b[n:]); {
			case nc == 0:
				return n, nil
			case nc < 0:
				return n, fmt.Errorf("parsing comment: %w", io.ErrUnexpectedEOF)
			case !utf8.Valid(b[n : n+nc]):
				return n, fmt.Errorf("invalid UTF-8 in comment")
			default:
				n += nc
			}
		default:
			return n, nil
		}
	}
	return n, nil
}

func consumeWhitespace(b []byte) (n int) {
	for len(b) > n && (b[n] == ' ' || b[n] == '\t' || b[n] == '\r' || b[n] == '\n') {
		n++
	}
	return n
}

// consumeComment consumes a line or block comment start in b.
// It returns the length of the comment if valid, otherwise
// it returns 0 if it is not a comment and -1 if it is invalid.
func consumeComment(b []byte) (n int) {
	var start, end []byte
	switch {
	case bytes.HasPrefix(b, lineCommentStart):
		start, end = lineCommentStart, lineCommentEnd
	case bytes.HasPrefix(b, blockCommentStart):
		start, end = blockCommentStart, blockCommentEnd
	default:
		return 0
	}
	i := bytes.Index(b[len(start):], end)
	if i < 0 {
		return -1
	}
	return len(start) + i + len(end)
}
