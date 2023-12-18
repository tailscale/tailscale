// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package opt defines optional types.
package opt

import (
	"fmt"
	"strconv"
)

// Bool represents an optional boolean to be JSON-encoded.  The string
// is either "true", "false", or the empty string to mean unset.
//
// As a special case, the underlying string may also be the string
// "unset" as as a synonym for the empty string. This lets the
// explicit unset value be exchanged over an encoding/json "omitempty"
// field without it being dropped.
type Bool string

// NewBool constructs a new Bool value equal to b. The returned Bool is set,
// unless Set("") or Clear() methods are called.
func NewBool(b bool) Bool {
	return Bool(strconv.FormatBool(b))
}

func (b *Bool) Set(v bool) {
	*b = Bool(strconv.FormatBool(v))
}

func (b *Bool) Clear() { *b = "" }

func (b Bool) Get() (v bool, ok bool) {
	switch b {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// Scan implements database/sql.Scanner.
func (b *Bool) Scan(src any) error {
	if src == nil {
		*b = ""
		return nil
	}
	switch src := src.(type) {
	case bool:
		if src {
			*b = "true"
		} else {
			*b = "false"
		}
		return nil
	case int64:
		if src == 0 {
			*b = "false"
		} else {
			*b = "true"
		}
		return nil
	default:
		return fmt.Errorf("opt.Bool.Scan: invalid type %T: %v", src, src)
	}
}

// EqualBool reports whether b is equal to v.
// If b is empty or not a valid bool, it reports false.
func (b Bool) EqualBool(v bool) bool {
	p, ok := b.Get()
	return ok && p == v
}

var (
	trueBytes  = []byte("true")
	falseBytes = []byte("false")
	nullBytes  = []byte("null")
)

func (b Bool) MarshalJSON() ([]byte, error) {
	switch b {
	case "true":
		return trueBytes, nil
	case "false":
		return falseBytes, nil
	case "", "unset":
		return nullBytes, nil
	}
	return nil, fmt.Errorf("invalid opt.Bool value %q", string(b))
}

func (b *Bool) UnmarshalJSON(j []byte) error {
	switch string(j) {
	case "true":
		*b = "true"
	case "false":
		*b = "false"
	case "null":
		*b = "unset"
	default:
		return fmt.Errorf("invalid opt.Bool value %q", j)
	}
	return nil
}
