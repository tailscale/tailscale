// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package opt defines optional types.
package opt

import (
	"fmt"
	"strconv"
)

// Bool represents an optional boolean to be JSON-encoded.
// The string can be empty (for unknown or unspecified), or
// "true" or "false".
type Bool string

func (b *Bool) Set(v bool) {
	*b = Bool(strconv.FormatBool(v))
}

func (b *Bool) Clear() { *b = "" }

func (b Bool) Get() (v bool, ok bool) {
	if b == "" {
		return
	}
	v, err := strconv.ParseBool(string(b))
	return v, err == nil
}

func (b Bool) And(v bool) Bool {
	if v {
		return b
	}
	return "false"
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
	case "":
		return nullBytes, nil
	}
	return nil, fmt.Errorf("invalid opt.Bool value %q", string(b))
}

func (b *Bool) UnmarshalJSON(j []byte) error {
	// Note: written with a bunch of ifs instead of a switch
	// because I'm sure the Go compiler optimizes away these
	// []byte->string allocations in an == comparison, but I'm too
	// lazy to check whether that's true in a switch also.
	if string(j) == "true" {
		*b = "true"
		return nil
	}
	if string(j) == "false" {
		*b = "false"
		return nil
	}
	if string(j) == "null" {
		*b = ""
		return nil
	}
	return fmt.Errorf("invalid opt.Bool value %q", j)
}
