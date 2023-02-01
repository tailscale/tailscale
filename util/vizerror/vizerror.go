// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package vizerror provides types and utility funcs for handling visible errors
// that are safe to display to end users.
package vizerror

import (
	"errors"
	"fmt"
)

// Error is an error that is safe to display to end users.
type Error struct {
	err error
}

// Error implements the error interface.
func (e Error) Error() string {
	return e.err.Error()
}

// New returns an Error that formats as the given text.
func New(text string) Error {
	return Error{errors.New(text)}
}

// Errorf returns an Error with the specified format and values.
func Errorf(format string, a ...any) Error {
	return Error{fmt.Errorf(format, a...)}
}

// Unwrap returns the underlying error.
func (e Error) Unwrap() error {
	return e.err
}

// Wrap err with a vizerror.Error.
func Wrap(err error) Error {
	return Error{err}
}
