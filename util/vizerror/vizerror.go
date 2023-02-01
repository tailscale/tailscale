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

// New returns an error that formats as the given text. Always returns a vizerror.Error.
func New(text string) error {
	return Error{errors.New(text)}
}

// Errorf returns an Error with the specified format and values. Always returns a vizerror.Error.
func Errorf(format string, a ...any) error {
	return Error{fmt.Errorf(format, a...)}
}

// Unwrap returns the underlying error.
func (e Error) Unwrap() error {
	return e.err
}

// Wrap err with a vizerror.Error.
func Wrap(err error) error {
	if err == nil {
		return nil
	}
	return Error{err}
}
