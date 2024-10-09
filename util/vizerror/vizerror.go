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
	err         error
	internalErr error
}

// Error implements the error interface.
func (e Error) Error() string {
	return e.err.Error()
}

// InternalError returns the internal error that should not be shown to end
// users. It will be nil if the user-visible error was not constructed using
// WithInternal.
func (e Error) InternalError() error {
	return e.internalErr
}

// New returns an error that formats as the given text. It always returns a vizerror.Error.
func New(text string) error {
	return Error{err: errors.New(text)}
}

// Errorf returns an Error with the specified format and values. It always returns a vizerror.Error.
func Errorf(format string, a ...any) error {
	return Error{err: fmt.Errorf(format, a...)}
}

// Unwrap returns the underlying error.
func (e Error) Unwrap() error {
	return e.err
}

// Wrap wraps err with a vizerror.Error.
//
// Deprecated: this is almost always the wrong thing to do. Are you really sure
// you know exactly what err.Error() will stringify to and be safe to show to
// users?
func Wrap(err error) error {
	if err == nil {
		return nil
	}
	return Error{err: err}
}

// As returns the first vizerror.Error in err's chain.
func As(err error) (e Error, ok bool) {
	ok = errors.As(err, &e)
	return
}

// WithInternal returns a new ErrorWithInternal combining a user-visible error
// string and an internal error to pass around for internal logging but not
// to be shown to end users.
func WithInternal(visibleError string, internalErr error) error {
	return Error{err: errors.New(visibleError), internalErr: internalErr}
}
