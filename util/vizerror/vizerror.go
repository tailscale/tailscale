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
	publicErr error // visible to end users
	wrapped   error // internal
}

// Error implements the error interface. The returned string is safe to display
// to end users.
func (e Error) Error() string {
	return e.publicErr.Error()
}

// New returns an error that formats as the given text. It always returns a vizerror.Error.
func New(publicMsg string) error {
	err := errors.New(publicMsg)
	return Error{
		publicErr: err,
		wrapped:   err,
	}
}

// Errorf returns an Error with the specified publicMsgFormat and values. It always returns a vizerror.Error.
//
// Warning: avoid using an error as one of the format arguments, as this will cause the text
// of that error to be displayed to the end user (which is probably not what you want).
func Errorf(publicMsgFormat string, a ...any) error {
	err := fmt.Errorf(publicMsgFormat, a...)
	return Error{
		publicErr: err,
		wrapped:   err,
	}
}

// Unwrap returns the underlying error.
//
// If the Error was constructed using [WrapWithMessage], this is the wrapped (internal) error
// and not the user-visible error message.
func (e Error) Unwrap() error {
	return e.wrapped
}

// Wrap wraps publicErr with a vizerror.Error.
//
// Deprecated: this is almost always the wrong thing to do. Are you really sure
// you know exactly what err.Error() will stringify to and be safe to show to
// users? [WrapWithMessage] is probably what you want.
func Wrap(publicErr error) error {
	if publicErr == nil {
		return nil
	}
	return Error{publicErr: publicErr, wrapped: publicErr}
}

// WrapWithMessage wraps the given error with a message that's safe to display
// to end users. The text of the wrapped error will not be displayed to end
// users.
//
// WrapWithMessage should almost always be preferred to [Wrap].
func WrapWithMessage(wrapped error, publicMsg string) error {
	return Error{
		publicErr: errors.New(publicMsg),
		wrapped:   wrapped,
	}
}

// As returns the first vizerror.Error in err's chain.
func As(err error) (e Error, ok bool) {
	ok = errors.As(err, &e)
	return
}
