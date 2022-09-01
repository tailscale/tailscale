// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package multierr provides a simple multiple-error type.
// It was inspired by github.com/go-multierror/multierror.
package multierr

import (
	"errors"
	"strings"
)

// An Error represents multiple errors.
type Error struct {
	errs []error
}

// Error implements the error interface.
func (e Error) Error() string {
	s := new(strings.Builder)
	s.WriteString("multiple errors:")
	for _, err := range e.errs {
		s.WriteString("\n\t")
		s.WriteString(err.Error())
	}
	return s.String()
}

// Errors returns a slice containing all errors in e.
func (e Error) Errors() []error {
	return append(e.errs[:0:0], e.errs...)
}

// New returns an error composed from errs.
// Some errors in errs get special treatment:
//   - nil errors are discarded
//   - errors of type Error are expanded into the top level
//
// If the resulting slice has length 0, New returns nil.
// If the resulting slice has length 1, New returns that error.
// If the resulting slice has length > 1, New returns that slice as an Error.
func New(errs ...error) error {
	dst := make([]error, 0, len(errs))
	for _, e := range errs {
		switch e := e.(type) {
		case nil:
			continue
		case Error:
			dst = append(dst, e.errs...)
		default:
			dst = append(dst, e)
		}
	}
	// dst has been filtered and splatted.
	switch len(dst) {
	case 0:
		return nil
	case 1:
		return dst[0]
	}
	// Zero any remaining elements of dst left over from errs, for GC.
	tail := dst[len(dst):cap(dst)]
	for i := range tail {
		tail[i] = nil
	}
	return Error{errs: dst}
}

// Is reports whether any error in e matches target.
func (e Error) Is(target error) bool {
	for _, err := range e.errs {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// As finds the first error in e that matches target, and if any is found,
// sets target to that error value and returns true. Otherwise, it returns false.
func (e Error) As(target any) bool {
	for _, err := range e.errs {
		if ok := errors.As(err, target); ok {
			return true
		}
	}
	return false
}
