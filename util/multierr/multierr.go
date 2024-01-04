// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package multierr provides a simple multiple-error type.
// It was inspired by github.com/go-multierror/multierror.
package multierr

import (
	"errors"
	"slices"
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
	return slices.Clone(e.errs)
}

// Unwrap returns the underlying errors as-is.
func (e Error) Unwrap() []error {
	// Do not clone since Unwrap requires callers to not mutate the slice.
	// See the documentation in the Go "errors" package.
	return e.errs
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
	// First count the number of errors to avoid allocating.
	var n int
	var errFirst error
	for _, e := range errs {
		switch e := e.(type) {
		case nil:
			continue
		case Error:
			n += len(e.errs)
			if errFirst == nil && len(e.errs) > 0 {
				errFirst = e.errs[0]
			}
		default:
			n++
			if errFirst == nil {
				errFirst = e
			}
		}
	}
	if n <= 1 {
		return errFirst // nil if n == 0
	}

	// More than one error, allocate slice and construct the multi-error.
	dst := make([]error, 0, n)
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

// Range performs a pre-order, depth-first iteration of the error tree
// by successively unwrapping all error values.
// For each iteration it calls fn with the current error value and
// stops iteration if it ever reports false.
func Range(err error, fn func(error) bool) bool {
	if err == nil {
		return true
	}
	if !fn(err) {
		return false
	}
	switch err := err.(type) {
	case interface{ Unwrap() error }:
		if err := err.Unwrap(); err != nil {
			if !Range(err, fn) {
				return false
			}
		}
	case interface{ Unwrap() []error }:
		for _, err := range err.Unwrap() {
			if !Range(err, fn) {
				return false
			}
		}
	}
	return true
}
