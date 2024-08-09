// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"errors"
	"net/http"
)

// AccessDeniedError is an error due to permissions.
type AccessDeniedError struct {
	// Err is the underlying error.
	Err error
}

// Error returns error message.
func (e *AccessDeniedError) Error() string { return e.Err.Error() }

// Unwrap returns an underlying error.
func (e *AccessDeniedError) Unwrap() error { return e.Err }

// ToHTTPStatus returns http.StatusForbidden.
func (e *AccessDeniedError) ToHTTPStatus() int { return http.StatusForbidden }

// NotFoundError is an error due to a missing resource.
type NotFoundError struct {
	// Err is the underlying error.
	Err error
}

// Error returns error message.
func (e *NotFoundError) Error() string { return e.Err.Error() }

// Unwrap returns an underlying error.
func (e *NotFoundError) Unwrap() error { return e.Err }

// ToHTTPStatus returns http.StatusNotFound.
func (e *NotFoundError) ToHTTPStatus() int { return http.StatusNotFound }

// BadArgsError is an error due to bad arguments.
type BadArgsError struct {
	// Err is the underlying error.
	Err error
}

// Error returns error message.
func (e *BadArgsError) Error() string { return e.Err.Error() }

// Unwrap returns an underlying error.
func (e *BadArgsError) Unwrap() error { return e.Err }

// ToHTTPStatus returns http.StatusBadRequest.
func (e *BadArgsError) ToHTTPStatus() int { return http.StatusBadRequest }

// ServiceUnavailableError is an error that can be represented by http.StatusServiceUnavailable.
type ServiceUnavailableError struct {
	Err error // Err is the underlying error.
}

// Error returns error message.
func (e *ServiceUnavailableError) Error() string { return e.Err.Error() }

// Unwrap returns an underlying error.
func (e *ServiceUnavailableError) Unwrap() error { return e.Err }

// ToHTTPStatus returns http.StatusServiceUnavailable.
func (e *ServiceUnavailableError) ToHTTPStatus() int { return http.StatusServiceUnavailable }

// InternalServerError is an error that can be represented by http.StatusInternalServerError.
type InternalServerError struct {
	Err error // Err is the underlying error.
}

// Error returns error message.
func (e *InternalServerError) Error() string { return e.Err.Error() }

// Unwrap returns an underlying error.
func (e *InternalServerError) Unwrap() error { return e.Err }

// ToHTTPStatus returns http.StatusInternalServerError.
func (e *InternalServerError) ToHTTPStatus() int { return http.StatusInternalServerError }

// NewAccessDeniedError returns a new AccessDeniedError with the specified text.
func NewAccessDeniedError(text string) *AccessDeniedError {
	return &AccessDeniedError{errors.New(text)}
}

// NewNotFoundError returns a new NotFoundError with the specified text.
func NewNotFoundError(text string) *NotFoundError {
	return &NotFoundError{errors.New(text)}
}

// NewBadArgsError returns a new BadArgsError with the specified text.
func NewBadArgsError(text string) *BadArgsError {
	return &BadArgsError{errors.New(text)}
}

// NewServiceUnavailableError returns a new ServiceUnavailableError with the specified text.
func NewServiceUnavailableError(text string) *ServiceUnavailableError {
	return &ServiceUnavailableError{errors.New(text)}
}

// NewInternalServerError returns a new InternalServerError with the specified text.
func NewInternalServerError(text string) *InternalServerError {
	return &InternalServerError{errors.New(text)}
}
