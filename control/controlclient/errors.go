// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import "errors"

// ControlClientError is an error type that can be returned by controlclient
// requests.
//
// It wraps an underlying error and an HTTP response and code.
type ControlClientError struct {
	err      error
	response string
	httpCode int
}

func (e *ControlClientError) Error() string {
	return e.err.Error()
}

// Retryable returns whether the error is retryable.
func (e *ControlClientError) Retryable() bool {
	switch {
	case errors.Is(e, ErrNoNodeKey),
		errors.Is(e, ErrHTTPPostFailure),
		errors.Is(e, ErrNoNoiseClient):
		return true
	case errors.Is(e, ErrHTTPFailure):
		// We're treating all HTTP errors as non-retriable here, but this could be made more sophisticated.
		// Notably, HTTP 500's are often retriable.
		// (barnstar) TODO: make this more sophisticated. See: https://github.com/tailscale/corp/issues/26811
		return false
	default:
		return false
	}
}

var ErrHTTPFailure = ErrControlClientError(errors.New("HTTP Error"))
var ErrNoNodeKey error = ErrControlClientError(errors.New("No Node Key"))
var ErrNoNoiseClient error = ErrControlClientError(errors.New("No Noise Client"))
var ErrHTTPPostFailure error = ErrControlClientError(errors.New("HTTP Post Failure"))

func ErrControlClientError(err error) error {
	return &ControlClientError{err, "", 0}
}

func ErrAuditLogHTTPFailure(errCode int, response []byte) error {
	return &ControlClientError{ErrHTTPFailure, string(response), errCode}
}
