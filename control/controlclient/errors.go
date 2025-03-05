// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import "errors"

// TxnError is an error type that can be returned by controlclient
// api requests.
//
// It wraps an underlying error and an HTTP response and code.
type TxnError struct {
	err      error
	response string
	httpCode int
}

// Error implements [error].
func (e *TxnError) Error() string {
	return e.err.Error()
}

// Retryable returns whether the error is retryable.
func (e *TxnError) Retryable() bool {
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

var ErrHTTPFailure = ErrTxnError(errors.New("HTTP Error"))
var ErrNoNodeKey error = ErrTxnError(errors.New("No Node Key"))
var ErrNoNoiseClient error = ErrTxnError(errors.New("No Noise Client"))
var ErrHTTPPostFailure error = ErrTxnError(errors.New("HTTP Post Failure"))

// ErrTxnError wraps an error in a TxnError.
func ErrTxnError(err error) error {
	return &TxnError{err, "", 0}
}

// ErrTxnHTTPFailure wraps an HTTP error in an TxnError.
func ErrTxnHTTPFailure(errCode int, response []byte) error {
	return &TxnError{ErrHTTPFailure, string(response), errCode}
}
