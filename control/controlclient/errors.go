// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"errors"
	"fmt"
)

// apiResponseError is an error type that can be returned by controlclient
// api requests.
//
// It wraps an underlying error and a flag for clients to query if the
// error is retryable via the Retryable() method.
type apiResponseError struct {
	err       error
	retryable bool
}

// Error implements [error].
func (e *apiResponseError) Error() string {
	return e.err.Error()
}

// Retryable reports whether the error is retryable.
func (e *apiResponseError) Retryable() bool {
	return e.retryable
}

var (
	errNoNodeKey       = retryableError(errors.New("no node key"))
	errNoNoiseClient   = retryableError(errors.New("no noise client"))
	errHTTPPostFailure = retryableError(errors.New("http failure"))
)

func retryableError(err error) error {
	return &apiResponseError{err, true}
}

func errBadHTTPResponse(code int, msg []byte) error {
	retryable := false
	switch code {
	case 429, 500, 502, 503, 504:
		retryable = true
	}
	return &apiResponseError{fmt.Errorf("%s: %w", msg, errors.New("http error")), retryable}
}
