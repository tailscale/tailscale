// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"errors"
	"fmt"
	"net/http"
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

func (e *apiResponseError) Unwrap() error { return e.err }

var (
	errNoNodeKey       = &apiResponseError{errors.New("no node key"), true}
	errNoNoiseClient   = &apiResponseError{errors.New("no noise client"), true}
	errHTTPPostFailure = &apiResponseError{errors.New("http failure"), true}
)

func errBadHTTPResponse(code int, msg string) error {
	retryable := false
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		retryable = true
	}
	return &apiResponseError{fmt.Errorf("http error %d: %s", code, msg), retryable}
}
