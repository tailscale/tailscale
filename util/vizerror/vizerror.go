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
type Error error

// New returns an error that formats as the given text.
func New(text string) error {
	return Error(errors.New(text))
}

// Errorf returns an error with the specified format and values.
func Errorf(format string, a ...any) error {
	return Error(fmt.Errorf(format, a...))
}
