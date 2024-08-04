// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import (
	"errors"

	"tailscale.com/types/ptr"
)

var (
	// ErrNotConfigured is returned when the requested policy setting is not configured.
	ErrNotConfigured = errors.New("not configured")
	// ErrTypeMismatch is returned when there's a type mismatch between the actual type
	// of the setting value and the expected type.
	ErrTypeMismatch = errors.New("type mismatch")
	// ErrNoSuchKey is returned by [DefinitionOf] when no policy setting
	// has been registered with the specified key.
	//
	// Until 2024-08-02, this error was also returned by a [Handler] when the specified
	// key did not have a value set. While the package maintains compatibility with this
	// usage of ErrNoSuchKey, it is recommended to return [ErrNotConfigured] from newer
	// [source.Store] implementations.
	ErrNoSuchKey = errors.New("no such key")
)

// ErrorText represents an error that occurs when reading or parsing a policy setting.
// This includes errors due to permissions issues, value type and format mismatches,
// and other platform- or source-specific errors. It does not include
// [ErrNotConfigured] and [ErrNoSuchKey], as those correspond to unconfigured
// policy settings rather than settings that cannot be read or parsed
// due to an error.
//
// ErrorText is used to marshal errors when a policy setting is sent over the wire,
// allowing the error to be logged or displayed. It does not preserve the
// type information of the underlying error.
type ErrorText string

// NewErrorText returns a [ErrorText] with the specified error message.
func NewErrorText(text string) *ErrorText {
	return ptr.To(ErrorText(text))
}

// NewErrorTextFromError returns an [ErrorText] with the text of the specified error,
// or nil if err is nil, [ErrNotConfigured], or [ErrNoSuchKey].
func NewErrorTextFromError(err error) *ErrorText {
	if err == nil || errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrNoSuchKey) {
		return nil
	}
	if err, ok := err.(*ErrorText); ok {
		return err
	}
	return ptr.To(ErrorText(err.Error()))
}

// Error implements error.
func (e ErrorText) Error() string {
	return string(e)
}

// MarshalText implements [encoding.TextMarshaler].
func (e ErrorText) MarshalText() (text []byte, err error) {
	return []byte(e.Error()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (e *ErrorText) UnmarshalText(text []byte) error {
	*e = ErrorText(text)
	return nil
}
