// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package setting

import "errors"

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

// Error is an error when reading or parsing a policy setting.
type Error struct {
	text string
}

// NewError returns a [Error] with the specified error message.
func NewError(text string) *Error {
	return &Error{text}
}

// WrapError returns an [Error] with the text of the specified error,
// or nil if err is nil, [ErrNotConfigured], or [ErrNoSuchKey].
func WrapError(err error) *Error {
	if err == nil || errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrNoSuchKey) {
		return nil
	}
	if err, ok := err.(*Error); ok {
		return err
	}
	return &Error{err.Error()}
}

// Error implements error.
func (e Error) Error() string {
	return e.text
}

// MarshalText implements [encoding.TextMarshaler].
func (e Error) MarshalText() (text []byte, err error) {
	return []byte(e.Error()), nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (e *Error) UnmarshalText(text []byte) error {
	e.text = string(text)
	return nil
}
