// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vizerror

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

func TestNew(t *testing.T) {
	err := New("abc")
	if err.Error() != "abc" {
		t.Errorf(`New("abc").Error() = %q, want %q`, err.Error(), "abc")
	}
}

func TestErrorf(t *testing.T) {
	err := Errorf("%w", fs.ErrNotExist)

	if got, want := err.Error(), "file does not exist"; got != want {
		t.Errorf("Errorf().Error() = %q, want %q", got, want)
	}

	// ensure error wrapping still works
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error chain does not contain fs.ErrNotExist")
	}
}

func TestAs(t *testing.T) {
	verr := New("visible error")
	err := fmt.Errorf("wrap: %w", verr)

	got, ok := As(err)
	if !ok {
		t.Errorf("As() return false, want true")
	}
	if got != verr {
		t.Errorf("As() returned error %v, want %v", got, verr)
	}
}

func TestWrap(t *testing.T) {
	wrapped := errors.New("wrapped")
	err := Wrap(wrapped)
	if err.Error() != "wrapped" {
		t.Errorf(`Wrap(wrapped).Error() = %q, want %q`, err.Error(), "wrapped")
	}
	if errors.Unwrap(err) != wrapped {
		t.Errorf("Unwrap = %q, want %q", errors.Unwrap(err), wrapped)
	}
}

func TestWrapWithMessage(t *testing.T) {
	wrapped := errors.New("wrapped")
	err := WrapWithMessage(wrapped, "safe")
	if err.Error() != "safe" {
		t.Errorf(`WrapWithMessage(wrapped, "safe").Error() = %q, want %q`, err.Error(), "safe")
	}
	if errors.Unwrap(err) != wrapped {
		t.Errorf("Unwrap = %q, want %q", errors.Unwrap(err), wrapped)
	}
}
