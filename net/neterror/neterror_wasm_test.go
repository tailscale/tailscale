// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package neterror

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"
)

func TestIsUDPReadFeedback(t *testing.T) {
	for _, err := range []error{nil, errors.New("unknown error"), fs.ErrClosed, io.ErrClosedPipe} {
		if IsUDPReadFeedback(err) {
			t.Errorf("IsUDPReadFeedback(%v) = true, want false", err)
		}
	}
}

func TestIsClosedPipeError(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("unknown error"), false},
		{fs.ErrClosed, true},
		{io.ErrClosedPipe, true},
	} {
		if got := IsClosedPipeError(tt.err); got != tt.want {
			t.Errorf("IsClosedPipeError(%v) = %v, want %v", tt.err, got, tt.want)
		}
		if got := IsClosedPipeError(fmt.Errorf("wrapped: %w", tt.err)); got != tt.want {
			t.Errorf("IsClosedPipeError(wrapped %v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
