// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ktimeout

import (
	"errors"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSetUserTimeoutCheckedInvalid(t *testing.T) {
	for _, timeout := range []time.Duration{
		-time.Millisecond,
		time.Nanosecond,
		time.Millisecond + time.Nanosecond,
		(math.MaxInt32 + 1) * time.Millisecond,
		time.Duration(math.MaxInt64),
	} {
		t.Run(timeout.String(), func(t *testing.T) {
			// No valid fd is needed: validation must precede socket access.
			err := SetUserTimeoutChecked(^uintptr(0), timeout)
			if err == nil || !strings.HasPrefix(err.Error(), "invalid TCP user timeout ") {
				t.Fatalf("invalid timeout error = %v; want validation error", err)
			}
		})
	}
}

func TestSetUserTimeoutCheckedUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		t.Skip("platform has a TCP_USER_TIMEOUT implementation")
	}
	for _, timeout := range []time.Duration{0, time.Second, math.MaxInt32 * time.Millisecond} {
		if err := SetUserTimeoutChecked(^uintptr(0), timeout); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("checked timeout %v: error = %v; want unsupported", timeout, err)
		}
		if err := SetUserTimeout(^uintptr(0), timeout); err != nil {
			t.Errorf("legacy timeout %v: error = %v; want no-op success", timeout, err)
		}
	}
}
