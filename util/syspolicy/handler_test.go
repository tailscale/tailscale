// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syspolicy

import "testing"

func TestDefaultHandlerReadValues(t *testing.T) {
	var h defaultHandler

	got, err := h.ReadString(string(AdminConsoleVisibility))
	if got != "" || err != ErrNoSuchKey {
		t.Fatalf("got %v err %v", got, err)
	}
	result, err := h.ReadUInt64(string(LogSCMInteractions))
	if result != 0 || err != ErrNoSuchKey {
		t.Fatalf("got %v err %v", result, err)
	}
}
