// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package healthmsg

import "testing"

func TestMessages(t *testing.T) {
	// Basic test that messages are defined and non-empty
	if WarnAcceptRoutesOff == "" {
		t.Error("WarnAcceptRoutesOff is empty")
	}
	if WarnExitNodeUsage == "" {
		t.Error("WarnExitNodeUsage is empty")
	}
}
