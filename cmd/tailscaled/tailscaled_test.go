// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main // import "tailscale.com/cmd/tailscaled"

import "testing"

func TestNothing(t *testing.T) {
	// This test does nothing on purpose, so we can run
	// GODEBUG=memprofilerate=1 go test -v -run=Nothing -memprofile=prof.mem
	// without any errors about no matching tests.
}
