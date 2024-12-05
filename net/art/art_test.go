// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package art

import (
	"os"
	"testing"

	"tailscale.com/util/cibuild"
)

func TestMain(m *testing.M) {
	if cibuild.On() {
		// Skip CI on GitHub for now
		// TODO: https://github.com/tailscale/tailscale/issues/7866
		os.Exit(0)
	}
	os.Exit(m.Run())
}
