// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package posture

import (
	"testing"

	"tailscale.com/types/logger"
)

func TestGetSerialNumber(t *testing.T) {
	// ensure GetSerialNumbers is implemented
	// or covered by a stub on a given platform.
	_, _ = GetSerialNumbers(logger.Discard)
}
