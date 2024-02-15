// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ethtool provides a doctor.Check that prints diagnostic information
// obtained from the 'ethtool' utility on the current system.
package ethtool

import (
	"context"

	"tailscale.com/types/logger"
)

// Check implements the doctor.Check interface.
type Check struct{}

func (Check) Name() string {
	return "ethtool"
}

func (Check) Run(_ context.Context, logf logger.Logf) error {
	return ethtoolImpl(logf)
}
