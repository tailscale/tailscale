// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package kernellog

import (
	"context"

	"tailscale.com/types/logger"
)

func (Check) Run(_ context.Context, logf logger.Logf) error {
	// Not supported; do nothing
	return nil
}
