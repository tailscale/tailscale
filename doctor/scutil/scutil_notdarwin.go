// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin

package scutil

import (
	"context"

	"tailscale.com/types/logger"
)

func (Check) Run(ctx context.Context, logf logger.Logf) error {
	// unimplemented
	return nil
}
