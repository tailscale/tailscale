// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package derp

import "context"

func (c *sclient) statsLoop(ctx context.Context) error {
	return nil
}
