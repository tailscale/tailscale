// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux

package derp

import "context"

func (c *sclient) statsLoop(ctx context.Context) error {
	return nil
}
