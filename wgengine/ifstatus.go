// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package wgengine

import (
	"tailscale.com/types/logger"
	"time"
)

// Dummy implementation that does nothing.
func waitIfaceUp(iface interface{}, timeout time.Duration, logf logger.Logf) error {
	return nil
}
