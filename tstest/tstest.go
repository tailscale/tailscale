// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tstest provides utilities for use in unit tests.
package tstest

import (
	"context"
	"time"

	"tailscale.com/logtail/backoff"
	"tailscale.com/types/logger"
)

// WaitFor retries try for up to maxWait.
// It returns nil once try returns nil the first time.
// If maxWait passes without success, it returns try's last error.
func WaitFor(maxWait time.Duration, try func() error) error {
	bo := backoff.NewBackoff("wait-for", logger.Discard, maxWait/4)
	deadline := time.Now().Add(maxWait)
	var err error
	for time.Now().Before(deadline) {
		err = try()
		if err == nil {
			break
		}
		bo.BackOff(context.Background(), err)
	}
	return err
}
