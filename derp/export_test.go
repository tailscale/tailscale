// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derp

import "time"

func (c *Client) RecvTimeoutForTest(timeout time.Duration) (m ReceivedMessage, err error) {
	return c.recvTimeout(timeout)
}
