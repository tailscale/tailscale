// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

func SetTestHookWatchLookConnectResult(f func(connectError error, wasSelfConnect bool) (keepRunning bool)) {
	testHookWatchLookConnectResult = f
}

// breakConnection breaks the connection, which should trigger a reconnect.
func (c *Client) BreakConnection(brokenClient *Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != brokenClient.client {
		return
	}
	if c.netConn != nil {
		c.netConn.Close()
		c.netConn = nil
	}
	c.client = nil
}

var RetryInterval = &retryInterval
