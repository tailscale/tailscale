// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lapitest

import (
	"context"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
)

// Client wraps a [local.Client] for testing purposes.
// It can be created using [Server.Client], [Server.ClientWithName],
// or [Server.ClientFor] and sends requests as the specified actor
// to the associated [Server].
type Client struct {
	tb testing.TB
	// Client is the underlying [local.Client] wrapped by the test client.
	// It is configured to send requests to the test server on behalf of the actor.
	*local.Client
	// Actor represents the user on whose behalf this client is making requests.
	// The server uses it to determine the client's identity and permissions.
	// The test can mutate the user to alter the actor's identity or permissions
	// before making a new request. It is typically an [ipnauth.TestActor],
	// unless the [Client] was created with s specific actor using [Server.ClientFor].
	Actor ipnauth.Actor
}

// Username returns username of the client's owner.
func (c *Client) Username() string {
	c.tb.Helper()
	name, err := c.Actor.Username()
	if err != nil {
		c.tb.Fatalf("Client.Username: %v", err)
	}
	return name
}

// WatchIPNBus is like [local.Client.WatchIPNBus] but returns a [local.IPNBusWatcher]
// that is closed when the test ends and a cancel function that stops the watcher.
// It fails the test if the underlying WatchIPNBus returns an error.
func (c *Client) WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (*local.IPNBusWatcher, context.CancelFunc) {
	c.tb.Helper()
	ctx, cancelWatcher := context.WithCancel(ctx)
	c.tb.Cleanup(cancelWatcher)
	watcher, err := c.Client.WatchIPNBus(ctx, mask)
	name, _ := c.Actor.Username()
	if err != nil {
		c.tb.Fatalf("Client.WatchIPNBus(%q): %v", name, err)
	}
	c.tb.Cleanup(func() { watcher.Close() })
	return watcher, cancelWatcher
}

// generateSequentialName generates a unique sequential name based on the given prefix and number n.
// It uses a base-26 encoding to create names like "User-A", "User-B", ..., "User-Z", "User-AA", etc.
func generateSequentialName(prefix string, n int) string {
	n++
	name := ""
	const numLetters = 'Z' - 'A' + 1
	for n > 0 {
		n--
		remainder := byte(n % numLetters)
		name = string([]byte{'A' + remainder}) + name
		n = n / numLetters
	}
	return prefix + "-" + name
}
