// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsconst

import "time"

const (
	// DefaultPingTimeout is the default time we wait for a pong reply
	// before assuming it's never coming.
	DefaultPingTimeout = 5 * time.Second

	// DefaultPingInterval is the default minimum time
	// between pings to an endpoint.
	DefaultPingInterval = 5 * time.Second
)
