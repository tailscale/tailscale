// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package osrouter contains OS-specific router implementations.
// This package has no API; it exists purely to import
// for the side effect of it registering itself with the wgengine/router
// package.
package osrouter

import "tailscale.com/wgengine/router"

// shutdownConfig is a routing configuration that removes all router
// state from the OS. It's the config used when callers pass in a nil
// Config.
var shutdownConfig router.Config
