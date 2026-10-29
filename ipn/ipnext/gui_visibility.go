// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnext

import (
	"tailscale.com/tailcfg"
	"tailscale.com/util/syspolicy/policyclient"
)

// GUIVisibilityProvider is an optional extension that interprets GUI
// visibility policy for IPN watchers.
type GUIVisibilityProvider interface {
	ForPolicy(*policyclient.PolicySnapshot) GUIVisibilityFilter
}

// GUIVisibilityFilter classifies peers for one watcher's effective policy.
type GUIVisibilityFilter interface {
	Hide(peer, self tailcfg.NodeView) bool
}
