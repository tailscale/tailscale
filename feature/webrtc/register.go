// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"tailscale.com/feature"
	"tailscale.com/wgengine/magicsock"
)

// featureName is the name of the feature implemented by this package.
const featureName = "webrtc"

func init() {
	feature.Register(featureName)
	magicsock.HookNewWebRTCManager.Set(newManager)
}

// newManager is the [magicsock.HookNewWebRTCManager] implementation. It returns
// an untyped nil [magicsock.WebRTCManager] (rather than a typed nil *Manager)
// when construction fails, so magicsock's nil check behaves correctly.
func newManager(b magicsock.WebRTCBackend) magicsock.WebRTCManager {
	if m := NewManager(b); m != nil {
		return m
	}
	return nil
}
