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
