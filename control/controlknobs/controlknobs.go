// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package controlknobs contains client options configurable from control which can be turned on
// or off. The ability to turn options on and off is for incrementally adding features in.
package controlknobs

import (
	"sync/atomic"

	"tailscale.com/envknob"
)

// disableUPnP indicates whether to attempt UPnP mapping.
var disableUPnP atomic.Bool

func init() {
	SetDisableUPnP(envknob.Bool("TS_DISABLE_UPNP"))
}

// DisableUPnP reports the last reported value from control
// whether UPnP portmapping should be disabled.
func DisableUPnP() bool {
	return disableUPnP.Load()
}

// SetDisableUPnP sets whether control says that UPnP should be
// disabled.
func SetDisableUPnP(v bool) {
	disableUPnP.Store(v)
}
