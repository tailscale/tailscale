// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package controlknobs contains client options configurable from control which can be turned on
// or off. The ability to turn options on and off is for incrementally adding features in.
package controlknobs

import (
	"sync/atomic"

	"tailscale.com/envknob"
)

// disableUPnP indicates whether to attempt UPnP mapping.
var disableUPnPControl atomic.Bool

var disableUPnpEnv = envknob.RegisterBool("TS_DISABLE_UPNP")

// DisableUPnP reports the last reported value from control
// whether UPnP portmapping should be disabled.
func DisableUPnP() bool {
	return disableUPnPControl.Load() || disableUPnpEnv()
}

// SetDisableUPnP sets whether control says that UPnP should be
// disabled.
func SetDisableUPnP(v bool) {
	disableUPnPControl.Store(v)
}
