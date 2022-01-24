// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package controlknobs contains client options configurable from control which can be turned on
// or off. The ability to turn options on and off is for incrementally adding features in.
package controlknobs

import (
	"tailscale.com/envknob"
	"tailscale.com/syncs"
)

// disableUPnP indicates whether to attempt UPnP mapping.
var disableUPnP syncs.AtomicBool

func init() {
	SetDisableUPnP(envknob.Bool("TS_DISABLE_UPNP"))
}

// DisableUPnP reports the last reported value from control
// whether UPnP portmapping should be disabled.
func DisableUPnP() bool {
	return disableUPnP.Get()
}

// SetDisableUPnP sets whether control says that UPnP should be
// disabled.
func SetDisableUPnP(v bool) {
	disableUPnP.Set(v)
}
