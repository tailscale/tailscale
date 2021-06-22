// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package controlknobs contains client options configurable from control which can be turned on
// or off. The ability to turn options on and off is for incrementally adding features in.
package controlknobs

import (
	"os"
	"strconv"
	"sync/atomic"

	"tailscale.com/types/opt"
)

// disableUPnP indicates whether to attempt UPnP mapping.
var disableUPnP atomic.Value

func init() {
	v, _ := strconv.ParseBool(os.Getenv("TS_DISABLE_UPNP"))
	var toStore opt.Bool
	toStore.Set(v)
	disableUPnP.Store(toStore)
}

// DisableUPnP reports the last reported value from control
// whether UPnP portmapping should be disabled.
func DisableUPnP() opt.Bool {
	v, _ := disableUPnP.Load().(opt.Bool)
	return v
}

// SetDisableUPnP will set whether UPnP connections are permitted or not,
// intended to be set from control.
func SetDisableUPnP(v opt.Bool) {
	old, ok := disableUPnP.Load().(opt.Bool)
	if !ok || old != v {
		disableUPnP.Store(v)
	}
}
