// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//+build !windows

package wgengine

import (
	"tailscale.com/types/logger"
)

// Dummy implementation that does nothing.
type ifaceWatcher struct {
}

func initWatcher(logf logger.Logf) (*ifaceWatcher, error) {
	return &ifaceWatcher{}, nil
}

func (iw *ifaceWatcher) setTun(ifc interface{}) {
}

func (iw *ifaceWatcher) Destroy() {
}
