// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

type ifaceWatcher struct {
	logf logger.Logf
	iface *tun.NativeTun
}

func initWatcher(logf logger.Logf) (*ifaceWatcher, error) {
	return &ifaceWatcher{logf: logger.WithPrefix(logf, "ifaceWatcher: ")}, nil
}

func (iw *ifaceWatcher) setTun(ifc interface{}) {
	iw.iface = ifc.(*tun.NativeTun)
	iw.logf("setTun LUID=%v", iw.iface.LUID())
}

func (iw *ifaceWatcher) Destroy() {
	iw.logf("Destroy")
}
