// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

type fakeRouter struct {
	tunname string
	logf    logger.Logf
}

func NewFakeRouter(logf logger.Logf, tunname string, dev *device.Device, tuntap tun.Device, netChanged func()) Router {
	return &fakeRouter{
		logf:    logf,
		tunname: tunname,
	}
}

func (r *fakeRouter) Up() error {
	r.logf("Warning: fakeRouter.Up: not implemented.\n")
	return nil
}

func (r *fakeRouter) SetRoutes(rs RouteSettings) error {
	r.logf("Warning: fakeRouter.SetRoutes: not implemented.\n")
	return nil
}

func (r *fakeRouter) Close() error {
	r.logf("Warning: fakeRouter.Close: not implemented.\n")
	return nil
}
