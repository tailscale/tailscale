// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// NewFakeRouter returns a new fake Router implementation whose
// implementation does nothing and always returns nil errors.
func NewFakeRouter(logf logger.Logf, _ *device.Device, _ tun.Device) (Router, error) {
	return fakeRouter{logf: logf}, nil
}

type fakeRouter struct {
	logf logger.Logf
}

func (r fakeRouter) Up() error {
	r.logf("Warning: fakeRouter.Up: not implemented.\n")
	return nil
}

func (r fakeRouter) SetRoutes(rs RouteSettings) error {
	r.logf("Warning: fakeRouter.SetRoutes: not implemented.\n")
	return nil
}

func (r fakeRouter) Close() error {
	r.logf("Warning: fakeRouter.Close: not implemented.\n")
	return nil
}
