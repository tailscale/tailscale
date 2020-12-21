// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// NewFakeRouter returns a Router that does nothing when called and
// always returns nil errors.
func NewFake(logf logger.Logf, _ *device.Device, _ tun.Device) (Router, error) {
	return fakeRouter{logf: logf}, nil
}

type fakeRouter struct {
	logf logger.Logf
}

func (r fakeRouter) Up() error {
	r.logf("[v1] warning: fakeRouter.Up: not implemented.")
	return nil
}

func (r fakeRouter) Set(cfg *Config) error {
	r.logf("[v1] warning: fakeRouter.Set: not implemented.")
	return nil
}

func (r fakeRouter) Close() error {
	r.logf("[v1] warning: fakeRouter.Close: not implemented.")
	return nil
}
