// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!linux || android) && !wasm && !tamago && !aix && !solaris && !illumos

package tstun

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

func createTUN(logf logger.Logf, name string, mtu, queues int) (tun.Device, error) {
	create := func() (tun.Device, error) {
		return tun.CreateTUN(name, mtu, tun.WithQueues(queues))
	}
	dev, err := create()
	if err != nil {
		return retryTUNAfterModprobe(logf, name, create, err, modprobeTunHook.GetOrNil())
	}
	return dev, nil
}
