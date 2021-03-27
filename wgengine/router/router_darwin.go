// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

func newUserspaceRouter(logf logger.Logf, tundev tun.Device) (Router, error) {
	return newUserspaceBSDRouter(logf, tundev)
}

func cleanup(logger.Logf, string) {
	// Nothing to do.
}
