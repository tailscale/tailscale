// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows,!linux,!darwin,!openbsd,!freebsd

package router

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

func newUserspaceRouter(cfg InitConfig) Router {
	return NewFakeRouter(cfg)
}

func cleanup(logger.Logf, string) {
	// Nothing to do here.
}
