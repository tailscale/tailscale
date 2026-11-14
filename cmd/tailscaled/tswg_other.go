// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || ts_omit_tswg

package main

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// newTSWGDevice reports ok=false: the tswg kernel data plane is Linux-only
// and omitted by the ts_omit_tswg build tag.
func newTSWGDevice(logger.Logf, string) (_ tun.Device, ok bool) {
	return nil, false
}

// removeStaleTSWGDevice does nothing: there are no tswg devices here.
func removeStaleTSWGDevice(logger.Logf, string) {}
