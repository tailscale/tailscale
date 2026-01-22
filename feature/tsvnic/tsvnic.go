// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

// Package tsvnic enables the experimental Windows driver.
package tsvnic

import (
	"github.com/dblohm7/wingoes"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"

	"github.com/tailscale/tsvnic-experiment/wgtun"
)

func init() {
	tstun.CreateTSVNIC.Set(createTUN)
}

func createTUN(logf logger.Logf, tunName string, mtu int) (tun.Device, error) {
	if err := wgtun.MaybeInstallDriver(); err != nil {
		return nil, err
	}
	guid := wingoes.MustGetGUID("{FC4CAFB3-26BA-4375-8450-97FB42C27531}")
	return wgtun.NewTUN(logger.WithPrefix(logf, "tsvnic: "), "Tailscale Tunnel (Experimental)", guid, mtu)
}
