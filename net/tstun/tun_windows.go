// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// WindowsTun is a [tun.Device] that provides access to Windows-specific
// functionality implemented by both wintun ([tun.NativeTun]) and tsvnic.
type WindowsTun interface {
	tun.Device
	// LUID returns Windows interface instance ID.
	LUID() uint64
	// ForceMTU causes subsequent [tun.Device.MTU] calls to return mtu and
	// sends a [tun.EventMTUUpdate] on the [tun.Device.Events] channel,
	// without changing the underlying interface MTU.
	ForceMTU(mtu int)
}

func init() {
	tun.WintunTunnelType = "Tailscale"
	guid, err := windows.GUIDFromString("{37217669-42da-4657-a55b-0d995d328250}")
	if err != nil {
		panic(err)
	}
	tun.WintunStaticRequestedGUID = &guid
}

func interfaceName(dev tun.Device) (string, error) {
	guid, err := winipcfg.LUID(dev.(WindowsTun).LUID()).GUID()
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}
