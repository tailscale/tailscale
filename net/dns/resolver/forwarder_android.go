// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package resolver

import (
	"net"

	"tailscale.com/net/netns"
	"tailscale.com/types/nettype"
)

func init() {
	lc := &net.ListenConfig{Control: netns.ControlFuncForDNS()}
	stdNetPacketListener = nettype.MakePacketListenerWithNetIP(lc)
}
