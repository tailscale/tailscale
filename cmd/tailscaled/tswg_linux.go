// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_tswg

package main

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/envknob"
	"tailscale.com/net/tstun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/tswg"
)

// useTSWG reports whether to try the experimental tswg kernel data plane
// (https://github.com/tailscale/tailscale/issues/426) instead of a TUN
// device and wireguard-go.
var useTSWG = envknob.RegisterBool("TS_DEBUG_TSWG")

// newTSWGDevice returns the tswg device named name for the kernel data
// plane, or ok=false (after logging why) if tswg isn't wanted or can't be
// used, in which case the caller falls back to a TUN device.
func newTSWGDevice(logf logger.Logf, name string) (_ tun.Device, ok bool) {
	if !useTSWG() {
		return nil, false
	}
	dev, err := tswg.NewTailscaleDevice(name, int(tstun.DefaultTUNMTU()))
	if err != nil {
		logf("tswg: not using the kernel data plane: %v; falling back to TUN", err)
		return nil, false
	}
	logf("tswg: using the kernel data plane on %s", name)
	return dev, true
}

// removeStaleTSWGDevice deletes a tswg device named name, as a previous
// tailscaled in kernel mode may have left behind, so that a TUN device can
// take its name.
func removeStaleTSWGDevice(logf logger.Logf, name string) {
	deleted, err := tswg.DeleteStaleLink(name)
	if err != nil {
		logf("tswg: %v", err)
	} else if deleted {
		logf("tswg: deleted a stale kernel device %s, for TUN to use its name", name)
	}
}
