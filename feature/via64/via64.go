// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

// Package via64 registers kernel 4via6 translation (net/via64/xlat) with the Linux router. It runs only when TS_DEBUG_4VIA6_KERNEL is set.
package via64

import (
	"net/netip"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/net/via64/xlat"
	"tailscale.com/net/via64/xlatbpf"
	"tailscale.com/types/preftype"
	"tailscale.com/wgengine/router/osrouter"
)

func init() {
	if !feature.Register("via64") {
		return
	}
	osrouter.HookNewVia64.Set(newDatapath)
	osrouter.HookVia64CleanUp.Set(xlat.Cleanup)
}

// x4 stands for every 4via6 client on the LAN side (RFC 7335's block).
var x4 = netip.MustParseAddr("192.0.0.6")

type datapath struct{ c *xlat.Controller }

func newDatapath(cfg osrouter.Via64Config) osrouter.Via64Datapath {
	return datapath{xlat.NewController(xlat.Config{
		Ingress:       cfg.Ingress,
		RulePriority:  cfg.RulePriority,
		Table:         cfg.Table,
		X4:            x4,
		NewBackend:    xlatbpf.New,
		Logf:          cfg.Logf,
		CheckInterval: 15 * time.Second,
		NetstackUDP:   !envknob.BoolDefaultTrue("TS_DEBUG_4VIA6_KERNEL_UDP"),
	})}
}

func (d datapath) Update(advertised []netip.Prefix, snat bool, netfilter preftype.NetfilterMode, tunIPv6 bool) error {
	_, err := d.c.Update(xlat.Desired{Advertised: advertised, SNAT: snat, Netfilter: netfilter, TunIPv6: tunIPv6})
	return err
}

func (d datapath) Reassert() { d.c.Reassert() }

func (d datapath) Close() error { return d.c.Close() }
