// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router"
)

func init() {
	router.HookCleanUp.Set(func(logf logger.Logf, netMon *netmon.Monitor, ifName string) {
		cleanAllTailscaleRoutes(logf)
	})
	router.HookNewUserspaceRouter.Set(func(opts router.NewOpts) (router.Router, error) {
		return newUserspaceRouter(opts.Logf, opts.Tun, opts.NetMon)
	})
}

func newUserspaceRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor) (router.Router, error) {
	r := &plan9Router{
		logf:   logf,
		tundev: tundev,
		netMon: netMon,
	}
	cleanAllTailscaleRoutes(logf)
	return r, nil
}

type plan9Router struct {
	logf   logger.Logf
	tundev tun.Device
	netMon *netmon.Monitor
	health *health.Tracker
}

func (r *plan9Router) Up() error {
	return nil
}

func (r *plan9Router) Set(cfg *router.Config) error {
	if cfg == nil {
		cleanAllTailscaleRoutes(r.logf)
		return nil
	}

	var self4, self6 netip.Addr
	for _, addr := range cfg.LocalAddrs {
		ctl := r.tundev.File()
		maskBits := addr.Bits()
		if addr.Addr().Is4() {
			// The mask sizes in Plan9 are in IPv6 bits, even for IPv4.
			maskBits += (128 - 32)
			self4 = addr.Addr()
		}
		if addr.Addr().Is6() {
			self6 = addr.Addr()
		}
		_, err := fmt.Fprintf(ctl, "add %s /%d\n", addr.Addr().String(), maskBits)
		r.logf("route/plan9: add %s /%d = %v", addr.Addr().String(), maskBits, err)
	}

	ipr, err := os.OpenFile("/net/iproute", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /net/iproute: %w", err)
	}
	defer ipr.Close()

	// TODO(bradfitz): read existing routes, delete ones tagged "tail"
	// that aren't in cfg.LocalRoutes.

	if _, err := fmt.Fprintf(ipr, "tag tail\n"); err != nil {
		return fmt.Errorf("tag tail: %w", err)
	}

	for _, route := range cfg.Routes {
		maskBits := route.Bits()
		if route.Addr().Is4() {
			// The mask sizes in Plan9 are in IPv6 bits, even for IPv4.
			maskBits += (128 - 32)
		}
		var nextHop netip.Addr
		if route.Addr().Is4() {
			nextHop = self4
		} else if route.Addr().Is6() {
			nextHop = self6
		}
		if !nextHop.IsValid() {
			r.logf("route/plan9: skipping route %s: no next hop (no self addr)", route.String())
			continue
		}
		r.logf("route/plan9: plan9.router: add %s /%d %s", route.Addr(), maskBits, nextHop)
		if _, err := fmt.Fprintf(ipr, "add %s /%d %s\n", route.Addr(), maskBits, nextHop); err != nil {
			return fmt.Errorf("add %s: %w", route.String(), err)
		}
	}

	if len(cfg.LocalRoutes) > 0 {
		r.logf("route/plan9: TODO: Set LocalRoutes %v", cfg.LocalRoutes)
	}
	if len(cfg.SubnetRoutes) > 0 {
		r.logf("route/plan9: TODO: Set SubnetRoutes %v", cfg.SubnetRoutes)
	}

	return nil
}

func (r *plan9Router) Close() error {
	// TODO(bradfitz): unbind
	return nil
}

func cleanAllTailscaleRoutes(logf logger.Logf) {
	routes, err := os.OpenFile("/net/iproute", os.O_RDWR, 0)
	if err != nil {
		logf("cleaning routes: %v", err)
		return
	}
	defer routes.Close()

	// Using io.ReadAll or os.ReadFile on /net/iproute fails; it results in a
	// 511 byte result when the actual /net/iproute contents are over 1k.
	// So do it in one big read instead. Who knows.
	routeBuf := make([]byte, 1<<20)
	n, err := routes.Read(routeBuf)
	if err != nil {
		logf("cleaning routes: %v", err)
		return
	}
	routeBuf = routeBuf[:n]

	bs := bufio.NewScanner(bytes.NewReader(routeBuf))
	for bs.Scan() {
		f := strings.Fields(bs.Text())
		if len(f) < 6 {
			continue
		}
		tag := f[4]
		if tag != "tail" {
			continue
		}
		_, err := fmt.Fprintf(routes, "remove %s %s\n", f[0], f[1])
		logf("router: cleaning route %s %s: %v", f[0], f[1], err)
	}
}
