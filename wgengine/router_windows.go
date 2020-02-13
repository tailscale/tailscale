// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"log"

	winipcfg "github.com/tailscale/winipcfg-go"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/logger"
)

type winRouter struct {
	logf                func(fmt string, args ...interface{})
	tunname             string
	dev                 *device.Device
	nativeTun           *tun.NativeTun
	routeChangeCallback *winipcfg.RouteChangeCallback
}

func NewUserspaceRouter(logf logger.Logf, tunname string, dev *device.Device, tuntap tun.Device, netChanged func()) Router {
	r := winRouter{
		logf:      logf,
		tunname:   tunname,
		dev:       dev,
		nativeTun: tuntap.(*tun.NativeTun),
	}
	return &r
}

func (r *winRouter) Up() error {
	// MonitorDefaultRoutes handles making sure our wireguard UDP
	// traffic goes through the old route, not recursively through the VPN.
	var err error
	r.routeChangeCallback, err = MonitorDefaultRoutes(r.dev, true, r.nativeTun)
	if err != nil {
		log.Fatalf("MonitorDefaultRoutes: %v\n", err)
	}
	return nil
}

func (r *winRouter) SetRoutes(rs RouteSettings) error {
	err := ConfigureInterface(rs.Cfg, r.nativeTun, rs.DNS, rs.DNSDomains)
	if err != nil {
		r.logf("ConfigureInterface: %v\n", err)
		return err
	}
	return nil
}

func (r *winRouter) Close() error {
	if r.routeChangeCallback != nil {
		r.routeChangeCallback.Unregister()
	}
	return nil
}
