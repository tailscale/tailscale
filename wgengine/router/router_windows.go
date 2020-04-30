// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"log"

	winipcfg "github.com/tailscale/winipcfg-go"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

type winRouter struct {
	logf                func(fmt string, args ...interface{})
	tunname             string
	nativeTun           *tun.NativeTun
	wgdev               *device.Device
	routeChangeCallback *winipcfg.RouteChangeCallback
}

func newUserspaceRouter(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}
	return &winRouter{
		logf:      logf,
		wgdev:     wgdev,
		tunname:   tunname,
		nativeTun: tundev.(*tun.NativeTun),
	}, nil
}

func (r *winRouter) Up() error {
	// MonitorDefaultRoutes handles making sure our wireguard UDP
	// traffic goes through the old route, not recursively through the VPN.
	var err error
	r.routeChangeCallback, err = monitorDefaultRoutes(r.wgdev, true, r.nativeTun)
	if err != nil {
		log.Fatalf("MonitorDefaultRoutes: %v\n", err)
	}
	return nil
}

func (r *winRouter) SetRoutes(rs RouteSettings) error {
	err := configureInterface(rs.Cfg, r.nativeTun, rs.DNS, rs.DNSDomains)
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
