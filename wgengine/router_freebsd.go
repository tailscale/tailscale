// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/types/logger"
)

// For now this router only supports the userspace WireGuard implementations.
//
// Work is currently underway for an in-kernel FreeBSD implementation of wireguard
// https://svnweb.freebsd.org/base?view=revision&revision=357986

const DefaultTunName = "tailscale0"

type freebsdRouter struct {
	logf    logger.Logf
	tunname string
	local   wgcfg.CIDR
	routes  map[wgcfg.CIDR]struct{}
}

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}
	return &freebsdRouter{
		logf:    logf,
		tunname: tunname,
	}, nil
}

func cmd(args ...string) *exec.Cmd {
	if len(args) == 0 {
		log.Fatalf("exec.Cmd(%#v) invalid; need argv[0]\n", args)
	}
	return exec.Command(args[0], args[1:]...)
}

func (r *freebsdRouter) Up() error {
	ifup := []string{"ifconfig", r.tunname, "up"}
	if out, err := cmd(ifup...).CombinedOutput(); err != nil {
		r.logf("running ifconfig failed: %v\n%s", err, out)
		return err
	}
	return nil
}

func (r *freebsdRouter) SetRoutes(rs RouteSettings) error {
	if rs.LocalAddr == (wgcfg.CIDR{}) {
		return nil
	}

	var errq error

	// Update the address.
	if rs.LocalAddr != r.local {
		// If the interface is already set, remove it.
		if r.local != (wgcfg.CIDR{}) {
			addrdel := []string{"ifconfig", r.tunname,
				"inet", r.local.String(), "-alias"}
			out, err := cmd(addrdel...).CombinedOutput()
			if err != nil {
				r.logf("addr del failed: %v: %v\n%s", addrdel, err, out)
				if errq == nil {
					errq = err
				}
			}
		}

		// Add the interface.
		addradd := []string{"ifconfig", r.tunname,
			"inet", rs.LocalAddr.String(), rs.LocalAddr.IP.String()}
		out, err := cmd(addradd...).CombinedOutput()
		if err != nil {
			r.logf("addr add failed: %v: %v\n%s", addradd, err, out)
			if errq == nil {
				errq = err
			}
		}
	}

	newRoutes := make(map[wgcfg.CIDR]struct{})
	for _, peer := range rs.Cfg.Peers {
		for _, route := range peer.AllowedIPs {
			newRoutes[route] = struct{}{}
		}
	}
	// Delete any pre-existing routes.
	for route := range r.routes {
		if _, keep := newRoutes[route]; !keep {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Mask)
			routedel := []string{"route", "-q", "-n",
				"del", "-inet", nstr,
				"-iface", r.tunname}
			out, err := cmd(routedel...).CombinedOutput()
			if err != nil {
				r.logf("route del failed: %v: %v\n%s", routedel, err, out)
				if errq == nil {
					errq = err
				}
			}
		}
	}
	// Add the routes.
	for route := range newRoutes {
		if _, exists := r.routes[route]; !exists {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Mask)
			routeadd := []string{"route", "-q", "-n",
				"add", "-inet", nstr,
				"-iface", r.tunname}
			out, err := cmd(routeadd...).CombinedOutput()
			if err != nil {
				r.logf("addr add failed: %v: %v\n%s", routeadd, err, out)
				if errq == nil {
					errq = err
				}
			}
		}
	}

	// Store the interface and routes so we know what to change on an update.
	r.local = rs.LocalAddr
	r.routes = newRoutes

	if err := r.replaceResolvConf(rs.DNS, rs.DNSDomains); err != nil {
		errq = fmt.Errorf("replacing resolv.conf failed: %v", err)
	}

	return errq
}

func (r *freebsdRouter) Close() error {
	return nil
}

// TODO(mbaillie): these are no-ops for now. They could re-use the Linux funcs
// (sans systemd parts), but I note Linux DNS is disabled(?) so leaving for now.
func (r *freebsdRouter) replaceResolvConf(_ []wgcfg.IP, _ []string) error { return nil }
func (r *freebsdRouter) restoreResolvConf() error                         { return nil }
