// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"log"
	"net"
	"os/exec"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/logger"
)

// For now this router only supports the userspace WireGuard implementations.
//
// There is an experimental kernel version in the works:
// https://git.zx2c4.com/wireguard-openbsd.
//
// TODO(mbaillie): netlink-style monitoring might be possible through
// `ifstated(8)`/`devd(8)`, or become possible with the OpenBSD kernel
// implementation. This merits further investigation.

type openbsdRouter struct {
	logf    logger.Logf
	tunname string
	local   wgcfg.CIDR
	routes  map[wgcfg.CIDR]struct{}
}

func NewUserspaceRouter(logf logger.Logf, tunname string, _ *device.Device, tuntap tun.Device, _ func()) Router {
	r := openbsdRouter{
		logf:    logf,
		tunname: tunname,
	}
	return &r
}

// TODO(mbaillie): extract as identical to linux version
func cmd(args ...string) *exec.Cmd {
	if len(args) == 0 {
		log.Fatalf("exec.Cmd(%#v) invalid; need argv[0]\n", args)
	}
	return exec.Command(args[0], args[1:]...)
}

func (r *openbsdRouter) Up() error {
	// TODO(mbaillie): MTU set elsewhere?

	ifup := []string{"ifconfig", r.tunname, "up"}
	if out, err := cmd(ifup...).CombinedOutput(); err != nil {
		r.logf("running ifconfig failed: %v\n%s", err, out)
		return err
	}
	return nil
}

func (r *openbsdRouter) SetRoutes(rs RouteSettings) error {
	var errq error

	if rs.LocalAddr != r.local {
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

			routedel := []string{"route", "-q", "-n",
				"del", "-inet", r.local.String(),
				"-iface", r.local.IP.String()}
			if out, err := cmd(routedel...).CombinedOutput(); err != nil {
				r.logf("route del failed: %v: %v\n%s", routedel, err, out)
				if errq == nil {
					errq = err
				}
			}
		}

		addradd := []string{"ifconfig", r.tunname,
			"inet", rs.LocalAddr.String(), "alias"}
		out, err := cmd(addradd...).CombinedOutput()
		if err != nil {
			r.logf("addr add failed: %v: %v\n%s", addradd, err, out)
			if errq == nil {
				errq = err
			}
		}

		routeadd := []string{"route", "-q", "-n",
			"add", "-inet", rs.LocalAddr.String(),
			"-iface", rs.LocalAddr.IP.String()}
		if out, err := cmd(routeadd...).CombinedOutput(); err != nil {
			r.logf("route add failed: %v: %v\n%s", routeadd, err, out)
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
	for route := range r.routes {
		if _, keep := newRoutes[route]; !keep {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Mask)
			routedel := []string{"route", "-q", "-n",
				"del", "-inet", nstr,
				"-iface", rs.LocalAddr.IP.String()}
			out, err := cmd(routedel...).CombinedOutput()
			if err != nil {
				r.logf("route del failed: %v: %v\n%s", routedel, err, out)
				if errq == nil {
					errq = err
				}
			}
		}
	}
	for route := range newRoutes {
		if _, exists := r.routes[route]; !exists {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Mask)
			routeadd := []string{"route", "-q", "-n",
				"add", "-inet", nstr,
				"-iface", rs.LocalAddr.IP.String()}
			out, err := cmd(routeadd...).CombinedOutput()
			if err != nil {
				r.logf("addr add failed: %v: %v\n%s", routeadd, err, out)
				if errq == nil {
					errq = err
				}
			}
		}
	}

	r.local = rs.LocalAddr
	r.routes = newRoutes

	if err := r.replaceResolvConf(rs.DNS, rs.DNSDomains); err != nil {
		errq = fmt.Errorf("replacing resolv.conf failed: %v", err)
	}

	return errq
}

func (r *openbsdRouter) Close() {
	out, err := cmd("ifconfig", r.tunname, "down").CombinedOutput()
	if err != nil {
		r.logf("running ifconfig failed: %v\n%s", err, out)
	}

	if err := r.restoreResolvConf(); err != nil {
		r.logf("failed to restore system resolv.conf: %v", err)
	}

	// TODO(mbaillie): wipe routes
}

// TODO(mbaillie): these are no-ops for now. They could re-use the Linux funcs
// (sans systemd parts), but I note Linux DNS is disabled(?) so leaving for now.
func (r *openbsdRouter) replaceResolvConf(_ []net.IP, _ []string) error { return nil }
func (r *openbsdRouter) restoreResolvConf() error                       { return nil }
