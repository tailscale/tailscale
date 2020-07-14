// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"errors"
	"fmt"
	"log"
	"os/exec"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

// For now this router only supports the WireGuard userspace implementation.
// There is an experimental kernel version in the works for OpenBSD:
// https://git.zx2c4.com/wireguard-openbsd.

type openbsdRouter struct {
	logf    logger.Logf
	tunname string
	local   netaddr.IPPrefix
	routes  map[netaddr.IPPrefix]struct{}

	dnsConfig DNSConfig
}

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}
	return &openbsdRouter{
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

func (r *openbsdRouter) Up() error {
	ifup := []string{"ifconfig", r.tunname, "up"}
	if out, err := cmd(ifup...).CombinedOutput(); err != nil {
		r.logf("running ifconfig failed: %v\n%s", err, out)
		return err
	}
	return nil
}

func (r *openbsdRouter) Set(cfg *Config) error {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	// TODO: support configuring multiple local addrs on interface.
	if len(cfg.LocalAddrs) != 1 {
		return errors.New("freebsd doesn't support setting multiple local addrs yet")
	}
	localAddr := cfg.LocalAddrs[0]

	var errq error

	if localAddr != r.local {
		if r.local != (netaddr.IPPrefix{}) {
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
			"inet", localAddr.String(), "alias"}
		out, err := cmd(addradd...).CombinedOutput()
		if err != nil {
			r.logf("addr add failed: %v: %v\n%s", addradd, err, out)
			if errq == nil {
				errq = err
			}
		}

		routeadd := []string{"route", "-q", "-n",
			"add", "-inet", localAddr.String(),
			"-iface", localAddr.IP.String()}
		if out, err := cmd(routeadd...).CombinedOutput(); err != nil {
			r.logf("route add failed: %v: %v\n%s", routeadd, err, out)
			if errq == nil {
				errq = err
			}
		}
	}

	newRoutes := make(map[netaddr.IPPrefix]struct{})
	for _, route := range cfg.Routes {
		newRoutes[route] = struct{}{}
	}
	for route := range r.routes {
		if _, keep := newRoutes[route]; !keep {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Bits)
			routedel := []string{"route", "-q", "-n",
				"del", "-inet", nstr,
				"-iface", localAddr.IP.String()}
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
			nstr := fmt.Sprintf("%v/%d", nip, route.Bits)
			routeadd := []string{"route", "-q", "-n",
				"add", "-inet", nstr,
				"-iface", localAddr.IP.String()}
			out, err := cmd(routeadd...).CombinedOutput()
			if err != nil {
				r.logf("addr add failed: %v: %v\n%s", routeadd, err, out)
				if errq == nil {
					errq = err
				}
			}
		}
	}

	r.local = localAddr
	r.routes = newRoutes

	if !r.dnsConfig.EquivalentTo(cfg.DNSConfig) {
		if err := dnsDirectUp(cfg.DNSConfig); err != nil {
			errq = fmt.Errorf("dns up: direct: %v", err)
		} else {
			r.dnsConfig = cfg.DNSConfig
		}
	}

	return errq
}

func (r *openbsdRouter) Close() error {
	cleanup(r.logf, r.tunname)
	return nil
}

func cleanup(logf logger.Logf, interfaceName string) {
	if err := dnsDirectDown(); err != nil {
		logf("dns down: direct: %v", err)
	}
	out, err := cmd("ifconfig", interfaceName, "down").CombinedOutput()
	if err != nil {
		logf("ifconfig down: %v\n%s", err, out)
	}
}
