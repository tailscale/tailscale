// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd

package router

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"

	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

type userspaceBSDRouter struct {
	logf    logger.Logf
	tunname string
	local   []netaddr.IPPrefix
	routes  map[netaddr.IPPrefix]struct{}
}

func newUserspaceBSDRouter(logf logger.Logf, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}

	return &userspaceBSDRouter{
		logf:    logf,
		tunname: tunname,
	}, nil
}

func (r *userspaceBSDRouter) addrsToRemove(newLocalAddrs []netaddr.IPPrefix) (remove []netaddr.IPPrefix) {
	for _, cur := range r.local {
		found := false
		for _, v := range newLocalAddrs {
			found = (v == cur)
			if found {
				break
			}
		}
		if !found {
			remove = append(remove, cur)
		}
	}
	return
}

func (r *userspaceBSDRouter) addrsToAdd(newLocalAddrs []netaddr.IPPrefix) (add []netaddr.IPPrefix) {
	for _, cur := range newLocalAddrs {
		found := false
		for _, v := range r.local {
			found = (v == cur)
			if found {
				break
			}
		}
		if !found {
			add = append(add, cur)
		}
	}
	return
}

func cmd(args ...string) *exec.Cmd {
	if len(args) == 0 {
		log.Fatalf("exec.Cmd(%#v) invalid; need argv[0]", args)
	}
	return exec.Command(args[0], args[1:]...)
}

func (r *userspaceBSDRouter) Up() error {
	ifup := []string{"ifconfig", r.tunname, "up"}
	if out, err := cmd(ifup...).CombinedOutput(); err != nil {
		r.logf("running ifconfig failed: %v\n%s", err, out)
		return err
	}
	return nil
}

func inet(p netaddr.IPPrefix) string {
	if p.IP.Is6() {
		return "inet6"
	}
	return "inet"
}

func (r *userspaceBSDRouter) Set(cfg *Config) (reterr error) {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	var errq error
	setErr := func(err error) {
		if errq == nil {
			errq = err
		}
	}

	// Update the addresses.
	for _, addr := range r.addrsToRemove(cfg.LocalAddrs) {
		arg := []string{"ifconfig", r.tunname, inet(addr), addr.String(), "-alias"}
		out, err := cmd(arg...).CombinedOutput()
		if err != nil {
			r.logf("addr del failed: %v => %v\n%s", arg, err, out)
			setErr(err)
		}
	}
	for _, addr := range r.addrsToAdd(cfg.LocalAddrs) {
		var arg []string
		if runtime.GOOS == "freebsd" && addr.IP.Is6() && addr.Bits == 128 {
			// FreeBSD rejects tun addresses of the form fc00::1/128 -> fc00::1,
			// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=218508
			// Instead add our whole /48, which works because we use a /48 route.
			// Full history: https://github.com/tailscale/tailscale/issues/1307
			tmp := netaddr.IPPrefix{IP: addr.IP, Bits: 48}
			arg = []string{"ifconfig", r.tunname, inet(tmp), tmp.String()}
		} else {
			arg = []string{"ifconfig", r.tunname, inet(addr), addr.String(), addr.IP.String()}
		}
		out, err := cmd(arg...).CombinedOutput()
		if err != nil {
			r.logf("addr add failed: %v => %v\n%s", arg, err, out)
			setErr(err)
		}
	}

	newRoutes := make(map[netaddr.IPPrefix]struct{})
	for _, route := range cfg.Routes {
		newRoutes[route] = struct{}{}
	}
	// Delete any pre-existing routes.
	for route := range r.routes {
		if _, keep := newRoutes[route]; !keep {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Bits)
			del := "del"
			if version.OS() == "macOS" {
				del = "delete"
			}
			routedel := []string{"route", "-q", "-n",
				del, "-" + inet(route), nstr,
				"-iface", r.tunname}
			out, err := cmd(routedel...).CombinedOutput()
			if err != nil {
				r.logf("route del failed: %v: %v\n%s", routedel, err, out)
				setErr(err)
			}
		}
	}
	// Add the routes.
	for route := range newRoutes {
		if _, exists := r.routes[route]; !exists {
			net := route.IPNet()
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Bits)
			routeadd := []string{"route", "-q", "-n",
				"add", "-" + inet(route), nstr,
				"-iface", r.tunname}
			out, err := cmd(routeadd...).CombinedOutput()
			if err != nil {
				r.logf("addr add failed: %v: %v\n%s", routeadd, err, out)
				setErr(err)
			}
		}
	}

	// Store the interface and routes so we know what to change on an update.
	if errq == nil {
		r.local = append([]netaddr.IPPrefix{}, cfg.LocalAddrs...)
	}
	r.routes = newRoutes

	return errq
}

func (r *userspaceBSDRouter) Close() error {
	return nil
}
