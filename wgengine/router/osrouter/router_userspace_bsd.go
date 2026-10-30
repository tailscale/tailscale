// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd

package osrouter

import (
	"bytes"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"

	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine/router"
)

type userspaceBSDRouter struct {
	logf    logger.Logf
	netMon  *netmon.Monitor
	health  *health.Tracker
	tunname string
	local   []netip.Prefix
	routes  map[netip.Prefix]bool
}

func newUserspaceBSDRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor, health *health.Tracker) (*userspaceBSDRouter, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}

	return &userspaceBSDRouter{
		logf:    logf,
		netMon:  netMon,
		health:  health,
		tunname: tunname,
	}, nil
}

func (r *userspaceBSDRouter) addrsToRemove(newLocalAddrs []netip.Prefix) (remove []netip.Prefix) {
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

func (r *userspaceBSDRouter) addrsToAdd(newLocalAddrs []netip.Prefix) (add []netip.Prefix) {
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

func inet(p netip.Prefix) string {
	if p.Addr().Is6() {
		return "inet6"
	}
	return "inet"
}

func (r *userspaceBSDRouter) Set(cfg *router.Config) (reterr error) {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	setErr := func(err error) {
		if reterr == nil {
			reterr = err
		}
	}
	addrsToRemove := r.addrsToRemove(cfg.LocalAddrs)

	// Removing an address drops the kernel routes through it, so the routes
	// of that address family must be deleted and re-added.
	resetFamily := map[bool]bool{} // keyed by Is4
	for _, addr := range addrsToRemove {
		resetFamily[addr.Addr().Is4()] = true
	}
	resetRoute := func(p netip.Prefix) bool { return resetFamily[p.Addr().Is4()] }

	// local tracks the addresses actually on the interface regardless of
	// route errors below. If it went stale, a later Set would re-add an
	// address that is already there, which FreeBSD does by deleting it
	// first, flushing every route through it.
	local := slices.Clone(r.local)

	// Update the addresses.
	for _, addr := range addrsToRemove {
		arg := []string{"ifconfig", r.tunname, inet(addr), addr.String(), "-alias"}
		out, err := cmd(arg...).CombinedOutput()
		if err != nil {
			r.logf("addr del failed: %v => %v\n%s", arg, err, out)
			setErr(err)
			continue
		}
		local = slices.DeleteFunc(local, func(p netip.Prefix) bool { return p == addr })
	}
	for _, addr := range r.addrsToAdd(cfg.LocalAddrs) {
		var arg []string
		if runtime.GOOS == "freebsd" && addr.Addr().Is6() && addr.Bits() == 128 {
			// FreeBSD rejects tun addresses of the form fc00::1/128 -> fc00::1,
			// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=218508
			// Instead add our whole /48, which works because we use a /48 route.
			// Full history: https://github.com/tailscale/tailscale/issues/1307
			tmp := netip.PrefixFrom(addr.Addr(), 48)
			arg = []string{"ifconfig", r.tunname, inet(tmp), tmp.String()}
		} else {
			arg = []string{"ifconfig", r.tunname, inet(addr), addr.String(), addr.Addr().String()}
		}
		out, err := cmd(arg...).CombinedOutput()
		if err != nil {
			r.logf("addr add failed: %v => %v\n%s", arg, err, out)
			setErr(err)
			continue
		}
		local = append(local, addr)
	}

	newRoutes := make(map[netip.Prefix]bool)
	for _, route := range cfg.Routes {
		if runtime.GOOS != "darwin" && route == tsaddr.TailscaleULARange() {
			// Because we added the interface address as a /48 above,
			// the kernel already created the Tailscale ULA route
			// implicitly. We mustn't try to add/delete it ourselves.
			continue
		}
		newRoutes[route] = true
	}
	// Delete any preexisting routes.
	for route := range r.routes {
		if resetRoute(route) || !newRoutes[route] {
			net := netipx.PrefixIPNet(route)
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Bits())
			del := "del"
			if version.OS() == "macOS" {
				del = "delete"
			}
			routedel := []string{"route", "-q", "-n",
				del, "-" + inet(route), nstr,
				"-iface", r.tunname}
			out, err := cmd(routedel...).CombinedOutput()
			if err != nil && !(resetRoute(route) && routeNotFound(out)) {
				r.logf("route del failed: %v: %v\n%s", routedel, err, out)
				setErr(err)
			}
		}
	}
	// Add the routes.
	for route := range newRoutes {
		if resetRoute(route) || !r.routes[route] {
			net := netipx.PrefixIPNet(route)
			nip := net.IP.Mask(net.Mask)
			nstr := fmt.Sprintf("%v/%d", nip, route.Bits())
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
	r.local = local
	r.routes = newRoutes

	return reterr
}

// routeNotFound reports whether route(8) output says the route to delete
// does not exist ("not in table" on macOS/OpenBSD, "has not been found" on
// FreeBSD), as when removing an address already took it away.
func routeNotFound(out []byte) bool {
	return bytes.Contains(out, []byte("not in table")) || bytes.Contains(out, []byte("has not been found"))
}

func (r *userspaceBSDRouter) Close() error {
	return nil
}
