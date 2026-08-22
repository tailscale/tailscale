// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd

package osrouter

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine/router"
)

func init() {
	router.HookNewUserspaceRouter.Set(func(opts router.NewOpts) (router.Router, error) {
		return newUserspaceBSDRouter(opts.Logf, opts.Tun, opts.NetMon, opts.Health)
	})
}

type userspaceBSDRouter struct {
	logf    logger.Logf
	netMon  *netmon.Monitor
	health  *health.Tracker
	tunname string
	local   []netip.Prefix
	routes  map[netip.Prefix]bool
	// localRoutes are routes that should bypass the tunnel (for LAN access).
	// These are tracked so we can remove them when they change.
	localRoutes map[netip.Prefix]localRouteInfo
	// bypassDefaultRoutes are IFSCOPE'd default routes via the original
	// physical gateway. They're only seen by sockets that bind to that
	// interface via IP_BOUND_IF (i.e. all of tailscaled's own sockets), so
	// tailscaled's traffic to the control plane, DERP, and other peers'
	// public endpoints still reaches the internet directly when the /1 exit
	// node routes are installed via utun.
	bypassDefaultRoutes map[netip.Prefix]localRouteInfo
}

// localRouteInfo stores info about a local route (one that bypasses the tunnel).
type localRouteInfo struct {
	gateway   netip.Addr // the gateway to route through
	ifaceName string     // the interface name
}

func newUserspaceBSDRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor, health *health.Tracker) (router.Router, error) {
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

// splitDefaultRoutes converts /0 routes into split /1 routes.
// On macOS, we can't simply add a default route (0.0.0.0/0) because it won't
// take precedence over the existing default route. Instead, we use two /1 routes
// that together cover all IP space but are more specific than /0.
// This is a common technique used by VPNs on macOS.
func splitDefaultRoutes(routes []netip.Prefix) []netip.Prefix {
	if runtime.GOOS != "darwin" {
		return routes
	}

	var result []netip.Prefix
	for _, route := range routes {
		if route == tsaddr.AllIPv4() {
			// Split 0.0.0.0/0 into 0.0.0.0/1 and 128.0.0.0/1
			result = append(result,
				netip.MustParsePrefix("0.0.0.0/1"),
				netip.MustParsePrefix("128.0.0.0/1"))
		} else if route == tsaddr.AllIPv6() {
			// Split ::/0 into ::/1 and 8000::/1
			result = append(result,
				netip.MustParsePrefix("::/1"),
				netip.MustParsePrefix("8000::/1"))
		} else {
			result = append(result, route)
		}
	}
	return result
}

// getDefaultGateway returns the default gateway IP and interface name.
// It looks for the current default route before we've added our routes.
func (r *userspaceBSDRouter) getDefaultGateway() (ipv4Gw, ipv6Gw netip.Addr, ifaceName string, err error) {
	// Use netmon to get the default route interface
	if r.netMon != nil {
		state := r.netMon.InterfaceState()
		if state != nil && state.DefaultRouteInterface != "" {
			ifaceName = state.DefaultRouteInterface
		}
	}

	// If we don't have netmon or couldn't get interface, try to find it
	if ifaceName == "" {
		idx, err := netmon.DefaultRouteInterfaceIndex()
		if err != nil {
			return netip.Addr{}, netip.Addr{}, "", err
		}
		iface, err := net.InterfaceByIndex(idx)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, "", err
		}
		ifaceName = iface.Name
	}

	// Don't use the tunnel interface as the gateway interface
	if strings.HasPrefix(ifaceName, "utun") || ifaceName == r.tunname {
		return netip.Addr{}, netip.Addr{}, "", fmt.Errorf("default interface is tunnel interface %s", ifaceName)
	}

	// Get the gateway IP using likelyHomeRouterIP
	gw, _, ok := netmon.LikelyHomeRouterIP()
	if ok && gw.Is4() {
		ipv4Gw = gw
	}

	return ipv4Gw, ipv6Gw, ifaceName, nil
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

	// If we're removing all addresses, we need to remove and re-add all
	// routes.
	resetRoutes := len(r.local) > 0 && len(addrsToRemove) == len(r.local)

	// Check if this config has exit node routes (default routes)
	hasExitNodeRoutes := false
	for _, route := range cfg.Routes {
		if route == tsaddr.AllIPv4() || route == tsaddr.AllIPv6() {
			hasExitNodeRoutes = true
			break
		}
	}

	// Get gateway info before modifying routes. We need it for the bypass
	// default route, the per-endpoint host routes, and any LAN-access local
	// routes — all of which sit alongside the /1 exit node routes.
	var ipv4Gw, ipv6Gw netip.Addr
	var gwIfaceName string
	if hasExitNodeRoutes {
		var err error
		ipv4Gw, ipv6Gw, gwIfaceName, err = r.getDefaultGateway()
		if err != nil {
			r.logf("warning: could not get default gateway for exit node bypass routes: %v", err)
		} else {
			r.logf("exit node: using gateway %v (iface %s) for bypass routes", ipv4Gw, gwIfaceName)
		}
	}

	// Update the addresses.
	for _, addr := range addrsToRemove {
		arg := []string{"ifconfig", r.tunname, inet(addr), addr.String(), "-alias"}
		out, err := cmd(arg...).CombinedOutput()
		if err != nil {
			r.logf("addr del failed: %v => %v\n%s", arg, err, out)
			setErr(err)
		}
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
		}
	}

	// On macOS, split /0 routes into /1 routes so they take precedence
	// over the existing default route.
	routes := splitDefaultRoutes(cfg.Routes)

	newRoutes := make(map[netip.Prefix]bool)
	for _, route := range routes {
		if runtime.GOOS != "darwin" && route == tsaddr.TailscaleULARange() {
			// Because we added the interface address as a /48 above,
			// the kernel already created the Tailscale ULA route
			// implicitly. We mustn't try to add/delete it ourselves.
			continue
		}
		newRoutes[route] = true
	}

	// Delete any preexisting tunnel routes.
	for route := range r.routes {
		if resetRoutes || !newRoutes[route] {
			r.delRoute(route, r.tunname)
		}
	}

	// Add the tunnel routes.
	for route := range newRoutes {
		if resetRoutes || !r.routes[route] {
			if err := r.addRoute(route, r.tunname); err != nil {
				r.logf("route add failed: %v: %v", route, err)
				setErr(err)
			}
		}
	}

	// Handle local routes (routes that should bypass the tunnel).
	// These are used for LAN access when using an exit node.
	if err := r.setLocalRoutes(cfg.LocalRoutes, ipv4Gw, ipv6Gw, gwIfaceName, hasExitNodeRoutes); err != nil {
		r.logf("local routes setup failed: %v", err)
		setErr(err)
	}

	// Install IFSCOPE'd default routes via the original gateway so
	// tailscaled's own sockets (which bind to the physical interface via
	// IP_BOUND_IF) can still reach the control plane, DERP, and peer
	// endpoints when the /1 exit node routes are active.
	if err := r.setBypassDefaultRoutes(ipv4Gw, ipv6Gw, gwIfaceName, hasExitNodeRoutes); err != nil {
		r.logf("bypass default route setup failed: %v", err)
		setErr(err)
	}

	// Store the interface and routes so we know what to change on an update.
	if reterr == nil {
		r.local = append([]netip.Prefix{}, cfg.LocalAddrs...)
	}
	r.routes = newRoutes

	return reterr
}

// addRoute adds a route via the specified interface.
func (r *userspaceBSDRouter) addRoute(route netip.Prefix, iface string) error {
	net := netipx.PrefixIPNet(route)
	nip := net.IP.Mask(net.Mask)
	nstr := fmt.Sprintf("%v/%d", nip, route.Bits())
	routeadd := []string{"route", "-q", "-n",
		"add", "-" + inet(route), nstr,
		"-iface", iface}
	out, err := cmd(routeadd...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %v\n%s", routeadd, err, out)
	}
	return nil
}

// addRouteViaGateway adds a route via the specified gateway IP.
func (r *userspaceBSDRouter) addRouteViaGateway(route netip.Prefix, gateway netip.Addr, iface string) error {
	net := netipx.PrefixIPNet(route)
	nip := net.IP.Mask(net.Mask)
	nstr := fmt.Sprintf("%v/%d", nip, route.Bits())
	routeadd := []string{"route", "-q", "-n",
		"add", "-" + inet(route), nstr,
		gateway.String()}
	// On macOS, we can also specify the interface with -ifscope to ensure
	// the route uses the correct interface even if there are multiple
	// interfaces with access to the same gateway.
	if version.OS() == "macOS" && iface != "" {
		routeadd = append(routeadd, "-ifscope", iface)
	}
	out, err := cmd(routeadd...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %v\n%s", routeadd, err, out)
	}
	return nil
}

// delRoute deletes a route via the specified interface.
func (r *userspaceBSDRouter) delRoute(route netip.Prefix, iface string) {
	net := netipx.PrefixIPNet(route)
	nip := net.IP.Mask(net.Mask)
	nstr := fmt.Sprintf("%v/%d", nip, route.Bits())
	del := "del"
	if version.OS() == "macOS" {
		del = "delete"
	}
	routedel := []string{"route", "-q", "-n",
		del, "-" + inet(route), nstr,
		"-iface", iface}
	out, err := cmd(routedel...).CombinedOutput()
	if err != nil {
		r.logf("route del failed: %v: %v\n%s", routedel, err, out)
	}
}

// delRouteViaGateway deletes a route that was added via a gateway.
func (r *userspaceBSDRouter) delRouteViaGateway(route netip.Prefix, gateway netip.Addr, iface string) {
	net := netipx.PrefixIPNet(route)
	nip := net.IP.Mask(net.Mask)
	nstr := fmt.Sprintf("%v/%d", nip, route.Bits())
	del := "del"
	if version.OS() == "macOS" {
		del = "delete"
	}
	routedel := []string{"route", "-q", "-n",
		del, "-" + inet(route), nstr,
		gateway.String()}
	if version.OS() == "macOS" && iface != "" {
		routedel = append(routedel, "-ifscope", iface)
	}
	out, err := cmd(routedel...).CombinedOutput()
	if err != nil {
		r.logf("local route del failed: %v: %v\n%s", routedel, err, out)
	}
}

// setLocalRoutes manages routes for local networks that should bypass the tunnel.
// When using an exit node with LAN access enabled, these routes ensure local
// traffic goes directly to the LAN instead of through the tunnel.
func (r *userspaceBSDRouter) setLocalRoutes(localRoutes []netip.Prefix, ipv4Gw, ipv6Gw netip.Addr, gwIfaceName string, hasExitNode bool) error {
	// On macOS, we need to add explicit routes for local networks when using
	// an exit node. Without these, the /1 routes would capture all traffic
	// including local traffic.
	if runtime.GOOS != "darwin" || !hasExitNode {
		// On FreeBSD or when not using an exit node, we don't need local routes.
		// Clear any existing local routes.
		for route, info := range r.localRoutes {
			r.delRouteViaGateway(route, info.gateway, info.ifaceName)
		}
		r.localRoutes = nil
		return nil
	}

	newLocalRoutes := make(map[netip.Prefix]localRouteInfo)
	for _, route := range localRoutes {
		var gw netip.Addr
		if route.Addr().Is4() {
			gw = ipv4Gw
		} else {
			gw = ipv6Gw
		}
		if !gw.IsValid() {
			r.logf("skipping local route %v: no gateway available", route)
			continue
		}
		newLocalRoutes[route] = localRouteInfo{gateway: gw, ifaceName: gwIfaceName}
	}

	// Delete routes that are no longer needed
	for route, info := range r.localRoutes {
		if _, ok := newLocalRoutes[route]; !ok {
			r.delRouteViaGateway(route, info.gateway, info.ifaceName)
		}
	}

	// Add new routes
	for route, info := range newLocalRoutes {
		if existing, ok := r.localRoutes[route]; ok && existing == info {
			// Route already exists with same gateway
			continue
		}
		// Delete old route if it exists with different gateway
		if existing, ok := r.localRoutes[route]; ok {
			r.delRouteViaGateway(route, existing.gateway, existing.ifaceName)
		}
		if err := r.addRouteViaGateway(route, info.gateway, info.ifaceName); err != nil {
			r.logf("failed to add local route %v via %v: %v", route, info.gateway, err)
			// Continue with other routes
		}
	}

	r.localRoutes = newLocalRoutes
	return nil
}

// setBypassDefaultRoutes installs IFSCOPE'd default routes via the original
// physical gateway. Such routes are only consulted by sockets that bind to that
// interface via IP_BOUND_IF, so they don't override the /1 routes used to
// redirect general traffic through the exit node tunnel — but they do let
// tailscaled's own sockets (which all use IP_BOUND_IF) reach external IPs
// without being captured by the /1 routes.
//
// Without this, only destinations that have an explicit IFSCOPE'd host route
// (e.g. the exit node's WireGuard endpoint) bypass the tunnel; the control
// plane, DERP servers, and other peers' public endpoints all get pulled into
// the tunnel and the responses come back addressed to our Tailscale IP rather
// than our physical IP, breaking those connections.
func (r *userspaceBSDRouter) setBypassDefaultRoutes(ipv4Gw, ipv6Gw netip.Addr, gwIfaceName string, hasExitNode bool) error {
	if runtime.GOOS != "darwin" || !hasExitNode {
		for route, info := range r.bypassDefaultRoutes {
			r.delRouteViaGateway(route, info.gateway, info.ifaceName)
		}
		r.bypassDefaultRoutes = nil
		return nil
	}

	newRoutes := make(map[netip.Prefix]localRouteInfo)
	if ipv4Gw.IsValid() && gwIfaceName != "" {
		newRoutes[tsaddr.AllIPv4()] = localRouteInfo{gateway: ipv4Gw, ifaceName: gwIfaceName}
	}
	if ipv6Gw.IsValid() && gwIfaceName != "" {
		newRoutes[tsaddr.AllIPv6()] = localRouteInfo{gateway: ipv6Gw, ifaceName: gwIfaceName}
	}

	for route, info := range r.bypassDefaultRoutes {
		if newInfo, ok := newRoutes[route]; !ok || newInfo != info {
			r.delRouteViaGateway(route, info.gateway, info.ifaceName)
		}
	}

	for route, info := range newRoutes {
		if existing, ok := r.bypassDefaultRoutes[route]; ok && existing == info {
			continue
		}
		if err := r.addRouteViaGateway(route, info.gateway, info.ifaceName); err != nil {
			r.logf("failed to add bypass default route %v via %v: %v", route, info.gateway, err)
			continue
		}
		r.logf("added bypass default route %v via %v (ifscope %s)", route, info.gateway, info.ifaceName)
	}

	r.bypassDefaultRoutes = newRoutes
	return nil
}

func (r *userspaceBSDRouter) Close() error {
	return nil
}
