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
	// endpointRoutes are host routes for WireGuard endpoints that should
	// bypass the tunnel. These prevent routing loops when exit node routes
	// (0.0.0.0/0 or ::/0) are active.
	endpointRoutes map[netip.Addr]localRouteInfo
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

	// Get gateway info before modifying routes, if we'll need it for local routes
	var ipv4Gw, ipv6Gw netip.Addr
	var gwIfaceName string
	if hasExitNodeRoutes && len(cfg.LocalRoutes) > 0 {
		var err error
		ipv4Gw, ipv6Gw, gwIfaceName, err = r.getDefaultGateway()
		if err != nil {
			r.logf("warning: could not get default gateway for local routes: %v", err)
		} else {
			r.logf("exit node: using gateway %v (iface %s) for local routes", ipv4Gw, gwIfaceName)
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

	// Handle WireGuard endpoint routes (host routes that bypass the tunnel).
	// These prevent routing loops when exit node routes are active.
	if err := r.setEndpointRoutes(cfg.ExitNodeEndpoints, ipv4Gw, ipv6Gw, gwIfaceName, hasExitNodeRoutes); err != nil {
		r.logf("endpoint routes setup failed: %v", err)
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

// setEndpointRoutes manages host routes for WireGuard endpoints that should bypass the tunnel.
// When using an exit node with /1 routes, these host routes ensure WireGuard endpoint
// traffic goes directly to the physical network instead of through the tunnel.
func (r *userspaceBSDRouter) setEndpointRoutes(endpoints []netip.Addr, ipv4Gw, ipv6Gw netip.Addr, gwIfaceName string, hasExitNode bool) error {
	// On macOS, we need to add explicit host routes for WireGuard endpoints when using
	// an exit node. Without these, the /1 routes would capture endpoint traffic,
	// creating a routing loop.
	if runtime.GOOS != "darwin" || !hasExitNode {
		// On FreeBSD or when not using an exit node, we don't need endpoint routes.
		// Clear any existing endpoint routes.
		for addr, info := range r.endpointRoutes {
			prefix := netip.PrefixFrom(addr, addr.BitLen())
			r.delRouteViaGateway(prefix, info.gateway, info.ifaceName)
		}
		r.endpointRoutes = nil
		return nil
	}

	newEndpointRoutes := make(map[netip.Addr]localRouteInfo)
	for _, addr := range endpoints {
		var gw netip.Addr
		if addr.Is4() {
			gw = ipv4Gw
		} else {
			gw = ipv6Gw
		}
		if !gw.IsValid() {
			r.logf("skipping endpoint route %v: no gateway available", addr)
			continue
		}
		newEndpointRoutes[addr] = localRouteInfo{gateway: gw, ifaceName: gwIfaceName}
	}

	// Delete routes that are no longer needed
	for addr, info := range r.endpointRoutes {
		if _, ok := newEndpointRoutes[addr]; !ok {
			prefix := netip.PrefixFrom(addr, addr.BitLen())
			r.delRouteViaGateway(prefix, info.gateway, info.ifaceName)
		}
	}

	// Add new routes
	for addr, info := range newEndpointRoutes {
		if existing, ok := r.endpointRoutes[addr]; ok && existing == info {
			// Route already exists with same gateway
			continue
		}
		// Delete old route if it exists with different gateway
		if existing, ok := r.endpointRoutes[addr]; ok {
			prefix := netip.PrefixFrom(addr, addr.BitLen())
			r.delRouteViaGateway(prefix, existing.gateway, existing.ifaceName)
		}
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		if err := r.addRouteViaGateway(prefix, info.gateway, info.ifaceName); err != nil {
			r.logf("failed to add endpoint route %v via %v: %v", addr, info.gateway, err)
			// Continue with other routes
		} else {
			r.logf("added endpoint route %v via %v (iface %s)", addr, info.gateway, info.ifaceName)
		}
	}

	r.endpointRoutes = newEndpointRoutes
	return nil
}

func (r *userspaceBSDRouter) Close() error {
	return nil
}
