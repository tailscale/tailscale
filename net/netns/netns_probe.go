// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netns contains the common code for using the Go net package
// in a logical "network namespace" to avoid routing loops where
// Tailscale-created packets would otherwise loop back through
// Tailscale routes.
//
// Despite the name netns, the exact mechanism used differs by
// operating system, and perhaps even by version of the OS.
//
// The netns package also handles connecting via SOCKS proxies when
// configured by the environment.

package netns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/gaissmai/bart"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

// tailscaleInterface returns the current machine's Tailscale interface, if any.
// If none is found, (nil, nil) is returned.
// A non-nil error is only returned on a problem listing the system interfaces.
// TODO (barnstar): netmon *usually* knows this (at least for darwing), but
// this is more portable.  It's still wildly different than the Windows method which
// checks the description strings.
func tailscaleInterface() (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				nip, ok := netip.AddrFromSlice(ipnet.IP)
				if ok && tsaddr.IsTailscaleIP(nip.Unmap()) {
					return &iface, nil
				}
			}
		}
	}
	return nil, nil
}

// inetReachability describes an interface and whether it was able to reach
// the provided address.
type inetReachability struct {
	iface net.Interface
	// TODO (barnstar): These are invariant.  reachable should be true if err==nil.
	reachable bool
	err       error
}

// Tuple of the destination host, port, and network.
// ie: "tcp4", "example.com", "80"
type HostPortNetwork struct {
	Host    string
	Port    string
	Network string
}

func (hpn HostPortNetwork) String() string {
	return fmt.Sprintf("%s/%s:%s", hpn.Network, hpn.Host, hpn.Port)
}

type probeOpts struct {
	logf    logger.Logf
	hpn     HostPortNetwork
	race    bool            // if true, we'll pick the first interface that responds.  sortf is ignored.
	filterf interfaceFilter // optional pre-filter for interfaces
	cache   *routeCache     // must be non-nil
}

type DefaultIfaceHintFn func() int

var defaultIfaceHintFn DefaultIfaceHintFn

// Platforms may set defaultIFQueryFn to a function that returns the platforms's high
// level view of the default interface index.
func SetDefaultIFQueryFn(fn DefaultIfaceHintFn) {
	defaultIfaceHintFn = fn
}

// uint
type bindFn func(c syscall.RawConn, ifidx uint32) error

// Returns the proper bind function for the given network and address.
// Currently only differentiates between IPv4 and IPv6 - and poorly.
func bindFnByAddrType(network, address string) bindFn {
	// Very naive check for IPv6.
	if strings.Contains(address, "]:") || strings.HasSuffix(network, "6") {
		return bindSocket6
	}
	return bindSocket4
}

type bindFunctionHook func(network, address string) bindFn

var getBindFn bindFunctionHook = bindFnByAddrType

var interfacesHookFn func() ([]net.Interface, error)

var interfacesHook = net.Interfaces

// ProbeInterfacesReachability probes all non-loopback, up interfaces
// concurrently to determine which can reach the given address. It returns
// a slice with one entry per probed interface in the same order as
// net.Interfaces() filtered by the probe criteria.
func probeInterfacesReachability(opts probeOpts) ([]inetReachability, error) {
	ifaces, err := interfacesHook()
	if err != nil {
		opts.logf("netns: ProbeInterfacesReachability: net.Interfaces: %v", err)
		return nil, err
	}

	results := make(chan inetReachability, len(ifaces))

	tsiface, _ := tailscaleInterface()

	var candidates []net.Interface
	for _, iface := range ifaces {
		// Individual platforms can exclude potential intefaces based on platorm-specific logic.
		// For example, on Darwin, we skip "utun" interfaces.
		if opts.filterf != nil && !opts.filterf(iface) {
			continue
		}

		// Only consider up, non-loopback interfaces.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagRunning == 0 {
			continue
		}

		// Skip the Tailscale interface.
		if tsiface != nil && iface.Index == tsiface.Index {
			continue
		}

		// require an IPv4 or IPv6 global unicast address
		if !ifaceHasV4OrGlobalV6(&iface) {
			continue
		}

		candidates = append(candidates, iface)
	}

	if len(candidates) == 0 {
		opts.logf("netns: ProbeInterfacesReachability: no candidate interfaces found")
		return nil, errors.New("no candidate interfaces")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, iface := range candidates {
		go func() {
			// Per-probe timeout.

			err := reachabilityHook(&iface, opts.hpn)

			select {
			case results <- inetReachability{iface: iface, reachable: err == nil, err: err}:
			case <-ctx.Done():
			}
		}()
	}

	out := make([]inetReachability, 0, len(candidates))
	timeout := time.After(600 * time.Millisecond)
	received := 0

	for received < len(candidates) {
		select {
		case r := <-results:
			// If we're racing, return the first reachable interface immediately.
			// TODO (barnstar): We should cache all reachable results so we can try alteratives if we
			// can't get the conn up and running later but signal early if we're racing.
			if opts.race && r.reachable {
				return []inetReachability{r}, nil
			}
			// .. otherwise, collect all results including the unreachable ones.
			out = append(out, r)
			received++
		case <-timeout:
			return out, fmt.Errorf("netns: probe timed out after %v; received %d/%d results", timeout, received, len(candidates))
		}
	}

	return out, nil
}

// For testing
type reachabilityHookFn func(iface *net.Interface, hpn HostPortNetwork) error

var reachabilityHook reachabilityHookFn = reachabilityCheck

func reachabilityCheck(iface *net.Interface, hpn HostPortNetwork) error {
	// Per-probe timeout.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer dialCancel()

	d := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			// (barnstar) TODO: The bind step here is still platform specific
			bindFn := getBindFn(network, address)
			return bindFn(c, uint32(iface.Index))
		},
	}

	dst := net.JoinHostPort(hpn.Host, hpn.Port)
	conn, err := d.DialContext(dialCtx, hpn.Network, dst)
	if err == nil {
		defer conn.Close()
	}
	return err
}

// Pre-filter for interfaces.  Platform-specific code can provide a filter
// to exclude certain interfaces from consideration.  For example, on Darwin,
// we exclude "utun" interfaces and various other types which will never provie
// have general internet connectivity.
type interfaceFilter func(net.Interface) bool

func filterInPlace[T any](s []T, keep func(T) bool) []T {
	i := 0
	for _, v := range s {
		if keep(v) {
			s[i] = v
			i++
		}
	}
	return s[:i]
}

var errUnspecifiedHost = errors.New("unspecified host")

func parseAddress(address string) (addr netip.Addr, err error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// error means the string didn't contain a port number, so use the string directly
		host = address
	}
	if host == "" {
		return addr, errUnspecifiedHost
	}

	return netip.ParseAddr(host)
}

// findInterfaceThatCanReach finds an interface that can reach the given host:port.
// It uses the provided filterf to exclude certain interfaces, and the
// sortf to prioritize certain interfaces. It returns the first interface that can reach
// the destination.
//
// TODO (barnstar): What this does NOT do is provide a way to flag an interface as "bad" if
// we can't get a connection up and running.  Ideally we race for the first candidate, try
// it for a partciular route, and if it fails, remove it from the route cache try a "different"
// candidate.  This requires the Dialer to be aware of this logic, and to be able to signal
// back to the route cache that a given interface is "bad" for a given destination.  We also
// need to cache all of the candidates found during probing so we can try them again later some
// related state.
//
// nil is returned if no interface can reach the destination.
func findInterfaceThatCanReach(opts probeOpts) (iface *net.Interface, err error) {
	// Try to parse the host as an IP address for cache lookup
	addr, err := parseAddress(opts.hpn.Host)
	if err == nil && addr.IsValid() {
		// Check cache first
		if cached := opts.cache.lookupCachedRoute(addr); cached != nil {
			opts.logf("netns: using cached interface %v for %v", cached.Name, opts.hpn)
			return cached, nil
		}
	}

	res, err := probeInterfacesReachability(opts)
	if err != nil {
		opts.logf("netns: ProbeInterfacesReachability error: %v", err)
		return nil, err
	}

	res = filterInPlace(res, func(r inetReachability) bool { return r.reachable })
	if len(res) == 0 {
		opts.logf("netns: could not find interface on network %v to reach %q:%q on %q: %v", opts.hpn.Network, opts.hpn.Host, opts.hpn.Port, opts.hpn.Network, err)
		return nil, nil
	}

	candidatesNames := make([]string, 0, len(res))
	for _, r := range res {
		candidatesNames = append(candidatesNames, r.iface.Name)
	}
	opts.logf("netns: found candidate interfaces that can reach %v:%v on %v:  %v", opts.hpn.Host, opts.hpn.Port, opts.hpn.Network, candidatesNames)
	iface = &res[0].iface

	if defaultIfaceHintFn != nil {
		defIdx := defaultIfaceHintFn()
		for _, r := range res {
			if r.iface.Index == defIdx {
				opts.logf("netns: using default iface hint")
				iface = &r.iface
				break
			}
		}
	}

	opts.logf("netns: returning interface %v at %v for %v:%v", iface.Name, iface.Index, opts.hpn.Host, opts.hpn.Port)

	// Cache the result if we have a valid IP address
	if addr.IsValid() {
		opts.cache.setCachedRoute(addr, iface)
	}

	return iface, nil
}

var ifaceHasV4AndGlobalV6Hook func(iface *net.Interface) bool

// ifaceHasV4AndGlobalV6 reports whether iface has at least one IPv4 address
// and at least one IPv6 address that is not link-local.
func ifaceHasV4OrGlobalV6(iface *net.Interface) bool {
	if ifaceHasV4AndGlobalV6Hook != nil {
		return ifaceHasV4AndGlobalV6Hook(iface)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP.IsGlobalUnicast() {
				return true
			}

		}
	}
	return false
}

var globalRouteCache *routeCache

// SetGlobalRouteCache sets the global route cache used by netns.
// It also subscribes the route cache to network change events from
// the provided event bus.
func SetGlobalRouteCache(rc *routeCache, e *eventbus.Bus, logf logger.Logf) {
	globalRouteCache = rc
	globalRouteCache.subscribeToNetworkChanges(e, logf)
}

func NewRouteCache() *routeCache {
	return &routeCache{
		v4: new(bart.Table[*net.Interface]),
		v6: new(bart.Table[*net.Interface]),
	}
}

type routeCache struct {
	mu syncs.Mutex
	v4 *bart.Table[*net.Interface] // IPv4 routing table
	v6 *bart.Table[*net.Interface] // IPv6 routing table
	ec *eventbus.Client
}

func (rc *routeCache) subscribeToNetworkChanges(eventBus *eventbus.Bus, logf logger.Logf) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.ec != nil {
		rc.ec.Close()
	}

	rc.ec = eventBus.Client("routeCache")
	eventbus.SubscribeFunc(rc.ec, func(cd netmon.ChangeDelta) {
		if cd.RebindLikelyRequired {
			logf("netns: routeCache: major clearing all cached routes due to network change: %v", cd)
			rc.ClearAllCachedRoutes()
		}
	})
	logf("netns: routeCache: subscribed to network change events")
}

func (rc *routeCache) lookupCachedRoute(addr netip.Addr) *net.Interface {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	iface, ok := rc.tableForAddr(addr).Lookup(addr)
	if !ok {
		return nil
	}
	return iface
}

func (rc *routeCache) setCachedRoute(addr netip.Addr, iface *net.Interface) {
	prefix := netip.PrefixFrom(addr, addrBits(addr))
	rc.setCachedRoutePrefix(prefix, iface)
}

func (rc *routeCache) setCachedRoutePrefix(prefix netip.Prefix, iface *net.Interface) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	addr := prefix.Addr()
	rc.tableForAddr(addr).Insert(prefix, iface)
}

func (rc *routeCache) clearCachedRoutePrefix(prefix netip.Prefix) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	addr := prefix.Addr()
	rc.tableForAddr(addr).Delete(prefix)
}

func (rc *routeCache) ClearCachedRoute(addr netip.Addr) {
	prefix := netip.PrefixFrom(addr, addrBits(addr))
	rc.clearCachedRoutePrefix(prefix)
}

func (rc *routeCache) ClearAllCachedRoutes() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.v4 = new(bart.Table[*net.Interface])
	rc.v6 = new(bart.Table[*net.Interface])
}

func addrBits(addr netip.Addr) int {
	if addr.Is6() {
		return 128
	}
	return 32
}

func (rc *routeCache) tableForAddr(addr netip.Addr) *bart.Table[*net.Interface] {
	if addr.Is6() {
		return rc.v6
	}
	return rc.v4
}
