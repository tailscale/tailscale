// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package interfaces

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"inet.af/netaddr"
	"tailscale.com/tsconst"
)

const (
	fallbackInterfaceMetric = uint32(0) // Used if we cannot get the actual interface metric
)

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPWindows
	getPAC = getPACWindows
}

func likelyHomeRouterIPWindows() (ret netaddr.IP, ok bool) {
	rs, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		log.Printf("routerIP/GetIPForwardTable2 error: %v", err)
		return
	}

	var ifaceMetricCache map[winipcfg.LUID]uint32

	getIfaceMetric := func(luid winipcfg.LUID) (metric uint32) {
		if ifaceMetricCache == nil {
			ifaceMetricCache = make(map[winipcfg.LUID]uint32)
		} else if m, ok := ifaceMetricCache[luid]; ok {
			return m
		}

		if iface, err := luid.IPInterface(windows.AF_INET); err == nil {
			metric = iface.Metric
		} else {
			log.Printf("routerIP/luid.IPInterface error: %v", err)
			metric = fallbackInterfaceMetric
		}

		ifaceMetricCache[luid] = metric
		return
	}

	unspec := net.IPv4(0, 0, 0, 0)
	var best *winipcfg.MibIPforwardRow2 // best (lowest metric) found so far, or nil

	for i := range rs {
		r := &rs[i]
		if r.Loopback || r.DestinationPrefix.PrefixLength != 0 || !r.DestinationPrefix.Prefix.IP().Equal(unspec) {
			// Not a default route, so skip
			continue
		}

		ip, ok := netaddr.FromStdIP(r.NextHop.IP())
		if !ok {
			// Not a valid gateway, so skip (won't happen though)
			continue
		}

		if best == nil {
			best = r
			ret = ip
			continue
		}

		// We can get here only if there are multiple default gateways defined (rare case),
		// in which case we need to calculate the effective metric.
		// Effective metric is sum of interface metric and route metric offset
		if ifaceMetricCache == nil {
			// If we're here it means that previous route still isn't updated, so update it
			best.Metric += getIfaceMetric(best.InterfaceLUID)
		}
		r.Metric += getIfaceMetric(r.InterfaceLUID)

		if best.Metric > r.Metric || best.Metric == r.Metric && ret.Compare(ip) > 0 {
			// Pick the route with lower metric, or lower IP if metrics are equal
			best = r
			ret = ip
		}
	}

	if !ret.IsZero() && !isPrivateIP(ret) {
		// Default route has a non-private gateway
		return netaddr.IP{}, false
	}

	return ret, !ret.IsZero()
}

// NonTailscaleMTUs returns a map of interface LUID to interface MTU,
// for all interfaces except Tailscale tunnels.
func NonTailscaleMTUs() (map[winipcfg.LUID]uint32, error) {
	mtus := map[winipcfg.LUID]uint32{}
	ifs, err := NonTailscaleInterfaces()
	for luid, iface := range ifs {
		mtus[luid] = iface.MTU
	}
	return mtus, err
}

// NonTailscaleInterfaces returns a map of interface LUID to interface
// for all interfaces except Tailscale tunnels.
func NonTailscaleInterfaces() (map[winipcfg.LUID]*winipcfg.IPAdapterAddresses, error) {
	ifs, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return nil, err
	}

	ret := map[winipcfg.LUID]*winipcfg.IPAdapterAddresses{}
	for _, iface := range ifs {
		if iface.Description() == tsconst.WintunInterfaceDesc {
			continue
		}
		ret[iface.LUID] = iface
	}

	return ret, nil
}

// GetWindowsDefault returns the interface that has the non-Tailscale
// default route for the given address family.
//
// It returns (nil, nil) if no interface is found.
func GetWindowsDefault(family winipcfg.AddressFamily) (*winipcfg.IPAdapterAddresses, error) {
	ifs, err := NonTailscaleInterfaces()
	if err != nil {
		return nil, err
	}

	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, err
	}

	bestMetric := ^uint32(0)
	var bestIface *winipcfg.IPAdapterAddresses
	for _, route := range routes {
		iface := ifs[route.InterfaceLUID]
		if route.DestinationPrefix.PrefixLength != 0 || iface == nil {
			continue
		}
		if iface.OperStatus == winipcfg.IfOperStatusUp && route.Metric < bestMetric {
			bestMetric = route.Metric
			bestIface = iface
		}
	}

	return bestIface, nil
}

func DefaultRouteInterface() (string, error) {
	iface, err := GetWindowsDefault(windows.AF_INET)
	if err != nil {
		return "", err
	}
	if iface == nil {
		return "(none)", nil
	}
	return fmt.Sprintf("%s (%s)", iface.FriendlyName(), iface.Description()), nil
}

var (
	winHTTP                  = windows.NewLazySystemDLL("winhttp.dll")
	detectAutoProxyConfigURL = winHTTP.NewProc("WinHttpDetectAutoProxyConfigUrl")

	kernel32   = windows.NewLazySystemDLL("kernel32.dll")
	globalFree = kernel32.NewProc("GlobalFree")
)

const (
	winHTTP_AUTO_DETECT_TYPE_DHCP  = 0x00000001
	winHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002
)

func getPACWindows() string {
	var res *uint16
	r, _, e := detectAutoProxyConfigURL.Call(
		winHTTP_AUTO_DETECT_TYPE_DHCP|winHTTP_AUTO_DETECT_TYPE_DNS_A,
		uintptr(unsafe.Pointer(&res)),
	)
	if r == 1 {
		if res == nil {
			log.Printf("getPACWindows: unexpected success with nil result")
			return ""
		}
		defer globalFree.Call(uintptr(unsafe.Pointer(res)))
		s := windows.UTF16PtrToString(res)
		if _, err := url.Parse(s); err != nil {
			log.Printf("getPACWindows: invalid URL %q from winhttp; ignoring", s)
			return ""
		}
		return s
	}
	const (
		ERROR_WINHTTP_AUTODETECTION_FAILED = 12180
	)
	if e == syscall.Errno(ERROR_WINHTTP_AUTODETECTION_FAILED) {
		// Common case on networks without advertised PAC.
		return ""
	}
	log.Printf("getPACWindows: %T=%v", e, e) // syscall.Errno=0x....
	return ""
}
