// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

type ifAliasReq struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

type darwinRouter struct {
	logf    logger.Logf
	tunname string
	point   net.IP
	routes  map[netaddr.IPPrefix]struct{}
}

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}
	return &darwinRouter{
		logf:    logf,
		tunname: tunname,
	}, nil
}

func (r *darwinRouter) Up() error {
	return nil
}

func (r *darwinRouter) Set(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	// TUN is point to point
	if len(cfg.LocalAddrs) != 1 {
		return errors.New("darwin doesn't support setting multiple local addrs yet")
	}

	localAddr := cfg.LocalAddrs[0]
	gateway := localAddr.IPNet().IP.To4()

	if !r.point.Equal(gateway) {
		if err := setGateway(r.tunname, gateway, localAddr.IPNet().Mask); err != nil {
			return err
		}
		r.point = gateway
	}

	newRoutes := make(map[netaddr.IPPrefix]struct{})
	for _, route := range cfg.Routes {
		newRoutes[route] = struct{}{}
	}

	// delete duplicate route
	for route := range r.routes {
		if _, keep := newRoutes[route]; !keep {
			if err := delRoute(gateway, route.IPNet().IP, route.IPNet().Mask); err != nil {
				return err
			}
		}
	}

	// add new route
	for route := range newRoutes {
		if _, exists := r.routes[route]; !exists {
			if err := addRoute(gateway, route.IPNet().IP, route.IPNet().Mask); err != nil {
				return err
			}
		}
	}

	for _, route := range cfg.Routes {
		if err := addRoute(gateway, route.IPNet().IP, route.IPNet().Mask); err != nil {
			return err
		}
	}

	r.routes = newRoutes
	return nil
}

func (r *darwinRouter) Close() error {
	return nil
}

func setGateway(name string, addr net.IP, mask net.IPMask) error {
	var ifr [unix.IFNAMSIZ]byte
	copy(ifr[:], name)

	var ip [4]byte
	copy(ip[:], addr)

	ifra := unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   ip,
	}

	var maskAddr [4]byte
	copy(maskAddr[:], mask)

	ifraMask := unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   maskAddr,
	}

	ifar := ifAliasReq{
		Name:    ifr,
		Addr:    ifra,
		Dstaddr: ifra,
		Mask:    ifraMask,
	}

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}

	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCAIFADDR),
		uintptr(unsafe.Pointer(&ifar)),
	); errno != 0 {
		return fmt.Errorf("Failed to set ip on %s Gateway: %v", name, errno)
	}

	routeAddr := []route.Addr{
		syscall.RTAX_DST:     &route.Inet4Addr{IP: ip},
		syscall.RTAX_GATEWAY: &route.LinkAddr{Name: name},
		syscall.RTAX_NETMASK: &route.Inet4Addr{IP: maskAddr},
	}

	return setRoute(unix.RTM_ADD, routeAddr)
}

func ipToInet4Addr(ip []byte) [4]byte {
	var ipAddr [4]byte
	copy(ipAddr[:], ip)

	return ipAddr
}

func addRoute(gateway, dstIP net.IP, mask net.IPMask) error {
	addr := []route.Addr{
		syscall.RTAX_DST:     &route.Inet4Addr{IP: ipToInet4Addr(dstIP)},
		syscall.RTAX_GATEWAY: &route.Inet4Addr{IP: ipToInet4Addr(gateway)},
		syscall.RTAX_NETMASK: &route.Inet4Addr{IP: ipToInet4Addr(mask)},
	}

	return setRoute(unix.RTM_ADD, addr)
}

func delRoute(gateway, dstIP net.IP, mask net.IPMask) error {
	addr := []route.Addr{
		syscall.RTAX_DST:     &route.Inet4Addr{IP: ipToInet4Addr(dstIP)},
		syscall.RTAX_GATEWAY: &route.Inet4Addr{IP: ipToInet4Addr(gateway)},
		syscall.RTAX_NETMASK: &route.Inet4Addr{IP: ipToInet4Addr(mask)},
	}

	return setRoute(unix.RTM_DELETE, addr)
}

func setRoute(tp int, addr []route.Addr) error {
	rtmsg := route.RouteMessage{
		Type:    tp,
		Version: unix.RTM_VERSION,
		Seq:     1,
		Addrs:   addr,
	}

	buf, err := rtmsg.Marshal()
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}

	if _, err = syscall.Write(fd, buf); err != nil {
		return fmt.Errorf("failed to set route %s", err.Error())
	}

	return nil
}
