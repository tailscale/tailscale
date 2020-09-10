// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"fmt"
	"log"
	"os/exec"
	"syscall"

	winipcfg "github.com/tailscale/winipcfg-go"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router/dns"
)

type winRouter struct {
	logf                func(fmt string, args ...interface{})
	tunname             string
	nativeTun           *tun.NativeTun
	wgdev               *device.Device
	routeChangeCallback *winipcfg.RouteChangeCallback
	dns                 *dns.Manager
}

func newUserspaceRouter(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}

	nativeTun := tundev.(*tun.NativeTun)
	guid := nativeTun.GUID().String()
	mconfig := dns.ManagerConfig{
		Logf:          logf,
		InterfaceName: guid,
	}

	return &winRouter{
		logf:      logf,
		wgdev:     wgdev,
		tunname:   tunname,
		nativeTun: nativeTun,
		dns:       dns.NewManager(mconfig),
	}, nil
}

func (r *winRouter) Up() error {
	r.removeFirewallAcceptRule()

	var err error
	r.routeChangeCallback, err = monitorDefaultRoutes(r.nativeTun)
	if err != nil {
		log.Fatalf("MonitorDefaultRoutes: %v", err)
	}
	return nil
}

// removeFirewallAcceptRule removes the "Tailscale-In" firewall rule.
//
// If it doesn't already exist, this currently returns an error but TODO: it should not.
//
// So callers should ignore its error for now.
func (r *winRouter) removeFirewallAcceptRule() error {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=Tailscale-In", "dir=in")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func (r *winRouter) addFirewallAcceptRule(ipStr string) error {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Tailscale-In", "dir=in", "action=allow", "localip="+ipStr, "profile=private", "enable=yes")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func (r *winRouter) Set(cfg *Config) error {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	r.removeFirewallAcceptRule()
	if len(cfg.LocalAddrs) == 1 && cfg.LocalAddrs[0].Bits == 32 {
		ipStr := cfg.LocalAddrs[0].IP.String()
		if err := r.addFirewallAcceptRule(ipStr); err != nil {
			r.logf("addFirewallRule(%q): %v", ipStr, err)
		} else {
			r.logf("added firewall rule Tailscale-In for %v", ipStr)
		}
	}

	err := configureInterface(cfg, r.nativeTun)
	if err != nil {
		r.logf("ConfigureInterface: %v", err)
		return err
	}

	if err := r.dns.Set(cfg.DNS); err != nil {
		return fmt.Errorf("dns set: %w", err)
	}

	return nil
}

func (r *winRouter) Close() error {
	r.removeFirewallAcceptRule()

	if err := r.dns.Down(); err != nil {
		return fmt.Errorf("dns down: %w", err)
	}
	if r.routeChangeCallback != nil {
		r.routeChangeCallback.Unregister()
	}

	return nil
}

func cleanup(logf logger.Logf, interfaceName string) {
	// Nothing to do here.
}
