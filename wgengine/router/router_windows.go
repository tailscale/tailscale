// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

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

	mu             sync.Mutex
	firewallRuleIP string // the IP rule exists for, or "" when rule is deleted
	didRemove      bool
}

func newUserspaceRouter(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}

	nativeTun := tundev.(*tun.NativeTun)
	guid := nativeTun.GUID().String()
	mconfig := dns.ManagerConfig{
		Logf:          logger.WithPrefix(logf, "dns: "),
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
	t0 := time.Now()
	r.routeChangeCallback, err = monitorDefaultRoutes(r.nativeTun)
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		return fmt.Errorf("monitorDefaultRoutes, after %v: %v", d, err)
	}
	r.logf("monitorDefaultRoutes done after %v", d)
	return nil
}

// removeFirewallAcceptRule removes the "Tailscale-In" firewall rule.
//
// If it doesn't already exist, this currently returns an error but TODO: it should not.
//
// So callers should ignore its error for now.
func (r *winRouter) removeFirewallAcceptRule() error {
	t0 := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.firewallRuleIP == "" && r.didRemove {
		// Already done.
		return nil
	}
	r.firewallRuleIP = ""
	r.didRemove = true

	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=Tailscale-In", "dir=in")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	d := time.Since(t0).Round(time.Millisecond)
	r.logf("after %v, removed firewall rule (wasPresent=%v)", d, err == nil)
	return err
}

// addFirewallAcceptRule adds a firewall rule to allow all incoming
// traffic to the given IP (the Tailscale adapter's IP) for network
// adapters in category private. (as previously set by
// setPrivateNetwork)
//
// It returns (false, nil) if the firewall rule was already previously  existed with this IP.
func (r *winRouter) addFirewallAcceptRule(ipStr string) (added bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ipStr == r.firewallRuleIP {
		return false, nil
	}
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Tailscale-In", "dir=in", "action=allow", "localip="+ipStr, "profile=private", "enable=yes")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err = cmd.Run()
	if err != nil {
		return false, err
	}
	r.firewallRuleIP = ipStr
	return true, nil
}

func (r *winRouter) Set(cfg *Config) error {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	if len(cfg.LocalAddrs) == 1 && cfg.LocalAddrs[0].Bits == 32 {
		ipStr := cfg.LocalAddrs[0].IP.String()
		if ok, err := r.addFirewallAcceptRule(ipStr); err != nil {
			r.logf("addFirewallRule(%q): %v", ipStr, err)
		} else if ok {
			r.logf("added firewall rule Tailscale-In for %v", ipStr)
		}
	} else {
		r.removeFirewallAcceptRule()
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
