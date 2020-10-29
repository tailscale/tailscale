// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/logtail/backoff"
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
	firewall            *firewallTweaker
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
		firewall:  &firewallTweaker{logf: logger.WithPrefix(logf, "firewall: ")},
	}, nil
}

func (r *winRouter) Up() error {
	r.firewall.clear()

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

func (r *winRouter) Set(cfg *Config) error {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	if len(cfg.LocalAddrs) == 1 && cfg.LocalAddrs[0].Bits == 32 {
		r.firewall.set(cfg.LocalAddrs[0].IP.String())
	} else {
		r.firewall.clear()
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
	r.firewall.clear()

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

// firewallTweaker changes the Windows firewall. Normally this wouldn't be so complicated,
// but it can be REALLY SLOW to change the Windows firewall for reasons not understood.
// Like 4 minutes slow. But usually it's tens of milliseconds.
// See https://github.com/tailscale/tailscale/issues/785.
// So this tracks the desired state and runs the actual adjusting code asynchrounsly.
type firewallTweaker struct {
	logf logger.Logf

	mu      sync.Mutex
	running bool   // doAsyncSet goroutine is running
	known   bool   // firewall is in known state (in lastVal)
	want    string // next value we want, or "" to delete the firewall rule
	lastVal string // last set value, if known
}

func (ft *firewallTweaker) clear() { ft.set("") }

func (ft *firewallTweaker) set(ip string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	if ip == "" {
		ft.logf("marking for removal")
	} else {
		ft.logf("marking desired IP %v", ip)
	}
	ft.want = ip
	if ft.running {
		// The doAsyncSet goroutine will check ft.want
		// before returning.
		return
	}
	ft.running = true
	go ft.doAsyncSet()
}

func (ft *firewallTweaker) doAsyncSet() {
	bo := backoff.NewBackoff("win-firewall", ft.logf, time.Minute)
	ctx := context.Background()

	ft.mu.Lock()
	for { // invariant: ft.mu must be locked when beginning this block
		val := ft.want
		if ft.known && ft.lastVal == val {
			ft.running = false
			ft.mu.Unlock()
			return
		}
		ft.mu.Unlock()

		var cmd *exec.Cmd
		t0 := time.Now()
		if val == "" {
			ft.logf("deleting Tailscale-In firewall rule")
			cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=Tailscale-In", "dir=in")
		} else {
			ft.logf("setting Tailscale-In firewall IP to %q", val)
			cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Tailscale-In", "dir=in", "action=allow", "localip="+val, "profile=private", "enable=yes")
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		err := cmd.Run()
		dur := time.Since(t0).Round(time.Millisecond)
		if err != nil && val == "" {
			// If we were deleting a rule that doesn't exist, netsh returns an error.
			// So just assume the delete worked.
			err = nil
		}
		if err != nil {
			ft.logf("updating Tailscale-In firewall IP to %q: %v (after %v)", val, err, dur)
		} else {
			ft.logf("updated firewall (to %q) in %v", val, dur)
		}
		bo.BackOff(ctx, err)

		ft.mu.Lock()
		ft.lastVal = val
		ft.known = (err == nil)
	}
}
