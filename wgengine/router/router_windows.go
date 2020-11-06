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
		Logf:          logf,
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

	var localAddrs []string
	for _, la := range cfg.LocalAddrs {
		localAddrs = append(localAddrs, la.String())
	}
	r.firewall.set(localAddrs)

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
	running bool     // doAsyncSet goroutine is running
	known   bool     // firewall is in known state (in lastVal)
	want    []string // next value we want, or "" to delete the firewall rule
	lastVal []string // last set value, if known
}

func (ft *firewallTweaker) clear() { ft.set(nil) }

// set takes the IPv4 and/or IPv6 CIDRs to allow; an empty slice
// removes the firwall rules.
//
// set takes ownership of the slice.
func (ft *firewallTweaker) set(cidrs []string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	if len(cidrs) == 0 {
		ft.logf("marking for removal")
	} else {
		ft.logf("marking allowed %v", cidrs)
	}
	ft.want = cidrs
	if ft.running {
		// The doAsyncSet goroutine will check ft.want
		// before returning.
		return
	}
	ft.logf("starting netsh goroutine")
	ft.running = true
	go ft.doAsyncSet()
}

func (ft *firewallTweaker) runFirewall(args ...string) (time.Duration, error) {
	t0 := time.Now()
	args = append([]string{"advfirewall", "firewall"}, args...)
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	return time.Since(t0).Round(time.Millisecond), err
}

func (ft *firewallTweaker) doAsyncSet() {
	bo := backoff.NewBackoff("win-firewall", ft.logf, time.Minute)
	ctx := context.Background()

	ft.mu.Lock()
	for { // invariant: ft.mu must be locked when beginning this block
		val := ft.want
		if ft.known && strsEqual(ft.lastVal, val) {
			ft.running = false
			ft.logf("ending netsh goroutine")
			ft.mu.Unlock()
			return
		}
		needClear := !ft.known || len(ft.lastVal) > 0 || len(val) == 0
		ft.mu.Unlock()

		if needClear {
			ft.logf("clearing Tailscale-In firewall rules...")
			// We ignore the error here, because netsh returns an error for
			// deleting something that doesn't match.
			// TODO(bradfitz): care? That'd involve querying it before/after to see
			// whether it was necessary/worked. But the output format is localized,
			// so can't rely on parsing English. Maybe need to use OLE, not netsh.exe?
			d, _ := ft.runFirewall("delete", "rule", "name=Tailscale-In", "dir=in")
			ft.logf("cleared Tailscale-In firewall rules in %v", d)
		}
		var err error
		for _, cidr := range val {
			ft.logf("adding Tailscale-In rule to allow %v ...", cidr)
			var d time.Duration
			d, err = ft.runFirewall("add", "rule", "name=Tailscale-In", "dir=in", "action=allow", "localip="+cidr, "profile=private", "enable=yes")
			if err != nil {
				ft.logf("error adding Tailscale-In rule to allow %v: %v", cidr, err)
				break
			}
			ft.logf("added Tailscale-In rule to allow %v in %v", cidr, d)
		}
		bo.BackOff(ctx, err)

		ft.mu.Lock()
		ft.lastVal = val
		ft.known = (err == nil)
	}
}

func strsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
