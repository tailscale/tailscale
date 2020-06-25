// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"log"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/tsdns"
)

// NewWatchdog wraps an Engine and makes sure that all methods complete
// within a reasonable amount of time.
//
// If they do not, the watchdog crashes the process.
func NewWatchdog(e Engine) Engine {
	return &watchdogEngine{
		wrap:    e,
		logf:    log.Printf,
		fatalf:  log.Fatalf,
		maxWait: 45 * time.Second,
	}
}

type watchdogEngine struct {
	wrap    Engine
	logf    func(format string, args ...interface{})
	fatalf  func(format string, args ...interface{})
	maxWait time.Duration
}

func (e *watchdogEngine) watchdogErr(name string, fn func() error) error {
	errCh := make(chan error)
	go func() {
		errCh <- fn()
	}()
	t := time.NewTimer(e.maxWait)
	select {
	case err := <-errCh:
		t.Stop()
		return err
	case <-t.C:
		buf := new(strings.Builder)
		pprof.Lookup("goroutine").WriteTo(buf, 1)
		e.logf("wgengine watchdog stacks:\n%s", buf.String())
		e.fatalf("wgengine: watchdog timeout on %s", name)
		return nil
	}
}

func (e *watchdogEngine) watchdog(name string, fn func()) {
	e.watchdogErr(name, func() error {
		fn()
		return nil
	})
}

func (e *watchdogEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config) error {
	return e.watchdogErr("Reconfig", func() error { return e.wrap.Reconfig(cfg, routerCfg) })
}
func (e *watchdogEngine) GetFilter() *filter.Filter {
	var x *filter.Filter
	e.watchdog("GetFilter", func() { x = e.wrap.GetFilter() })
	return x
}
func (e *watchdogEngine) SetFilter(filt *filter.Filter) {
	e.watchdog("SetFilter", func() { e.wrap.SetFilter(filt) })
}
func (e *watchdogEngine) SetDNSMap(dm *tsdns.Map) {
	e.watchdog("SetDNSMap", func() { e.wrap.SetDNSMap(dm) })
}
func (e *watchdogEngine) SetStatusCallback(cb StatusCallback) {
	e.watchdog("SetStatusCallback", func() { e.wrap.SetStatusCallback(cb) })
}
func (e *watchdogEngine) UpdateStatus(sb *ipnstate.StatusBuilder) {
	e.watchdog("UpdateStatus", func() { e.wrap.UpdateStatus(sb) })
}
func (e *watchdogEngine) SetNetInfoCallback(cb NetInfoCallback) {
	e.watchdog("SetNetInfoCallback", func() { e.wrap.SetNetInfoCallback(cb) })
}
func (e *watchdogEngine) RequestStatus() {
	e.watchdog("RequestStatus", func() { e.wrap.RequestStatus() })
}
func (e *watchdogEngine) LinkChange(isExpensive bool) {
	e.watchdog("LinkChange", func() { e.wrap.LinkChange(isExpensive) })
}
func (e *watchdogEngine) SetDERPMap(m *tailcfg.DERPMap) {
	e.watchdog("SetDERPMap", func() { e.wrap.SetDERPMap(m) })
}
func (e *watchdogEngine) SetNetworkMap(nm *controlclient.NetworkMap) {
	e.watchdog("SetNetworkMap", func() { e.wrap.SetNetworkMap(nm) })
}
func (e *watchdogEngine) SetDiscoPrivateKey(k key.Private) {
	e.watchdog("SetDiscoPrivateKey", func() { e.wrap.SetDiscoPrivateKey(k) })
}
func (e *watchdogEngine) Close() {
	e.watchdog("Close", e.wrap.Close)
}
func (e *watchdogEngine) Wait() {
	e.wrap.Wait()
}
