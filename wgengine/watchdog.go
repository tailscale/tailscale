// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js
// +build !js

package wgengine

import (
	"fmt"
	"log"
	"net/netip"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// NewWatchdog wraps an Engine and makes sure that all methods complete
// within a reasonable amount of time.
//
// If they do not, the watchdog crashes the process.
func NewWatchdog(e Engine) Engine {
	if envknob.Bool("TS_DEBUG_DISABLE_WATCHDOG") {
		return e
	}
	return &watchdogEngine{
		wrap:     e,
		logf:     log.Printf,
		fatalf:   log.Fatalf,
		maxWait:  45 * time.Second,
		inFlight: make(map[inFlightKey]time.Time),
	}
}

type inFlightKey struct {
	op  string
	ctr uint64
}

type watchdogEngine struct {
	wrap    Engine
	logf    func(format string, args ...any)
	fatalf  func(format string, args ...any)
	maxWait time.Duration

	// Track the start time(s) of in-flight operations
	inFlightMu  sync.Mutex
	inFlight    map[inFlightKey]time.Time
	inFlightCtr uint64
}

func (e *watchdogEngine) watchdogErr(name string, fn func() error) error {
	// Track all in-flight operations so we can print more useful error
	// messages on watchdog failure
	e.inFlightMu.Lock()
	key := inFlightKey{
		op:  name,
		ctr: e.inFlightCtr,
	}
	e.inFlightCtr++
	e.inFlight[key] = time.Now()
	e.inFlightMu.Unlock()

	defer func() {
		e.inFlightMu.Lock()
		defer e.inFlightMu.Unlock()
		delete(e.inFlight, key)
	}()

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

		// Collect the list of in-flight operations for debugging.
		var (
			b   []byte
			now = time.Now()
		)
		e.inFlightMu.Lock()
		for k, t := range e.inFlight {
			dur := now.Sub(t).Round(time.Millisecond)
			b = fmt.Appendf(b, "in-flight[%d]: name=%s duration=%v start=%s\n", k.ctr, k.op, dur, t.Format(time.RFC3339Nano))
		}
		e.inFlightMu.Unlock()

		// Print everything as a single string to avoid log
		// rate limits.
		e.logf("wgengine watchdog in-flight:\n%s", b)
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

func (e *watchdogEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *dns.Config, debug *tailcfg.Debug) error {
	return e.watchdogErr("Reconfig", func() error { return e.wrap.Reconfig(cfg, routerCfg, dnsCfg, debug) })
}
func (e *watchdogEngine) GetLinkMonitor() *monitor.Mon {
	return e.wrap.GetLinkMonitor()
}
func (e *watchdogEngine) GetFilter() *filter.Filter {
	return e.wrap.GetFilter()
}
func (e *watchdogEngine) SetFilter(filt *filter.Filter) {
	e.watchdog("SetFilter", func() { e.wrap.SetFilter(filt) })
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
func (e *watchdogEngine) SetNetworkMap(nm *netmap.NetworkMap) {
	e.watchdog("SetNetworkMap", func() { e.wrap.SetNetworkMap(nm) })
}
func (e *watchdogEngine) AddNetworkMapCallback(callback NetworkMapCallback) func() {
	var fn func()
	e.watchdog("AddNetworkMapCallback", func() { fn = e.wrap.AddNetworkMapCallback(callback) })
	return func() { e.watchdog("RemoveNetworkMapCallback", fn) }
}
func (e *watchdogEngine) DiscoPublicKey() (k key.DiscoPublic) {
	e.watchdog("DiscoPublicKey", func() { k = e.wrap.DiscoPublicKey() })
	return k
}
func (e *watchdogEngine) Ping(ip netip.Addr, pingType tailcfg.PingType, cb func(*ipnstate.PingResult)) {
	e.watchdog("Ping", func() { e.wrap.Ping(ip, pingType, cb) })
}
func (e *watchdogEngine) RegisterIPPortIdentity(ipp netip.AddrPort, tsIP netip.Addr) {
	e.watchdog("RegisterIPPortIdentity", func() { e.wrap.RegisterIPPortIdentity(ipp, tsIP) })
}
func (e *watchdogEngine) UnregisterIPPortIdentity(ipp netip.AddrPort) {
	e.watchdog("UnregisterIPPortIdentity", func() { e.wrap.UnregisterIPPortIdentity(ipp) })
}
func (e *watchdogEngine) WhoIsIPPort(ipp netip.AddrPort) (tsIP netip.Addr, ok bool) {
	e.watchdog("UnregisterIPPortIdentity", func() { tsIP, ok = e.wrap.WhoIsIPPort(ipp) })
	return tsIP, ok
}
func (e *watchdogEngine) Close() {
	e.watchdog("Close", e.wrap.Close)
}
func (e *watchdogEngine) GetInternals() (tw *tstun.Wrapper, c *magicsock.Conn, d *dns.Manager, ok bool) {
	if ig, ok := e.wrap.(InternalsGetter); ok {
		return ig.GetInternals()
	}
	return
}
func (e *watchdogEngine) GetResolver() (r *resolver.Resolver, ok bool) {
	if re, ok := e.wrap.(ResolvingEngine); ok {
		return re.GetResolver()
	}
	return nil, false
}
func (e *watchdogEngine) PeerForIP(ip netip.Addr) (ret PeerForIP, ok bool) {
	e.watchdog("PeerForIP", func() { ret, ok = e.wrap.PeerForIP(ip) })
	return ret, ok
}

func (e *watchdogEngine) Wait() {
	e.wrap.Wait()
}
