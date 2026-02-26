// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_debug

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
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/clientmetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgint"
)

type watchdogEvent string

const (
	Any               watchdogEvent = "Any"
	Reconfig          watchdogEvent = "Reconfig"
	ResetAndStop      watchdogEvent = "ResetAndStop"
	SetFilter         watchdogEvent = "SetFilter"
	SetJailedFilter   watchdogEvent = "SetJailedFilter"
	SetStatusCallback watchdogEvent = "SetStatusCallback"
	UpdateStatus      watchdogEvent = "UpdateStatus"
	RequestStatus     watchdogEvent = "RequestStatus"
	SetNetworkMap     watchdogEvent = "SetNetworkMap"
	Ping              watchdogEvent = "Ping"
	Close             watchdogEvent = "Close"
	PeerForIPEvent    watchdogEvent = "PeerForIP"
)

var (
	watchdogMetrics = map[watchdogEvent]*clientmetric.Metric{
		Any:               clientmetric.NewCounter("watchdog_timeout_any_total"),
		Reconfig:          clientmetric.NewCounter("watchdog_timeout_reconfig"),
		ResetAndStop:      clientmetric.NewCounter("watchdog_timeout_resetandstop"),
		SetFilter:         clientmetric.NewCounter("watchdog_timeout_setfilter"),
		SetJailedFilter:   clientmetric.NewCounter("watchdog_timeout_setjailedfilter"),
		SetStatusCallback: clientmetric.NewCounter("watchdog_timeout_setstatuscallback"),
		UpdateStatus:      clientmetric.NewCounter("watchdog_timeout_updatestatus"),
		RequestStatus:     clientmetric.NewCounter("watchdog_timeout_requeststatus"),
		SetNetworkMap:     clientmetric.NewCounter("watchdog_timeout_setnetworkmap"),
		Ping:              clientmetric.NewCounter("watchdog_timeout_ping"),
		Close:             clientmetric.NewCounter("watchdog_timeout_close"),
		PeerForIPEvent:    clientmetric.NewCounter("watchdog_timeout_peerforipevent"),
	}
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
	op  watchdogEvent
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

func (e *watchdogEngine) watchdogErr(event watchdogEvent, fn func() error) error {
	// Track all in-flight operations so we can print more useful error
	// messages on watchdog failure
	e.inFlightMu.Lock()

	key := inFlightKey{
		op:  event,
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
		e.recordEvent(event)
		e.inFlightMu.Unlock()

		// Print everything as a single string to avoid log
		// rate limits.
		e.logf("wgengine watchdog in-flight:\n%s", b)
		e.fatalf("wgengine: watchdog timeout on %s", event)
		return nil
	}
}

func (e *watchdogEngine) recordEvent(event watchdogEvent) {
	if watchdogMetrics == nil {
		return
	}

	mEvent, ok := watchdogMetrics[event]
	if ok {
		mEvent.Add(1)
	}
	mAny, ok := watchdogMetrics[Any]
	if ok {
		mAny.Add(1)
	}
}

func (e *watchdogEngine) watchdog(event watchdogEvent, fn func()) {
	e.watchdogErr(event, func() error {
		fn()
		return nil
	})
}

func (e *watchdogEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *dns.Config) error {
	return e.watchdogErr(Reconfig, func() error { return e.wrap.Reconfig(cfg, routerCfg, dnsCfg) })
}

func (e *watchdogEngine) ResetAndStop() (st *Status, err error) {
	e.watchdog(ResetAndStop, func() {
		st, err = e.wrap.ResetAndStop()
	})
	return st, err
}

func (e *watchdogEngine) GetFilter() *filter.Filter {
	return e.wrap.GetFilter()
}

func (e *watchdogEngine) SetFilter(filt *filter.Filter) {
	e.watchdog(SetFilter, func() { e.wrap.SetFilter(filt) })
}

func (e *watchdogEngine) GetJailedFilter() *filter.Filter {
	return e.wrap.GetJailedFilter()
}

func (e *watchdogEngine) SetJailedFilter(filt *filter.Filter) {
	e.watchdog(SetJailedFilter, func() { e.wrap.SetJailedFilter(filt) })
}

func (e *watchdogEngine) SetStatusCallback(cb StatusCallback) {
	e.watchdog(SetStatusCallback, func() { e.wrap.SetStatusCallback(cb) })
}

func (e *watchdogEngine) UpdateStatus(sb *ipnstate.StatusBuilder) {
	e.watchdog(UpdateStatus, func() { e.wrap.UpdateStatus(sb) })
}

func (e *watchdogEngine) RequestStatus() {
	e.watchdog(RequestStatus, func() { e.wrap.RequestStatus() })
}

func (e *watchdogEngine) SetNetworkMap(nm *netmap.NetworkMap) {
	e.watchdog(SetNetworkMap, func() { e.wrap.SetNetworkMap(nm) })
}

func (e *watchdogEngine) Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult)) {
	e.watchdog(Ping, func() { e.wrap.Ping(ip, pingType, size, cb) })
}

func (e *watchdogEngine) Close() {
	e.watchdog(Close, e.wrap.Close)
}

func (e *watchdogEngine) PeerForIP(ip netip.Addr) (ret PeerForIP, ok bool) {
	e.watchdog(PeerForIPEvent, func() { ret, ok = e.wrap.PeerForIP(ip) })
	return ret, ok
}

func (e *watchdogEngine) Done() <-chan struct{} {
	return e.wrap.Done()
}

func (e *watchdogEngine) InstallCaptureHook(cb packet.CaptureCallback) {
	if !buildfeatures.HasCapture {
		return
	}
	e.wrap.InstallCaptureHook(cb)
}

func (e *watchdogEngine) PeerByKey(pubKey key.NodePublic) (_ wgint.Peer, ok bool) {
	return e.wrap.PeerByKey(pubKey)
}
