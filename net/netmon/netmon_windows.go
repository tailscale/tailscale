// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

var (
	errClosed = errors.New("closed")
)

type eventMessage struct {
	eventType string
}

func (eventMessage) ignore() bool { return false }

type winMon struct {
	logf                  logger.Logf
	ctx                   context.Context
	cancel                context.CancelFunc
	isActive              func() bool
	messagec              chan eventMessage
	addressChangeCallback *winipcfg.UnicastAddressChangeCallback
	routeChangeCallback   *winipcfg.RouteChangeCallback

	mu      sync.Mutex
	lastLog time.Time // time we last logged about any windows change event

	// noDeadlockTicker exists just to have something scheduled as
	// far as the Go runtime is concerned. Otherwise "tailscaled
	// debug --monitor" thinks it's deadlocked with nothing to do,
	// as Go's runtime doesn't know about callbacks registered with
	// Windows.
	noDeadlockTicker *time.Ticker
}

func newOSMon(logf logger.Logf, pm *Monitor) (osMon, error) {
	m := &winMon{
		logf:             logf,
		isActive:         pm.isActive,
		messagec:         make(chan eventMessage, 1),
		noDeadlockTicker: time.NewTicker(5000 * time.Hour), // arbitrary
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())

	var err error
	m.addressChangeCallback, err = winipcfg.RegisterUnicastAddressChangeCallback(m.unicastAddressChanged)
	if err != nil {
		m.logf("winipcfg.RegisterUnicastAddressChangeCallback error: %v", err)
		m.cancel()
		return nil, err
	}

	m.routeChangeCallback, err = winipcfg.RegisterRouteChangeCallback(m.routeChanged)
	if err != nil {
		m.addressChangeCallback.Unregister()
		m.logf("winipcfg.RegisterRouteChangeCallback error: %v", err)
		m.cancel()
		return nil, err
	}

	return m, nil
}

func (m *winMon) IsInterestingInterface(iface string) bool { return true }

func (m *winMon) Close() (ret error) {
	m.cancel()
	m.noDeadlockTicker.Stop()

	if m.addressChangeCallback != nil {
		if err := m.addressChangeCallback.Unregister(); err != nil {
			m.logf("addressChangeCallback.Unregister error: %v", err)
			ret = err
		} else {
			m.addressChangeCallback = nil
		}
	}

	if m.routeChangeCallback != nil {
		if err := m.routeChangeCallback.Unregister(); err != nil {
			m.logf("routeChangeCallback.Unregister error: %v", err)
			ret = err
		} else {
			m.routeChangeCallback = nil
		}
	}

	return
}

func (m *winMon) Receive() (message, error) {
	if m.ctx.Err() != nil {
		m.logf("Receive call on closed monitor")
		return nil, errClosed
	}

	t0 := time.Now()

	select {
	case msg := <-m.messagec:
		now := time.Now()
		m.mu.Lock()
		sinceLast := now.Sub(m.lastLog)
		m.lastLog = now
		m.mu.Unlock()
		// If it's either been awhile since we last logged
		// anything, or if this some route/addr that's not
		// about a Tailscale IP ("ts" prefix), then log. This
		// is mainly limited to suppress the flood about our own
		// route updates after connecting to a large tailnet
		// and all the IPv4 /32 routes.
		if sinceLast > 5*time.Second || !strings.HasPrefix(msg.eventType, "ts") {
			m.logf("got windows change event after %v: evt=%s", time.Since(t0).Round(time.Millisecond), msg.eventType)
		}
		return msg, nil
	case <-m.ctx.Done():
		return nil, errClosed
	}
}

// unicastAddressChanged is the callback we register with Windows to call when unicast address changes.
func (m *winMon) unicastAddressChanged(_ winipcfg.MibNotificationType, row *winipcfg.MibUnicastIPAddressRow) {
	if !m.isActive() {
		// Avoid starting a goroutine that sends events to messagec,
		// or sending messages to messagec directly, if the monitor
		// hasn't started and Receive is not yet reading from messagec.
		//
		// Doing so can lead to goroutine leaks or deadlocks, especially
		// if the monitor is never started.
		return
	}

	what := "addr"
	if ip := row.Address.Addr(); ip.IsValid() && tsaddr.IsTailscaleIP(ip.Unmap()) {
		what = "tsaddr"
	}

	// start a goroutine to finish our work, to return to Windows out of this callback
	go m.somethingChanged(what)
}

// routeChanged is the callback we register with Windows to call when route changes.
func (m *winMon) routeChanged(_ winipcfg.MibNotificationType, row *winipcfg.MibIPforwardRow2) {
	if !m.isActive() {
		// Avoid starting a goroutine that sends events to messagec,
		// or sending messages to messagec directly, if the monitor
		// hasn't started and Receive is not yet reading from messagec.
		//
		// Doing so can lead to goroutine leaks or deadlocks, especially
		// if the monitor is never started.
		return
	}

	what := "route"
	ip := row.DestinationPrefix.Prefix().Addr().Unmap()
	if ip.IsValid() && tsaddr.IsTailscaleIP(ip) {
		what = "tsroute"
	}
	// start a goroutine to finish our work, to return to Windows out of this callback
	go m.somethingChanged(what)
}

// somethingChanged gets called from OS callbacks whenever address or route changes.
func (m *winMon) somethingChanged(evt string) {
	select {
	case <-m.ctx.Done():
		return
	case m.messagec <- eventMessage{eventType: evt}:
		return
	}
}

// isActive reports whether this monitor has been started and not yet closed.
func (m *Monitor) isActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started && !m.closed
}
