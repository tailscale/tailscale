// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

var (
	errClosed = errors.New("closed")
)

type eventMessage struct {
	eventType string
}

func (eventMessage) ignore() bool { return false }

type winMon struct {
	logf                    logger.Logf
	ctx                     context.Context
	cancel                  context.CancelFunc
	isActive                func() bool
	messagec                chan eventMessage
	addressChangeCallback   *winipcfg.UnicastAddressChangeCallback
	routeChangeCallback     *winipcfg.RouteChangeCallback
	interfaceChangeCallback *winipcfg.InterfaceChangeCallback

	// defaultInterface4 and defaultInterface6 cache the default interface
	// index for each address family. They are invalidated directly by OS
	// change notifications, rather than by the monitor's debounced State,
	// which only records the IPv4 default route and no interface or route
	// metrics.
	defaultInterface4 defaultInterfaceCache
	defaultInterface6 defaultInterfaceCache

	mu      sync.Mutex
	lastLog time.Time // time we last logged about any windows change event

	// noDeadlockTicker exists just to have something scheduled as
	// far as the Go runtime is concerned. Otherwise "tailscaled
	// debug --monitor" thinks it's deadlocked with nothing to do,
	// as Go's runtime doesn't know about callbacks registered with
	// Windows.
	noDeadlockTicker *time.Ticker
}

func newOSMon(_ *eventbus.Bus, logf logger.Logf, pm *Monitor) (osMon, error) {
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
		m.Close()
		return nil, err
	}

	m.routeChangeCallback, err = winipcfg.RegisterRouteChangeCallback(m.routeChanged)
	if err != nil {
		m.logf("winipcfg.RegisterRouteChangeCallback error: %v", err)
		m.Close()
		return nil, err
	}

	m.interfaceChangeCallback, err = winipcfg.RegisterInterfaceChangeCallback(m.interfaceChanged)
	if err != nil {
		m.logf("winipcfg.RegisterInterfaceChangeCallback error: %v; default interface caching disabled", err)
		// The cache cannot be invalidated correctly without interface change
		// notifications, so disable it. Route and address monitoring is
		// unaffected.
		m.defaultInterface4.disable()
		m.defaultInterface6.disable()
	}

	return m, nil
}

// WindowsDefaultInterfaceIndex returns the index of the non-Tailscale default
// interface for family, which must be AF_INET or AF_INET6. Zero means no default
// interface was found. Nonzero results are cached until an OS network change
// notification; zero results and errors are not cached. Static and closed
// monitors, and monitors without the required notification subscriptions,
// perform uncached lookups, as do lookups that cannot stabilize under repeated
// network changes.
func (m *Monitor) WindowsDefaultInterfaceIndex(family winipcfg.AddressFamily) (uint32, error) {
	var cache *defaultInterfaceCache
	wm, _ := m.om.(*winMon)
	switch family {
	case windows.AF_INET:
		if wm != nil {
			cache = &wm.defaultInterface4
		}
	case windows.AF_INET6:
		if wm != nil {
			cache = &wm.defaultInterface6
		}
	default:
		return 0, errors.New("invalid address family for Windows default interface")
	}
	lookup := func() (uint32, error) {
		iface, err := GetWindowsDefault(family)
		if err != nil || iface == nil {
			return 0, err
		}
		return iface.IfIndex, nil
	}
	if cache == nil {
		return lookup()
	}
	return cache.get(lookup)
}

func (m *winMon) invalidateDefaultInterfaces() {
	m.defaultInterface4.invalidate()
	m.defaultInterface6.invalidate()
}

// interfaceChanged covers changes to interface metrics, enabled address families,
// and connectivity, which can change the best default without changing a route.
func (m *winMon) interfaceChanged(_ winipcfg.MibNotificationType, _ *winipcfg.MibIPInterfaceRow) {
	m.invalidateDefaultInterfaces()
}

func (m *winMon) Close() (ret error) {
	m.defaultInterface4.disable()
	m.defaultInterface6.disable()
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

	if m.interfaceChangeCallback != nil {
		if err := m.interfaceChangeCallback.Unregister(); err != nil {
			m.logf("interfaceChangeCallback.Unregister error: %v", err)
			ret = err
		} else {
			m.interfaceChangeCallback = nil
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
	m.invalidateDefaultInterfaces()
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
	m.invalidateDefaultInterfaces()
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
