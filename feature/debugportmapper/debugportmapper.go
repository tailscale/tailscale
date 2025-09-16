// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package debugportmapper registers support for debugging Tailscale's
// portmapping support.
package debugportmapper

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn/localapi"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

func init() {
	localapi.Register("debug-portmap", serveDebugPortmap)
}

func serveDebugPortmap(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain")

	dur, err := time.ParseDuration(r.FormValue("duration"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	gwSelf := r.FormValue("gateway_and_self")

	trueFunc := func() bool { return true }
	// Update portmapper debug flags
	debugKnobs := &portmapper.DebugKnobs{VerboseLogs: true}
	switch r.FormValue("type") {
	case "":
	case "pmp":
		debugKnobs.DisablePCPFunc = trueFunc
		debugKnobs.DisableUPnPFunc = trueFunc
	case "pcp":
		debugKnobs.DisablePMPFunc = trueFunc
		debugKnobs.DisableUPnPFunc = trueFunc
	case "upnp":
		debugKnobs.DisablePCPFunc = trueFunc
		debugKnobs.DisablePMPFunc = trueFunc
	default:
		http.Error(w, "unknown portmap debug type", http.StatusBadRequest)
		return
	}
	if k := h.LocalBackend().ControlKnobs(); k != nil {
		if k.DisableUPnP.Load() {
			debugKnobs.DisableUPnPFunc = trueFunc
		}
	}

	if defBool(r.FormValue("log_http"), false) {
		debugKnobs.LogHTTP = true
	}

	var (
		logLock     sync.Mutex
		handlerDone bool
	)
	logf := func(format string, args ...any) {
		if !strings.HasSuffix(format, "\n") {
			format = format + "\n"
		}

		logLock.Lock()
		defer logLock.Unlock()

		// The portmapper can call this log function after the HTTP
		// handler returns, which is not allowed and can cause a panic.
		// If this happens, ignore the log lines since this typically
		// occurs due to a client disconnect.
		if handlerDone {
			return
		}

		// Write and flush each line to the client so that output is streamed
		fmt.Fprintf(w, format, args...)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	defer func() {
		logLock.Lock()
		handlerDone = true
		logLock.Unlock()
	}()

	ctx, cancel := context.WithTimeout(r.Context(), dur)
	defer cancel()

	done := make(chan bool, 1)

	var c *portmapper.Client
	c = portmapper.NewClient(portmapper.Config{
		Logf:       logger.WithPrefix(logf, "portmapper: "),
		NetMon:     h.LocalBackend().NetMon(),
		DebugKnobs: debugKnobs,
		EventBus:   h.LocalBackend().EventBus(),
		OnChange: func() {
			logf("portmapping changed.")
			logf("have mapping: %v", c.HaveMapping())

			if ext, ok := c.GetCachedMappingOrStartCreatingOne(); ok {
				logf("cb: mapping: %v", ext)
				select {
				case done <- true:
				default:
				}
				return
			}
			logf("cb: no mapping")
		},
	})
	defer c.Close()

	bus := eventbus.New()
	defer bus.Close()
	netMon, err := netmon.New(bus, logger.WithPrefix(logf, "monitor: "))
	if err != nil {
		logf("error creating monitor: %v", err)
		return
	}

	gatewayAndSelfIP := func() (gw, self netip.Addr, ok bool) {
		if a, b, ok := strings.Cut(gwSelf, "/"); ok {
			gw = netip.MustParseAddr(a)
			self = netip.MustParseAddr(b)
			return gw, self, true
		}
		return netMon.GatewayAndSelfIP()
	}

	c.SetGatewayLookupFunc(gatewayAndSelfIP)

	gw, selfIP, ok := gatewayAndSelfIP()
	if !ok {
		logf("no gateway or self IP; %v", netMon.InterfaceState())
		return
	}
	logf("gw=%v; self=%v", gw, selfIP)

	uc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return
	}
	defer uc.Close()
	c.SetLocalPort(uint16(uc.LocalAddr().(*net.UDPAddr).Port))

	res, err := c.Probe(ctx)
	if err != nil {
		logf("error in Probe: %v", err)
		return
	}
	logf("Probe: %+v", res)

	if !res.PCP && !res.PMP && !res.UPnP {
		logf("no portmapping services available")
		return
	}

	if ext, ok := c.GetCachedMappingOrStartCreatingOne(); ok {
		logf("mapping: %v", ext)
	} else {
		logf("no mapping")
	}

	select {
	case <-done:
	case <-ctx.Done():
		if r.Context().Err() == nil {
			logf("serveDebugPortmap: context done: %v", ctx.Err())
		} else {
			h.Logf("serveDebugPortmap: context done: %v", ctx.Err())
		}
	}
}

func defBool(a string, def bool) bool {
	if a == "" {
		return def
	}
	v, err := strconv.ParseBool(a)
	if err != nil {
		return def
	}
	return v
}
