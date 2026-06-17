// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package connreject registers the connection-rejection diagnostics
// feature. It owns a [*connreject.Aggregator] that records rejection
// events and exposes them via the debug-rejects LocalAPI endpoint and
// the GET /debug/rejects c2n endpoint.
//
// The feature wires itself into the local backend's TUN wrapper and
// engine via callbacks installed at extension Init. Recording is gated
// at runtime by the [tailcfg.NodeAttrConnReject] node attribute; when
// the attribute is not set, recorded events are silently dropped by the
// aggregator.
package connreject

import (
	"encoding/json"
	"net/http"

	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/connreject"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
)

// featureName is the feature tag used for feature.Register and the
// ipnext extension name.
const featureName = "connreject"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
	localapi.Register("debug-rejects", serveDebugRejects)
	ipnlocal.RegisterC2N("GET /debug/rejects", handleC2NDebugRejects)
}

// connRejectCallbacker is the optional interface that this feature
// type-asserts at runtime to install its callback. The assertion fails
// silently in min builds where no underlying type implements it.
type connRejectCallbacker interface {
	SetConnRejectCallback(func(connreject.Event))
}

// extension owns a per-LocalBackend [connreject.Aggregator] and installs
// callbacks that feed it.
type extension struct {
	logf logger.Logf
	sb   ipnext.SafeBackend
	agg  *connreject.Aggregator
}

func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		logf: logger.WithPrefix(logf, featureName+": "),
		sb:   sb,
		agg:  connreject.NewAggregator(connreject.DefaultMax()),
	}, nil
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string { return featureName }

// Init implements [ipnext.Extension]. It installs callbacks on the
// tundev and engine so they can deliver rejection events to the
// aggregator, and subscribes to self-node changes to flip the runtime
// enable bit.
//
// Init tolerates a nil SafeBackend (e.g. in unit tests that construct
// the extension directly without going through newExtension); in that
// case the callbacks aren't installed but OnSelfChange still works.
func (e *extension) Init(host ipnext.Host) error {
	if e.sb != nil {
		if tun, ok := any(e.sb.Sys().Tun.Get()).(connRejectCallbacker); ok {
			tun.SetConnRejectCallback(e.note)
		}
		if eng, ok := e.sb.Sys().Engine.Get().(connRejectCallbacker); ok {
			eng.SetConnRejectCallback(e.note)
		}
	}
	host.Hooks().OnSelfChange.Add(e.onSelfChange)
	return nil
}

// note delivers a rejection event to the aggregator. The aggregator
// applies its own enable gate and direction dispatch.
func (e *extension) note(evt connreject.Event) {
	e.agg.Note(evt)
}

// Shutdown implements [ipnext.Extension]. It uninstalls the callbacks
// and disables the aggregator.
func (e *extension) Shutdown() error {
	e.uninstallCallbacks()
	e.agg.SetEnabled(false)
	return nil
}

// uninstallCallbacks clears the callbacks installed during Init. It is
// safe to call when no SafeBackend was wired (e.g. unit tests).
func (e *extension) uninstallCallbacks() {
	if e.sb == nil {
		return
	}
	if tun, ok := any(e.sb.Sys().Tun.Get()).(connRejectCallbacker); ok {
		tun.SetConnRejectCallback(nil)
	}
	if eng, ok := e.sb.Sys().Engine.Get().(connRejectCallbacker); ok {
		eng.SetConnRejectCallback(nil)
	}
}

func (e *extension) onSelfChange(self tailcfg.NodeView) {
	enabled := self.HasCap(tailcfg.NodeAttrConnReject)
	if prev := e.agg.SetEnabled(enabled); prev != enabled {
		if enabled {
			e.logf("enabled via NodeAttrConnReject")
		} else {
			e.logf("disabled via NodeAttrConnReject")
		}
	}
}

func buildResponse(a *connreject.Aggregator) connreject.DebugRejectsResponse {
	return connreject.DebugRejectsResponse{
		Enabled:  a.Enabled(),
		Outgoing: a.Outgoing(),
		Incoming: a.Incoming(),
	}
}

func serveDebugRejects(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "debug-rejects access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	var e *extension
	if !h.LocalBackend().FindMatchingExtension(&e) {
		http.Error(w, "connreject extension unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, buildResponse(e.agg))
}

func handleC2NDebugRejects(lb *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	var e *extension
	if !lb.FindMatchingExtension(&e) {
		http.Error(w, "connreject extension unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, buildResponse(e.agg))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
