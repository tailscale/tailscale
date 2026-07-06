// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package remoteconfig registers a c2n endpoint that lets the control
// plane invoke this node's LocalAPI when Prefs.RemoteConfig is true.
//
// # Trust model
//
// Tailscale's default posture is per-feature double opt-in: the tailnet
// admin can request something server-side, but the local machine owner
// still has to consent (via CLI, GUI, or LocalAPI) for each individual
// setting. RemoteConfig is a different, more permissive posture: a
// single client-side "I trust the tailnet admin" switch. Once
// Prefs.RemoteConfig is true, the control plane can invoke any of this
// node's LocalAPI endpoints (which includes read/write of every pref)
// with no further local consent.
//
// This is appropriate when the tailnet admin owns the machine (e.g. a
// corporate fleet device) or when the local user has explicitly
// delegated full control to the tailnet admin. It should NOT be used
// on personal or BYOD devices where the tailnet admin is not fully
// trusted.
package remoteconfig

import (
	"net/http"
	"strings"

	"tailscale.com/feature"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
)

// c2nPrefix is the c2n URL path prefix under which requests are
// proxied to this node's LocalAPI at /localapi/*, regardless of the
// LocalAPI version (v0, v1, ...).
const c2nPrefix = "/remoteapi/localapi/"

// localAPIStrip is the portion of c2nPrefix that must be stripped from
// the incoming c2n path to yield the LocalAPI path.
const localAPIStrip = "/remoteapi"

func init() {
	feature.Register("remoteconfig")
	ipnlocal.RegisterC2NPrefix(c2nPrefix, handleC2NRemoteAPI)
}

// handleC2NRemoteAPI proxies c2n requests under /remoteapi/localapi/*
// to this node's LocalAPI at /localapi/*, with full read/write
// permission, when the local machine has opted in via Prefs.RemoteConfig.
//
// See the package doc for the trust model this handler represents.
func handleC2NRemoteAPI(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	prefs := b.Prefs()
	if !prefs.Valid() || !prefs.RemoteConfig() {
		http.Error(w, "remote config not enabled by local machine", http.StatusForbidden)
		return
	}
	if !strings.HasPrefix(r.URL.Path, c2nPrefix) {
		http.Error(w, "unexpected remote-config path", http.StatusBadRequest)
		return
	}

	// Rewrite the URL from /remoteapi/localapi/X to /localapi/X on a
	// shallow clone so we don't mutate the caller's Request.
	u := *r.URL
	u.Path = strings.TrimPrefix(r.URL.Path, localAPIStrip)
	if r.URL.RawPath != "" {
		u.RawPath = strings.TrimPrefix(r.URL.RawPath, localAPIStrip)
	}
	r2 := r.WithContext(r.Context())
	r2.URL = &u
	if u.Path == r.URL.Path {
		// Prefix strip did nothing; refuse rather than looping.
		http.Error(w, "unexpected remote-config path", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(u.Path, "/localapi/") {
		http.Error(w, "unexpected remote-config path", http.StatusBadRequest)
		return
	}

	lah := localapi.NewHandler(localapi.HandlerConfig{
		Actor:    ipnauth.Self,
		Backend:  b,
		Logf:     b.Logger(),
		LogID:    b.BackendLogID(),
		EventBus: b.Sys().Bus.Get(),
	})
	lah.PermitRead = true
	lah.PermitWrite = true
	lah.ServeHTTP(w, r2)
}
