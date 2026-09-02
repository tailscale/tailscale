// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captiveportal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/util/httpm"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
)

func init() {
	localapi.Register("captive-portal-allow-lan", serveAllowLAN)
}

// serveAllowLAN temporarily takes the local network back out of the tunnel so
// that a captive portal's login page hosted there can be reached while an exit
// node holds the default route.
//
// POST grants the exception; DELETE gives it back early, which a GUI should do
// as soon as the user says they are done. It expires on its own after
// [maxLANBypass] regardless, and is revoked as soon as a detection run comes
// back clean.
//
// This is deliberately not a general "allow local network access" API. It only
// answers while a portal we can actually help with is being reported, so that
// the only way to reach it is the situation it exists for. The default route is
// never touched.
func serveAllowLAN(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "captive portal detection is not enabled", http.StatusServiceUnavailable)
		return
	}
	if !h.PermitWrite {
		http.Error(w, "captive-portal-allow-lan access denied", http.StatusForbidden)
		return
	}

	switch r.Method {
	case httpm.DELETE:
		e.revokeLANBypass()
		w.WriteHeader(http.StatusNoContent)
		return
	case httpm.POST:
	default:
		http.Error(w, "use POST or DELETE", http.StatusMethodNotAllowed)
		return
	}

	if code, err := e.canGrantLANBypass(); err != nil {
		http.Error(w, err.Error(), code)
		return
	}

	d := maxLANBypass
	if v := r.FormValue("duration"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid duration %q: %v", v, err), http.StatusBadRequest)
			return
		}
		d = parsed
	}

	until := e.grantLANBypass(d)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apitype.CaptivePortalAllowLANResponse{Until: until})
}

// canGrantLANBypass reports whether a temporary local network exception is
// warranted right now, returning the HTTP status and an error explaining why
// not if it isn't.
//
// The distinction between the refusals matters to a GUI: one is worth retrying
// after another detection pass, and the other never will be.
func (e *Extension) canGrantLANBypass() (int, error) {
	// Only while we are reporting the one case this helps with. In particular
	// this refuses when the login page is off the local network
	// ([captivePortalBlockedWarnable]), where opening the local network up
	// would be a leak that bought the user nothing.
	//
	// This does mean a GUI can be refused because a detection pass happened to
	// clear the warning between offering the button and the user pressing it.
	// Reporting that honestly is better than granting a leak on the strength of
	// a warning we are no longer standing behind.
	st := e.health.CurrentState()
	if st == nil {
		return http.StatusServiceUnavailable, errors.New("no health state available")
	}
	ws, ok := st.Warnings[captivePortalWarnable.Code]
	if !ok || ws.Args[health.ArgExitNodeBlocksPortal] == "" {
		return http.StatusConflict, errors.New("no captive portal login page is currently blocked by an exit node")
	}

	// An administrator who has pinned local network access off has made a
	// decision that a portal login does not override. We are not going to grant
	// a leak the policy forbids; the user can turn off their exit node instead.
	polc := e.sb.Sys().PolicyClientOrDefault()
	if po, err := polc.GetPreferenceOption(pkey.ExitNodeAllowLANAccess, ptype.ShowChoiceByPolicy); err == nil && po.IsNever() {
		return http.StatusForbidden, errors.New("local network access while using an exit node is disallowed by policy")
	}
	return http.StatusOK, nil
}
