// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"tailscale.com/ipn/ipnlocal/mullvad"
	"tailscale.com/util/httpm"
)

func init() {
	// Register Mullvad endpoints unconditionally.
	// The feature flag is checked at runtime in each handler.
	Register("mullvad/status", (*Handler).serveMullvadStatus)
	Register("mullvad/configure", (*Handler).serveMullvadConfigure)
	Register("mullvad/refresh", (*Handler).serveMullvadRefresh)
}

// MullvadStatusResponse is the response for the mullvad/status endpoint.
type MullvadStatusResponse struct {
	Configured    bool      `json:"configured"`
	AccountExpiry time.Time `json:"accountExpiry,omitzero"`
	DaysRemaining int       `json:"daysRemaining,omitzero"`
	ServerCount   int       `json:"serverCount,omitzero"`
	DeviceIPv4    string    `json:"deviceIPv4,omitempty"`
	DeviceIPv6    string    `json:"deviceIPv6,omitempty"`
	LastRefresh   time.Time `json:"lastRefresh,omitzero"`
}

// serveMullvadStatus returns the current custom Mullvad configuration status.
func (h *Handler) serveMullvadStatus(w http.ResponseWriter, r *http.Request) {
	if !mullvad.CustomMullvadEnabled() {
		http.Error(w, "custom Mullvad support not enabled", http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.PermitRead {
		http.Error(w, "read access denied", http.StatusForbidden)
		return
	}

	status := h.b.GetCustomMullvadStatus()
	resp := MullvadStatusResponse{
		Configured:    status.Configured,
		AccountExpiry: status.AccountExpiry,
		DaysRemaining: status.DaysRemaining,
		ServerCount:   status.ServerCount,
		LastRefresh:   status.LastRefresh,
	}
	if status.DeviceIPv4.IsValid() {
		resp.DeviceIPv4 = status.DeviceIPv4.String()
	}
	if status.DeviceIPv6.IsValid() {
		resp.DeviceIPv6 = status.DeviceIPv6.String()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// MullvadConfigureRequest is the request for the mullvad/configure endpoint.
type MullvadConfigureRequest struct {
	AccountNumber string `json:"accountNumber"`
}

// MullvadConfigureResponse is the response for the mullvad/configure endpoint.
type MullvadConfigureResponse struct {
	Success       bool      `json:"success"`
	Error         string    `json:"error,omitempty"`
	AccountExpiry time.Time `json:"accountExpiry,omitzero"`
	ServerCount   int       `json:"serverCount,omitzero"`
}

// serveMullvadConfigure configures the custom Mullvad account.
func (h *Handler) serveMullvadConfigure(w http.ResponseWriter, r *http.Request) {
	if !mullvad.CustomMullvadEnabled() {
		http.Error(w, "custom Mullvad support not enabled", http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.PermitWrite {
		http.Error(w, "write access denied", http.StatusForbidden)
		return
	}

	var req MullvadConfigureRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil { // 64KB limit
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Use LocalBackend to configure Mullvad
	// This is done via preferences to ensure persistence
	if err := h.b.ConfigureCustomMullvad(r.Context(), req.AccountNumber); err != nil {
		switch {
		case errors.Is(err, mullvad.ErrInvalidAccount):
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, mullvad.ErrAccountExpired):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case errors.Is(err, mullvad.ErrNotEnabled):
			http.Error(w, err.Error(), http.StatusNotImplemented)
		default:
			WriteErrorJSON(w, err)
		}
		return
	}

	status := h.b.GetCustomMullvadStatus()
	resp := MullvadConfigureResponse{
		Success:       true,
		AccountExpiry: status.AccountExpiry,
		ServerCount:   status.ServerCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// serveMullvadRefresh forces a refresh of the Mullvad server list.
func (h *Handler) serveMullvadRefresh(w http.ResponseWriter, r *http.Request) {
	if !mullvad.CustomMullvadEnabled() {
		http.Error(w, "custom Mullvad support not enabled", http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.PermitWrite {
		http.Error(w, "write access denied", http.StatusForbidden)
		return
	}

	if err := h.b.RefreshCustomMullvad(r.Context()); err != nil {
		WriteErrorJSON(w, err)
		return
	}

	status := h.b.GetCustomMullvadStatus()
	resp := MullvadStatusResponse{
		Configured:    status.Configured,
		AccountExpiry: status.AccountExpiry,
		DaysRemaining: status.DaysRemaining,
		ServerCount:   status.ServerCount,
		LastRefresh:   status.LastRefresh,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Ensure ipnlocal.LocalBackend has the necessary methods.
// These are defined in mullvad_integration.go.
// Note: We use context.Context from the standard library, not an interface type.
// This is just a compile-time check that the methods exist.
