// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"tailscale.com/feature/loginbeacon/api"
	"tailscale.com/ipn"
	"tailscale.com/ipn/localapi"
)

// serveResources handles the login beacon resource API.
func serveResources(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/localapi/v0/loginbeacon")
	method := r.Method
	if !h.PermitWrite && (method != http.MethodGet || !h.PermitRead) {
		http.Error(w, "permission denied", http.StatusForbidden)
		return
	}
	var e *extension
	if !h.LocalBackend().FindMatchingExtension(&e) {
		http.Error(w, "loginbeacon extension not available", http.StatusServiceUnavailable)
		return
	}
	owner := ipn.WindowsUserID("")
	if h.Actor != nil {
		owner = h.Actor.UserID()
	}
	switch {
	case path == "/" || path == "/requests":
		if !allowMethod(w, method, http.MethodGet) {
			return
		}
		status := e.status()
		if path == "/" {
			writeJSON(w, status)
		} else {
			writeJSON(w, status.Requests)
		}
	case strings.HasPrefix(path, "/requests/"):
		id, action, _ := strings.Cut(strings.TrimPrefix(path, "/requests/"), "/")
		want := http.MethodDelete
		if action == "approval" {
			want = http.MethodPost
		} else if action != "" {
			http.NotFound(w, r)
			return
		}
		if !allowMethod(w, method, want) {
			return
		}
		rid, err := api.ParseID(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if want == http.MethodDelete {
			e.deleteRequest(rid)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		url, err := e.approve(r.Context(), rid)
		if err != nil {
			writeResult(w, err, http.StatusBadGateway)
			return
		}
		writeJSON(w, api.Approval{RequestID: hex.EncodeToString(rid[:]), AuthURL: url})
	case path == "/receiver":
		if !allowMethod(w, method, http.MethodPut, http.MethodDelete) {
			return
		}
		writeResult(w, e.setReceiverActivity(method == http.MethodPut), http.StatusConflict)
	case strings.HasPrefix(path, "/broadcasts/"):
		if !allowMethod(w, method, http.MethodPut, http.MethodDelete) {
			return
		}
		id := strings.TrimPrefix(path, "/broadcasts/")
		if _, err := api.ParseID(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var config api.Broadcast
		if method == http.MethodPut {
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&config); err != nil {
				http.Error(w, "invalid broadcast configuration", http.StatusBadRequest)
				return
			}
			if err := dec.Decode(new(any)); err != io.EOF {
				http.Error(w, "expected one JSON object", http.StatusBadRequest)
				return
			}
			if !config.Expires.After(time.Now()) || config.Expires.After(time.Now().Add(api.MaxBroadcastDuration)) || len(config.Hostname) > maxHostname {
				http.Error(w, "invalid hostname or expiry (maximum ten minutes)", http.StatusBadRequest)
				return
			}
		}
		err := e.changeBroadcast(id, owner, config, method == http.MethodPut)
		status := http.StatusConflict
		if errors.Is(err, errPolicyDenied) {
			status = http.StatusForbidden
		}
		writeResult(w, err, status)
	default:
		http.NotFound(w, r)
	}
}

func allowMethod(w http.ResponseWriter, method string, methods ...string) bool {
	for _, want := range methods {
		if method == want {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(value)
}

func writeResult(w http.ResponseWriter, err error, status int) {
	if err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch {
	case errors.Is(err, errNoPendingBeacon):
		status = http.StatusNotFound
	case errors.Is(err, errApprovalInProgress):
		status = http.StatusConflict
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	}
	http.Error(w, err.Error(), status)
}

func (e *extension) status() api.Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := api.Status{
		Allowed: !e.policyDenied, AcceptRequests: e.acceptRequests,
		Receiving: e.receiving && e.acceptRequests && !e.policyDenied,
		Requests:  []api.Pending{},
	}
	if e.sender != nil && (e.automaticSender || e.broadcastEnabled) && !e.policyDenied {
		status.BroadcastID = e.broadcastID
		status.BroadcastExpires = e.broadcastConfig.Expires
	}
	if e.receiver != nil && e.acceptRequests && !e.policyDenied {
		status.Requests = e.receiver.requests()
	}
	return status
}

// Each attempt has an ID so retries and delayed cleanup cannot affect replacements.
func (e *extension) changeBroadcast(id string, owner ipn.WindowsUserID, config api.Broadcast, enabled bool) error {
	e.broadcastMu.Lock()
	defer e.broadcastMu.Unlock()
	e.mu.Lock()
	switch {
	case enabled && e.policyDenied:
		e.mu.Unlock()
		return errPolicyDenied
	case !enabled && e.broadcastID != id:
		e.mu.Unlock()
		return nil
	case e.broadcastID != "" && e.broadcastOwner != owner:
		e.mu.Unlock()
		return errors.New("loginbeacon: another user owns the active attempt")
	case enabled && e.broadcastID == id:
		same := e.broadcastConfig == config
		e.mu.Unlock()
		if !same {
			return errors.New("loginbeacon: attempt configuration mismatch")
		}
		return nil
	}
	e.automaticSender = false // explicit actions override appliance automation until restart
	e.mu.Unlock()
	if err := e.setBroadcastLocked(enabled, config.Hostname); err != nil || !enabled {
		return err
	}
	e.mu.Lock()
	e.broadcastID, e.broadcastOwner, e.broadcastConfig = id, owner, config
	e.mu.Unlock()
	e.wakeReceiverControl() // the lifecycle worker owns attempt expiry as well as reception
	return nil
}
