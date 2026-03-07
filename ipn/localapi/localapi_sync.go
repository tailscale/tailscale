// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_sync

package localapi

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"

	"tailscale.com/tailsync"
	"tailscale.com/util/httpm"
)

func init() {
	Register("sync/roots", (*Handler).serveSyncRoots)
	Register("sync/sessions", (*Handler).serveSyncSessions)
	Register("sync/status", (*Handler).serveSyncStatus)
}

// serveSyncRoots handles management of tailsync roots.
//
// PUT - adds or updates a root
// DELETE - removes a root
// GET - lists all roots
func (h *Handler) serveSyncRoots(w http.ResponseWriter, r *http.Request) {
	if !h.b.SyncSharingEnabled() {
		http.Error(w, `tailsync sharing not enabled, please add the attribute "sync:share" to this node in your ACLs' "nodeAttrs" section`, http.StatusForbidden)
		return
	}
	switch r.Method {
	case httpm.PUT:
		var root tailsync.Root
		if err := json.NewDecoder(r.Body).Decode(&root); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		root.Path = path.Clean(root.Path)
		fi, err := os.Stat(root.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !fi.IsDir() {
			http.Error(w, "not a directory", http.StatusBadRequest)
			return
		}
		if err := h.b.SyncSetRoot(&root); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case httpm.DELETE:
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.b.SyncRemoveRoot(string(b)); err != nil {
			if err == tailsync.ErrRootNotFound {
				http.Error(w, "root not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case httpm.GET:
		roots := h.b.SyncGetRoots()
		if roots == nil {
			roots = make([]*tailsync.Root, 0)
		}
		json.NewEncoder(w).Encode(roots)
	default:
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}

// serveSyncSessions handles management of tailsync sessions.
//
// PUT - adds or updates a session
// DELETE - removes a session
// GET - lists all sessions
func (h *Handler) serveSyncSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case httpm.PUT:
		var session tailsync.Session
		if err := json.NewDecoder(r.Body).Decode(&session); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.b.SyncSetSession(&session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case httpm.DELETE:
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.b.SyncRemoveSession(string(b)); err != nil {
			if err == tailsync.ErrSessionNotFound {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case httpm.GET:
		sessions := h.b.SyncGetSessions()
		if sessions == nil {
			sessions = make([]*tailsync.Session, 0)
		}
		json.NewEncoder(w).Encode(sessions)
	default:
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}

// serveSyncStatus returns status for all sync sessions or a specific one.
//
// GET - returns all session statuses, or a single one if ?name=X is specified
func (h *Handler) serveSyncStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	if name != "" {
		st, err := h.b.SyncGetSessionStatus(name)
		if err != nil {
			if err == tailsync.ErrSessionNotFound {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(st)
		return
	}

	statuses := h.b.SyncGetAllStatuses()
	if statuses == nil {
		statuses = make([]*tailsync.SessionStatus, 0)
	}
	json.NewEncoder(w).Encode(statuses)
}
