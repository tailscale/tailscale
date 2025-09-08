// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package localapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path"

	"tailscale.com/drive"
	"tailscale.com/util/httpm"
)

func init() {
	Register("drive/fileserver-address", (*Handler).serveDriveServerAddr)
	Register("drive/shares", (*Handler).serveShares)
}

// serveDriveServerAddr handles updates of the Taildrive file server address.
func (h *Handler) serveDriveServerAddr(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.PUT {
		http.Error(w, "only PUT allowed", http.StatusMethodNotAllowed)
		return
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.b.DriveSetServerAddr(string(b))
	w.WriteHeader(http.StatusCreated)
}

// serveShares handles the management of Taildrive shares.
//
// PUT - adds or updates an existing share
// DELETE - removes a share
// GET - gets a list of all shares, sorted by name
// POST - renames an existing share
func (h *Handler) serveShares(w http.ResponseWriter, r *http.Request) {
	if !h.b.DriveSharingEnabled() {
		http.Error(w, `taildrive sharing not enabled, please add the attribute "drive:share" to this node in your ACLs' "nodeAttrs" section`, http.StatusForbidden)
		return
	}
	switch r.Method {
	case httpm.PUT:
		var share drive.Share
		err := json.NewDecoder(r.Body).Decode(&share)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		share.Path = path.Clean(share.Path)
		fi, err := os.Stat(share.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !fi.IsDir() {
			http.Error(w, "not a directory", http.StatusBadRequest)
			return
		}
		if drive.AllowShareAs() {
			// share as the connected user
			username, err := h.Actor.Username()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			share.As = username
		}
		err = h.b.DriveSetShare(&share)
		if err != nil {
			if errors.Is(err, drive.ErrInvalidShareName) {
				http.Error(w, "invalid share name", http.StatusBadRequest)
				return
			}
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
		err = h.b.DriveRemoveShare(string(b))
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "share not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case httpm.POST:
		var names [2]string
		err := json.NewDecoder(r.Body).Decode(&names)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = h.b.DriveRenameShare(names[0], names[1])
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "share not found", http.StatusNotFound)
				return
			}
			if os.IsExist(err) {
				http.Error(w, "share name already used", http.StatusBadRequest)
				return
			}
			if errors.Is(err, drive.ErrInvalidShareName) {
				http.Error(w, "invalid share name", http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case httpm.GET:
		shares := h.b.DriveGetShares()
		err := json.NewEncoder(w).Encode(shares)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
	}
}
