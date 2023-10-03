// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/localapi"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
)

type Handler struct {
	*localapi.Handler
}

func (h *Handler) serveFiles(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "file access denied", http.StatusForbidden)
		return
	}
	suffix, ok := strings.CutPrefix(r.URL.EscapedPath(), "/localapi/v0/files/")
	if !ok {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}
	if suffix == "" {
		if r.Method != "GET" {
			http.Error(w, "want GET to list files", 400)
			return
		}
		ctx := r.Context()
		if s := r.FormValue("waitsec"); s != "" && s != "0" {
			d, err := strconv.Atoi(s)
			if err != nil {
				http.Error(w, "invalid waitsec", http.StatusBadRequest)
				return
			}
			deadline := time.Now().Add(time.Duration(d) * time.Second)
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
		wfs, err := h.b.AwaitWaitingFiles(ctx)
		if err != nil && ctx.Err() == nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(wfs)
		return
	}
	name, err := url.PathUnescape(suffix)
	if err != nil {
		http.Error(w, "bad filename", 400)
		return
	}
	if r.Method == "DELETE" {
		if err := h.b.DeleteFile(name); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rc, size, err := h.b.OpenFile(name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Length", fmt.Sprint(size))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, rc)
}

func (h *Handler) serveFileTargets(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "want GET to list targets", 400)
		return
	}
	fts, err := h.b.FileTargets()
	if err != nil {
		WriteErrorJSON(w, err)
		return
	}
	mak.NonNilSliceForJSON(&fts)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fts)
}

// serveFilePut sends a file to another node.
//
// It's sometimes possible for clients to do this themselves, without
// tailscaled, except in the case of tailscaled running in
// userspace-networking ("netstack") mode, in which case tailscaled
// needs to a do a netstack dial out.
//
// Instead, the CLI also goes through tailscaled so it doesn't need to be
// aware of the network mode in use.
//
// macOS/iOS have always used this localapi method to simplify the GUI
// clients.
//
// The Windows client currently (2021-11-30) uses the peerapi (/v0/put/)
// directly, as the Windows GUI always runs in tun mode anyway.
//
// URL format:
//
//   - PUT /localapi/v0/file-put/:stableID/:escaped-filename
func (h *Handler) serveFilePut(w http.ResponseWriter, r *http.Request) {
	metricFilePutCalls.Add(1)

	if !h.PermitWrite {
		http.Error(w, "file access denied", http.StatusForbidden)
		return
	}
	if r.Method != "PUT" {
		http.Error(w, "want PUT to put file", 400)
		return
	}
	fts, err := h.b.FileTargets()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	upath, ok := strings.CutPrefix(r.URL.EscapedPath(), "/localapi/v0/file-put/")
	if !ok {
		http.Error(w, "misconfigured", http.StatusInternalServerError)
		return
	}
	stableIDStr, filenameEscaped, ok := strings.Cut(upath, "/")
	if !ok {
		http.Error(w, "bogus URL", 400)
		return
	}
	stableID := tailcfg.StableNodeID(stableIDStr)

	var ft *apitype.FileTarget
	for _, x := range fts {
		if x.Node.StableID == stableID {
			ft = x
			break
		}
	}
	if ft == nil {
		http.Error(w, "node not found", 404)
		return
	}
	dstURL, err := url.Parse(ft.PeerAPIURL)
	if err != nil {
		http.Error(w, "bogus peer URL", 500)
		return
	}
	outReq, err := http.NewRequestWithContext(r.Context(), "PUT", "http://peer/v0/put/"+filenameEscaped, r.Body)
	if err != nil {
		http.Error(w, "bogus outreq", 500)
		return
	}
	outReq.ContentLength = r.ContentLength

	rp := httputil.NewSingleHostReverseProxy(dstURL)
	rp.Transport = h.b.Dialer().PeerAPITransport()
	rp.ServeHTTP(w, outReq)
}
