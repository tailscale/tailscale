// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_sync

package ipnlocal

import (
	"net/http"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/tailsync"
)

const tailsyncPrefix = "/v0/sync"

func init() {
	peerAPIHandlerPrefixes[tailsyncPrefix] = handleServeSync
}

func handleServeSync(hi PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	h := hi.(*peerAPIHandler)

	h.logfv1("tailsync: got %s request from %s", r.Method, h.peerNode.Key().ShortString())
	if !h.ps.b.SyncSharingEnabled() {
		h.logf("tailsync: not enabled")
		http.Error(w, "tailsync not enabled", http.StatusNotFound)
		return
	}

	capsMap := h.PeerCaps()
	syncCaps, ok := capsMap[tailcfg.PeerCapabilityTailsync]
	if !ok {
		h.logf("tailsync: not permitted")
		http.Error(w, "tailsync not permitted", http.StatusForbidden)
		return
	}

	rawPerms := make([][]byte, 0, len(syncCaps))
	for _, cap := range syncCaps {
		rawPerms = append(rawPerms, []byte(cap))
	}

	p, err := tailsync.ParsePermissions(rawPerms)
	if err != nil {
		h.logf("tailsync: error parsing permissions: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fs, ok := h.ps.b.sys.FileSync.GetOK()
	if !ok {
		h.logf("tailsync: not supported on platform")
		http.Error(w, "tailsync not supported on platform", http.StatusNotFound)
		return
	}

	r.URL.Path = strings.TrimPrefix(r.URL.Path, tailsyncPrefix)
	fs.ServeHTTPWithPerms(p, w, r)
}
