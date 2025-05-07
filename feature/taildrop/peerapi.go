// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package taildrop

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/httphdr"
)

func init() {
	ipnlocal.RegisterPeerAPIHandler("/v0/put/", handlePeerPut)
}

var (
	metricPutCalls = clientmetric.NewCounter("peerapi_put")
)

// canPutFile reports whether h can put a file ("Taildrop") to this node.
func canPutFile(h ipnlocal.PeerAPIHandler) bool {
	if h.Peer().UnsignedPeerAPIOnly() {
		// Unsigned peers can't send files.
		return false
	}
	return h.IsSelfUntagged() || h.PeerCaps().HasCapability(tailcfg.PeerCapabilityFileSharingSend)
}

func handlePeerPut(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "miswired", http.StatusInternalServerError)
		return
	}
	handlePeerPutWithBackend(h, ext, w, r)
}

// extensionForPut is the subset of taildrop extension that taildrop
// file put needs. This is pulled out for testability.
type extensionForPut interface {
	manager() *manager
	hasCapFileSharing() bool
	Clock() tstime.Clock
}

func handlePeerPutWithBackend(h ipnlocal.PeerAPIHandler, ext extensionForPut, w http.ResponseWriter, r *http.Request) {
	if r.Method == "PUT" {
		metricPutCalls.Add(1)
	}

	taildropMgr := ext.manager()
	if taildropMgr == nil {
		h.Logf("taildrop: no taildrop manager")
		http.Error(w, "failed to get taildrop manager", http.StatusInternalServerError)
		return
	}

	if !canPutFile(h) {
		http.Error(w, ErrNoTaildrop.Error(), http.StatusForbidden)
		return
	}
	if !ext.hasCapFileSharing() {
		http.Error(w, ErrNoTaildrop.Error(), http.StatusForbidden)
		return
	}
	rawPath := r.URL.EscapedPath()
	prefix, ok := strings.CutPrefix(rawPath, "/v0/put/")
	if !ok {
		http.Error(w, "misconfigured internals", http.StatusForbidden)
		return
	}
	baseName, err := url.PathUnescape(prefix)
	if err != nil {
		http.Error(w, ErrInvalidFileName.Error(), http.StatusBadRequest)
		return
	}
	enc := json.NewEncoder(w)
	switch r.Method {
	case "GET":
		id := clientID(h.Peer().StableID())
		if prefix == "" {
			// List all the partial files.
			files, err := taildropMgr.PartialFiles(id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := enc.Encode(files); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				h.Logf("json.Encoder.Encode error: %v", err)
				return
			}
		} else {
			// Stream all the block hashes for the specified file.
			next, close, err := taildropMgr.HashPartialFile(id, baseName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer close()
			for {
				switch cs, err := next(); {
				case err == io.EOF:
					return
				case err != nil:
					http.Error(w, err.Error(), http.StatusInternalServerError)
					h.Logf("HashPartialFile.next error: %v", err)
					return
				default:
					if err := enc.Encode(cs); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						h.Logf("json.Encoder.Encode error: %v", err)
						return
					}
				}
			}
		}
	case "PUT":
		t0 := ext.Clock().Now()
		id := clientID(h.Peer().StableID())

		var offset int64
		if rangeHdr := r.Header.Get("Range"); rangeHdr != "" {
			ranges, ok := httphdr.ParseRange(rangeHdr)
			if !ok || len(ranges) != 1 || ranges[0].Length != 0 {
				http.Error(w, "invalid Range header", http.StatusBadRequest)
				return
			}
			offset = ranges[0].Start
		}
		n, err := taildropMgr.PutFile(clientID(fmt.Sprint(id)), baseName, r.Body, offset, r.ContentLength)
		switch err {
		case nil:
			d := ext.Clock().Since(t0).Round(time.Second / 10)
			h.Logf("got put of %s in %v from %v/%v", approxSize(n), d, h.RemoteAddr().Addr(), h.Peer().ComputedName)
			io.WriteString(w, "{}\n")
		case ErrNoTaildrop:
			http.Error(w, err.Error(), http.StatusForbidden)
		case ErrInvalidFileName:
			http.Error(w, err.Error(), http.StatusBadRequest)
		case ErrFileExists:
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	default:
		http.Error(w, "expected method GET or PUT", http.StatusMethodNotAllowed)
	}
}

func approxSize(n int64) string {
	if n <= 1<<10 {
		return "<=1KB"
	}
	if n <= 1<<20 {
		return "<=1MB"
	}
	return fmt.Sprintf("~%dMB", n>>20)
}
