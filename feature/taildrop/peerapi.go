// Copyright (c) Tailscale Inc & contributors
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
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/httphdr"
)

var (
	metricPutCalls        = clientmetric.NewCounter("peerapi_put")
	metricPutRequestCalls = clientmetric.NewCounter("peerapi_put_request")

	// Counted where the owner's decision is recorded, not where it's reported,
	// so a polling sender doesn't inflate them.
	metricConsentApproved = clientmetric.NewCounter("taildrop_consent_approved")
	metricConsentDenied   = clientmetric.NewCounter("taildrop_consent_denied")

	// metricPutConsentRejected counts PUTs turned away for want of valid
	// consent.
	metricPutConsentRejected = clientmetric.NewCounter("peerapi_put_consent_rejected")
)

// putAuth is how far a peer gets on its own, before the device owner is asked.
type putAuth int

const (
	// putDenied means the peer may not send files and may not ask to.
	putDenied putAuth = iota

	// putNeedsConsent means the peer may only send if the device owner
	// approves the transfer. Nothing else can authorize it.
	putNeedsConsent

	// putAllowed means the peer may send without the owner being asked.
	putAllowed
)

// putAuthFor reports how far h is authorized to get in sending us a file.
//
// Unsigned peers are excluded. Same-user untagged transfers are
// implicitly allowed unless the testing override is enabled. Transfers
// involving another user or a tagged endpoint require both the opt-in
// preference (checked by the handlers) and consent;
// an ACL capability cannot waive either requirement.
func putAuthFor(h ipnlocal.PeerAPIHandler, consentForOwnDevices bool) putAuth {
	if h.Peer().UnsignedPeerAPIOnly() {
		// Unsigned peers have no verified sender identity to present.
		return putDenied
	}
	if h.IsSelfUntagged() && !consentForOwnDevices {
		return putAllowed
	}
	return putNeedsConsent
}

// canPutFile reports whether h may send us a file at all, with or without the
// owner being asked first.
func canPutFile(h ipnlocal.PeerAPIHandler, consentForOwnDevices bool) bool {
	return putAuthFor(h, consentForOwnDevices) != putDenied
}

func handlePeerPut(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "miswired", http.StatusInternalServerError)
		return
	}
	handlePeerPutWithBackend(h, ext, w, r)
}

func handlePeerPutRequest(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	ext, ok := ipnlocal.GetExt[*Extension](h.LocalBackend())
	if !ok {
		http.Error(w, "miswired", http.StatusInternalServerError)
		return
	}
	handlePeerPutRequestWithBackend(h, ext, w, r)
}

// extensionForPut is the subset of taildrop extension that taildrop
// file put needs. This is pulled out for testability.
type extensionForPut interface {
	manager() *manager
	hasCapFileSharing() bool
	Clock() tstime.Clock
}

// handlePeerPutRequestWithBackend serves POST /v0/put-request/{filename}, the
// consent request a sender makes before it may PUT a file.
//
// The sender polls this endpoint: the first call registers the request and
// prompts the device owner, and subsequent calls report the same request's state
// without re-prompting.
func handlePeerPutRequestWithBackend(h ipnlocal.PeerAPIHandler, ext extensionForPut, w http.ResponseWriter, r *http.Request) {
	metricPutRequestCalls.Add(1)

	if r.Method != "POST" {
		http.Error(w, "expected method POST", http.StatusMethodNotAllowed)
		return
	}

	mgr := ext.manager()
	if mgr == nil {
		h.Logf("taildrop: no taildrop manager")
		http.Error(w, "failed to get taildrop manager", http.StatusInternalServerError)
		return
	}

	// Authorize before prompting: a peer that may not send files at all is
	// rejected outright, so it can't use the prompt to pester the owner.
	auth := putAuthFor(h, mgr.consentForOwnDevices())
	if auth == putDenied || !ext.hasCapFileSharing() {
		http.Error(w, ErrNoTaildrop.Error(), http.StatusForbidden)
		return
	}

	if auth == putNeedsConsent && !mgr.allowExternalTaildrop() {
		w.Header().Set(hdrConsentError, string(ConsentNotAllowed))
		http.Error(w, ErrConsentNotAllowed.Error(), http.StatusForbidden)
		return
	}

	if auth == putAllowed {
		// Tells senders that understand the protocol to go straight to a plain
		// PUT; peers too old to know this endpoint get a 404 and reach the same
		// conclusion.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	baseName, ok := putBaseName(w, r, "/v0/put-request/")
	if !ok {
		return
	}
	if err := validateBaseName(baseName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req PutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid PutRequest JSON", http.StatusBadRequest)
		return
	}
	if err := req.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	state, token, err := mgr.requestConsent(h.Peer().StableID(), h.Peer().ComputedName(), baseName, req)
	if err != nil {
		if err == ErrConsentLimit {
			w.Header().Set("Retry-After", "60")
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		if err == ErrConsentMismatch {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.Logf("taildrop: consent request failed: %v", err)
		http.Error(w, "consent request failed", http.StatusInternalServerError)
		return
	}

	switch state {
	case ConsentNotRequired:
		w.WriteHeader(http.StatusNoContent)
	case ConsentPending:
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusAccepted)
	case ConsentApproved:
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(token); err != nil {
			h.Logf("taildrop: encoding consent token: %v", err)
		}
	case ConsentDenied:
		w.Header().Set(hdrConsentError, ErrConsentDenied.Error())
		http.Error(w, ErrConsentDenied.Error(), http.StatusForbidden)
	default:
		http.Error(w, "unexpected consent state", http.StatusInternalServerError)
	}
}

// putBaseName extracts and unescapes the filename from a PeerAPI put path,
// writing an error response and reporting false if it can't.
func putBaseName(w http.ResponseWriter, r *http.Request, prefix string) (string, bool) {
	escaped, ok := strings.CutPrefix(r.URL.EscapedPath(), prefix)
	if !ok {
		http.Error(w, "misconfigured internals", http.StatusForbidden)
		return "", false
	}
	baseName, err := url.PathUnescape(escaped)
	if err != nil {
		http.Error(w, ErrInvalidFileName.Error(), http.StatusBadRequest)
		return "", false
	}
	return baseName, true
}

// consentErrStatus maps a consent failure to the HTTP status that tells the
// sender what to do next: re-request consent, retry later, or give up.
func consentErrStatus(err error) int {
	switch err {
	case ErrConsentRequired, ErrConsentExpired, ErrConsentInvalid, ErrConsentMismatch:
		return http.StatusForbidden
	case ErrConsentUnknown:
		return http.StatusForbidden
	case ErrConsentConsumed:
		return http.StatusConflict
	case ErrConsentMalformed:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
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

	forceOwn := taildropMgr.consentForOwnDevices()
	auth := putAuthFor(h, forceOwn)
	if r.Method == "PUT" {
		h.Logf("taildrop: receive authorization: same-user=%v, allow-external=%v, force-own=%v, needs-consent=%v",
			h.IsSelfUntagged(), taildropMgr.allowExternalTaildrop(), forceOwn, auth == putNeedsConsent)
	}
	if auth == putDenied {
		http.Error(w, ErrNoTaildrop.Error(), http.StatusForbidden)
		return
	}
	needsConsent := auth == putNeedsConsent
	if needsConsent && !taildropMgr.allowExternalTaildrop() {
		w.Header().Set(hdrConsentError, string(ConsentNotAllowed))
		http.Error(w, ErrConsentNotAllowed.Error(), http.StatusForbidden)
		return
	}
	if !ext.hasCapFileSharing() {
		http.Error(w, ErrNoTaildrop.Error(), http.StatusForbidden)
		return
	}
	baseName, ok := putBaseName(w, r, "/v0/put/")
	if !ok {
		return
	}
	enc := json.NewEncoder(w)
	switch r.Method {
	case "GET":
		id := clientID(h.Peer().StableID())
		if baseName == "" {
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

		// Verify consent before reading any of the body, so an unapproved
		// sender never gets to write a byte to disk.
		var nonce [32]byte
		var expectedHash string
		if needsConsent {
			var cerr error
			nonce, cerr = taildropMgr.beginConsentedPut(h.Peer().StableID(), baseName, r.Header, offset, r.ContentLength)
			if cerr != nil {
				metricPutConsentRejected.Add(1)
				h.Logf("taildrop: rejecting put from %v: %v", h.Peer().StableID(), cerr)
				w.Header().Set(hdrConsentError, cerr.Error())
				http.Error(w, cerr.Error(), consentErrStatus(cerr))
				return
			}
			taildropMgr.consent.mu.Lock()
			expectedHash = taildropMgr.consent.records[nonce].Hash
			taildropMgr.consent.mu.Unlock()
		}

		n, err := taildropMgr.PutFile(clientID(fmt.Sprint(id)), baseName, r.Body, offset, r.ContentLength, expectedHash)
		if needsConsent {
			taildropMgr.endConsentedPut(nonce, n, err)
		}
		switch err {
		case nil:
			d := ext.Clock().Since(t0).Round(time.Second / 10)
			h.Logf("got put of %s in %v from %v/%v", approxSize(n), d, h.RemoteAddr().Addr(), h.Peer().ComputedName)
			io.WriteString(w, "{}\n")
		case ErrNoTaildrop:
			http.Error(w, err.Error(), http.StatusForbidden)
		case ErrConsentHashMismatch:
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
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
