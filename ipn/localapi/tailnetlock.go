// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package localapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/httpm"
)

func init() {
	Register("tka/affected-sigs", (*Handler).serveTKAAffectedSigs)
	Register("tka/cosign-recovery-aum", (*Handler).serveTKACosignRecoveryAUM)
	Register("tka/disable", (*Handler).serveTKADisable)
	Register("tka/force-local-disable", (*Handler).serveTKALocalDisable)
	Register("tka/generate-recovery-aum", (*Handler).serveTKAGenerateRecoveryAUM)
	Register("tka/init", (*Handler).serveTKAInit)
	Register("tka/log", (*Handler).serveTKALog)
	Register("tka/modify", (*Handler).serveTKAModify)
	Register("tka/sign", (*Handler).serveTKASign)
	Register("tka/status", (*Handler).serveTKAStatus)
	Register("tka/submit-recovery-aum", (*Handler).serveTKASubmitRecoveryAUM)
	Register("tka/verify-deeplink", (*Handler).serveTKAVerifySigningDeeplink)
	Register("tka/wrap-preauth-key", (*Handler).serveTKAWrapPreauthKey)
}

func (h *Handler) serveTKAStatus(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "lock status access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "use GET", http.StatusMethodNotAllowed)
		return
	}

	j, err := json.MarshalIndent(h.b.NetworkLockStatus(), "", "\t")
	if err != nil {
		http.Error(w, "JSON encoding error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func (h *Handler) serveTKASign(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "lock sign access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	type signRequest struct {
		NodeKey        key.NodePublic
		RotationPublic []byte
	}
	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := h.b.NetworkLockSign(req.NodeKey, req.RotationPublic); err != nil {
		http.Error(w, "signing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) serveTKAInit(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "lock init access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	type initRequest struct {
		Keys               []tka.Key
		DisablementValues  [][]byte
		SupportDisablement []byte
	}
	var req initRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if !h.b.NetworkLockAllowed() {
		http.Error(w, "Tailnet Lock is not supported on your pricing plan", http.StatusForbidden)
		return
	}

	if err := h.b.NetworkLockInit(req.Keys, req.DisablementValues, req.SupportDisablement); err != nil {
		http.Error(w, "initialization failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	j, err := json.MarshalIndent(h.b.NetworkLockStatus(), "", "\t")
	if err != nil {
		http.Error(w, "JSON encoding error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func (h *Handler) serveTKAModify(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "network-lock modify access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	type modifyRequest struct {
		AddKeys    []tka.Key
		RemoveKeys []tka.Key
	}
	var req modifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := h.b.NetworkLockModify(req.AddKeys, req.RemoveKeys); err != nil {
		http.Error(w, "network-lock modify failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(204)
}

func (h *Handler) serveTKAWrapPreauthKey(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "network-lock modify access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	type wrapRequest struct {
		TSKey  string
		TKAKey string // key.NLPrivate.MarshalText
	}
	var req wrapRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 12*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	var priv key.NLPrivate
	if err := priv.UnmarshalText([]byte(req.TKAKey)); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	wrappedKey, err := h.b.NetworkLockWrapPreauthKey(req.TSKey, priv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(wrappedKey))
}

func (h *Handler) serveTKAVerifySigningDeeplink(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "signing deeplink verification access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	type verifyRequest struct {
		URL string
	}
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON for verifyRequest body", http.StatusBadRequest)
		return
	}

	res := h.b.NetworkLockVerifySigningDeeplink(req.URL)
	j, err := json.MarshalIndent(res, "", "\t")
	if err != nil {
		http.Error(w, "JSON encoding error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func (h *Handler) serveTKADisable(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "network-lock modify access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	body := io.LimitReader(r.Body, 1024*1024)
	secret, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "reading secret", http.StatusBadRequest)
		return
	}

	if err := h.b.NetworkLockDisable(secret); err != nil {
		http.Error(w, "network-lock disable failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) serveTKALocalDisable(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "network-lock modify access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	// Require a JSON stanza for the body as an additional CSRF protection.
	var req struct{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := h.b.NetworkLockForceLocalDisable(); err != nil {
		http.Error(w, "network-lock local disable failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) serveTKALog(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "use GET", http.StatusMethodNotAllowed)
		return
	}

	limit := 50
	if limitStr := r.FormValue("limit"); limitStr != "" {
		lm, err := strconv.Atoi(limitStr)
		if err != nil {
			http.Error(w, "parsing 'limit' parameter: "+err.Error(), http.StatusBadRequest)
			return
		}
		limit = int(lm)
	}

	updates, err := h.b.NetworkLockLog(limit)
	if err != nil {
		http.Error(w, "reading log failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	j, err := json.MarshalIndent(updates, "", "\t")
	if err != nil {
		http.Error(w, "JSON encoding error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func (h *Handler) serveTKAAffectedSigs(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	keyID, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}

	sigs, err := h.b.NetworkLockAffectedSigs(keyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	j, err := json.MarshalIndent(sigs, "", "\t")
	if err != nil {
		http.Error(w, "JSON encoding error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func (h *Handler) serveTKAGenerateRecoveryAUM(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	type verifyRequest struct {
		Keys     []tkatype.KeyID
		ForkFrom string
	}
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON for verifyRequest body", http.StatusBadRequest)
		return
	}

	var forkFrom tka.AUMHash
	if req.ForkFrom != "" {
		if err := forkFrom.UnmarshalText([]byte(req.ForkFrom)); err != nil {
			http.Error(w, "decoding fork-from: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	res, err := h.b.NetworkLockGenerateRecoveryAUM(req.Keys, forkFrom)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(res.Serialize())
}

func (h *Handler) serveTKACosignRecoveryAUM(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	body := io.LimitReader(r.Body, 1024*1024)
	aumBytes, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "reading AUM", http.StatusBadRequest)
		return
	}
	var aum tka.AUM
	if err := aum.Unserialize(aumBytes); err != nil {
		http.Error(w, "decoding AUM", http.StatusBadRequest)
		return
	}

	res, err := h.b.NetworkLockCosignRecoveryAUM(&aum)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(res.Serialize())
}

func (h *Handler) serveTKASubmitRecoveryAUM(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	body := io.LimitReader(r.Body, 1024*1024)
	aumBytes, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "reading AUM", http.StatusBadRequest)
		return
	}
	var aum tka.AUM
	if err := aum.Unserialize(aumBytes); err != nil {
		http.Error(w, "decoding AUM", http.StatusBadRequest)
		return
	}

	if err := h.b.NetworkLockSubmitRecoveryAUM(&aum); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
