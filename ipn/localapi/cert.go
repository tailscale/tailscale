// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js && !ts_omit_acme

package localapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"tailscale.com/ipn/ipnlocal"
)

func init() {
	Register("cert/", (*Handler).serveCert)
}

func (h *Handler) serveCert(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite && !h.PermitCert {
		http.Error(w, "cert access denied", http.StatusForbidden)
		return
	}
	domain, ok := strings.CutPrefix(r.URL.Path, "/localapi/v0/cert/")
	if !ok {
		http.Error(w, "internal handler config wired wrong", 500)
		return
	}
	var minValidity time.Duration
	if minValidityStr := r.URL.Query().Get("min_validity"); minValidityStr != "" {
		var err error
		minValidity, err = time.ParseDuration(minValidityStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid validity parameter: %v", err), http.StatusBadRequest)
			return
		}
	}
	pair, err := h.b.GetCertPEMWithValidity(r.Context(), domain, minValidity)
	if err != nil {
		// TODO(bradfitz): 500 is a little lazy here. The errors returned from
		// GetCertPEM (and everywhere) should carry info info to get whether
		// they're 400 vs 403 vs 500 at minimum. And then we should have helpers
		// (in tsweb probably) to return an error that looks at the error value
		// to determine the HTTP status code.
		http.Error(w, fmt.Sprint(err), 500)
		return
	}
	serveKeyPair(w, r, pair)
}

func serveKeyPair(w http.ResponseWriter, r *http.Request, p *ipnlocal.TLSCertKeyPair) {
	w.Header().Set("Content-Type", "text/plain")
	switch r.URL.Query().Get("type") {
	case "", "crt", "cert":
		w.Write(p.CertPEM)
	case "key":
		w.Write(p.KeyPEM)
	case "pair":
		w.Write(p.KeyPEM)
		w.Write(p.CertPEM)
	default:
		http.Error(w, `invalid type; want "cert" (default), "key", or "pair"`, 400)
	}
}
