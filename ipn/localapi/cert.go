// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !ios && !android && !js

package localapi

import (
	"fmt"
	"net/http"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/util/strs"
)

func (h *Handler) serveCert(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite && !h.PermitCert {
		http.Error(w, "cert access denied", http.StatusForbidden)
		return
	}
	domain, ok := strs.CutPrefix(r.URL.Path, "/localapi/v0/cert/")
	if !ok {
		http.Error(w, "internal handler config wired wrong", 500)
		return
	}
	pair, err := h.b.GetCertPEM(r.Context(), domain)
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
