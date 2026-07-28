// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
)

// handleC2NTLSCertStatus returns info about the last TLS certificate
// issued for the provided domain. It is the implementation of
// [ipnlocal.HookHandleC2NTLSCertStatus]; control calls it to clean up
// DNS TXT records when they're no longer needed by LetsEncrypt.
//
// It does not kick off a cert fetch or async refresh. It only reports
// anything that's already sitting on disk, and only reports metadata
// about the public cert (stuff that'd be the in CT logs anyway).
func (e *extension) handleC2NTLSCertStatus(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	cs, err := e.getCertStore(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	domain := r.FormValue("domain")
	if domain == "" {
		http.Error(w, "no 'domain'", http.StatusBadRequest)
		return
	}

	ret := &tailcfg.C2NTLSCertInfo{}
	pair, err := getCertPEMCached(cs, domain, b.Clock().Now())
	ret.Valid = err == nil
	if err != nil {
		ret.Error = err.Error()
		if errors.Is(err, errCertExpired) {
			ret.Expired = true
		} else if errors.Is(err, ipn.ErrStateNotExist) {
			ret.Missing = true
			ret.Error = "no certificate"
		}
	} else {
		block, _ := pem.Decode(pair.CertPEM)
		if block == nil {
			ret.Error = "invalid PEM"
			ret.Valid = false
		} else {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ret.Error = fmt.Sprintf("invalid certificate: %v", err)
				ret.Valid = false
			} else {
				ret.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
				ret.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
			}
		}
	}

	writeJSON(w, ret)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
