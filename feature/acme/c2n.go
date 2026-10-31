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
	domain := r.FormValue("domain")
	if domain == "" {
		http.Error(w, "no 'domain'", http.StatusBadRequest)
		return
	}

	ret, err := e.certStatus(b, domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, ret)
}

// certStatus reports the state of the cached TLS certificate for domain. It
// does not kick off a cert fetch or async refresh; it only reports what is
// already on disk, and only metadata about the public cert (stuff that'd be in
// CT logs anyway). The error is non-nil only if the cert store itself can't be
// reached.
func (e *extension) certStatus(b *ipnlocal.LocalBackend, domain string) (*tailcfg.C2NTLSCertInfo, error) {
	cs, err := e.getCertStore(b)
	if err != nil {
		return nil, err
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
		return ret, nil
	}
	block, _ := pem.Decode(pair.CertPEM)
	if block == nil {
		ret.Error = "invalid PEM"
		ret.Valid = false
		return ret, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		ret.Error = fmt.Sprintf("invalid certificate: %v", err)
		ret.Valid = false
		return ret, nil
	}
	ret.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	ret.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	return ret, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
