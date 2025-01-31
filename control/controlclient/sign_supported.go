// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

// darwin,cgo is also supported by certstore but untested, so it is not enabled.

package controlclient

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/tailscale/certstore"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/syspolicy"
)

// getMachineCertificateSubject returns the exact name of a Subject that needs
// to be present in an identity's certificate chain to sign a RegisterRequest,
// formatted as per pkix.Name.String(). The Subject may be that of the identity
// itself, an intermediate CA or the root CA.
//
// If getMachineCertificateSubject() returns "" then no lookup will occur and
// each RegisterRequest will be unsigned.
//
// Example: "CN=Tailscale Inc Test Root CA,OU=Tailscale Inc Test Certificate Authority,O=Tailscale Inc,ST=ON,C=CA"
func getMachineCertificateSubject() string {
	machineCertSubject, _ := syspolicy.GetString(syspolicy.MachineCertificateSubject, "")
	return machineCertSubject
}

var (
	errNoMatch    = errors.New("no matching certificate")
	errBadRequest = errors.New("malformed request")
)

func isSupportedCertificate(cert *x509.Certificate) bool {
	return cert.PublicKeyAlgorithm == x509.RSA
}

func isSubjectInChain(subject string, chain []*x509.Certificate) bool {
	if len(chain) == 0 || chain[0] == nil {
		return false
	}

	for _, c := range chain {
		if c == nil {
			continue
		}
		if c.Subject.String() == subject {
			return true
		}
	}

	return false
}

func selectIdentityFromSlice(subject string, ids []certstore.Identity, now time.Time) (certstore.Identity, []*x509.Certificate) {
	var bestCandidate struct {
		id    certstore.Identity
		chain []*x509.Certificate
	}

	for _, id := range ids {
		chain, err := id.CertificateChain()
		if err != nil {
			continue
		}

		if len(chain) < 1 {
			continue
		}

		if !isSupportedCertificate(chain[0]) {
			continue
		}

		if now.Before(chain[0].NotBefore) || now.After(chain[0].NotAfter) {
			// Certificate is not valid at this time
			continue
		}

		if !isSubjectInChain(subject, chain) {
			continue
		}

		// Select the most recently issued certificate. If there is a tie, pick
		// one arbitrarily.
		if len(bestCandidate.chain) > 0 && bestCandidate.chain[0].NotBefore.After(chain[0].NotBefore) {
			continue
		}

		bestCandidate.id = id
		bestCandidate.chain = chain
	}

	return bestCandidate.id, bestCandidate.chain
}

// findIdentity locates an identity from the Windows or Darwin certificate
// store. It returns the first certificate with a matching Subject anywhere in
// its certificate chain, so it is possible to search for the leaf certificate,
// intermediate CA or root CA. If err is nil then the returned identity will
// never be nil (if no identity is found, the error errNoMatch will be
// returned). If an identity is returned then its certificate chain is also
// returned.
func findIdentity(subject string, st certstore.Store) (certstore.Identity, []*x509.Certificate, error) {
	ids, err := st.Identities()
	if err != nil {
		return nil, nil, err
	}

	selected, chain := selectIdentityFromSlice(subject, ids, clock.Now())

	for _, id := range ids {
		if id != selected {
			id.Close()
		}
	}

	if selected == nil {
		return nil, nil, errNoMatch
	}

	return selected, chain, nil
}

// signRegisterRequest looks for a suitable machine identity from the local
// system certificate store, and if one is found, signs the RegisterRequest
// using that identity's public key. In addition to the signature, the full
// certificate chain is included so that the control server can validate the
// certificate from a copy of the root CA's certificate.
func signRegisterRequest(req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey key.MachinePublic) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("signRegisterRequest: %w", err)
		}
	}()

	if req.Timestamp == nil {
		return errBadRequest
	}

	machineCertificateSubject := getMachineCertificateSubject()
	if machineCertificateSubject == "" {
		return errCertificateNotConfigured
	}

	st, err := certstore.Open(certstore.System)
	if err != nil {
		return fmt.Errorf("open cert store: %w", err)
	}
	defer st.Close()

	id, chain, err := findIdentity(machineCertificateSubject, st)
	if err != nil {
		return fmt.Errorf("find identity: %w", err)
	}
	defer id.Close()

	signer, err := id.Signer()
	if err != nil {
		return fmt.Errorf("create signer: %w", err)
	}

	cl := 0
	for _, c := range chain {
		cl += len(c.Raw)
	}
	req.DeviceCert = make([]byte, 0, cl)
	for _, c := range chain {
		req.DeviceCert = append(req.DeviceCert, c.Raw...)
	}

	req.SignatureType = tailcfg.SignatureV2
	h, err := HashRegisterRequest(req.SignatureType, req.Timestamp.UTC(), serverURL, req.DeviceCert, serverPubKey, machinePubKey)
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}

	req.Signature, err = signer.Sign(nil, h, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	return nil
}
