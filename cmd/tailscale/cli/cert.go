// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
)

func jout(v interface{}) {
	j, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%T: %s\n", v, j)
}

func checkCertDomain(st *ipnstate.Status, domain string) error {
	if domain == "" {
		return errors.New("missing domain name")
	}
	for _, d := range st.CertDomains {
		if d == domain {
			return nil
		}
	}
	// Transitional way while server doesn't yet populate CertDomains: also permit the client
	// attempting Self.DNSName.
	okay := st.CertDomains[:len(st.CertDomains):len(st.CertDomains)]
	if st.Self != nil {
		if v := strings.Trim(st.Self.DNSName, "."); v != "" {
			if v == domain {
				return nil
			}
			okay = append(okay, v)
		}
	}
	switch len(okay) {
	case 0:
		return errors.New("your Tailscale account does not support getting TLS certs")
	case 1:
		return fmt.Errorf("invalid domain %q; only %q is permitted", domain, okay[0])
	default:
		return fmt.Errorf("invalid domain %q; must be one of %q", domain, okay)
	}
}

func debugGetCert(ctx context.Context, domain string) error {
	st, err := tailscale.Status(ctx)
	if err != nil {
		return fmt.Errorf("getting tailscale status: %w", err)
	}
	if err := checkCertDomain(st, domain); err != nil {
		return err
	}

	key, err := acmeKey()
	if err != nil {
		return err
	}
	ac := &acme.Client{
		Key: key,
	}

	logf := log.Printf

	a, err := ac.GetReg(ctx, "unused")
	switch {
	case err == nil:
		// Great, already registered.
		logf("Already had ACME account.")
	case err == acme.ErrNoAccount:
		a, err = ac.Register(ctx, new(acme.Account), acme.AcceptTOS)
		if err == acme.ErrAccountAlreadyExists {
			// Potential race. Double check.
			a, err = ac.GetReg(ctx, "unused")
		}
		if err != nil {
			return fmt.Errorf("acme.Register: %w", err)
		}
		logf("Registered ACME account.")
		jout(a)
	default:
		return fmt.Errorf("acme.GetReg: %w", err)

	}
	if a.Status != acme.StatusValid {
		return fmt.Errorf("unexpected ACME account status %q", a.Status)
	}

	order, err := ac.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return err
	}
	jout(order)

	for _, aurl := range order.AuthzURLs {
		az, err := ac.GetAuthorization(ctx, aurl)
		if err != nil {
			return err
		}
		jout(az)
		for _, ch := range az.Challenges {
			if ch.Type == "dns-01" {
				rec, err := ac.DNS01ChallengeRecord(ch.Token)
				if err != nil {
					return err
				}
				err = tailscale.SetDNS(ctx, "_acme-challenge."+domain, rec)
				log.Printf("SetDNS of %q = %v", rec, err)

				chal, err := ac.Accept(ctx, ch)
				if err != nil {
					return fmt.Errorf("Accept: %v", err)
				}
				jout(chal)
				break
			}
		}
	}

	t0 := time.Now()
	orderURI := order.URI
	for {
		order, err = ac.WaitOrder(ctx, orderURI)
		if err == nil {
			break
		}
		if oe, ok := err.(*acme.OrderError); ok && oe.Status == acme.StatusInvalid {
			if time.Since(t0) > 2*time.Minute {
				return errors.New("timeout waiting for order to not be invalid")
			}
			log.Printf("order invalid; waiting...")
			select {
			case <-time.After(5 * time.Second):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return fmt.Errorf("WaitOrder: %v", err)
	}
	jout(order)

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	var pemBuf bytes.Buffer
	if err := encodeECDSAKey(&pemBuf, certPrivKey); err != nil {
		return err
	}
	if err := ioutil.WriteFile(domain+".key", pemBuf.Bytes(), 0600); err != nil {
		return err
	}

	csr, err := certRequest(certPrivKey, domain, nil)
	if err != nil {
		return err
	}

	der, _, err := ac.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("CreateOrder: %v", err)
	}
	pemBuf.Reset()
	for _, b := range der {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&pemBuf, pb); err != nil {
			return err
		}
	}
	if err := ioutil.WriteFile(domain+".crt", pemBuf.Bytes(), 0644); err != nil {
		return err
	}
	os.Stdout.Write(pemBuf.Bytes())
	fmt.Printf("\nPublic cert and private key written to %s.crt and %s.key\n", domain, domain)
	return nil
}

// certRequest generates a CSR for the given common name cn and optional SANs.
func certRequest(key crypto.Signer, cn string, ext []pkix.Extension, san ...string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		DNSNames:        san,
		ExtraExtensions: ext,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

func acmeKey() (crypto.Signer, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	file := filepath.Join(cacheDir, "tailscale-acme")
	if err := os.MkdirAll(file, 0700); err != nil {
		return nil, err
	}
	cacheFile := filepath.Join(file, "acme-account.key.pem")
	if v, err := ioutil.ReadFile(cacheFile); err == nil {
		priv, _ := pem.Decode(v)
		if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
			return nil, errors.New("acme/autocert: invalid account key found in cache")
		}
		return parsePrivateKey(priv.Bytes)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var pemBuf bytes.Buffer
	if err := encodeECDSAKey(&pemBuf, privKey); err != nil {
		return nil, err
	}
	if err := ioutil.WriteFile(cacheFile, pemBuf.Bytes(), 0600); err != nil {
		return nil, err
	}
	return privKey, nil
}

func encodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

// parsePrivateKey is a copy of x/crypto/acme's parsePrivateKey.
//
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
//
// Inspired by parsePrivateKey in crypto/tls/tls.go.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("acme/autocert: unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("acme/autocert: failed to parse private key")
}
