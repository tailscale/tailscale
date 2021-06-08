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
	"strconv"
	"strings"

	"golang.org/x/crypto/acme"
	"tailscale.com/client/tailscale"
)

func jout(v interface{}) {
	j, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%T: %s\n", v, j)
}

func debugGetCert(ctx context.Context, cert string) error {
	key, err := acmeKey()
	if err != nil {
		return err
	}
	ac := &acme.Client{
		Key: key,
	}
	d, err := ac.Discover(ctx)
	if err != nil {
		return err
	}
	jout(d)

	if reg, _ := strconv.ParseBool(os.Getenv("TS_DEBUG_ACME_REGISTER")); reg {
		acct, err := ac.Register(ctx, new(acme.Account), acme.AcceptTOS)
		if err != nil {
			return fmt.Errorf("Register: %v", err)
		}
		jout(acct)
	}

	order, err := ac.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: cert}})
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
				err = tailscale.SetDNS(ctx, "_acme-challenge."+cert, rec)
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

	order, err = ac.WaitOrder(ctx, order.URI)
	if err != nil {
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
	if err := ioutil.WriteFile("acme-debug.key", pemBuf.Bytes(), 0600); err != nil {
		return err
	}

	csr, err := certRequest(certPrivKey, cert, nil)
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
	if err := ioutil.WriteFile("acme-debug.crt", pemBuf.Bytes(), 0600); err != nil {
		return err
	}
	os.Stdout.Write(pemBuf.Bytes())
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
