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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/peterbourgon/ff/v2/ffcli"
	"golang.org/x/crypto/acme"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
)

var debugCmd = &ffcli.Command{
	Name: "debug",
	Exec: runDebug,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("debug", flag.ExitOnError)
		fs.BoolVar(&debugArgs.goroutines, "daemon-goroutines", false, "If true, dump the tailscaled daemon's goroutines")
		fs.BoolVar(&debugArgs.ipn, "ipn", false, "If true, subscribe to IPN notifications")
		fs.BoolVar(&debugArgs.prefs, "prefs", false, "If true, dump active prefs")
		fs.BoolVar(&debugArgs.pretty, "pretty", false, "If true, pretty-print output (for --prefs)")
		fs.BoolVar(&debugArgs.netMap, "netmap", true, "whether to include netmap in --ipn mode")
		fs.BoolVar(&debugArgs.localCreds, "local-creds", false, "print how to connect to local tailscaled")
		fs.StringVar(&debugArgs.file, "file", "", "get, delete:NAME, or NAME")
		fs.StringVar(&debugArgs.getCert, "get-cert", "", "hostname to start ACME flow for (debug)")
		return fs
	})(),
}

var debugArgs struct {
	localCreds bool
	goroutines bool
	ipn        bool
	netMap     bool
	file       string
	prefs      bool
	pretty     bool
	getCert    string
}

func runDebug(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown arguments")
	}
	if debugArgs.getCert != "" {
		return debugGetCert(ctx, debugArgs.getCert)
	}
	if debugArgs.localCreds {
		port, token, err := safesocket.LocalTCPPortAndToken()
		if err == nil {
			fmt.Printf("curl -u:%s http://localhost:%d/localapi/v0/status\n", token, port)
			return nil
		}
		if runtime.GOOS == "windows" {
			fmt.Printf("curl http://localhost:41112/localapi/v0/status\n")
			return nil
		}
		fmt.Printf("curl --unix-socket %s http://foo/localapi/v0/status\n", paths.DefaultTailscaledSocket())
		return nil
	}
	if debugArgs.prefs {
		prefs, err := tailscale.GetPrefs(ctx)
		if err != nil {
			return err
		}
		if debugArgs.pretty {
			fmt.Println(prefs.Pretty())
		} else {
			j, _ := json.MarshalIndent(prefs, "", "\t")
			fmt.Println(string(j))
		}
		return nil
	}
	if debugArgs.goroutines {
		goroutines, err := tailscale.Goroutines(ctx)
		if err != nil {
			return err
		}
		os.Stdout.Write(goroutines)
		return nil
	}
	if debugArgs.ipn {
		c, bc, ctx, cancel := connect(ctx)
		defer cancel()

		bc.SetNotifyCallback(func(n ipn.Notify) {
			if !debugArgs.netMap {
				n.NetMap = nil
			}
			j, _ := json.MarshalIndent(n, "", "\t")
			fmt.Printf("%s\n", j)
		})
		bc.RequestEngineStatus()
		pump(ctx, bc, c)
		return errors.New("exit")
	}
	if debugArgs.file != "" {
		if debugArgs.file == "get" {
			wfs, err := tailscale.WaitingFiles(ctx)
			if err != nil {
				log.Fatal(err)
			}
			e := json.NewEncoder(os.Stdout)
			e.SetIndent("", "\t")
			e.Encode(wfs)
			return nil
		}
		delete := strings.HasPrefix(debugArgs.file, "delete:")
		if delete {
			return tailscale.DeleteWaitingFile(ctx, strings.TrimPrefix(debugArgs.file, "delete:"))
		}
		rc, size, err := tailscale.GetWaitingFile(ctx, debugArgs.file)
		if err != nil {
			return err
		}
		log.Printf("Size: %v\n", size)
		io.Copy(os.Stdout, rc)
		return nil
	}
	return nil
}

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

	/*
		acct, err := ac.Register(ctx, new(acme.Account), acme.AcceptTOS)
		if err != nil {
			return fmt.Errorf("Register: %v", err)
		}
		j, err = json.MarshalIndent(acct, "", "\t")
		if err != nil {
			return err
		}
		os.Stdout.Write(j)
	*/

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
