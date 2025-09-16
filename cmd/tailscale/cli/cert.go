// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"software.sslmate.com/src/go-pkcs12"
	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
	"tailscale.com/version"
)

func init() {
	maybeCertCmd = func() *ffcli.Command {
		return &ffcli.Command{
			Name:       "cert",
			Exec:       runCert,
			ShortHelp:  "Get TLS certs",
			ShortUsage: "tailscale cert [flags] <domain>",
			FlagSet: (func() *flag.FlagSet {
				fs := newFlagSet("cert")
				fs.StringVar(&certArgs.certFile, "cert-file", "", "output cert file or \"-\" for stdout; defaults to DOMAIN.crt if --cert-file and --key-file are both unset")
				fs.StringVar(&certArgs.keyFile, "key-file", "", "output key file or \"-\" for stdout; defaults to DOMAIN.key if --cert-file and --key-file are both unset")
				fs.BoolVar(&certArgs.serve, "serve-demo", false, "if true, serve on port :443 using the cert as a demo, instead of writing out the files to disk")
				fs.DurationVar(&certArgs.minValidity, "min-validity", 0, "ensure the certificate is valid for at least this duration; the output certificate is never expired if this flag is unset or 0, but the lifetime may vary; the maximum allowed min-validity depends on the CA")
				return fs
			})(),
		}
	}
}

var certArgs struct {
	certFile    string
	keyFile     string
	serve       bool
	minValidity time.Duration
}

func runCert(ctx context.Context, args []string) error {
	if certArgs.serve {
		s := &http.Server{
			Addr: ":443",
			TLSConfig: &tls.Config{
				GetCertificate: localClient.GetCertificate,
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS != nil && !strings.Contains(r.Host, ".") && r.Method == "GET" {
					if v, ok := localClient.ExpandSNIName(r.Context(), r.Host); ok {
						http.Redirect(w, r, "https://"+v+r.URL.Path, http.StatusTemporaryRedirect)
						return
					}
				}
				fmt.Fprintf(w, "<h1>Hello from Tailscale</h1>It works.")
			}),
		}
		switch len(args) {
		case 0:
			// Nothing.
		case 1:
			s.Addr = args[0]
		default:
			return errors.New("too many arguments; max 1 allowed with --serve-demo (the listen address)")
		}

		log.Printf("running TLS server on %s ...", s.Addr)
		return s.ListenAndServeTLS("", "")
	}

	if len(args) != 1 {
		var hint bytes.Buffer
		if st, err := localClient.Status(ctx); err == nil {
			if st.BackendState != ipn.Running.String() {
				fmt.Fprintf(&hint, "\nTailscale is not running.\n")
			} else if len(st.CertDomains) == 0 {
				fmt.Fprintf(&hint, "\nHTTPS cert support is not enabled/configured for your tailnet.\n")
			} else if len(st.CertDomains) == 1 {
				fmt.Fprintf(&hint, "\nFor domain, use %q.\n", st.CertDomains[0])
			} else {
				fmt.Fprintf(&hint, "\nValid domain options: %q.\n", st.CertDomains)
			}
		}
		return fmt.Errorf("Usage: tailscale cert [flags] <domain>%s", hint.Bytes())
	}
	domain := args[0]

	printf := func(format string, a ...any) {
		printf(format, a...)
	}
	if certArgs.certFile == "-" || certArgs.keyFile == "-" {
		printf = log.Printf
		log.SetFlags(0)
	}
	if certArgs.certFile == "" && certArgs.keyFile == "" {
		certArgs.certFile = domain + ".crt"
		certArgs.keyFile = domain + ".key"
	}
	certPEM, keyPEM, err := localClient.CertPairWithValidity(ctx, domain, certArgs.minValidity)
	if err != nil {
		return err
	}
	needMacWarning := version.IsSandboxedMacOS()
	macWarn := func() {
		if !needMacWarning {
			return
		}
		needMacWarning = false
		dir := "io.tailscale.ipn.macos"
		if version.IsMacSysExt() {
			dir = "io.tailscale.ipn.macsys"
		}
		printf("Warning: the macOS CLI runs in a sandbox; this binary's filesystem writes go to $HOME/Library/Containers/%s/Data\n", dir)
	}
	if certArgs.certFile != "" {
		certChanged, err := writeIfChanged(certArgs.certFile, certPEM, 0644)
		if err != nil {
			return err
		}
		if certArgs.certFile != "-" {
			macWarn()
			if certChanged {
				printf("Wrote public cert to %v\n", certArgs.certFile)
			} else {
				printf("Public cert unchanged at %v\n", certArgs.certFile)
			}
		}
	}
	if dst := certArgs.keyFile; dst != "" {
		contents := keyPEM
		if isPKCS12(dst) {
			var err error
			contents, err = convertToPKCS12(certPEM, keyPEM)
			if err != nil {
				return err
			}
		}
		keyChanged, err := writeIfChanged(dst, contents, 0600)
		if err != nil {
			return err
		}
		if certArgs.keyFile != "-" {
			macWarn()
			if keyChanged {
				printf("Wrote private key to %v\n", dst)
			} else {
				printf("Private key unchanged at %v\n", dst)
			}
		}
	}
	return nil
}

func writeIfChanged(filename string, contents []byte, mode os.FileMode) (changed bool, err error) {
	if filename == "-" {
		Stdout.Write(contents)
		return false, nil
	}
	if old, err := os.ReadFile(filename); err == nil && bytes.Equal(contents, old) {
		return false, nil
	}
	if err := atomicfile.WriteFile(filename, contents, mode); err != nil {
		return false, err
	}
	return true, nil
}

func isPKCS12(dst string) bool {
	return strings.HasSuffix(dst, ".p12") || strings.HasSuffix(dst, ".pfx")
}

func convertToPKCS12(certPEM, keyPEM []byte) ([]byte, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, c := range cert.Certificate {
		cert, err := x509.ParseCertificate(c)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certs")
	}
	// TODO(bradfitz): I'm not sure this is right yet. The goal was to make this
	// work for https://github.com/tailscale/tailscale/issues/2928 but I'm still
	// fighting Windows.
	return pkcs12.Encode(rand.Reader, cert.PrivateKey, certs[0], certs[1:], "" /* no password */)
}
