// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/atomicfile"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/version"
)

var certCmd = &ffcli.Command{
	Name:       "cert",
	Exec:       runCert,
	ShortHelp:  "get TLS certs",
	ShortUsage: "cert [flags] <domain>",
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("cert")
		fs.StringVar(&certArgs.certFile, "cert-file", "", "output cert file or \"-\" for stdout; defaults to DOMAIN.crt if --cert-file and --key-file are both unset")
		fs.StringVar(&certArgs.keyFile, "key-file", "", "output cert file or \"-\" for stdout; defaults to DOMAIN.key if --cert-file and --key-file are both unset")
		fs.BoolVar(&certArgs.serve, "serve-demo", false, "if true, serve on port :443 using the cert as a demo, instead of writing out the files to disk")
		return fs
	})(),
}

var certArgs struct {
	certFile string
	keyFile  string
	serve    bool
}

func runCert(ctx context.Context, args []string) error {
	if certArgs.serve {
		s := &http.Server{
			TLSConfig: &tls.Config{
				GetCertificate: tailscale.GetCertificate,
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
		log.Printf("running TLS server on :443 ...")
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
	certPEM, keyPEM, err := tailscale.CertPair(ctx, domain)
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
	if certArgs.keyFile != "" {
		keyChanged, err := writeIfChanged(certArgs.keyFile, keyPEM, 0600)
		if err != nil {
			return err
		}
		if certArgs.keyFile != "-" {
			macWarn()
			if keyChanged {
				printf("Wrote private key to %v\n", certArgs.keyFile)
			} else {
				printf("Private key unchanged at %v\n", certArgs.keyFile)
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
