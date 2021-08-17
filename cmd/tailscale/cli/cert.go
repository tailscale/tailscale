// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/client/tailscale"
)

var certCmd = &ffcli.Command{
	Name:       "cert",
	Exec:       runCert,
	ShortHelp:  "get TLS certs",
	ShortUsage: "cert [flags] <domain>",
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("cert", flag.ExitOnError)
		fs.StringVar(&certArgs.certFile, "cert-file", "", "output cert file; defaults to DOMAIN.crt")
		fs.StringVar(&certArgs.keyFile, "key-file", "", "output cert file; defaults to DOMAIN.key")
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
				fmt.Fprintf(w, "<h1>Hello from Tailscale</h1>It works.")
			}),
		}
		log.Printf("running TLS server on :443 ...")
		return s.ListenAndServeTLS("", "")
	}

	if len(args) != 1 {
		return fmt.Errorf("Usage: tailscale cert [flags] <domain>")
	}
	domain := args[0]

	if certArgs.certFile == "" {
		certArgs.certFile = domain + ".crt"
	}
	if certArgs.keyFile == "" {
		certArgs.keyFile = domain + ".key"
	}
	certPEM, keyPEM, err := tailscale.CertPair(ctx, domain)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(certArgs.certFile, certPEM, 0644); err != nil {
		return err
	}
	if err := ioutil.WriteFile(certArgs.keyFile, keyPEM, 0600); err != nil {
		return err
	}
	fmt.Printf("Wrote public cert to %v\n", certArgs.certFile)
	fmt.Printf("Wrote private key to %v\n", certArgs.keyFile)
	return nil
}
