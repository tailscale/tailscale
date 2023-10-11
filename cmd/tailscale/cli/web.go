// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"crypto/tls"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/web"
	"tailscale.com/util/cmpx"
)

var webCmd = &ffcli.Command{
	Name:       "web",
	ShortUsage: "web [flags]",
	ShortHelp:  "Run a web server for controlling Tailscale",

	LongHelp: strings.TrimSpace(`
"tailscale web" runs a webserver for controlling the Tailscale daemon.

It's primarily intended for use on Synology, QNAP, and other
NAS devices where a web interface is the natural place to control
Tailscale, as opposed to a CLI or a native app.
`),

	FlagSet: (func() *flag.FlagSet {
		webf := newFlagSet("web")
		webf.StringVar(&webArgs.listen, "listen", "localhost:8088", "listen address; use port 0 for automatic")
		webf.BoolVar(&webArgs.cgi, "cgi", false, "run as CGI script")
		webf.BoolVar(&webArgs.dev, "dev", false, "run web client in developer mode [this flag is in development, use is unsupported]")
		webf.StringVar(&webArgs.prefix, "prefix", "", "URL prefix added to requests (for cgi or reverse proxies)")
		return webf
	})(),
	Exec: runWeb,
}

var webArgs struct {
	listen string
	cgi    bool
	dev    bool
	prefix string
}

func tlsConfigFromEnvironment() *tls.Config {
	crt := os.Getenv("TLS_CRT_PEM")
	key := os.Getenv("TLS_KEY_PEM")
	if crt == "" || key == "" {
		return nil
	}

	// We support passing in the complete certificate and key from environment
	// variables because pfSense stores its cert+key in the PHP config. We populate
	// TLS_CRT_PEM and TLS_KEY_PEM from PHP code before starting tailscale web.
	// These are the PEM-encoded Certificate and Private Key.

	cert, err := tls.X509KeyPair([]byte(crt), []byte(key))
	if err != nil {
		log.Printf("tlsConfigFromEnvironment: %v", err)

		// Fallback to unencrypted HTTP.
		return nil
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func runWeb(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("too many non-flag arguments: %q", args)
	}

	webServer, err := web.NewServer(web.ServerOpts{
		DevMode:     webArgs.dev,
		CGIMode:     webArgs.cgi,
		PathPrefix:  webArgs.prefix,
		LocalClient: &localClient,
	})
	if err != nil {
		log.Printf("tailscale.web: %v", err)
		return err
	}
	defer webServer.Shutdown()

	if webArgs.cgi {
		if err := cgi.Serve(webServer); err != nil {
			log.Printf("tailscale.cgi: %v", err)
			return err
		}
		return nil
	}

	tlsConfig := tlsConfigFromEnvironment()
	if tlsConfig != nil {
		server := &http.Server{
			Addr:      webArgs.listen,
			TLSConfig: tlsConfig,
			Handler:   webServer,
		}

		log.Printf("web server running on: https://%s", server.Addr)
		return server.ListenAndServeTLS("", "")
	} else {
		log.Printf("web server running on: %s", urlOfListenAddr(webArgs.listen))
		return http.ListenAndServe(webArgs.listen, webServer)
	}
}

// urlOfListenAddr parses a given listen address into a formatted URL
func urlOfListenAddr(addr string) string {
	host, port, _ := net.SplitHostPort(addr)
	return fmt.Sprintf("http://%s", net.JoinHostPort(cmpx.Or(host, "127.0.0.1"), port))
}
