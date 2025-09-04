// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsidp command is an OpenID Connect Identity Provider server.
//
// See https://github.com/tailscale/tailscale/issues/10263 for background.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/cmd/tsidp/server"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	"tailscale.com/version"
)

// funnelClientsFile is the file where client IDs and secrets for OIDC clients
// accessing the IDP over Funnel are persisted.
// Migrated from legacy/tsidp.go:62
const funnelClientsFile = "oidc-funnel-clients.json"

// Command line flags
// Migrated from legacy/tsidp.go:64-73
var (
	flagVerbose            = flag.Bool("verbose", false, "be verbose")
	flagPort               = flag.Int("port", 443, "port to listen on")
	flagLocalPort          = flag.Int("local-port", -1, "allow requests from localhost")
	flagUseLocalTailscaled = flag.Bool("use-local-tailscaled", false, "use local tailscaled instead of tsnet")
	flagFunnel             = flag.Bool("funnel", false, "use Tailscale Funnel to make tsidp available on the public internet")
	flagHostname           = flag.String("hostname", "idp", "tsnet hostname to use instead of idp")
	flagDir                = flag.String("dir", "", "tsnet state directory; a default one will be created if not provided")
	flagEnableSTS          = flag.Bool("enable-sts", false, "enable OIDC STS token exchange support")
)

// main initializes and starts the tsidp server
// Migrated from legacy/tsidp.go:75-239
func main() {
	flag.Parse()
	ctx := context.Background()
	if !envknob.UseWIPCode() {
		log.Fatal("cmd/tsidp is a work in progress and has not been security reviewed;\nits use requires TAILSCALE_USE_WIP_CODE=1 be set in the environment for now.")
	}

	var (
		lc          *local.Client
		st          *ipnstate.Status
		err         error
		watcherChan chan error
		cleanup     func()

		lns []net.Listener
	)
	if *flagUseLocalTailscaled {
		lc = &local.Client{}
		st, err = lc.StatusWithoutPeers(ctx)
		if err != nil {
			log.Fatalf("getting status: %v", err)
		}
		portStr := fmt.Sprint(*flagPort)
		anySuccess := false
		for _, ip := range st.TailscaleIPs {
			ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), portStr))
			if err != nil {
				log.Printf("failed to listen on %v: %v", ip, err)
				continue
			}
			anySuccess = true
			ln = tls.NewListener(ln, &tls.Config{
				GetCertificate: lc.GetCertificate,
			})
			lns = append(lns, ln)
		}
		if !anySuccess {
			log.Fatalf("failed to listen on any of %v", st.TailscaleIPs)
		}

		// tailscaled needs to be setting an HTTP header for funneled requests
		// that older versions don't provide.
		// TODO(naman): is this the correct check?
		if *flagFunnel && !version.AtLeast(st.Version, "1.71.0") {
			log.Fatalf("Local tailscaled not new enough to support -funnel. Update Tailscale or use tsnet mode.")
		}
		cleanup, watcherChan, err = server.ServeOnLocalTailscaled(ctx, lc, st, uint16(*flagPort), *flagFunnel)
		if err != nil {
			log.Fatalf("could not serve on local tailscaled: %v", err)
		}
		defer cleanup()
	} else {
		hostinfo.SetApp("tsidp")
		ts := &tsnet.Server{
			Hostname: *flagHostname,
			Dir:      *flagDir,
		}
		if *flagVerbose {
			ts.Logf = log.Printf
		}
		st, err = ts.Up(ctx)
		if err != nil {
			log.Fatal(err)
		}
		lc, err = ts.LocalClient()
		if err != nil {
			log.Fatalf("getting local client: %v", err)
		}
		var ln net.Listener
		if *flagFunnel {
			if err := ipn.CheckFunnelAccess(uint16(*flagPort), st.Self); err != nil {
				log.Fatalf("%v", err)
			}
			ln, err = ts.ListenFunnel("tcp", fmt.Sprintf(":%d", *flagPort))
		} else {
			ln, err = ts.ListenTLS("tcp", fmt.Sprintf(":%d", *flagPort))
		}
		if err != nil {
			log.Fatal(err)
		}
		lns = append(lns, ln)
	}

	srv := server.New(
		lc,
		*flagFunnel,
		*flagUseLocalTailscaled,
		*flagEnableSTS,
	)
	
	if *flagPort != 443 {
		srv.SetServerURL(fmt.Sprintf("https://%s:%d", strings.TrimSuffix(st.Self.DNSName, "."), *flagPort))
	} else {
		srv.SetServerURL(fmt.Sprintf("https://%s", strings.TrimSuffix(st.Self.DNSName, ".")))
	}

	// Load funnel clients from disk if they exist, regardless of whether funnel is enabled
	// This ensures OIDC clients persist across restarts
	f, err := os.Open(funnelClientsFile)
	if err == nil {
		var funnelClients map[string]*server.FunnelClient
		if err := json.NewDecoder(f).Decode(&funnelClients); err != nil {
			log.Fatalf("could not parse %s: %v", funnelClientsFile, err)
		}
		f.Close()
		srv.SetFunnelClients(funnelClients)
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("could not open %s: %v", funnelClientsFile, err)
	}

	log.Printf("Running tsidp at %s ...", srv.ServerURL())

	if *flagLocalPort != -1 {
		loopbackURL := fmt.Sprintf("http://localhost:%d", *flagLocalPort)
		log.Printf("Also running tsidp at %s ...", loopbackURL)
		srv.SetLoopbackURL(loopbackURL)
		ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *flagLocalPort))
		if err != nil {
			log.Fatal(err)
		}
		lns = append(lns, ln)
	}

	// Start token cleanup routine
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	defer cleanupCancel()

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				srv.CleanupExpiredTokens()
				if *flagVerbose {
					log.Printf("Cleaned up expired tokens")
				}
			case <-cleanupCtx.Done():
				return
			}
		}
	}()

	for _, ln := range lns {
		httpServer := http.Server{
			Handler: srv,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, server.CtxConn{}, c)
			},
		}
		go httpServer.Serve(ln)
	}
	// need to catch os.Interrupt, otherwise deferred cleanup code doesn't run
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt)
	select {
	case <-exitChan:
		log.Printf("interrupt, exiting")
		return
	case <-watcherChan:
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			log.Printf("watcher closed, exiting")
			return
		}
		log.Fatalf("watcher error: %v", err)
		return
	}
}