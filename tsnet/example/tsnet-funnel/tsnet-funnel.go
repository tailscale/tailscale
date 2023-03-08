// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tsnet-funnel server demonstrates how to use tsnet with Funnel.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

var (
	addr = flag.String("addr", ":443", "address to listen on")
)

func enableFunnel(ctx context.Context, s *tsnet.Server) error {
	st, err := s.Up(ctx)
	if err != nil {
		return err
	}
	if len(st.CertDomains) == 0 {
		return errors.New("tsnet: you must enable HTTPS in the admin panel to proceed")
	}
	domain := st.CertDomains[0]

	hp := ipn.HostPort(net.JoinHostPort(domain, "443"))

	srvConfig := &ipn.ServeConfig{
		AllowFunnel: map[ipn.HostPort]bool{
			hp: true,
		},
	}
	lc, err := s.LocalClient()
	if err != nil {
		return err
	}
	return lc.SetServeConfig(ctx, srvConfig)
}

func main() {
	flag.Parse()
	s := new(tsnet.Server)
	defer s.Close()
	ctx := context.Background()
	if err := enableFunnel(ctx, s); err != nil {
		log.Fatal(err)
	}

	ln, err := s.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}

	ln = tls.NewListener(ln, &tls.Config{
		GetCertificate: lc.GetCertificate,
	})
	httpServer := &http.Server{
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				// First unwrap the TLS connection to get the underlying
				// net.Conn.
				c = tc.NetConn()
			}
			// Then check if the underlying net.Conn is a FunnelConn.
			if fc, ok := c.(*ipn.FunnelConn); ok {
				ctx = context.WithValue(ctx, funnelKey{}, true)
				ctx = context.WithValue(ctx, funnelSrcKey{}, fc.Src)
			}
			return ctx
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isFunnel(r.Context()) {
				fmt.Fprintln(w, "<html><body><h1>Hello, internet!</h1>")
				fmt.Fprintln(w, "<p>You are connected over the internet!</p>")
				fmt.Fprintf(w, "<p>You are coming from %v</p></html>\n", funnelSrc(r.Context()))
			} else {
				fmt.Fprintln(w, "<html><body><h1>Hello, tailnet!</h1>")
				fmt.Fprintln(w, "<p>You are connected over the tailnet!</p>")
				who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
				if err != nil {
					log.Printf("WhoIs(%v): %v", r.RemoteAddr, err)
					fmt.Fprintf(w, "<p>I do not know who you are</p>")
				} else if len(who.Node.Tags) > 0 {
					fmt.Fprintf(w, "<p>You are using a tagged node: %v</p>\n", who.Node.Tags)
				} else {
					fmt.Fprintf(w, "<p>You are %v</p>\n", who.UserProfile.DisplayName)
				}
				fmt.Fprintf(w, "<p>You are coming from %v</p></html>\n", r.RemoteAddr)
			}
		}),
	}
	log.Fatal(httpServer.Serve(ln))
}

// funnelKey is a context key used to indicate that a request is coming
// over the internet.
// It is not used by tsnet, but is used by this example to demonstrate
// how to detect when a request is coming over the internet rather than
// over the tailnet.
type funnelKey struct{}

// funnelSrcKey is a context key used to indicate the source of a
// request.
type funnelSrcKey struct{}

// isFunnel reports whether the request is coming over the internet.
func isFunnel(ctx context.Context) bool {
	v, _ := ctx.Value(funnelKey{}).(bool)
	return v
}

func funnelSrc(ctx context.Context) netip.AddrPort {
	v, _ := ctx.Value(funnelSrcKey{}).(netip.AddrPort)
	return v
}
