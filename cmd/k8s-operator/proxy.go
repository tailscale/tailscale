// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

type whoIsKey struct{}

// authProxy is an http.Handler that authenticates requests using the Tailscale
// LocalAPI and then proxies them to the Kubernetes API.
type authProxy struct {
	logf logger.Logf
	lc   *tailscale.LocalClient
	rp   *httputil.ReverseProxy
}

func (h *authProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	who, err := h.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		h.logf("failed to authenticate caller: %v", err)
		http.Error(w, "failed to authenticate caller", http.StatusInternalServerError)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), whoIsKey{}, who))
	h.rp.ServeHTTP(w, r)
}

// runAuthProxy runs an HTTP server that authenticates requests using the
// Tailscale LocalAPI and then proxies them to the Kubernetes API.
// It listens on :443 and uses the Tailscale HTTPS certificate.
// s will be started if it is not already running.
// rt is used to proxy requests to the Kubernetes API.
//
// It never returns.
func runAuthProxy(s *tsnet.Server, rt http.RoundTripper, logf logger.Logf) {
	ln, err := s.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("could not listen on :443: %v", err)
	}
	u, err := url.Parse(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	if err != nil {
		log.Fatalf("runAuthProxy: failed to parse URL %v", err)
	}

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatalf("could not get local client: %v", err)
	}
	ap := &authProxy{
		logf: logf,
		lc:   lc,
		rp: &httputil.ReverseProxy{
			Director: func(r *http.Request) {
				// We want to proxy to the Kubernetes API, but we want to use
				// the caller's identity to do so. We do this by impersonating
				// the caller using the Kubernetes User Impersonation feature:
				// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation

				// Out of paranoia, remove all authentication headers that might
				// have been set by the client.
				r.Header.Del("Authorization")
				r.Header.Del("Impersonate-Group")
				r.Header.Del("Impersonate-User")
				r.Header.Del("Impersonate-Uid")
				for k := range r.Header {
					if strings.HasPrefix(k, "Impersonate-Extra-") {
						r.Header.Del(k)
					}
				}

				// Now add the impersonation headers that we want.
				who := r.Context().Value(whoIsKey{}).(*apitype.WhoIsResponse)
				if who.Node.IsTagged() {
					// Use the nodes FQDN as the username, and the nodes tags as the groups.
					// "Impersonate-Group" requires "Impersonate-User" to be set.
					r.Header.Set("Impersonate-User", strings.TrimSuffix(who.Node.Name, "."))
					for _, tag := range who.Node.Tags {
						r.Header.Add("Impersonate-Group", tag)
					}
				} else {
					r.Header.Set("Impersonate-User", who.UserProfile.LoginName)
				}

				// Replace the URL with the Kubernetes APIServer.
				r.URL.Scheme = u.Scheme
				r.URL.Host = u.Host
			},
			Transport: rt,
		},
	}
	hs := &http.Server{
		// Kubernetes uses SPDY for exec and port-forward, however SPDY is
		// incompatible with HTTP/2; so disable HTTP/2 in the proxy.
		TLSConfig: &tls.Config{
			GetCertificate: lc.GetCertificate,
			NextProtos:     []string{"http/1.1"},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      ap,
	}
	if err := hs.ServeTLS(ln, "", ""); err != nil {
		log.Fatalf("runAuthProxy: failed to serve %v", err)
	}
}
