// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
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

func runAuthProxy(lc *tailscale.LocalClient, ls net.Listener, rt http.RoundTripper, logf logger.Logf) {
	u, err := url.Parse(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	if err != nil {
		log.Fatalf("runAuthProxy: failed to parse URL %v", err)
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
					r.Header.Set("Impersonate-User", who.Node.Name)
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
	if err := http.Serve(tls.NewListener(ls, &tls.Config{
		GetCertificate: lc.GetCertificate,
	}), ap); err != nil {
		log.Fatalf("runAuthProxy: failed to serve %v", err)
	}
}
