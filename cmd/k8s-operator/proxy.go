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

	"go.uber.org/zap"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/hostinfo"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

type whoIsKey struct{}

// whoIsFromRequest returns the WhoIsResponse previously stashed by a call to
// addWhoIsToRequest.
func whoIsFromRequest(r *http.Request) *apitype.WhoIsResponse {
	return r.Context().Value(whoIsKey{}).(*apitype.WhoIsResponse)
}

// addWhoIsToRequest stashes who in r's context, retrievable by a call to
// whoIsFromRequest.
func addWhoIsToRequest(r *http.Request, who *apitype.WhoIsResponse) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), whoIsKey{}, who))
}

// launchAuthProxy launches the auth proxy, which is a small HTTP server that
// authenticates requests using the Tailscale LocalAPI and then proxies them to
// the kube-apiserver.
func launchAuthProxy(zlog *zap.SugaredLogger, restConfig *rest.Config, s *tsnet.Server) {
	hostinfo.SetApp("k8s-operator-proxy")
	startlog := zlog.Named("launchAuthProxy")
	cfg, err := restConfig.TransportConfig()
	if err != nil {
		startlog.Fatalf("could not get rest.TransportConfig(): %v", err)
	}

	// Kubernetes uses SPDY for exec and port-forward, however SPDY is
	// incompatible with HTTP/2; so disable HTTP/2 in the proxy.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig, err = transport.TLSConfigFor(cfg)
	if err != nil {
		startlog.Fatalf("could not get transport.TLSConfigFor(): %v", err)
	}
	tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)

	rt, err := transport.HTTPWrappersForConfig(cfg, tr)
	if err != nil {
		startlog.Fatalf("could not get rest.TransportConfig(): %v", err)
	}
	go runAuthProxy(s, rt, zlog.Named("auth-proxy").Infof)
}

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
	h.rp.ServeHTTP(w, addWhoIsToRequest(r, who))
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
				// Replace the URL with the Kubernetes APIServer.
				r.URL.Scheme = u.Scheme
				r.URL.Host = u.Host

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
				if err := addImpersonationHeaders(r); err != nil {
					panic("failed to add impersonation headers: " + err.Error())
				}
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

const capabilityName = "https://tailscale.com/cap/kubernetes"

type capRule struct {
	// Impersonate is a list of rules that specify how to impersonate the caller
	// when proxying to the Kubernetes API.
	Impersonate *impersonateRule `json:"impersonate,omitempty"`
}

// TODO(maisem): move this to some well-known location so that it can be shared
// with control.
type impersonateRule struct {
	Groups []string `json:"groups,omitempty"`
}

// addImpersonationHeaders adds the appropriate headers to r to impersonate the
// caller when proxying to the Kubernetes API. It uses the WhoIsResponse stashed
// in the context by the authProxy.
func addImpersonationHeaders(r *http.Request) error {
	who := whoIsFromRequest(r)
	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, capabilityName)
	if err != nil {
		return fmt.Errorf("failed to unmarshal capability: %v", err)
	}

	var groupsAdded set.Slice[string]
	for _, rule := range rules {
		if rule.Impersonate == nil {
			continue
		}
		for _, group := range rule.Impersonate.Groups {
			if groupsAdded.Contains(group) {
				continue
			}
			r.Header.Add("Impersonate-Group", group)
			groupsAdded.Add(group)
		}
	}

	if !who.Node.IsTagged() {
		r.Header.Set("Impersonate-User", who.UserProfile.LoginName)
		return nil
	}
	// "Impersonate-Group" requires "Impersonate-User" to be set, so we set it
	// to the node FQDN for tagged nodes.
	r.Header.Set("Impersonate-User", strings.TrimSuffix(who.Node.Name, "."))

	// For legacy behavior (before caps), set the groups to the nodes tags.
	if groupsAdded.Slice().Len() == 0 {
		for _, tag := range who.Node.Tags {
			r.Header.Add("Impersonate-Group", tag)
		}
	}
	return nil
}
