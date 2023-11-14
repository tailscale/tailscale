// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

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

	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
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

var counterNumRequestsProxied = clientmetric.NewCounter("k8s_auth_proxy_requests_proxied")

type apiServerProxyMode int

const (
	apiserverProxyModeDisabled apiServerProxyMode = iota
	apiserverProxyModeEnabled
	apiserverProxyModeNoAuth
)

func parseAPIProxyMode() apiServerProxyMode {
	haveAuthProxyEnv := os.Getenv("AUTH_PROXY") != ""
	haveAPIProxyEnv := os.Getenv("APISERVER_PROXY") != ""
	switch {
	case haveAPIProxyEnv && haveAuthProxyEnv:
		log.Fatal("AUTH_PROXY and APISERVER_PROXY are mutually exclusive")
	case haveAuthProxyEnv:
		var authProxyEnv = defaultBool("AUTH_PROXY", false) // deprecated
		if authProxyEnv {
			return apiserverProxyModeEnabled
		}
		return apiserverProxyModeDisabled
	case haveAPIProxyEnv:
		var apiProxyEnv = defaultEnv("APISERVER_PROXY", "") // true, false or "noauth"
		switch apiProxyEnv {
		case "true":
			return apiserverProxyModeEnabled
		case "false", "":
			return apiserverProxyModeDisabled
		case "noauth":
			return apiserverProxyModeNoAuth
		default:
			panic(fmt.Sprintf("unknown APISERVER_PROXY value %q", apiProxyEnv))
		}
	}
	return apiserverProxyModeDisabled
}

// TODO: cleanup, return errors etc
// maybeLaunchAPIServerProxy launches the auth proxy, which is a small HTTP server
// that authenticates requests using the Tailscale LocalAPI and then proxies
// them to the kube-apiserver.
func maybeConfigureAPIServerProxy(c managerConfig, mgr manager.Manager) error {
	if c.apiServerProxyMode == apiserverProxyModeDisabled {
		return nil
	}
	startlog := mgr.GetLogger().WithName("lauchAPIProxy")
	startlog.Info("configuring api-server proxy")
	restConfig := c.restConfig
	if c.apiServerProxyMode == apiserverProxyModeNoAuth {
		restConfig = rest.AnonymousClientConfig(c.restConfig)
	}
	cfg, err := restConfig.TransportConfig()
	if err != nil {
		return fmt.Errorf("error retrieving transport config: %v", err)
	}

	// Kubernetes uses SPDY for exec and port-forward, however SPDY is
	// incompatible with HTTP/2; so disable HTTP/2 in the proxy.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig, err = transport.TLSConfigFor(cfg)
	if err != nil {
		return fmt.Errorf("error getting transport config: %v", err)
	}
	tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)

	rt, err := transport.HTTPWrappersForConfig(cfg, tr)
	if err != nil {
		return fmt.Errorf("error getting http wrapper: %v", err)
	}
	pr := &proxyRunnable{
		ts:   c.ts,
		rt:   rt,
		logf: mgr.GetLogger().WithName("proxyRunnable").Info,
		mode: c.apiServerProxyMode,
	}
	if err := mgr.Add(pr); err != nil {
		return fmt.Errorf("error adding proxy runnable:%v", err)
	}
	return nil
}

var _ manager.LeaderElectionRunnable = &proxyRunnable{}
var _ manager.Runnable = &proxyRunnable{}

type proxyRunnable struct {
	ts   tsSetupFunc
	rt   http.RoundTripper
	mode apiServerProxyMode
	logf logger.Logf
}

func (pr *proxyRunnable) NeedLeaderElection() bool {
	return true
}

// apiserverProxy is an http.Handler that authenticates requests using the Tailscale
// LocalAPI and then proxies them to the Kubernetes API.
type apiserverProxy struct {
	logf logger.Logf
	lc   *tailscale.LocalClient
	rp   *httputil.ReverseProxy
}

func (h *apiserverProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	who, err := h.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		h.logf("failed to authenticate caller: %v", err)
		http.Error(w, "failed to authenticate caller", http.StatusInternalServerError)
		return
	}
	counterNumRequestsProxied.Add(1)
	h.rp.ServeHTTP(w, addWhoIsToRequest(r, who))
}

// runAPIServerProxy runs an HTTP server that authenticates requests using the
// Tailscale LocalAPI and then proxies them to the Kubernetes API.
// It listens on :443 and uses the Tailscale HTTPS certificate.
// s will be started if it is not already running.
// rt is used to proxy requests to the Kubernetes API.
//
// mode controls how the proxy behaves:
//   - apiserverProxyModeDisabled: the proxy is not started.
//   - apiserverProxyModeEnabled: the proxy is started and requests are impersonated using the
//     caller's identity from the Tailscale LocalAPI.
//   - apiserverProxyModeNoAuth: the proxy is started and requests are not impersonated and
//     are passed through to the Kubernetes API.
//
// It never returns.
// func runAPIServerProxy(s *tsnet.Server, rt http.RoundTripper, logf logger.Logf, mode apiServerProxyMode) {
func (p *proxyRunnable) Start(ctx context.Context) error {
	p.logf("starting proxy runnable")
	if p.mode == apiserverProxyModeDisabled {
		return nil
	}
	server := p.ts().server
	ln, err := server.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("could not listen on :443: %v", err)
	}
	p.logf("listening on", "addr", ln.Addr())
	u, err := url.Parse(fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")))
	if err != nil {
		log.Fatalf("runAPIServerProxy: failed to parse URL %v", err)
	}
	p.logf("will be forwarding requests to", "url", u)

	lc, err := server.LocalClient()
	if err != nil {
		log.Fatalf("could not get local client: %v", err)
	}

	ap := &apiserverProxy{
		logf: p.logf,
		lc:   lc,
		rp: &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				// Replace the URL with the Kubernetes APIServer.

				r.Out.URL.Scheme = u.Scheme
				r.Out.URL.Host = u.Host
				if p.mode == apiserverProxyModeNoAuth {
					// If we are not providing authentication, then we are just
					// proxying to the Kubernetes API, so we don't need to do
					// anything else.
					return
				}

				// We want to proxy to the Kubernetes API, but we want to use
				// the caller's identity to do so. We do this by impersonating
				// the caller using the Kubernetes User Impersonation feature:
				// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation

				// Out of paranoia, remove all authentication headers that might
				// have been set by the client.
				r.Out.Header.Del("Authorization")
				r.Out.Header.Del("Impersonate-Group")
				r.Out.Header.Del("Impersonate-User")
				r.Out.Header.Del("Impersonate-Uid")
				for k := range r.Out.Header {
					if strings.HasPrefix(k, "Impersonate-Extra-") {
						r.Out.Header.Del(k)
					}
				}

				// Now add the impersonation headers that we want.
				if err := addImpersonationHeaders(r.Out); err != nil {
					panic("failed to add impersonation headers: " + err.Error())
				}
				p.logf("will be forwarding with headers", "user", r.Out.Header.Get("Impersonate-User"))
				p.logf("will be forwarding with headers", "group", r.Out.Header.Get("Impersonate-Group"))
			},
			Transport: p.rt,
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
	p.logf("about to serve TLS")
	if err := hs.ServeTLS(ln, "", ""); err != nil {
		p.logf("error serving: %v", err)
		return fmt.Errorf("runAPIServerProxy: failed to serve %v", err)
	}
	return nil
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
// in the context by the apiserverProxy.
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
