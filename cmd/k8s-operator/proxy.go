// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	ksr "tailscale.com/k8s-operator/sessionrecording"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/ctxkey"
	"tailscale.com/util/set"
)

var (
	// counterNumRequestsproxies counts the number of API server requests proxied via this proxy.
	counterNumRequestsProxied = clientmetric.NewCounter("k8s_auth_proxy_requests_proxied")
	whoIsKey                  = ctxkey.New("", (*apitype.WhoIsResponse)(nil))
)

type apiServerProxyMode int

func (a apiServerProxyMode) String() string {
	switch a {
	case apiserverProxyModeDisabled:
		return "disabled"
	case apiserverProxyModeEnabled:
		return "auth"
	case apiserverProxyModeNoAuth:
		return "noauth"
	default:
		return "unknown"
	}
}

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

// maybeLaunchAPIServerProxy launches the auth proxy, which is a small HTTP server
// that authenticates requests using the Tailscale LocalAPI and then proxies
// them to the kube-apiserver.
func maybeLaunchAPIServerProxy(zlog *zap.SugaredLogger, restConfig *rest.Config, s *tsnet.Server, mode apiServerProxyMode) {
	if mode == apiserverProxyModeDisabled {
		return
	}
	startlog := zlog.Named("launchAPIProxy")
	if mode == apiserverProxyModeNoAuth {
		restConfig = rest.AnonymousClientConfig(restConfig)
	}
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
	go runAPIServerProxy(s, rt, zlog.Named("apiserver-proxy"), mode, restConfig.Host)
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
func runAPIServerProxy(ts *tsnet.Server, rt http.RoundTripper, log *zap.SugaredLogger, mode apiServerProxyMode, host string) {
	if mode == apiserverProxyModeDisabled {
		return
	}
	ln, err := ts.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("could not listen on :443: %v", err)
	}
	u, err := url.Parse(host)
	if err != nil {
		log.Fatalf("runAPIServerProxy: failed to parse URL %v", err)
	}

	lc, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("could not get local client: %v", err)
	}

	ap := &apiserverProxy{
		log:         log,
		lc:          lc,
		mode:        mode,
		upstreamURL: u,
		ts:          ts,
	}
	ap.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			ap.addImpersonationHeadersAsRequired(pr.Out)
		},
		Transport: rt,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ap.serveDefault)
	mux.HandleFunc("POST /api/v1/namespaces/{namespace}/pods/{pod}/exec", ap.serveExecSPDY)
	mux.HandleFunc("GET /api/v1/namespaces/{namespace}/pods/{pod}/exec", ap.serveExecWS)

	hs := &http.Server{
		// Kubernetes uses SPDY for exec and port-forward, however SPDY is
		// incompatible with HTTP/2; so disable HTTP/2 in the proxy.
		TLSConfig: &tls.Config{
			GetCertificate: lc.GetCertificate,
			NextProtos:     []string{"http/1.1"},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      mux,
	}
	log.Infof("API server proxy in %q mode is listening on %s", mode, ln.Addr())
	if err := hs.ServeTLS(ln, "", ""); err != nil {
		log.Fatalf("runAPIServerProxy: failed to serve %v", err)
	}
}

// apiserverProxy is an [net/http.Handler] that authenticates requests using the Tailscale
// LocalAPI and then proxies them to the Kubernetes API.
type apiserverProxy struct {
	log *zap.SugaredLogger
	lc  *tailscale.LocalClient
	rp  *httputil.ReverseProxy

	mode        apiServerProxyMode
	ts          *tsnet.Server
	upstreamURL *url.URL
}

// serveDefault is the default handler for Kubernetes API server requests.
func (ap *apiserverProxy) serveDefault(w http.ResponseWriter, r *http.Request) {
	who, err := ap.whoIs(r)
	if err != nil {
		ap.authError(w, err)
		return
	}
	counterNumRequestsProxied.Add(1)
	ap.rp.ServeHTTP(w, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
}

// serveExecSPDY serves 'kubectl exec' requests for sessions streamed over SPDY,
// optionally configuring the kubectl exec sessions to be recorded.
func (ap *apiserverProxy) serveExecSPDY(w http.ResponseWriter, r *http.Request) {
	ap.execForProto(w, r, ksr.SPDYProtocol)
}

// serveExecWS serves 'kubectl exec' requests for sessions streamed over WebSocket,
// optionally configuring the kubectl exec sessions to be recorded.
func (ap *apiserverProxy) serveExecWS(w http.ResponseWriter, r *http.Request) {
	ap.execForProto(w, r, ksr.WSProtocol)
}

func (ap *apiserverProxy) execForProto(w http.ResponseWriter, r *http.Request, proto ksr.Protocol) {
	const (
		podNameKey       = "pod"
		namespaceNameKey = "namespace"
		upgradeHeaderKey = "Upgrade"
	)

	who, err := ap.whoIs(r)
	if err != nil {
		ap.authError(w, err)
		return
	}
	counterNumRequestsProxied.Add(1)
	failOpen, addrs, err := determineRecorderConfig(who)
	if err != nil {
		ap.log.Errorf("error trying to determine whether the 'kubectl exec' session needs to be recorded: %v", err)
		return
	}
	if failOpen && len(addrs) == 0 { // will not record
		ap.rp.ServeHTTP(w, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
		return
	}
	ksr.CounterSessionRecordingsAttempted.Add(1) // at this point we know that users intended for this session to be recorded
	if !failOpen && len(addrs) == 0 {
		msg := "forbidden: 'kubectl exec' session must be recorded, but no recorders are available."
		ap.log.Error(msg)
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	wantsHeader := upgradeHeaderForProto[proto]
	if h := r.Header.Get(upgradeHeaderKey); h != wantsHeader {
		msg := fmt.Sprintf("[unexpected] unable to verify that streaming protocol is %s, wants Upgrade header %q, got: %q", proto, wantsHeader, h)
		if failOpen {
			msg = msg + "; failure mode is 'fail open'; continuing session without recording."
			ap.log.Warn(msg)
			ap.rp.ServeHTTP(w, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
			return
		}
		ap.log.Error(msg)
		msg += "; failure mode is 'fail closed'; closing connection."
		http.Error(w, msg, http.StatusForbidden)
		return
	}

	opts := ksr.HijackerOpts{
		Req:       r,
		W:         w,
		Proto:     proto,
		TS:        ap.ts,
		Who:       who,
		Addrs:     addrs,
		FailOpen:  failOpen,
		Pod:       r.PathValue(podNameKey),
		Namespace: r.PathValue(namespaceNameKey),
		Log:       ap.log,
	}
	h := ksr.New(opts)

	ap.rp.ServeHTTP(h, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
}

func (h *apiserverProxy) addImpersonationHeadersAsRequired(r *http.Request) {
	r.URL.Scheme = h.upstreamURL.Scheme
	r.URL.Host = h.upstreamURL.Host
	if h.mode == apiserverProxyModeNoAuth {
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
	if err := addImpersonationHeaders(r, h.log); err != nil {
		log.Printf("failed to add impersonation headers: " + err.Error())
	}
}

func (ap *apiserverProxy) whoIs(r *http.Request) (*apitype.WhoIsResponse, error) {
	return ap.lc.WhoIs(r.Context(), r.RemoteAddr)
}

func (ap *apiserverProxy) authError(w http.ResponseWriter, err error) {
	ap.log.Errorf("failed to authenticate caller: %v", err)
	http.Error(w, "failed to authenticate caller", http.StatusInternalServerError)
}

const (
	// oldCapabilityName is a legacy form of
	// tailfcg.PeerCapabilityKubernetes capability. The only capability rule
	// that is respected for this form is group impersonation - for
	// backwards compatibility reasons.
	// TODO (irbekrm): determine if anyone uses this and remove if possible.
	oldCapabilityName = "https://" + tailcfg.PeerCapabilityKubernetes
)

// addImpersonationHeaders adds the appropriate headers to r to impersonate the
// caller when proxying to the Kubernetes API. It uses the WhoIsResponse stashed
// in the context by the apiserverProxy.
func addImpersonationHeaders(r *http.Request, log *zap.SugaredLogger) error {
	log = log.With("remote", r.RemoteAddr)
	who := whoIsKey.Value(r.Context())
	rules, err := tailcfg.UnmarshalCapJSON[kubetypes.KubernetesCapRule](who.CapMap, tailcfg.PeerCapabilityKubernetes)
	if len(rules) == 0 && err == nil {
		// Try the old capability name for backwards compatibility.
		rules, err = tailcfg.UnmarshalCapJSON[kubetypes.KubernetesCapRule](who.CapMap, oldCapabilityName)
	}
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
			log.Debugf("adding group impersonation header for user group %s", group)
		}
	}

	if !who.Node.IsTagged() {
		r.Header.Set("Impersonate-User", who.UserProfile.LoginName)
		log.Debugf("adding user impersonation header for user %s", who.UserProfile.LoginName)
		return nil
	}
	// "Impersonate-Group" requires "Impersonate-User" to be set, so we set it
	// to the node FQDN for tagged nodes.
	nodeName := strings.TrimSuffix(who.Node.Name, ".")
	r.Header.Set("Impersonate-User", nodeName)
	log.Debugf("adding user impersonation header for node name %s", nodeName)

	// For legacy behavior (before caps), set the groups to the nodes tags.
	if groupsAdded.Slice().Len() == 0 {
		for _, tag := range who.Node.Tags {
			r.Header.Add("Impersonate-Group", tag)
			log.Debugf("adding group impersonation header for node tag %s", tag)
		}
	}
	return nil
}

// determineRecorderConfig determines recorder config from requester's peer
// capabilities. Determines whether a 'kubectl exec' session from this requester
// needs to be recorded and what recorders the recording should be sent to.
func determineRecorderConfig(who *apitype.WhoIsResponse) (failOpen bool, recorderAddresses []netip.AddrPort, _ error) {
	if who == nil {
		return false, nil, errors.New("[unexpected] cannot determine caller")
	}
	failOpen = true
	rules, err := tailcfg.UnmarshalCapJSON[kubetypes.KubernetesCapRule](who.CapMap, tailcfg.PeerCapabilityKubernetes)
	if err != nil {
		return failOpen, nil, fmt.Errorf("failed to unmarshal Kubernetes capability: %w", err)
	}
	if len(rules) == 0 {
		return failOpen, nil, nil
	}

	for _, rule := range rules {
		if len(rule.RecorderAddrs) != 0 {
			// TODO (irbekrm): here or later determine if the
			// recorders behind those addrs are online - else we
			// spend 30s trying to reach a recorder whose tailscale
			// status is offline.
			recorderAddresses = append(recorderAddresses, rule.RecorderAddrs...)
		}
		if rule.EnforceRecorder {
			failOpen = false
		}
	}
	return failOpen, recorderAddresses, nil
}

var upgradeHeaderForProto = map[ksr.Protocol]string{
	ksr.SPDYProtocol: "SPDY/3.1",
	ksr.WSProtocol:   "websocket",
}
