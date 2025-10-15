// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package apiproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	ksr "tailscale.com/k8s-operator/sessionrecording"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/net/netx"
	"tailscale.com/sessionrecording"
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

// NewAPIServerProxy creates a new APIServerProxy that's ready to start once Run
// is called. No network traffic will flow until Run is called.
//
// authMode controls how the proxy behaves:
//   - true: the proxy is started and requests are impersonated using the
//     caller's Tailscale identity and the rules defined in the tailnet ACLs.
//   - false: the proxy is started and requests are passed through to the
//     Kubernetes API without any auth modifications.
func NewAPIServerProxy(zlog *zap.SugaredLogger, restConfig *rest.Config, ts *tsnet.Server, mode kubetypes.APIServerProxyMode, https bool) (*APIServerProxy, error) {
	if mode == kubetypes.APIServerProxyModeNoAuth {
		restConfig = rest.AnonymousClientConfig(restConfig)
	}

	cfg, err := restConfig.TransportConfig()
	if err != nil {
		return nil, fmt.Errorf("could not get rest.TransportConfig(): %w", err)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig, err = transport.TLSConfigFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not get transport.TLSConfigFor(): %w", err)
	}
	tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)

	rt, err := transport.HTTPWrappersForConfig(cfg, tr)
	if err != nil {
		return nil, fmt.Errorf("could not get rest.TransportConfig(): %w", err)
	}

	u, err := url.Parse(restConfig.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("the API server proxy requires host and scheme but got: %q", restConfig.Host)
	}

	lc, err := ts.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("could not get local client: %w", err)
	}

	ap := &APIServerProxy{
		log:           zlog,
		lc:            lc,
		authMode:      mode == kubetypes.APIServerProxyModeAuth,
		https:         https,
		upstreamURL:   u,
		ts:            ts,
		sendEventFunc: sessionrecording.SendEvent,
		eventsEnabled: envknob.Bool("TS_EXPERIMENTAL_KUBE_API_EVENTS"),
	}
	ap.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			ap.addImpersonationHeadersAsRequired(pr.Out)
		},
		Transport: rt,
	}

	return ap, nil
}

// Run starts the HTTP server that authenticates requests using the
// Tailscale LocalAPI and then proxies them to the Kubernetes API.
// It listens on :443 and uses the Tailscale HTTPS certificate.
//
// It return when ctx is cancelled or ServeTLS fails.
func (ap *APIServerProxy) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", ap.serveDefault)
	mux.HandleFunc("POST /api/v1/namespaces/{namespace}/pods/{pod}/exec", ap.serveExecSPDY)
	mux.HandleFunc("GET /api/v1/namespaces/{namespace}/pods/{pod}/exec", ap.serveExecWS)
	mux.HandleFunc("POST /api/v1/namespaces/{namespace}/pods/{pod}/attach", ap.serveAttachSPDY)
	mux.HandleFunc("GET /api/v1/namespaces/{namespace}/pods/{pod}/attach", ap.serveAttachWS)

	ap.hs = &http.Server{
		Handler:      mux,
		ErrorLog:     zap.NewStdLog(ap.log.Desugar()),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	mode := "noauth"
	if ap.authMode {
		mode = "auth"
	}
	var proxyLn net.Listener
	var serve func(ln net.Listener) error
	if ap.https {
		var err error
		proxyLn, err = ap.ts.Listen("tcp", ":443")
		if err != nil {
			return fmt.Errorf("could not listen on :443: %w", err)
		}
		serve = func(ln net.Listener) error {
			return ap.hs.ServeTLS(ln, "", "")
		}

		// Kubernetes uses SPDY for exec and port-forward, however SPDY is
		// incompatible with HTTP/2; so disable HTTP/2 in the proxy.
		ap.hs.TLSConfig = &tls.Config{
			GetCertificate: ap.lc.GetCertificate,
			NextProtos:     []string{"http/1.1"},
		}
	} else {
		var err error
		proxyLn, err = net.Listen("tcp", "localhost:80")
		if err != nil {
			return fmt.Errorf("could not listen on :80: %w", err)
		}
		serve = ap.hs.Serve
	}

	errs := make(chan error)
	go func() {
		ap.log.Infof("API server proxy in %s mode is listening on %s", mode, proxyLn.Addr())
		if err := serve(proxyLn); err != nil && err != http.ErrServerClosed {
			errs <- fmt.Errorf("error serving: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errs:
		ap.hs.Close()
		return err
	}

	// Graceful shutdown with a timeout of 10s.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return ap.hs.Shutdown(shutdownCtx)
}

// APIServerProxy is an [net/http.Handler] that authenticates requests using the Tailscale
// LocalAPI and then proxies them to the Kubernetes API.
type APIServerProxy struct {
	log *zap.SugaredLogger
	lc  *local.Client
	rp  *httputil.ReverseProxy

	authMode    bool // Whether to run with impersonation using caller's tailnet identity.
	https       bool // Whether to serve on https for the device hostname; true for k8s-operator, false (and localhost) for k8s-proxy.
	ts          *tsnet.Server
	hs          *http.Server
	upstreamURL *url.URL

	sendEventFunc func(ap netip.AddrPort, event io.Reader, dial netx.DialFunc) error

	// Flag used to enable sending API requests as events to tsrecorder.
	eventsEnabled bool
}

// serveDefault is the default handler for Kubernetes API server requests.
func (ap *APIServerProxy) serveDefault(w http.ResponseWriter, r *http.Request) {
	who, err := ap.whoIs(r)
	if err != nil {
		ap.authError(w, err)
		return
	}

	if err = ap.recordRequestAsEvent(r, who); err != nil {
		msg := fmt.Sprintf("error recording Kubernetes API request: %v", err)
		ap.log.Errorf(msg)
		http.Error(w, msg, http.StatusBadGateway)
		return
	}

	counterNumRequestsProxied.Add(1)

	ap.rp.ServeHTTP(w, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
}

// serveExecSPDY serves '/exec' requests for sessions streamed over SPDY,
// optionally configuring the kubectl exec sessions to be recorded.
func (ap *APIServerProxy) serveExecSPDY(w http.ResponseWriter, r *http.Request) {
	ap.sessionForProto(w, r, ksr.ExecSessionType, ksr.SPDYProtocol)
}

// serveExecWS serves '/exec' requests for sessions streamed over WebSocket,
// optionally configuring the kubectl exec sessions to be recorded.
func (ap *APIServerProxy) serveExecWS(w http.ResponseWriter, r *http.Request) {
	ap.sessionForProto(w, r, ksr.ExecSessionType, ksr.WSProtocol)
}

// serveAttachSPDY serves '/attach' requests for sessions streamed over SPDY,
// optionally configuring the kubectl exec sessions to be recorded.
func (ap *APIServerProxy) serveAttachSPDY(w http.ResponseWriter, r *http.Request) {
	ap.sessionForProto(w, r, ksr.AttachSessionType, ksr.SPDYProtocol)
}

// serveAttachWS serves '/attach' requests for sessions streamed over WebSocket,
// optionally configuring the kubectl exec sessions to be recorded.
func (ap *APIServerProxy) serveAttachWS(w http.ResponseWriter, r *http.Request) {
	ap.sessionForProto(w, r, ksr.AttachSessionType, ksr.WSProtocol)
}

func (ap *APIServerProxy) sessionForProto(w http.ResponseWriter, r *http.Request, sessionType ksr.SessionType, proto ksr.Protocol) {
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

	if err = ap.recordRequestAsEvent(r, who); err != nil {
		msg := fmt.Sprintf("error recording Kubernetes API request: %v", err)
		ap.log.Errorf(msg)
		http.Error(w, msg, http.StatusBadGateway)
		return
	}

	counterNumRequestsProxied.Add(1)
	failOpen, addrs, err := determineRecorderConfig(who)
	if err != nil {
		ap.log.Errorf("error trying to determine whether the 'kubectl %s' session needs to be recorded: %v", sessionType, err)
		return
	}
	if failOpen && len(addrs) == 0 { // will not record
		ap.rp.ServeHTTP(w, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
		return
	}
	ksr.CounterSessionRecordingsAttempted.Add(1) // at this point we know that users intended for this session to be recorded
	if !failOpen && len(addrs) == 0 {
		msg := fmt.Sprintf("forbidden: 'kubectl %s' session must be recorded, but no recorders are available.", sessionType)
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
		Req:         r,
		W:           w,
		Proto:       proto,
		SessionType: sessionType,
		TS:          ap.ts,
		Who:         who,
		Addrs:       addrs,
		FailOpen:    failOpen,
		Pod:         r.PathValue(podNameKey),
		Namespace:   r.PathValue(namespaceNameKey),
		Log:         ap.log,
	}
	h := ksr.NewHijacker(opts)

	ap.rp.ServeHTTP(h, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
}

func (ap *APIServerProxy) recordRequestAsEvent(req *http.Request, who *apitype.WhoIsResponse) error {
	if !ap.eventsEnabled {
		return nil
	}

	failOpen, addrs, err := determineRecorderConfig(who)
	if err != nil {
		return fmt.Errorf("error trying to determine whether the kubernetes api request needs to be recorded: %w", err)
	}
	if len(addrs) == 0 {
		if failOpen {
			return nil
		} else {
			return fmt.Errorf("forbidden: kubernetes api request must be recorded, but no recorders are available")
		}
	}

	factory := &request.RequestInfoFactory{
		APIPrefixes:          sets.NewString("api", "apis"),
		GrouplessAPIPrefixes: sets.NewString("api"),
	}

	reqInfo, err := factory.NewRequestInfo(req)
	if err != nil {
		return fmt.Errorf("error parsing request %s %s: %w", req.Method, req.URL.Path, err)
	}

	kubeReqInfo := sessionrecording.KubernetesRequestInfo{
		IsResourceRequest: reqInfo.IsResourceRequest,
		Path:              reqInfo.Path,
		Verb:              reqInfo.Verb,
		APIPrefix:         reqInfo.APIPrefix,
		APIGroup:          reqInfo.APIGroup,
		APIVersion:        reqInfo.APIVersion,
		Namespace:         reqInfo.Namespace,
		Resource:          reqInfo.Resource,
		Subresource:       reqInfo.Subresource,
		Name:              reqInfo.Name,
		Parts:             reqInfo.Parts,
		FieldSelector:     reqInfo.FieldSelector,
		LabelSelector:     reqInfo.LabelSelector,
	}
	event := &sessionrecording.Event{
		Timestamp:  time.Now().Unix(),
		Kubernetes: kubeReqInfo,
		Type:       sessionrecording.KubernetesAPIEventType,
		UserAgent:  req.UserAgent(),
		Request: sessionrecording.Request{
			Method:          req.Method,
			Path:            req.URL.String(),
			QueryParameters: req.URL.Query(),
		},
		Source: sessionrecording.Source{
			NodeID: who.Node.StableID,
			Node:   strings.TrimSuffix(who.Node.Name, "."),
		},
	}

	if !who.Node.IsTagged() {
		event.Source.NodeUser = who.UserProfile.LoginName
		event.Source.NodeUserID = who.UserProfile.ID
	} else {
		event.Source.NodeTags = who.Node.Tags
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	event.Request.Body = bodyBytes

	var errs []error
	// TODO: ChaosInTheCRD ensure that if there are multiple addrs timing out we don't experience slowdown on client waiting for response.
	fail := true
	for _, addr := range addrs {
		data := new(bytes.Buffer)
		if err := json.NewEncoder(data).Encode(event); err != nil {
			return fmt.Errorf("error marshaling request event: %w", err)
		}

		if err := ap.sendEventFunc(addr, data, ap.ts.Dial); err != nil {
			if apiSupportErr, ok := err.(sessionrecording.EventAPINotSupportedErr); ok {
				ap.log.Warnf(apiSupportErr.Error())
				fail = false
			} else {
				err := fmt.Errorf("error sending event to recorder with address %q: %v", addr.String(), err)
				errs = append(errs, err)
			}
		} else {
			return nil
		}
	}

	merr := errors.Join(errs...)
	if fail && failOpen {
		msg := fmt.Sprintf("[unexpected] failed to send event to recorders with errors: %s", merr.Error())
		msg = msg + "; failure mode is 'fail open'; continuing request without recording."
		ap.log.Warn(msg)
		return nil
	}

	return merr
}

func (ap *APIServerProxy) addImpersonationHeadersAsRequired(r *http.Request) {
	r.URL.Scheme = ap.upstreamURL.Scheme
	r.URL.Host = ap.upstreamURL.Host
	if !ap.authMode {
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
	if err := addImpersonationHeaders(r, ap.log); err != nil {
		ap.log.Errorf("failed to add impersonation headers: %v", err)
	}
}

func (ap *APIServerProxy) whoIs(r *http.Request) (*apitype.WhoIsResponse, error) {
	who, remoteErr := ap.lc.WhoIs(r.Context(), r.RemoteAddr)
	if remoteErr == nil {
		ap.log.Debugf("WhoIs from remote addr: %s", r.RemoteAddr)
		return who, nil
	}

	var fwdErr error
	fwdFor := r.Header.Get("X-Forwarded-For")
	if fwdFor != "" && !ap.https {
		who, fwdErr = ap.lc.WhoIs(r.Context(), fwdFor)
		if fwdErr == nil {
			ap.log.Debugf("WhoIs from X-Forwarded-For header: %s", fwdFor)
			return who, nil
		}
	}

	return nil, errors.Join(remoteErr, fwdErr)
}

func (ap *APIServerProxy) authError(w http.ResponseWriter, err error) {
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
