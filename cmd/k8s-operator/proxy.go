// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
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

// maybeLaunchAPIServerProxy launches the auth proxy, which is a small HTTP server
// that authenticates requests using the Tailscale LocalAPI and then proxies
// them to the kube-apiserver.
func maybeLaunchAPIServerProxy(zlog *zap.SugaredLogger, restConfig *rest.Config, s *tsnet.Server, mode apiServerProxyMode) {
	if mode == apiserverProxyModeDisabled {
		return
	}
	startlog := zlog.Named("launchAPIProxy")
	// if mode == apiserverProxyModeNoAuth {
	// 	restConfig = rest.AnonymousClientConfig(restConfig)
	// }
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

// apiserverProxy is an http.Handler that authenticates requests using the Tailscale
// LocalAPI and then proxies them to the Kubernetes API.
type apiserverProxy struct {
	log  *zap.SugaredLogger
	lc   *tailscale.LocalClient
	rp   *httputil.ReverseProxy
	mode apiServerProxyMode

	upstreamURL    *url.URL
	upstreamClient *http.Client
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders removes hop-by-hop headers.
func removeHopByHopHeaders(h http.Header) {
	// RFC 7230, section 6.1: Remove headers listed in the "Connection" header.
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
	// RFC 2616, section 13.5.1: Remove a set of known hop-by-hop headers.
	// This behavior is superseded by the RFC 7230 Connection header, but
	// preserve it for backwards compatibility.
	for _, f := range hopHeaders {
		h.Del(f)
	}
}

func (h *apiserverProxy) addImpersonationHeadersAsRequired(r *http.Request) {
	// Replace the URL with the Kubernetes APIServer.

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
		panic("failed to add impersonation headers: " + err.Error())
	}
}

func (h *apiserverProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	who, err := h.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		h.log.Errorf("failed to authenticate caller: %v", err)
		http.Error(w, "failed to authenticate caller", http.StatusInternalServerError)
		return
	}
	counterNumRequestsProxied.Add(1)
	r = addWhoIsToRequest(r, who)
	if r.Method != "POST" || path.Base(r.URL.Path) != "exec" { // also check for pod
		h.rp.ServeHTTP(w, r)
		return
	}
	// hj := w.(http.Hijacker)
	// reqConn, brw, err := hj.Hijack()
	// if err != nil {
	// 	return
	// }
	// defer reqConn.Close()
	// if err := brw.Flush(); err != nil {
	// 	return
	// }
	// reqConn = netutil.NewDrainBufConn(reqConn, brw.Reader)
	// respConn, err := net.Dial("tcp", h.upstreamURL.Host)
	// if err != nil {
	// 	h.log.Errorf("failed to dial upstream: %v", err)
	// 	return
	// }
	// defer respConn.Close()

	req2 := r.Clone(r.Context())
	h.addImpersonationHeadersAsRequired(req2)

	req2.Body = io.NopCloser(io.TeeReader(r.Body, os.Stdout))
	defer r.Body.Close()

	h.rp.ServeHTTP(&teeResponseWriter{
		ResponseWriter: w,
		hj:             w.(http.Hijacker),
		multiWriter:    io.MultiWriter(os.Stdout, w),
	}, req2)
}

type teeResponseWriter struct {
	http.ResponseWriter
	hj          http.Hijacker
	multiWriter io.Writer
}

func (w *teeResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	reqConn, brw, err := w.hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile("/tmp/recording.cast", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, err
	}
	r := &recording{
		start:    time.Now(),
		failOpen: true,
		out:      f,
	}
	lc := &loggingConn{Conn: reqConn, lw: &loggingWriter{
		r:                   r,
		recordingFailedOpen: false,
	}}

	ch := CastHeader{
		Version:   2,
		Timestamp: r.start.Unix(),
	}
	j, err := json.Marshal(ch)
	if err != nil {
		return nil, nil, err
	}
	j = append(j, '\n')
	if _, err := f.Write(j); err != nil {
		return nil, nil, err
	}

	return lc, brw, nil
}

func (w *teeResponseWriter) Write(b []byte) (int, error) {
	return w.multiWriter.Write(b)
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
func runAPIServerProxy(s *tsnet.Server, rt http.RoundTripper, log *zap.SugaredLogger, mode apiServerProxyMode, host string) {
	if mode == apiserverProxyModeDisabled {
		return
	}
	ln, err := s.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("could not listen on :443: %v", err)
	}
	u, err := url.Parse(host)
	if err != nil {
		log.Fatalf("runAPIServerProxy: failed to parse URL %v", err)
	}

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatalf("could not get local client: %v", err)
	}
	ap := &apiserverProxy{
		log:         log,
		lc:          lc,
		mode:        mode,
		upstreamURL: u,
	}
	ap.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			ap.addImpersonationHeadersAsRequired(pr.Out)
		},
		Transport: rt,
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
	log.Infof("listening on %s", ln.Addr())
	if err := hs.ServeTLS(ln, "", ""); err != nil {
		log.Fatalf("runAPIServerProxy: failed to serve %v", err)
	}
}

const (
	capabilityName    = "tailscale.com/cap/kubernetes"
	oldCapabilityName = "https://" + capabilityName
)

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
func addImpersonationHeaders(r *http.Request, log *zap.SugaredLogger) error {
	log = log.With("remote", r.RemoteAddr)
	who := whoIsFromRequest(r)
	rules, err := tailcfg.UnmarshalCapJSON[capRule](who.CapMap, capabilityName)
	if len(rules) == 0 && err == nil {
		// Try the old capability name for backwards compatibility.
		rules, err = tailcfg.UnmarshalCapJSON[capRule](who.CapMap, oldCapabilityName)
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

// CastHeader is the header of an asciinema file.
type CastHeader struct {
	// Version is the asciinema file format version.
	Version int `json:"version"`

	// Width is the terminal width in characters.
	// It is non-zero for Pty sessions.
	Width int `json:"width"`

	// Height is the terminal height in characters.
	// It is non-zero for Pty sessions.
	Height int `json:"height"`

	// Timestamp is the unix timestamp of when the recording started.
	Timestamp int64 `json:"timestamp"`

	// Env is the environment variables of the session.
	// Only "TERM" is set (2023-03-22).
	Env map[string]string `json:"env"`

	// Command is the command that was executed.
	// Typically empty for shell sessions.
	Command string `json:"command,omitempty"`

	// Tailscale-specific fields:
	// SrcNode is the FQDN of the node originating the connection.
	// It is also the MagicDNS name for the node.
	// It does not have a trailing dot.
	// e.g. "host.tail-scale.ts.net"
	SrcNode string `json:"srcNode"`

	// SrcNodeID is the node ID of the node originating the connection.
	SrcNodeID tailcfg.StableNodeID `json:"srcNodeID"`

	// SrcNodeTags is the list of tags on the node originating the connection (if any).
	SrcNodeTags []string `json:"srcNodeTags,omitempty"`

	// SrcNodeUserID is the user ID of the node originating the connection (if not tagged).
	SrcNodeUserID tailcfg.UserID `json:"srcNodeUserID,omitempty"` // if not tagged

	// SrcNodeUser is the LoginName of the node originating the connection (if not tagged).
	SrcNodeUser string `json:"srcNodeUser,omitempty"`

	// SSHUser is the username as presented by the client.
	SSHUser string `json:"sshUser"` // as presented by the client

	// LocalUser is the effective username on the server.
	LocalUser string `json:"localUser"`

	// ConnectionID uniquely identifies a connection made to the SSH server.
	// It may be shared across multiple sessions over the same connection in
	// case of SSH multiplexing.
	ConnectionID string `json:"connectionID"`
}

// loggingWriter is an io.Writer wrapper that writes first an
// asciinema JSON cast format recording line, and then writes to w.
type loggingWriter struct {
	r *recording

	// recordingFailedOpen specifies whether we've failed to write to
	// r.out and should stop trying. It is set to true if we fail to write
	// to r.out and r.failOpen is set.
	recordingFailedOpen bool
}

func (w *loggingWriter) Write(p []byte) (n int, err error) {
	if w.recordingFailedOpen {
		return 0, nil
	}
	j, err := json.Marshal([]any{
		time.Since(w.r.start).Seconds(),
		"o",
		string(p),
	})
	if err != nil {
		return 0, err
	}
	j = append(j, '\n')
	if err := w.writeCastLine(j); err != nil {
		if !w.r.failOpen {
			return 0, err
		}
		w.recordingFailedOpen = true
	}
	return len(p), nil
}

func (w *loggingWriter) writeCastLine(j []byte) error {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if w.r.out == nil {
		return errors.New("logger closed")
	}
	_, err := w.r.out.Write(j)
	if err != nil {
		return fmt.Errorf("logger Write: %w", err)
	}
	return nil
}

type loggingConn struct {
	mu     sync.Mutex // guards writes to r.out
	closed bool
	net.Conn
	lw *loggingWriter
}

func (c *loggingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.lw.Write(b[:n])
	return n, err
}

func (c *loggingConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.lw.r.Close()
	return c.Conn.Close()
}

// recording is the state for an SSH session recording.
type recording struct {
	start time.Time

	// failOpen specifies whether the session should be allowed to
	// continue if writing to the recording fails.
	failOpen bool

	mu  sync.Mutex // guards writes to, close of out
	out io.WriteCloser
}

func (r *recording) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.out == nil {
		return nil
	}
	err := r.out.Close()
	r.out = nil
	return err
}
