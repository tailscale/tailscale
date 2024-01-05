// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

	upstreamURL *url.URL
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
	if r.Method != "POST" || r.Header.Get("Upgrade") != "SPDY/3.1" {
		h.rp.ServeHTTP(w, r)
		return
	}

	h.rp.ServeHTTP(&spdyHijacker{
		req:            r,
		who:            who,
		ResponseWriter: w,
	}, r)
}

type spdyRemoteConnRecorder struct {
	net.Conn
	lw *loggingWriter
	ch CastHeader

	stdinStreamID  atomic.Uint32
	stdoutStreamID atomic.Uint32
	stderrStreamID atomic.Uint32
	resizeStreamID atomic.Uint32
	errorStreamID  atomic.Uint32

	wmu    sync.Mutex // sequences writes
	closed bool

	rmu                 sync.Mutex // sequences reads
	writeCastHeaderOnce sync.Once

	zlibReqReader zlibReader
	writeBuf      bytes.Buffer
	readBuf       bytes.Buffer
}

func (c *spdyRemoteConnRecorder) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	if c.writeBuf.Len() > 0 {
		c.Conn.Write(c.writeBuf.Bytes())
	}
	c.writeBuf.Reset()
	c.closed = true
	err := c.Conn.Close()
	c.lw.Close()
	return err
}

func (c *spdyRemoteConnRecorder) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.writeBuf.Write(b)

	var sf spdyFrame
	ok, err := sf.Parse(c.writeBuf.Bytes())
	if err != nil {
		return 0, err
	}
	if !ok {
		return len(b), nil
	}
	c.writeBuf.Next(len(sf.Raw))

	if !sf.Ctrl {
		// For the streams we care about, write the payload to the recording
		// file BEFORE writing the frame to the connection.
		switch sf.StreamID {
		case c.stdoutStreamID.Load(), c.stderrStreamID.Load():
			if _, err := c.lw.Write(sf.Payload); err != nil {
				return 0, err
			}
		}
	}
	_, err = c.Conn.Write(sf.Raw)
	return len(b), err
}

func (c *spdyRemoteConnRecorder) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	c.readBuf.Write(b[:n])

	var sf spdyFrame
	ok, err := sf.Parse(c.readBuf.Bytes())
	if err != nil {
		return 0, err
	}
	if !ok {
		return n, nil
	}
	c.readBuf.Next(len(sf.Raw))
	if !sf.Ctrl {
		switch sf.StreamID {
		case c.resizeStreamID.Load():
			var err error
			c.writeCastHeaderOnce.Do(func() {
				var resizeMsg struct {
					Width  int `json:"width"`
					Height int `json:"height"`
				}
				if err = json.Unmarshal(sf.Payload, &resizeMsg); err != nil {
					return
				}
				c.ch.Width = resizeMsg.Width
				c.ch.Height = resizeMsg.Height
				var j []byte
				j, err = json.Marshal(c.ch)
				if err != nil {
					return
				}
				j = append(j, '\n')
				_, err = c.lw.f.Write(j)
			})
			if err != nil {
				return 0, err
			}
		}
		return n, nil
	}
	// We always want to parse the headers, even if we don't care about the
	// frame, as we need to advance the zlib reader otherwise we will get
	// garbage.
	header, err := sf.parseHeaders(&c.zlibReqReader)
	if err != nil {
		return 0, err
	}
	if sf.Type == 1 {
		sf.StreamID = binary.BigEndian.Uint32(sf.Payload[0:4])
		switch header.Get("Streamtype") {
		case "stdin":
			c.stdinStreamID.Store(sf.StreamID)
		case "stdout":
			c.stdoutStreamID.Store(sf.StreamID)
		case "stderr":
			c.stderrStreamID.Store(sf.StreamID)
		case "resize":
			c.resizeStreamID.Store(sf.StreamID)
		case "error":
			c.errorStreamID.Store(sf.StreamID)
		}
	}
	return n, nil
}

func readInt24(b []byte) int {
	_ = b[2] // bounds check hint to compiler; see golang.org/issue/14808
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

type spdyFrame struct {
	Raw []byte

	// Common frame fields:
	Ctrl    bool
	Flags   uint8
	Length  int
	Payload []byte

	// Control frame fields:
	Version uint16
	Type    uint16

	// Data frame fields:
	StreamID uint32
}

func (sf *spdyFrame) Parse(b []byte) (ok bool, _ error) {
	have := len(b)
	if have < 8 {
		return false, nil // need more
	}
	// Can read frame header.
	payloadLength := readInt24(b[5:8])
	frameLength := int(payloadLength) + 8
	if have < frameLength {
		return false, nil // need more
	}

	frame := b[:frameLength:frameLength]

	sf.Raw = frame
	sf.Length = payloadLength
	sf.Payload = frame[8:frameLength]

	sf.Ctrl = frame[0]&0x80 != 0

	// Have full frame.
	if !sf.Ctrl {
		sf.StreamID = binary.BigEndian.Uint32(frame[0:4]) // First bit is 0.
		return true, nil
	}

	sf.Version = binary.BigEndian.Uint16(frame[0:2]) & 0x7f
	sf.Type = binary.BigEndian.Uint16(frame[2:4])
	sf.Flags = frame[4]
	return true, nil
}

func (sf *spdyFrame) parseHeaders(z *zlibReader) (http.Header, error) {
	if !sf.Ctrl {
		return nil, fmt.Errorf("not a control frame")
	}
	switch sf.Type {
	case 1: // SYN_STREAM
		if len(sf.Payload) < 10 {
			return nil, fmt.Errorf("SYN_STREAM frame too short")
		}
		z.Set(sf.Payload[10:])
		return parseHeaders(z)
	case 2, 6: // SYN_REPLY, HEADERS
		if len(sf.Payload) < 4 {
			return nil, fmt.Errorf("SYN_REPLY/HEADERS frame too short")
		}
		if len(sf.Payload) == 4 {
			return nil, nil
		}
		z.Set(sf.Payload[4:])
		return parseHeaders(z)
	}
	return nil, nil
}

type zlibReader struct {
	io.ReadCloser
	underlying io.LimitedReader
}

func (z *zlibReader) Read(b []byte) (int, error) {
	if z.ReadCloser == nil {
		r, err := zlib.NewReaderDict(&z.underlying, []byte(spdyTxtDictionary))
		if err != nil {
			return 0, err
		}
		z.ReadCloser = r
	}
	return z.ReadCloser.Read(b)
}

func (z *zlibReader) Set(b []byte) {
	z.underlying.R = bytes.NewReader(b)
	z.underlying.N = int64(len(b))
}

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func parseHeaders(decompressor io.Reader) (http.Header, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	buf.Reset()

	readUint32 := func() (uint32, error) {
		if _, err := io.CopyN(buf, decompressor, 4); err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint32(buf.Next(4)), nil
	}

	readLenBytes := func() ([]byte, error) {
		xLen, err := readUint32()
		if err != nil {
			return nil, err
		}
		if _, err := io.CopyN(buf, decompressor, int64(xLen)); err != nil {
			return nil, err
		}
		return buf.Next(int(xLen)), nil
	}

	numHeaders, err := readUint32()
	if err != nil {
		return nil, err
	}
	h := make(http.Header, numHeaders)
	for i := uint32(0); i < numHeaders; i++ {
		name, err := readLenBytes()
		if err != nil {
			return nil, err
		}
		ns := string(name)
		if _, ok := h[ns]; ok {
			return nil, fmt.Errorf("duplicate header %q", ns)
		}
		val, err := readLenBytes()
		if err != nil {
			return nil, err
		}
		for _, v := range bytes.Split(val, delimByte) {
			h.Add(ns, string(v))
		}
	}
	return h, nil
}

var delimByte = []byte{0}

type spdyHijacker struct {
	http.ResponseWriter
	req *http.Request
	who *apitype.WhoIsResponse
}

func (w *spdyHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	reqConn, brw, err := w.ResponseWriter.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// e.g. "/api/v1/namespaces/default/pods/foobar/exec
	suf, ok := strings.CutPrefix(w.req.URL.Path, "/api/v1/namespaces/")
	if !ok {
		return reqConn, brw, nil
	}
	ns, suf, ok := strings.Cut(suf, "/pods/")
	if !ok {
		return reqConn, brw, nil
	}
	pod, action, ok := strings.Cut(suf, "/")
	if !ok {
		return reqConn, brw, nil
	}
	if action != "exec" {
		return reqConn, brw, nil
	}

	f, err := os.OpenFile("/tmp/recording.cast", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, nil, err
	}
	lc := &spdyRemoteConnRecorder{
		Conn: reqConn,
		lw: &loggingWriter{
			start:    time.Now(),
			failOpen: true,
			f:        f,
		},
	}

	qp := w.req.URL.Query()
	ch := CastHeader{
		Version:   2,
		Namespace: ns,
		Pod:       pod,
		Timestamp: lc.lw.start.Unix(),
		Command:   strings.Join(qp["command"], " "),
		SrcNode:   strings.TrimSuffix(w.who.Node.Name, "."),
		SrcNodeID: w.who.Node.StableID,
	}
	if !w.who.Node.IsTagged() {
		ch.SrcNodeUser = w.who.UserProfile.LoginName
		ch.SrcNodeUserID = w.who.Node.User
	} else {
		ch.SrcNodeTags = w.who.Node.Tags
	}
	lc.ch = ch

	return lc, brw, nil
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

	// Namespace and Pod are the namespace and pod that the session is running in.
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`

	// Width is the terminal width in characters.
	Width int `json:"width"`

	// Height is the terminal height in characters.
	Height int `json:"height"`

	// Timestamp is the unix timestamp of when the recording started.
	Timestamp int64 `json:"timestamp"`

	// Command is the command that was executed.
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

	// Container is the name of the container (if any) that the session is running in.
	Container string `json:"container,omitempty"`
}

// loggingWriter is an io.Writer wrapper that writes first an
// asciinema JSON cast format recording line, and then writes to w.
type loggingWriter struct {
	start time.Time

	// failOpen specifies whether the session should be allowed to
	// continue if writing to the recording fails.
	failOpen bool

	// recordingFailedOpen specifies whether we've failed to write to
	// r.out and should stop trying. It is set to true if we fail to write
	// to r.out and r.failOpen is set.
	recordingFailedOpen bool

	mu sync.Mutex // guards writes to f
	f  io.WriteCloser
}

func (w *loggingWriter) Write(p []byte) (n int, err error) {
	if w.recordingFailedOpen {
		return 0, nil
	}
	j, err := json.Marshal([]any{
		time.Since(w.start).Seconds(),
		"o",
		string(p),
	})
	if err != nil {
		return 0, err
	}
	j = append(j, '\n')
	if err := w.writeCastLine(j); err != nil {
		if !w.failOpen {
			return 0, err
		}
		w.recordingFailedOpen = true
	}
	return len(p), nil
}

func (w *loggingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

func (w *loggingWriter) writeCastLine(j []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return errors.New("logger closed")
	}
	_, err := w.f.Write(j)
	if err != nil {
		return fmt.Errorf("logger Write: %w", err)
	}
	return nil
}

// spdyTxtDictionary is the dictionary defined in the SPDY spec.
// https://datatracker.ietf.org/doc/html/draft-mbelshe-httpbis-spdy-00#section-2.6.10.1
var spdyTxtDictionary = []byte{
	0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69, // - - - - o p t i
	0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68, // o n s - - - - h
	0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70, // e a d - - - - p
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70, // o s t - - - - p
	0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65, // u t - - - - d e
	0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05, // l e t e - - - -
	0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00, // t r a c e - - -
	0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00, // - a c c e p t -
	0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70, // - - - a c c e p
	0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, // t - c h a r s e
	0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63, // t - - - - a c c
	0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f, // e p t - e n c o
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f, // d i n g - - - -
	0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c, // a c c e p t - l
	0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00, // a n g u a g e -
	0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70, // - - - a c c e p
	0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, // t - r a n g e s
	0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00, // - - - - a g e -
	0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77, // - - - a l l o w
	0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68, // - - - - a u t h
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, // o r i z a t i o
	0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63, // n - - - - c a c
	0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, // h e - c o n t r
	0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f, // o l - - - - c o
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, // n n e c t i o n
	0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, // - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65, // e n t - b a s e
	0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74, // - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f, // e n t - e n c o
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, // d i n g - - - -
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, // c o n t e n t -
	0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, // l a n g u a g e
	0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74, // - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, // e n t - l e n g
	0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, // t h - - - - c o
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f, // n t e n t - l o
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, // c a t i o n - -
	0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, // - - c o n t e n
	0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00, // t - m d 5 - - -
	0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, // - c o n t e n t
	0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, // - r a n g e - -
	0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, // - - c o n t e n
	0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00, // t - t y p e - -
	0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00, // - - d a t e - -
	0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00, // - - e t a g - -
	0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, // - - e x p e c t
	0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69, // - - - - e x p i
	0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66, // r e s - - - - f
	0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68, // r o m - - - - h
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69, // o s t - - - - i
	0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, // f - m a t c h -
	0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f, // - - - i f - m o
	0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73, // d i f i e d - s
	0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d, // i n c e - - - -
	0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d, // i f - n o n e -
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00, // m a t c h - - -
	0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67, // - i f - r a n g
	0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d, // e - - - - i f -
	0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, // u n m o d i f i
	0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65, // e d - s i n c e
	0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74, // - - - - l a s t
	0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, // - m o d i f i e
	0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63, // d - - - - l o c
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, // a t i o n - - -
	0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72, // - m a x - f o r
	0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00, // w a r d s - - -
	0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00, // - p r a g m a -
	0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79, // - - - p r o x y
	0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, // - a u t h e n t
	0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00, // i c a t e - - -
	0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61, // - p r o x y - a
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, // u t h o r i z a
	0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05, // t i o n - - - -
	0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00, // r a n g e - - -
	0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72, // - r e f e r e r
	0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72, // - - - - r e t r
	0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00, // y - a f t e r -
	0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, // - - - s e r v e
	0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00, // r - - - - t e -
	0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c, // - - - t r a i l
	0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72, // e r - - - - t r
	0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65, // a n s f e r - e
	0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, // n c o d i n g -
	0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61, // - - - u p g r a
	0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73, // d e - - - - u s
	0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, // e r - a g e n t
	0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79, // - - - - v a r y
	0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00, // - - - - v i a -
	0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69, // - - - w a r n i
	0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77, // n g - - - - w w
	0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, // w - a u t h e n
	0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, // t i c a t e - -
	0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, // - - m e t h o d
	0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00, // - - - - g e t -
	0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, // - - - s t a t u
	0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30, // s - - - - 2 0 0
	0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76, // - O K - - - - v
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, // e r s i o n - -
	0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, // - - H T T P - 1
	0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72, // - 1 - - - - u r
	0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62, // l - - - - p u b
	0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73, // l i c - - - - s
	0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69, // e t - c o o k i
	0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65, // e - - - - k e e
	0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00, // p - a l i v e -
	0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69, // - - - o r i g i
	0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32, // n 1 0 0 1 0 1 2
	0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35, // 0 1 2 0 2 2 0 5
	0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30, // 2 0 6 3 0 0 3 0
	0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33, // 2 3 0 3 3 0 4 3
	0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37, // 0 5 3 0 6 3 0 7
	0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30, // 4 0 2 4 0 5 4 0
	0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34, // 6 4 0 7 4 0 8 4
	0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31, // 0 9 4 1 0 4 1 1
	0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31, // 4 1 2 4 1 3 4 1
	0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34, // 4 4 1 5 4 1 6 4
	0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34, // 1 7 5 0 2 5 0 4
	0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e, // 5 0 5 2 0 3 - N
	0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f, // o n - A u t h o
	0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65, // r i t a t i v e
	0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, // - I n f o r m a
	0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20, // t i o n 2 0 4 -
	0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, // N o - C o n t e
	0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f, // n t 3 0 1 - M o
	0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d, // v e d - P e r m
	0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34, // a n e n t l y 4
	0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52, // 0 0 - B a d - R
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30, // e q u e s t 4 0
	0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68, // 1 - U n a u t h
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30, // o r i z e d 4 0
	0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64, // 3 - F o r b i d
	0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e, // d e n 4 0 4 - N
	0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64, // o t - F o u n d
	0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65, // 5 0 0 - I n t e
	0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72, // r n a l - S e r
	0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f, // v e r - E r r o
	0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74, // r 5 0 1 - N o t
	0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65, // - I m p l e m e
	0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20, // n t e d 5 0 3 -
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20, // S e r v i c e -
	0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, // U n a v a i l a
	0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46, // b l e J a n - F
	0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41, // e b - M a r - A
	0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a, // p r - M a y - J
	0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41, // u n - J u l - A
	0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20, // u g - S e p t -
	0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20, // O c t - N o v -
	0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30, // D e c - 0 0 - 0
	0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e, // 0 - 0 0 - M o n
	0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57, // - - T u e - - W
	0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c, // e d - - T h u -
	0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61, // - F r i - - S a
	0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20, // t - - S u n - -
	0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b, // G M T c h u n k
	0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, // e d - t e x t -
	0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61, // h t m l - i m a
	0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69, // g e - p n g - i
	0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67, // m a g e - j p g
	0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67, // - i m a g e - g
	0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, // i f - a p p l i
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, // c a t i o n - x
	0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, // m l - a p p l i
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, // c a t i o n - x
	0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c, // h t m l - x m l
	0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, // - t e x t - p l
	0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74, // a i n - t e x t
	0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72, // - j a v a s c r
	0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c, // i p t - p u b l
	0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, // i c p r i v a t
	0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, // e m a x - a g e
	0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65, // - g z i p - d e
	0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64, // f l a t e - s d
	0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, // c h c h a r s e
	0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63, // t - u t f - 8 c
	0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69, // h a r s e t - i
	0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d, // s o - 8 8 5 9 -
	0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a, // 1 - u t f - - -
	0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e, // - e n q - 0 -
}
