// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	pathpkg "path"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/netutil"
	"tailscale.com/tailcfg"
	"tailscale.com/util/strs"
)

// serveHTTPContextKey is the context.Value key for a *serveHTTPContext.
type serveHTTPContextKey struct{}

type serveHTTPContext struct {
	SrcAddr  netip.AddrPort
	DestPort uint16
}

func (b *LocalBackend) HandleIngressTCPConn(ingressPeer *tailcfg.Node, target ipn.HostPort, srcAddr netip.AddrPort, getConn func() (net.Conn, bool), sendRST func()) {
	b.mu.Lock()
	sc := b.serveConfig
	b.mu.Unlock()

	if !sc.Valid() {
		b.logf("localbackend: got ingress conn w/o serveConfig; rejecting")
		sendRST()
		return
	}

	if !sc.AllowIngress().Get(target) {
		b.logf("localbackend: got ingress conn for unconfigured %q; rejecting", target)
		sendRST()
		return
	}

	_, port, err := net.SplitHostPort(string(target))
	if err != nil {
		b.logf("localbackend: got ingress conn for bad target %q; rejecting", target)
		sendRST()
		return
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		b.logf("localbackend: got ingress conn for bad target %q; rejecting", target)
		sendRST()
		return
	}
	// TODO(bradfitz): pass ingressPeer etc in context to HandleInterceptedTCPConn,
	// extend serveHTTPContext or similar.
	b.HandleInterceptedTCPConn(uint16(port16), srcAddr, getConn, sendRST)
}

func (b *LocalBackend) HandleInterceptedTCPConn(dport uint16, srcAddr netip.AddrPort, getConn func() (net.Conn, bool), sendRST func()) {
	b.mu.Lock()
	sc := b.serveConfig
	b.mu.Unlock()

	if !sc.Valid() {
		b.logf("[unexpected] localbackend: got TCP conn w/o serveConfig; from %v to port %v", srcAddr, dport)
		sendRST()
		return
	}

	tcph, ok := sc.TCP().GetOk(int(dport))
	if !ok {
		b.logf("[unexpected] localbackend: got TCP conn without TCP config for port %v; from %v", dport, srcAddr)
		sendRST()
		return
	}

	if tcph.HTTPS() {
		conn, ok := getConn()
		if !ok {
			b.logf("localbackend: getConn didn't complete from %v to port %v", srcAddr, dport)
			return
		}
		hs := &http.Server{
			TLSConfig: &tls.Config{
				GetCertificate: b.getTLSServeCertForPort(dport),
			},
			Handler: http.HandlerFunc(b.serveWebHandler),
			BaseContext: func(_ net.Listener) context.Context {
				return context.WithValue(context.Background(), serveHTTPContextKey{}, &serveHTTPContext{
					SrcAddr:  srcAddr,
					DestPort: dport,
				})
			},
		}
		hs.ServeTLS(netutil.NewOneConnListener(conn, nil), "", "")
		return
	}

	if backDst := tcph.TCPForward(); backDst != "" {
		if tcph.TerminateTLS() {
			b.logf("TODO(bradfitz): finish")
			sendRST()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		backConn, err := b.dialer.SystemDial(ctx, "tcp", backDst)
		cancel()
		if err != nil {
			b.logf("localbackend: failed to TCP proxy port %v (from %v) to %s: %v", dport, srcAddr, backDst, err)
			sendRST()
			return
		}
		conn, ok := getConn()
		if !ok {
			b.logf("localbackend: getConn didn't complete from %v to port %v", srcAddr, dport)
			backConn.Close()
			return
		}
		defer conn.Close()
		defer backConn.Close()

		// TODO(bradfitz): do the RegisterIPPortIdentity and
		// UnregisterIPPortIdentity stuff that netstack does

		errc := make(chan error, 1)
		go func() {
			_, err := io.Copy(backConn, conn)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(conn, backConn)
			errc <- err
		}()
		<-errc
		return
	}

	b.logf("closing TCP conn to port %v (from %v) with actionless TCPPortHandler", dport, srcAddr)
	sendRST()
}

func (b *LocalBackend) getServeHandler(r *http.Request) (_ ipn.HTTPHandlerView, at string, ok bool) {
	var z ipn.HTTPHandlerView // zero value

	if r.TLS == nil {
		return z, "", false
	}

	sctx, ok := r.Context().Value(serveHTTPContextKey{}).(*serveHTTPContext)
	if !ok {
		b.logf("[unexpected] localbackend: no serveHTTPContext in request")
		return z, "", false
	}
	wsc, ok := b.webServerConfig(r.TLS.ServerName, sctx.DestPort)
	if !ok {
		return z, "", false
	}

	if h, ok := wsc.Handlers().GetOk(r.URL.Path); ok {
		return h, r.URL.Path, true
	}
	path := path.Clean(r.URL.Path)
	for {
		withSlash := path + "/"
		if h, ok := wsc.Handlers().GetOk(withSlash); ok {
			return h, withSlash, true
		}
		if h, ok := wsc.Handlers().GetOk(path); ok {
			return h, path, true
		}
		if path == "/" {
			return z, "", false
		}
		path = pathpkg.Dir(path)
	}
}

func (b *LocalBackend) serveWebHandler(w http.ResponseWriter, r *http.Request) {
	h, mountPoint, ok := b.getServeHandler(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if s := h.Text(); s != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, s)
		return
	}
	if v := h.Path(); v != "" {
		b.serveFileOrDirectory(w, r, v, mountPoint)
		return
	}
	if v := h.Proxy(); v != "" {
		// TODO(bradfitz): this is a lot of setup per HTTP request. We should
		// build the whole http.Handler with all the muxing and child handlers
		// only on start/config change. But this works for now (2022-11-09).
		targetURL, insecure := expandProxyArg(v)
		u, err := url.Parse(targetURL)
		if err != nil {
			http.Error(w, "bad proxy config", http.StatusInternalServerError)
			return
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		rp.Transport = &http.Transport{
			DialContext: b.dialer.SystemDial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		}
		rp.ServeHTTP(w, r)
		return
	}

	http.Error(w, "empty handler", 500)
}

func (b *LocalBackend) serveFileOrDirectory(w http.ResponseWriter, r *http.Request, fileOrDir, mountPoint string) {
	fi, err := os.Stat(fileOrDir)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	if fi.Mode().IsRegular() {
		if mountPoint != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(fileOrDir)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		http.ServeContent(w, r, path.Base(mountPoint), fi.ModTime(), f)
		return
	}
	if !fi.IsDir() {
		http.Error(w, "not a file or directory", 500)
		return
	}
	if len(r.URL.Path) < len(mountPoint) && r.URL.Path+"/" == mountPoint {
		http.Redirect(w, r, mountPoint, http.StatusFound)
		return
	}

	var fs http.Handler = http.FileServer(http.Dir(fileOrDir))
	if mountPoint != "/" {
		fs = http.StripPrefix(strings.TrimSuffix(mountPoint, "/"), fs)
	}
	fs.ServeHTTP(&fixLocationHeaderResponseWriter{
		ResponseWriter: w,
		mountPoint:     mountPoint,
	}, r)
}

// fixLocationHeaderResponseWriter is an http.ResponseWriter wrapper that, upon
// flushing HTTP headers, prefixes any Location header with the mount point.
type fixLocationHeaderResponseWriter struct {
	http.ResponseWriter
	mountPoint string
	fixOnce    sync.Once // guards call to fix
}

func (w *fixLocationHeaderResponseWriter) fix() {
	h := w.ResponseWriter.Header()
	if v := h.Get("Location"); v != "" {
		h.Set("Location", w.mountPoint+v)
	}
}

func (w *fixLocationHeaderResponseWriter) WriteHeader(code int) {
	w.fixOnce.Do(w.fix)
	w.ResponseWriter.WriteHeader(code)
}

func (w *fixLocationHeaderResponseWriter) Write(p []byte) (int, error) {
	w.fixOnce.Do(w.fix)
	return w.ResponseWriter.Write(p)
}

// expandProxyArg returns a URL from s, where s can be of form:
//
// * port number ("8080")
// * host:port ("localhost:8080")
// * full URL ("http://localhost:8080", in which case it's returned unchanged)
// * insecure TLS ("https+insecure://127.0.0.1:4430")
func expandProxyArg(s string) (targetURL string, insecureSkipVerify bool) {
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s, false
	}
	if rest, ok := strs.CutPrefix(s, "https+insecure://"); ok {
		return "https://" + rest, true
	}
	if allNumeric(s) {
		return "http://127.0.0.1:" + s, false
	}
	return "http://" + s, false
}

func allNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func (b *LocalBackend) webServerConfig(sniName string, port uint16) (c ipn.WebServerConfigView, ok bool) {
	key := ipn.HostPort(fmt.Sprintf("%s:%v", sniName, port))

	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.serveConfig.Valid() {
		return c, false
	}
	return b.serveConfig.Web().GetOk(key)
}

func (b *LocalBackend) getTLSServeCertForPort(port uint16) func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hi == nil || hi.ServerName == "" {
			return nil, errors.New("no SNI ServerName")
		}
		_, ok := b.webServerConfig(hi.ServerName, port)
		if !ok {
			return nil, errors.New("no webserver configured for name/port")
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		pair, err := b.GetCertPEM(ctx, hi.ServerName)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
}
