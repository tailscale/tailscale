// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	pathpkg "path"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/netutil"
)

var runDevWebServer = envknob.RegisterBool("TS_DEV_WEBSERVER")

func (b *LocalBackend) HandleInterceptedTCPConn(c net.Conn) {
	if !runDevWebServer() {
		b.logf("localbackend: closing TCP conn from %v to %v", c.RemoteAddr(), c.LocalAddr())
		c.Close()
		return
	}

	// TODO(bradfitz): look up how; sniff SNI if ambiguous
	hs := &http.Server{
		TLSConfig: &tls.Config{
			GetCertificate: b.getTLSServeCert,
		},
		Handler: http.HandlerFunc(b.serveWebHandler),
	}
	hs.ServeTLS(netutil.NewOneConnListener(c, nil), "", "")
}

func (b *LocalBackend) getServeHandler(r *http.Request) (_ ipn.HTTPHandlerView, ok bool) {
	var z ipn.HTTPHandlerView // zero value

	if r.TLS == nil {
		return z, false
	}

	sni := r.TLS.ServerName
	port := "443" // TODO(bradfitz): fix
	key := ipn.HostPort(net.JoinHostPort(sni, port))

	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.serveConfig.Valid() {
		return z, false
	}

	wsc, ok := b.serveConfig.Web().GetOk(key)
	if !ok {
		return z, false
	}
	path := r.URL.Path
	for {
		if h, ok := wsc.Handlers().GetOk(path); ok {
			return h, true
		}
		if path == "/" {
			return z, false
		}
		path = pathpkg.Dir(path)
	}
}

func (b *LocalBackend) serveWebHandler(w http.ResponseWriter, r *http.Request) {
	h, ok := b.getServeHandler(r)
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
		io.WriteString(w, "TODO(bradfitz): serve file")
		return
	}
	if v := h.Proxy(); v != "" {
		io.WriteString(w, "TODO(bradfitz): proxy")
		return
	}

	http.Error(w, "empty handler", 500)
}

func (b *LocalBackend) getTLSServeCert(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hi == nil || hi.ServerName == "" {
		return nil, errors.New("no SNI ServerName")
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
