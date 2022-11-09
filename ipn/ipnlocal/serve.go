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
	"net/netip"
	pathpkg "path"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/net/netutil"
)

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

	conn, ok := getConn()
	if !ok {
		return
	}

	// TODO(bradfitz): look up how; sniff SNI if ambiguous
	hs := &http.Server{
		TLSConfig: &tls.Config{
			GetCertificate: b.getTLSServeCert,
		},
		Handler: http.HandlerFunc(b.serveWebHandler),
	}
	hs.ServeTLS(netutil.NewOneConnListener(conn, nil), "", "")
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
