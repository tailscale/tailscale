// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package httpconnect implements HTTP CONNECT request proxying.
package httpconnect

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"

	"tailscale.com/types/logger"
)

type Connect struct {
	Dialer     func(ctx context.Context, netw, addr string) (net.Conn, error)
	Logf       logger.Logf
	AllowedURI string // if set, requests can only connect to this URI

	// Username and Password, if set, are the required proxy auth credentials.
	Username, Password string

	authHeader string // encoded Username+Password for header comparison
}

func (c *Connect) uriAllowed(w http.ResponseWriter, r *http.Request) bool {
	if c.AllowedURI == "" {
		return true
	}
	if r.RequestURI == c.AllowedURI {
		return true
	}
	if c.Logf != nil {
		c.Logf("invalid CONNECT target %q; want %q", r.RequestURI, c.AllowedURI)
	}
	http.Error(w, "Bad CONNECT target.", http.StatusForbidden)
	return false
}

func (c *Connect) authorized(w http.ResponseWriter, r *http.Request) bool {
	if c.Username == "" && c.Password == "" {
		return true
	}
	if c.authHeader == "" {
		c.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
	}
	if r.Header.Get("Proxy-Authorization") == c.authHeader {
		return true
	}
	w.Header().Set("Proxy-Authenticate", `Basic, realm="tailnet"`)
	http.Error(w, "Proxy Authentication Required", 407)
	return false
}

func (c *Connect) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" {
		panic("[unexpected] miswired")
	}
	if !c.uriAllowed(w, r) || !c.authorized(w, r) {
		return
	}

	dst := r.RequestURI
	conn, err := c.Dialer(r.Context(), "tcp", dst)
	if err != nil {
		if c.Logf != nil {
			c.Logf("error CONNECT dialing %v: %v", dst, err)
		}
		w.Header().Set("Tailscale-Connect-Error", err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer conn.Close()

	cc, ccbuf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer cc.Close()

	io.WriteString(cc, "HTTP/1.1 200 OK\r\n\r\n")

	var clientSrc io.Reader = ccbuf
	if ccbuf.Reader.Buffered() == 0 {
		// In the common case (with no
		// buffered data), read directly from
		// the underlying client connection to
		// save some memory, letting the
		// bufio.Reader/Writer get GC'ed.
		clientSrc = cc
	}

	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(cc, conn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(conn, clientSrc)
		errc <- err
	}()
	<-errc
}
