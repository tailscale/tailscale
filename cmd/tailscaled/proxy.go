// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_outboundproxy

// HTTP proxy code

package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/types/logger"
)

func init() {
	hookRegisterOutboundProxyFlags.Set(registerOutboundProxyFlags)
	hookOutboundProxyListen.Set(outboundProxyListen)
}

func registerOutboundProxyFlags() {
	flag.StringVar(&args.socksAddr, "socks5-server", "", `optional [ip]:port to run a SOCK5 server (e.g. "localhost:1080")`)
	flag.StringVar(&args.httpProxyAddr, "outbound-http-proxy-listen", "", `optional [ip]:port to run an outbound HTTP proxy (e.g. "localhost:8080")`)
}

// outboundProxyListen creates listeners for local SOCKS and HTTP proxies, if
// the respective addresses are not empty. args.socksAddr and args.httpProxyAddr
// can be the same, in which case the SOCKS5 Listener will receive connections
// that look like they're speaking SOCKS and httpListener will receive
// everything else.
//
// socksListener and httpListener can be nil, if their respective addrs are
// empty.
//
// The returned func closes over those two (possibly nil) listeners and
// starts the respective servers on the listener when called.
func outboundProxyListen() proxyStartFunc {
	socksAddr, httpAddr := args.socksAddr, args.httpProxyAddr

	if socksAddr == httpAddr && socksAddr != "" && !strings.HasSuffix(socksAddr, ":0") {
		ln, err := net.Listen("tcp", socksAddr)
		if err != nil {
			log.Fatalf("proxy listener: %v", err)
		}
		return mkProxyStartFunc(proxymux.SplitSOCKSAndHTTP(ln))
	}

	var socksListener, httpListener net.Listener
	var err error
	if socksAddr != "" {
		socksListener, err = net.Listen("tcp", socksAddr)
		if err != nil {
			log.Fatalf("SOCKS5 listener: %v", err)
		}
		if strings.HasSuffix(socksAddr, ":0") {
			// Log kernel-selected port number so integration tests
			// can find it portably.
			log.Printf("SOCKS5 listening on %v", socksListener.Addr())
		}
	}
	if httpAddr != "" {
		httpListener, err = net.Listen("tcp", httpAddr)
		if err != nil {
			log.Fatalf("HTTP proxy listener: %v", err)
		}
		if strings.HasSuffix(httpAddr, ":0") {
			// Log kernel-selected port number so integration tests
			// can find it portably.
			log.Printf("HTTP proxy listening on %v", httpListener.Addr())
		}
	}

	return mkProxyStartFunc(socksListener, httpListener)
}

func mkProxyStartFunc(socksListener, httpListener net.Listener) proxyStartFunc {
	return func(logf logger.Logf, dialer *tsdial.Dialer) {
		var addrs []string
		if httpListener != nil {
			hs := &http.Server{Handler: httpProxyHandler(dialer.UserDial)}
			go func() {
				log.Fatalf("HTTP proxy exited: %v", hs.Serve(httpListener))
			}()
			addrs = append(addrs, httpListener.Addr().String())
		}
		if socksListener != nil {
			ss := &socks5.Server{
				Logf:   logger.WithPrefix(logf, "socks5: "),
				Dialer: dialer.UserDial,
			}
			go func() {
				log.Fatalf("SOCKS5 server exited: %v", ss.Serve(socksListener))
			}()
			addrs = append(addrs, socksListener.Addr().String())
		}
		tshttpproxy.SetSelfProxy(addrs...)
	}
}

// httpProxyHandler returns an HTTP proxy http.Handler using the
// provided backend dialer.
func httpProxyHandler(dialer func(ctx context.Context, netw, addr string) (net.Conn, error)) http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {}, // no change
		Transport: &http.Transport{
			DialContext: dialer,
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			backURL := r.RequestURI
			if strings.HasPrefix(backURL, "/") || backURL == "*" {
				http.Error(w, "bogus RequestURI; must be absolute URL or CONNECT", 400)
				return
			}
			rp.ServeHTTP(w, r)
			return
		}

		// CONNECT support:

		dst := r.RequestURI
		c, err := dialer(r.Context(), "tcp", dst)
		if err != nil {
			w.Header().Set("Tailscale-Connect-Error", err.Error())
			http.Error(w, err.Error(), 500)
			return
		}
		defer c.Close()

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
			_, err := io.Copy(cc, c)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(c, clientSrc)
			errc <- err
		}()
		<-errc
	})
}
