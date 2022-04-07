// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"tailscale.com/control/controlbase"
	"tailscale.com/net/socks5"
	"tailscale.com/types/key"
)

func TestControlHTTP(t *testing.T) {
	tests := []struct {
		name  string
		proxy proxy
	}{
		// direct connection
		{
			name:  "no_proxy",
			proxy: nil,
		},
		// SOCKS5
		{
			name:  "socks5",
			proxy: &socksProxy{},
		},
		// HTTP->HTTP
		{
			name: "http_to_http",
			proxy: &httpProxy{
				useTLS:       false,
				allowConnect: false,
				allowHTTP:    true,
			},
		},
		// HTTP->HTTPS
		{
			name: "http_to_https",
			proxy: &httpProxy{
				useTLS:       false,
				allowConnect: true,
				allowHTTP:    false,
			},
		},
		// HTTP->any (will pick HTTP)
		{
			name: "http_to_any",
			proxy: &httpProxy{
				useTLS:       false,
				allowConnect: true,
				allowHTTP:    true,
			},
		},
		// HTTPS->HTTP
		{
			name: "https_to_http",
			proxy: &httpProxy{
				useTLS:       true,
				allowConnect: false,
				allowHTTP:    true,
			},
		},
		// HTTPS->HTTPS
		{
			name: "https_to_https",
			proxy: &httpProxy{
				useTLS:       true,
				allowConnect: true,
				allowHTTP:    false,
			},
		},
		// HTTPS->any (will pick HTTP)
		{
			name: "https_to_any",
			proxy: &httpProxy{
				useTLS:       true,
				allowConnect: true,
				allowHTTP:    true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testControlHTTP(t, test.proxy)
		})
	}
}

func testControlHTTP(t *testing.T, proxy proxy) {
	client, server := key.NewMachine(), key.NewMachine()

	const testProtocolVersion = 1
	sch := make(chan serverResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := AcceptHTTP(context.Background(), w, r, server, testProtocolVersion)
		if err != nil {
			log.Print(err)
		}
		res := serverResult{
			err: err,
		}
		if conn != nil {
			res.clientAddr = conn.RemoteAddr().String()
			res.version = conn.ProtocolVersion()
			res.peer = conn.Peer()
			res.conn = conn
		}
		sch <- res
	})

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("HTTP listen: %v", err)
	}
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("HTTPS listen: %v", err)
	}

	httpServer := &http.Server{Handler: handler}
	go httpServer.Serve(httpLn)
	defer httpServer.Close()

	httpsServer := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig(t),
	}
	go httpsServer.ServeTLS(httpsLn, "", "")
	defer httpsServer.Close()

	//ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//defer cancel()

	a := dialParams{
		ctx:         context.Background(), //ctx,
		host:        "localhost",
		httpPort:    strconv.Itoa(httpLn.Addr().(*net.TCPAddr).Port),
		httpsPort:   strconv.Itoa(httpsLn.Addr().(*net.TCPAddr).Port),
		machineKey:  client,
		controlKey:  server.Public(),
		version:     testProtocolVersion,
		insecureTLS: true,
	}

	if proxy != nil {
		proxyEnv := proxy.Start(t)
		defer proxy.Close()
		proxyURL, err := url.Parse(proxyEnv)
		if err != nil {
			t.Fatal(err)
		}
		a.proxyFunc = func(*http.Request) (*url.URL, error) {
			return proxyURL, nil
		}
	} else {
		a.proxyFunc = func(*http.Request) (*url.URL, error) {
			return nil, nil
		}
	}

	conn, err := a.dial()
	if err != nil {
		t.Fatalf("dialing controlhttp: %v", err)
	}
	defer conn.Close()
	si := <-sch
	if si.conn != nil {
		defer si.conn.Close()
	}
	if si.err != nil {
		t.Fatalf("controlhttp server got error: %v", err)
	}
	if clientVersion := conn.ProtocolVersion(); si.version != clientVersion {
		t.Fatalf("client and server don't agree on protocol version: %d vs %d", clientVersion, si.version)
	}
	if si.peer != client.Public() {
		t.Fatalf("server got peer pubkey %s, want %s", si.peer, client.Public())
	}
	if spub := conn.Peer(); spub != server.Public() {
		t.Fatalf("client got peer pubkey %s, want %s", spub, server.Public())
	}
	if proxy != nil && !proxy.ConnIsFromProxy(si.clientAddr) {
		t.Fatalf("client connected from %s, which isn't the proxy", si.clientAddr)
	}
}

type serverResult struct {
	err        error
	clientAddr string
	version    int
	peer       key.MachinePublic
	conn       *controlbase.Conn
}

type proxy interface {
	Start(*testing.T) string
	Close()
	ConnIsFromProxy(string) bool
}

type socksProxy struct {
	sync.Mutex
	proxy           socks5.Server
	ln              net.Listener
	clientConnAddrs map[string]bool // addrs of the local end of outgoing conns from proxy
}

func (s *socksProxy) Start(t *testing.T) (url string) {
	t.Helper()
	s.Lock()
	defer s.Unlock()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for SOCKS server: %v", err)
	}
	s.ln = ln
	s.clientConnAddrs = map[string]bool{}
	s.proxy.Logf = t.Logf
	s.proxy.Dialer = s.dialAndRecord
	go s.proxy.Serve(ln)
	return fmt.Sprintf("socks5://%s", ln.Addr().String())
}

func (s *socksProxy) Close() {
	s.Lock()
	defer s.Unlock()
	s.ln.Close()
}

func (s *socksProxy) dialAndRecord(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	s.Lock()
	defer s.Unlock()
	s.clientConnAddrs[conn.LocalAddr().String()] = true
	return conn, nil
}

func (s *socksProxy) ConnIsFromProxy(addr string) bool {
	s.Lock()
	defer s.Unlock()
	return s.clientConnAddrs[addr]
}

type httpProxy struct {
	useTLS       bool // take incoming connections over TLS
	allowConnect bool // allow CONNECT for TLS
	allowHTTP    bool // allow plain HTTP proxying

	sync.Mutex
	ln              net.Listener
	rp              httputil.ReverseProxy
	s               http.Server
	clientConnAddrs map[string]bool // addrs of the local end of outgoing conns from proxy
}

func (h *httpProxy) Start(t *testing.T) (url string) {
	t.Helper()
	h.Lock()
	defer h.Unlock()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for HTTP proxy: %v", err)
	}
	h.ln = ln
	h.rp = httputil.ReverseProxy{
		Director: func(*http.Request) {},
		Transport: &http.Transport{
			DialContext: h.dialAndRecord,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}
	h.clientConnAddrs = map[string]bool{}
	h.s.Handler = h
	if h.useTLS {
		h.s.TLSConfig = tlsConfig(t)
		go h.s.ServeTLS(h.ln, "", "")
		return fmt.Sprintf("https://%s", ln.Addr().String())
	} else {
		go h.s.Serve(h.ln)
		return fmt.Sprintf("http://%s", ln.Addr().String())
	}
}

func (h *httpProxy) Close() {
	h.Lock()
	defer h.Unlock()
	h.s.Close()
}

func (h *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "CONNECT" {
		if !h.allowHTTP {
			http.Error(w, "http proxy not allowed", 500)
			return
		}
		h.rp.ServeHTTP(w, r)
		return
	}

	if !h.allowConnect {
		http.Error(w, "connect not allowed", 500)
		return
	}

	dst := r.RequestURI
	c, err := h.dialAndRecord(context.Background(), "tcp", dst)
	if err != nil {
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

	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(cc, c)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(c, ccbuf)
		errc <- err
	}()
	<-errc
}

func (h *httpProxy) dialAndRecord(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	h.Lock()
	defer h.Unlock()
	h.clientConnAddrs[conn.LocalAddr().String()] = true
	return conn, nil
}

func (h *httpProxy) ConnIsFromProxy(addr string) bool {
	h.Lock()
	defer h.Unlock()
	return h.clientConnAddrs[addr]
}

func tlsConfig(t *testing.T) *tls.Config {
	// Cert and key taken from the example code in the crypto/tls
	// package.
	certPem := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}
