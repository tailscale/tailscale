// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netmon"
	"tailscale.com/net/socks5"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

type httpTestParam struct {
	name  string
	proxy proxy

	// makeHTTPHangAfterUpgrade makes the HTTP response hang after sending a
	// 101 switching protocols.
	makeHTTPHangAfterUpgrade bool

	doEarlyWrite bool

	httpInDial bool
}

func TestControlHTTP(t *testing.T) {
	tests := []httpTestParam{
		// direct connection
		{
			name:  "no_proxy",
			proxy: nil,
		},
		// direct connection but port 80 is MITM'ed and broken
		{
			name:                     "port80_broken_mitm",
			proxy:                    nil,
			makeHTTPHangAfterUpgrade: true,
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
		// Early write
		{
			name:         "early_write",
			doEarlyWrite: true,
		},
		// Dialer needed to make another HTTP request along the way (e.g. to
		// resolve the hostname via BootstrapDNS).
		{
			name:       "http_request_in_dial",
			httpInDial: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testControlHTTP(t, test)
		})
	}
}

func testControlHTTP(t *testing.T, param httpTestParam) {
	proxy := param.proxy
	client, server := key.NewMachine(), key.NewMachine()

	const testProtocolVersion = 1
	const earlyWriteMsg = "Hello, world!"
	sch := make(chan serverResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var earlyWriteFn func(protocolVersion int, w io.Writer) error
		if param.doEarlyWrite {
			earlyWriteFn = func(protocolVersion int, w io.Writer) error {
				if protocolVersion != testProtocolVersion {
					t.Errorf("unexpected protocol version %d; want %d", protocolVersion, testProtocolVersion)
					return fmt.Errorf("unexpected protocol version %d; want %d", protocolVersion, testProtocolVersion)
				}
				_, err := io.WriteString(w, earlyWriteMsg)
				return err
			}
		}
		conn, err := AcceptHTTP(context.Background(), w, r, server, earlyWriteFn)
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

	var httpHandler http.Handler = handler
	const fallbackDelay = 50 * time.Millisecond
	clock := tstest.NewClock(tstest.ClockOpts{Step: 2 * fallbackDelay})
	// Advance once to init the clock.
	clock.Now()
	if param.makeHTTPHangAfterUpgrade {
		httpHandler = brokenMITMHandler(clock)
	}
	httpServer := &http.Server{Handler: httpHandler}
	go httpServer.Serve(httpLn)
	defer httpServer.Close()

	httpsServer := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig(t),
	}
	go httpsServer.ServeTLS(httpsLn, "", "")
	defer httpsServer.Close()

	ctx := context.Background()
	const debugTimeout = false
	if debugTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}

	netMon := netmon.NewStatic()
	dialer := tsdial.NewDialer(netMon)
	a := &Dialer{
		Hostname:             "localhost",
		HTTPPort:             strconv.Itoa(httpLn.Addr().(*net.TCPAddr).Port),
		HTTPSPort:            strconv.Itoa(httpsLn.Addr().(*net.TCPAddr).Port),
		MachineKey:           client,
		ControlKey:           server.Public(),
		NetMon:               netMon,
		ProtocolVersion:      testProtocolVersion,
		Dialer:               dialer.SystemDial,
		Logf:                 t.Logf,
		omitCertErrorLogging: true,
		testFallbackDelay:    fallbackDelay,
		Clock:                clock,
	}

	if param.httpInDial {
		// Spin up a separate server to get a different port on localhost.
		secondServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { return }))
		defer secondServer.Close()

		prev := a.Dialer
		a.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "GET", secondServer.URL, nil)
			if err != nil {
				t.Errorf("http.NewRequest: %v", err)
			}
			r, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("http.Get: %v", err)
			}
			r.Body.Close()

			return prev(ctx, network, addr)
		}
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

	conn, err := a.dial(ctx)
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
	if param.doEarlyWrite {
		buf := make([]byte, len(earlyWriteMsg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("reading early write: %v", err)
		}
		if string(buf) != earlyWriteMsg {
			t.Errorf("early write = %q; want %q", buf, earlyWriteMsg)
		}
	}

	// When no proxy is used, the RemoteAddr of the returned connection should match
	// one of the listeners of the test server.
	if proxy == nil {
		var expectedAddrs []string
		for _, ln := range []net.Listener{httpLn, httpsLn} {
			expectedAddrs = append(expectedAddrs, fmt.Sprintf("127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port))
			expectedAddrs = append(expectedAddrs, fmt.Sprintf("[::1]:%d", ln.Addr().(*net.TCPAddr).Port))
		}
		if !slices.Contains(expectedAddrs, conn.RemoteAddr().String()) {
			t.Errorf("unexpected remote addr: %s, want %s", conn.RemoteAddr(), expectedAddrs)
		}
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
	closed          bool
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
	s.proxy.Logf = func(format string, a ...any) {
		s.Lock()
		defer s.Unlock()
		if s.closed {
			return
		}
		t.Logf(format, a...)
	}
	s.proxy.Dialer = s.dialAndRecord
	go s.proxy.Serve(ln)
	return fmt.Sprintf("socks5://%s", ln.Addr().String())
}

func (s *socksProxy) Close() {
	s.Lock()
	defer s.Unlock()
	if s.closed {
		return
	}
	s.closed = true
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

func brokenMITMHandler(clock tstime.Clock) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Upgrade", upgradeHeaderValue)
		w.Header().Set("Connection", "upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
		w.(http.Flusher).Flush()
		// Advance the clock to trigger HTTPs fallback.
		clock.Now()
		<-r.Context().Done()
	}
}

func TestDialPlan(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only works on Linux due to multiple localhost addresses")
	}

	client, server := key.NewMachine(), key.NewMachine()

	const (
		testProtocolVersion = 1
	)

	getRandomPort := func() string {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer ln.Close()
		_, port, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return port
	}

	// We need consistent ports for each address; these are chosen
	// randomly and we hope that they won't conflict during this test.
	httpPort := getRandomPort()
	httpsPort := getRandomPort()

	makeHandler := func(t *testing.T, name string, host netip.Addr, wrap func(http.Handler) http.Handler) {
		done := make(chan struct{})
		t.Cleanup(func() {
			close(done)
		})
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := AcceptHTTP(context.Background(), w, r, server, nil)
			if err != nil {
				log.Print(err)
			} else {
				defer conn.Close()
			}
			w.Header().Set("X-Handler-Name", name)
			<-done
		})
		if wrap != nil {
			handler = wrap(handler)
		}

		httpLn, err := net.Listen("tcp", host.String()+":"+httpPort)
		if err != nil {
			t.Fatalf("HTTP listen: %v", err)
		}
		httpsLn, err := net.Listen("tcp", host.String()+":"+httpsPort)
		if err != nil {
			t.Fatalf("HTTPS listen: %v", err)
		}

		httpServer := &http.Server{Handler: handler}
		go httpServer.Serve(httpLn)
		t.Cleanup(func() {
			httpServer.Close()
		})

		httpsServer := &http.Server{
			Handler:   handler,
			TLSConfig: tlsConfig(t),
			ErrorLog:  logger.StdLogger(logger.WithPrefix(t.Logf, "http.Server.ErrorLog: ")),
		}
		go httpsServer.ServeTLS(httpsLn, "", "")
		t.Cleanup(func() {
			httpsServer.Close()
		})
		return
	}

	fallbackAddr := netip.MustParseAddr("127.0.0.1")
	goodAddr := netip.MustParseAddr("127.0.0.2")
	otherAddr := netip.MustParseAddr("127.0.0.3")
	other2Addr := netip.MustParseAddr("127.0.0.4")
	brokenAddr := netip.MustParseAddr("127.0.0.10")

	testCases := []struct {
		name string
		plan *tailcfg.ControlDialPlan
		wrap func(http.Handler) http.Handler
		want netip.Addr

		allowFallback bool
	}{
		{
			name: "single",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				{IP: goodAddr, Priority: 1, DialTimeoutSec: 10},
			}},
			want: goodAddr,
		},
		{
			name: "broken-then-good",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				// Dials the broken one, which fails, and then
				// eventually dials the good one and succeeds
				{IP: brokenAddr, Priority: 2, DialTimeoutSec: 10},
				{IP: goodAddr, Priority: 1, DialTimeoutSec: 10, DialStartDelaySec: 1},
			}},
			want: goodAddr,
		},
		// TODO(#8442): fix this test
		// {
		// 	name: "multiple-priority-fast-path",
		// 	plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
		// 		// Dials some good IPs and our bad one (which
		// 		// hangs forever), which then hits the fast
		// 		// path where we bail without waiting.
		// 		{IP: brokenAddr, Priority: 1, DialTimeoutSec: 10},
		// 		{IP: goodAddr, Priority: 1, DialTimeoutSec: 10},
		// 		{IP: other2Addr, Priority: 1, DialTimeoutSec: 10},
		// 		{IP: otherAddr, Priority: 2, DialTimeoutSec: 10},
		// 	}},
		// 	want: otherAddr,
		// },
		{
			name: "multiple-priority-slow-path",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				// Our broken address is the highest priority,
				// so we don't hit our fast path.
				{IP: brokenAddr, Priority: 10, DialTimeoutSec: 10},
				{IP: otherAddr, Priority: 2, DialTimeoutSec: 10},
				{IP: goodAddr, Priority: 1, DialTimeoutSec: 10},
			}},
			want: otherAddr,
		},
		{
			name: "fallback",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				{IP: brokenAddr, Priority: 1, DialTimeoutSec: 1},
			}},
			want:          fallbackAddr,
			allowFallback: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// TODO(awly): replace this with tstest.NewClock and update the
			// test to advance the clock correctly.
			clock := tstime.StdClock{}
			makeHandler(t, "fallback", fallbackAddr, nil)
			makeHandler(t, "good", goodAddr, nil)
			makeHandler(t, "other", otherAddr, nil)
			makeHandler(t, "other2", other2Addr, nil)
			makeHandler(t, "broken", brokenAddr, func(h http.Handler) http.Handler {
				return brokenMITMHandler(clock)
			})

			dialer := closeTrackDialer{
				t:     t,
				inner: tsdial.NewDialer(netmon.NewStatic()).SystemDial,
				conns: make(map[*closeTrackConn]bool),
			}
			defer dialer.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// By default, we intentionally point to something that
			// we know won't connect, since we want a fallback to
			// DNS to be an error.
			host := "example.com"
			if tt.allowFallback {
				host = "localhost"
			}

			drained := make(chan struct{})
			a := &Dialer{
				Hostname:             host,
				HTTPPort:             httpPort,
				HTTPSPort:            httpsPort,
				MachineKey:           client,
				ControlKey:           server.Public(),
				ProtocolVersion:      testProtocolVersion,
				Dialer:               dialer.Dial,
				Logf:                 t.Logf,
				DialPlan:             tt.plan,
				proxyFunc:            func(*http.Request) (*url.URL, error) { return nil, nil },
				drainFinished:        drained,
				omitCertErrorLogging: true,
				testFallbackDelay:    50 * time.Millisecond,
				Clock:                clock,
			}

			conn, err := a.dial(ctx)
			if err != nil {
				t.Fatalf("dialing controlhttp: %v", err)
			}
			defer conn.Close()

			raddr := conn.RemoteAddr().(*net.TCPAddr)

			got, ok := netip.AddrFromSlice(raddr.IP)
			if !ok {
				t.Errorf("invalid remote IP: %v", raddr.IP)
			} else if got != tt.want {
				t.Errorf("got connection from %q; want %q", got, tt.want)
			} else {
				t.Logf("successfully connected to %q", raddr.String())
			}

			// Wait until our dialer drains so we can verify that
			// all connections are closed.
			<-drained
		})
	}
}

type closeTrackDialer struct {
	t     testing.TB
	inner dnscache.DialContextFunc
	mu    sync.Mutex
	conns map[*closeTrackConn]bool
}

func (d *closeTrackDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.inner(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	ct := &closeTrackConn{Conn: c, d: d}

	d.mu.Lock()
	d.conns[ct] = true
	d.mu.Unlock()
	return ct, nil
}

func (d *closeTrackDialer) Done() {
	// Unfortunately, tsdial.Dialer.SystemDial closes connections
	// asynchronously in a goroutine, so we can't assume that everything is
	// closed by the time we get here.
	//
	// Sleep/wait a few times on the assumption that things will close
	// "eventually".
	const iters = 100
	for i := range iters {
		d.mu.Lock()
		if len(d.conns) == 0 {
			d.mu.Unlock()
			return
		}

		// Only error on last iteration
		if i != iters-1 {
			d.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		for conn := range d.conns {
			d.t.Errorf("expected close of conn %p; RemoteAddr=%q", conn, conn.RemoteAddr().String())
		}
		d.mu.Unlock()
	}
}

func (d *closeTrackDialer) noteClose(c *closeTrackConn) {
	d.mu.Lock()
	delete(d.conns, c) // safe if already deleted
	d.mu.Unlock()
}

type closeTrackConn struct {
	net.Conn
	d *closeTrackDialer
}

func (c *closeTrackConn) Close() error {
	c.d.noteClose(c)
	return c.Conn.Close()
}
