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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/health"
	"tailscale.com/net/memnet"
	"tailscale.com/net/netmon"
	"tailscale.com/net/socks5"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/must"
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
		conn, err := controlhttpserver.AcceptHTTP(context.Background(), w, r, server, earlyWriteFn)
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
		HealthTracker:        health.NewTracker(eventbustest.NewBus(t)),
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

// slowListener wraps a memnet listener to delay accept operations
type slowListener struct {
	net.Listener
	delay time.Duration
}

func (sl *slowListener) Accept() (net.Conn, error) {
	// Add delay before accepting connections
	timer := time.NewTimer(sl.delay)
	defer timer.Stop()
	<-timer.C

	return sl.Listener.Accept()
}

func newSlowListener(inner net.Listener, delay time.Duration) net.Listener {
	return &slowListener{
		Listener: inner,
		delay:    delay,
	}
}

func brokenMITMHandler(clock tstime.Clock) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Upgrade", controlhttpcommon.UpgradeHeaderValue)
		w.Header().Set("Connection", "upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
		w.(http.Flusher).Flush()
		// Advance the clock to trigger HTTPs fallback.
		clock.Now()
		<-r.Context().Done()
	}
}

func TestDialPlan(t *testing.T) {
	testCases := []struct {
		name          string
		plan          *tailcfg.ControlDialPlan
		want          []netip.Addr
		allowFallback bool
		maxDuration   time.Duration
	}{
		{
			name: "single",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				{IP: netip.MustParseAddr("10.0.0.2"), DialTimeoutSec: 10},
			}},
			want: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			name: "broken-then-good",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				{IP: netip.MustParseAddr("10.0.0.10"), DialTimeoutSec: 10},
				{IP: netip.MustParseAddr("10.0.0.2"), DialTimeoutSec: 10, DialStartDelaySec: 1},
			}},
			want: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			name: "multiple-candidates-with-broken",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				// Multiple good IPs plus a broken one
				// Should succeed with any of the good ones
				{IP: netip.MustParseAddr("10.0.0.10"), DialTimeoutSec: 10},
				{IP: netip.MustParseAddr("10.0.0.2"), DialTimeoutSec: 10},
				{IP: netip.MustParseAddr("10.0.0.4"), DialTimeoutSec: 10},
				{IP: netip.MustParseAddr("10.0.0.3"), DialTimeoutSec: 10},
			}},
			want: []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.4"), netip.MustParseAddr("10.0.0.3")},
		},
		{
			name: "multiple-candidates-race",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				{IP: netip.MustParseAddr("10.0.0.10"), DialTimeoutSec: 10},
				{IP: netip.MustParseAddr("10.0.0.3"), DialTimeoutSec: 10},
				{IP: netip.MustParseAddr("10.0.0.2"), DialTimeoutSec: 10},
			}},
			want: []netip.Addr{netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("10.0.0.2")},
		},
		{
			name: "fallback",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				{IP: netip.MustParseAddr("10.0.0.10"), DialTimeoutSec: 1},
			}},
			want:          []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			allowFallback: true,
		},
		{
			// In tailscale/corp#32534 we discovered that a prior implementation
			// of the dial race was waiting for all dials to complete when the
			// top priority dial was failing. This delay was long enough that in
			// real scenarios the server will close the connection due to
			// inactivity, because the client does not send the first inside of
			// noise request soon enough. This test is a regression guard
			// against that behavior - proving that the dial returns promptly
			// even if there is some cause of a slow race.
			name: "slow-endpoint-doesnt-block",
			plan: &tailcfg.ControlDialPlan{Candidates: []tailcfg.ControlIPCandidate{
				{IP: netip.MustParseAddr("10.0.0.12"), Priority: 5, DialTimeoutSec: 10},
				{IP: netip.MustParseAddr("10.0.0.2"), Priority: 1, DialTimeoutSec: 10},
			}},
			want:        []netip.Addr{netip.MustParseAddr("10.0.0.2")},
			maxDuration: 2 * time.Second, // Must complete quickly, not wait for slow endpoint
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				runDialPlanTest(t, tt.plan, tt.want, tt.allowFallback, tt.maxDuration)
			})
		})
	}
}

func runDialPlanTest(t *testing.T, plan *tailcfg.ControlDialPlan, want []netip.Addr, allowFallback bool, maxDuration time.Duration) {
	client, server := key.NewMachine(), key.NewMachine()

	const (
		testProtocolVersion = 1
		httpPort            = "80"
		httpsPort           = "443"
	)

	memNetwork := &memnet.Network{}

	fallbackAddr := netip.MustParseAddr("10.0.0.1")
	goodAddr := netip.MustParseAddr("10.0.0.2")
	otherAddr := netip.MustParseAddr("10.0.0.3")
	other2Addr := netip.MustParseAddr("10.0.0.4")
	brokenAddr := netip.MustParseAddr("10.0.0.10")
	slowAddr := netip.MustParseAddr("10.0.0.12")

	makeHandler := func(t *testing.T, name string, host netip.Addr, wrap func(http.Handler) http.Handler) {
		done := make(chan struct{})
		t.Cleanup(func() {
			close(done)
		})
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := controlhttpserver.AcceptHTTP(context.Background(), w, r, server, nil)
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

		httpLn := must.Get(memNetwork.Listen("tcp", host.String()+":"+httpPort))
		httpsLn := must.Get(memNetwork.Listen("tcp", host.String()+":"+httpsPort))

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
	}

	// Use synctest's controlled time
	clock := tstime.StdClock{}
	makeHandler(t, "fallback", fallbackAddr, nil)
	makeHandler(t, "good", goodAddr, nil)
	makeHandler(t, "other", otherAddr, nil)
	makeHandler(t, "other2", other2Addr, nil)
	makeHandler(t, "broken", brokenAddr, func(h http.Handler) http.Handler {
		return brokenMITMHandler(clock)
	})
	// Create slow listener that delays accept by 5 seconds
	makeSlowHandler := func(t *testing.T, name string, host netip.Addr, delay time.Duration) {
		done := make(chan struct{})
		t.Cleanup(func() {
			close(done)
		})
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := controlhttpserver.AcceptHTTP(context.Background(), w, r, server, nil)
			if err != nil {
				log.Print(err)
			} else {
				defer conn.Close()
			}
			w.Header().Set("X-Handler-Name", name)
			<-done
		})

		httpLn, err := memNetwork.Listen("tcp", host.String()+":"+httpPort)
		if err != nil {
			t.Fatalf("HTTP listen: %v", err)
		}
		httpsLn, err := memNetwork.Listen("tcp", host.String()+":"+httpsPort)
		if err != nil {
			t.Fatalf("HTTPS listen: %v", err)
		}

		slowHttpLn := newSlowListener(httpLn, delay)
		slowHttpsLn := newSlowListener(httpsLn, delay)

		httpServer := &http.Server{Handler: handler}
		go httpServer.Serve(slowHttpLn)
		t.Cleanup(func() {
			httpServer.Close()
		})

		httpsServer := &http.Server{
			Handler:   handler,
			TLSConfig: tlsConfig(t),
			ErrorLog:  logger.StdLogger(logger.WithPrefix(t.Logf, "http.Server.ErrorLog: ")),
		}
		go httpsServer.ServeTLS(slowHttpsLn, "", "")
		t.Cleanup(func() {
			httpsServer.Close()
		})
	}
	makeSlowHandler(t, "slow", slowAddr, 5*time.Second)

	// memnetDialer with connection tracking, so we can catch connection leaks.
	dialer := &memnetDialer{
		inner: memNetwork.Dial,
		t:     t,
	}
	defer dialer.waitForAllClosedSynctest()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host := "example.com"
	if allowFallback {
		host = fallbackAddr.String()
	}

	a := &Dialer{
		Hostname:             host,
		HTTPPort:             httpPort,
		HTTPSPort:            httpsPort,
		MachineKey:           client,
		ControlKey:           server.Public(),
		ProtocolVersion:      testProtocolVersion,
		Dialer:               dialer.Dial,
		Logf:                 t.Logf,
		DialPlan:             plan,
		proxyFunc:            func(*http.Request) (*url.URL, error) { return nil, nil },
		omitCertErrorLogging: true,
		testFallbackDelay:    50 * time.Millisecond,
		Clock:                clock,
		HealthTracker:        health.NewTracker(eventbustest.NewBus(t)),
	}

	start := time.Now()
	conn, err := a.dial(ctx)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("dialing controlhttp: %v", err)
	}
	defer conn.Close()

	if maxDuration > 0 && duration > maxDuration {
		t.Errorf("dial took %v, expected < %v (should not wait for slow endpoints)", duration, maxDuration)
	}

	raddr := conn.RemoteAddr()
	raddrStr := raddr.String()

	// split on "|" first to remove memnet pipe suffix
	addrPart := raddrStr
	if idx := strings.Index(raddrStr, "|"); idx >= 0 {
		addrPart = raddrStr[:idx]
	}

	host, _, err2 := net.SplitHostPort(addrPart)
	if err2 != nil {
		t.Fatalf("failed to parse remote address %q: %v", addrPart, err2)
	}

	got, err3 := netip.ParseAddr(host)
	if err3 != nil {
		t.Errorf("invalid remote IP: %v", host)
	} else {
		found := slices.Contains(want, got)
		if !found {
			t.Errorf("got connection from %q; want one of %v", got, want)
		} else {
			t.Logf("successfully connected to %q", raddr.String())
		}
	}
}

// memnetDialer wraps memnet.Network.Dial to track connections for testing
type memnetDialer struct {
	inner func(ctx context.Context, network, addr string) (net.Conn, error)
	t     *testing.T
	mu    sync.Mutex
	conns map[net.Conn]string // conn -> remote address for debugging
}

func (d *memnetDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.inner(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	if d.conns == nil {
		d.conns = make(map[net.Conn]string)
	}
	d.conns[conn] = conn.RemoteAddr().String()
	d.t.Logf("tracked connection opened to %s", conn.RemoteAddr())
	d.mu.Unlock()

	return &memnetTrackedConn{Conn: conn, dialer: d}, nil
}

func (d *memnetDialer) waitForAllClosedSynctest() {
	const maxWait = 15 * time.Second
	const checkInterval = 100 * time.Millisecond

	for range int(maxWait / checkInterval) {
		d.mu.Lock()
		remaining := len(d.conns)
		if remaining == 0 {
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()

		time.Sleep(checkInterval)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, addr := range d.conns {
		d.t.Errorf("connection to %s was not closed after %v", addr, maxWait)
	}
}

func (d *memnetDialer) noteClose(conn net.Conn) {
	d.mu.Lock()
	if addr, exists := d.conns[conn]; exists {
		d.t.Logf("tracked connection closed to %s", addr)
		delete(d.conns, conn)
	}
	d.mu.Unlock()
}

type memnetTrackedConn struct {
	net.Conn
	dialer *memnetDialer
}

func (c *memnetTrackedConn) Close() error {
	c.dialer.noteClose(c.Conn)
	return c.Conn.Close()
}
