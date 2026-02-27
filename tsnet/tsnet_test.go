// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/net/proxy"

	"tailscale.com/client/local"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/deptest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
)

// TestListener_Server ensures that the listener type always keeps the Server
// method, which is used by some external applications to identify a tsnet.Listener
// from other net.Listeners, as well as access the underlying Server.
func TestListener_Server(t *testing.T) {
	s := &Server{}
	ln := listener{s: s}
	if ln.Server() != s {
		t.Errorf("listener.Server() returned %v, want %v", ln.Server(), s)
	}
}

func TestListenerPort(t *testing.T) {
	errNone := errors.New("sentinel start error")

	tests := []struct {
		network string
		addr    string
		wantErr bool
	}{
		{"tcp", ":80", false},
		{"foo", ":80", true},
		{"tcp", ":http", false},  // built-in name to Go; doesn't require cgo, /etc/services
		{"tcp", ":https", false}, // built-in name to Go; doesn't require cgo, /etc/services
		{"tcp", ":gibberishsdlkfj", true},
		{"tcp", ":%!d(string=80)", true}, // issue 6201
		{"udp", ":80", false},
		{"udp", "100.102.104.108:80", false},
		{"udp", "not-an-ip:80", true},
		{"udp4", ":80", false},
		{"udp4", "100.102.104.108:80", false},
		{"udp4", "not-an-ip:80", true},

		// Verify network type matches IP
		{"tcp4", "1.2.3.4:80", false},
		{"tcp6", "1.2.3.4:80", true},
		{"tcp4", "[12::34]:80", true},
		{"tcp6", "[12::34]:80", false},
	}
	for _, tt := range tests {
		s := &Server{}
		s.initOnce.Do(func() { s.initErr = errNone })
		_, err := s.Listen(tt.network, tt.addr)
		gotErr := err != nil && err != errNone
		if gotErr != tt.wantErr {
			t.Errorf("Listen(%q, %q) error = %v, want %v", tt.network, tt.addr, gotErr, tt.wantErr)
		}
	}
}

var verboseDERP = flag.Bool("verbose-derp", false, "if set, print DERP and STUN logs")
var verboseNodes = flag.Bool("verbose-nodes", false, "if set, print tsnet.Server logs")

func startControl(t *testing.T) (controlURL string, control *testcontrol.Server) {
	// Corp#4520: don't use netns for tests.
	netns.SetEnabled(false)
	t.Cleanup(func() {
		netns.SetEnabled(true)
	})

	derpLogf := logger.Discard
	if *verboseDERP {
		derpLogf = t.Logf
	}
	derpMap := integration.RunDERPAndSTUN(t, derpLogf, "127.0.0.1")
	control = &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           t.Logf,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL = control.HTTPTestServer.URL
	t.Logf("testcontrol listening on %s", controlURL)
	return controlURL, control
}

type testCertIssuer struct {
	mu    sync.Mutex
	certs map[string]ipnlocal.TLSCertKeyPair // keyed by hostname

	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

func newCertIssuer() *testCertIssuer {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	t := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, t, t, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	rootCA, err := x509.ParseCertificate(rootDER)
	if err != nil {
		panic(err)
	}
	return &testCertIssuer{
		root:    rootCA,
		rootKey: rootKey,
		certs:   map[string]ipnlocal.TLSCertKeyPair{},
	}
}

func (tci *testCertIssuer) getCert(hostname string) (*ipnlocal.TLSCertKeyPair, error) {
	tci.mu.Lock()
	defer tci.mu.Unlock()
	cert, ok := tci.certs[hostname]
	if ok {
		return &cert, nil
	}

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, tci.root, &certPrivKey.PublicKey, tci.rootKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	if err != nil {
		return nil, err
	}
	cert = ipnlocal.TLSCertKeyPair{
		CertPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}),
		KeyPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		}),
	}
	tci.certs[hostname] = cert
	return &cert, nil
}

func (tci *testCertIssuer) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(tci.root)
	return p
}

var testCertRoot = newCertIssuer()

func startServer(t *testing.T, ctx context.Context, controlURL, hostname string) (*Server, netip.Addr, key.NodePublic) {
	t.Helper()

	tmp := filepath.Join(t.TempDir(), hostname)
	os.MkdirAll(tmp, 0755)
	s := &Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	if *verboseNodes {
		s.Logf = t.Logf
	}
	t.Cleanup(func() { s.Close() })

	status, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.lb.ConfigureCertsForTest(testCertRoot.getCert)

	return s, status.TailscaleIPs[0], status.Self.PublicKey
}

func TestDialBlocks(t *testing.T) {
	tstest.Shard(t)
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)

	// Make one tsnet that blocks until it's up.
	s1, _, _ := startServer(t, ctx, controlURL, "s1")

	ln, err := s1.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Then make another tsnet node that will only be woken up
	// upon the first dial.
	tmp := filepath.Join(t.TempDir(), "s2")
	os.MkdirAll(tmp, 0755)
	s2 := &Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   "s2",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	if *verboseNodes {
		s2.Logf = log.Printf
	}
	t.Cleanup(func() { s2.Close() })

	c, err := s2.Dial(ctx, "tcp", "s1:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
}

// TestConn tests basic TCP connections between two tsnet Servers, s1 and s2:
//
//   - s1, a subnet router, first listens on its TCP :8081.
//   - s2 can connect to s1:8081
//   - s2 cannot connect to s1:8082 (no listener)
//   - s2 can dial through the subnet router functionality (getting a synthetic RST
//     that we verify we generated & saw)
func TestConn(t *testing.T) {
	tstest.Shard(t)
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, c := startControl(t)
	s1, s1ip, s1PubKey := startServer(t, ctx, controlURL, "s1")

	// Track whether we saw an attempted dial to 192.0.2.1:8081.
	var saw192DocNetDial atomic.Bool
	s1.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		t.Logf("s1: fallback TCP handler called for %v -> %v", src, dst)
		if dst.String() == "192.0.2.1:8081" {
			saw192DocNetDial.Store(true)
		}
		return nil, true // nil handler but intercept=true means to send RST
	})

	lc1 := must.Get(s1.LocalClient())

	must.Get(lc1.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		},
		AdvertiseRoutesSet: true,
	}))
	c.SetSubnetRoutes(s1PubKey, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})

	// Start s2 after s1 is fully set up, including advertising its routes,
	// otherwise the test is flaky if the test starts dialing through s2 before
	// our test control server has told s2 about s1's routes.
	s2, _, _ := startServer(t, ctx, controlURL, "s2")
	lc2 := must.Get(s2.LocalClient())

	must.Get(lc2.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			RouteAll: true,
		},
		RouteAllSet: true,
	}))

	// ping to make sure the connection is up.
	res, err := lc2.Ping(ctx, s1ip, tailcfg.PingTSMP)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ping success: %#+v", res)

	// pass some data through TCP.
	ln, err := s1.Listen("tcp", ":8081")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	s1Conns := make(chan net.Conn)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				t.Errorf("s1.Accept: %v", err)
				return
			}
			select {
			case s1Conns <- c:
			case <-ctx.Done():
				c.Close()
			}
		}
	}()

	w, err := s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8081", s1ip))
	if err != nil {
		t.Fatal(err)
	}

	want := "hello"
	if _, err := io.WriteString(w, want); err != nil {
		t.Fatal(err)
	}

	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for connection")
	case r := <-s1Conns:
		got := make([]byte, len(want))
		_, err := io.ReadAtLeast(r, got, len(got))
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("got: %q", got)
		if string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}

	// Dial a non-existent port on s1 and expect it to fail.
	_, err = s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8082", s1ip)) // some random port
	if err == nil {
		t.Fatalf("unexpected success; should have seen a connection refused error")
	}
	t.Logf("got expected failure: %v", err)

	// s1 is a subnet router for TEST-NET-1 (192.0.2.0/24). Let's dial to that
	// subnet from s2 to ensure a listener without an IP address (i.e. our
	// ":8081" listen above) only matches destination IPs corresponding to the
	// s1 node's IP addresses, and not to any random IP of a subnet it's routing.
	//
	// The RegisterFallbackTCPHandler on s1 above handles sending a RST when the
	// TCP SYN arrives from s2. But we bound it to 5 seconds lest a regression
	// like tailscale/tailscale#17805 recur.
	s2dialer := s2.Sys().Dialer.Get()
	s2dialer.SetSystemDialerForTest(func(ctx context.Context, netw, addr string) (net.Conn, error) {
		t.Logf("s2: unexpected system dial called for %s %s", netw, addr)
		return nil, fmt.Errorf("system dialer called unexpectedly for %s %s", netw, addr)
	})
	docCtx, docCancel := context.WithTimeout(ctx, 5*time.Second)
	defer docCancel()
	_, err = s2.Dial(docCtx, "tcp", "192.0.2.1:8081")
	if err == nil {
		t.Fatalf("unexpected success; should have seen a connection refused error")
	}
	if !saw192DocNetDial.Load() {
		t.Errorf("expected s1's fallback TCP handler to have been called for 192.0.2.1:8081")
	}
}

func TestLoopbackLocalAPI(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/8557")
	tstest.Shard(t)
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)
	s1, _, _ := startServer(t, ctx, controlURL, "s1")

	addr, proxyCred, localAPICred, err := s1.Loopback()
	if err != nil {
		t.Fatal(err)
	}
	if proxyCred == localAPICred {
		t.Fatal("proxy password matches local API password, they should be different")
	}

	url := "http://" + addr + "/localapi/v0/status"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Errorf("GET %s returned %d, want 403 without Sec- header", url, res.StatusCode)
	}

	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Tailscale", "localapi")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Errorf("GET %s returned %d, want 401 without basic auth", url, res.StatusCode)
	}

	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("", localAPICred)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Errorf("GET %s returned %d, want 403 without Sec- header", url, res.StatusCode)
	}

	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Tailscale", "localapi")
	req.SetBasicAuth("", localAPICred)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Errorf("GET /status returned %d, want 200", res.StatusCode)
	}
}

func TestLoopbackSOCKS5(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/8198")
	tstest.Shard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)
	s1, s1ip, _ := startServer(t, ctx, controlURL, "s1")
	s2, _, _ := startServer(t, ctx, controlURL, "s2")

	addr, proxyCred, _, err := s2.Loopback()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := s1.Listen("tcp", ":8081")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	auth := &proxy.Auth{User: "tsnet", Password: proxyCred}
	socksDialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	w, err := socksDialer.Dial("tcp", fmt.Sprintf("%s:8081", s1ip))
	if err != nil {
		t.Fatal(err)
	}

	r, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	want := "hello"
	if _, err := io.WriteString(w, want); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadAtLeast(r, got, len(got)); err != nil {
		t.Fatal(err)
	}
	t.Logf("got: %q", got)
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTailscaleIPs(t *testing.T) {
	tstest.Shard(t)
	controlURL, _ := startControl(t)

	tmp := t.TempDir()
	tmps1 := filepath.Join(tmp, "s1")
	os.MkdirAll(tmps1, 0755)
	s1 := &Server{
		Dir:        tmps1,
		ControlURL: controlURL,
		Hostname:   "s1",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	defer s1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s1status, err := s1.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var upIp4, upIp6 netip.Addr
	for _, ip := range s1status.TailscaleIPs {
		if ip.Is6() {
			upIp6 = ip
		}
		if ip.Is4() {
			upIp4 = ip
		}
	}

	sIp4, sIp6 := s1.TailscaleIPs()
	if !(upIp4 == sIp4 && upIp6 == sIp6) {
		t.Errorf("s1.TailscaleIPs returned a different result than S1.Up, (%s, %s) != (%s, %s)",
			sIp4, upIp4, sIp6, upIp6)
	}
}

// TestListenerCleanup is a regression test to verify that s.Close doesn't
// deadlock if a listener is still open.
func TestListenerCleanup(t *testing.T) {
	tstest.Shard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)
	s1, _, _ := startServer(t, ctx, controlURL, "s1")

	ln, err := s1.Listen("tcp", ":8081")
	if err != nil {
		t.Fatal(err)
	}

	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	if err := ln.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second ln.Close error: %v, want net.ErrClosed", err)
	}

	// Verify that handling a connection from gVisor (from a packet arriving)
	// after a listener closed doesn't panic (previously: sending on a closed
	// channel) or hang.
	c := &closeTrackConn{}
	ln.(*listener).handle(c)
	if !c.closed {
		t.Errorf("c.closed = false, want true")
	}
}

type closeTrackConn struct {
	net.Conn
	closed bool
}

func (wc *closeTrackConn) Close() error {
	wc.closed = true
	return nil
}

// tests https://github.com/tailscale/tailscale/issues/6973 -- that we can start a tsnet server,
// stop it, and restart it, even on Windows.
func TestStartStopStartGetsSameIP(t *testing.T) {
	tstest.Shard(t)
	controlURL, _ := startControl(t)

	tmp := t.TempDir()
	tmps1 := filepath.Join(tmp, "s1")
	os.MkdirAll(tmps1, 0755)

	newServer := func() *Server {
		return &Server{
			Dir:        tmps1,
			ControlURL: controlURL,
			Hostname:   "s1",
			Logf:       tstest.WhileTestRunningLogger(t),
		}
	}
	s1 := newServer()
	defer s1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s1status, err := s1.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}

	firstIPs := s1status.TailscaleIPs
	t.Logf("IPs: %v", firstIPs)

	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2 := newServer()
	defer s2.Close()

	s2status, err := s2.Up(ctx)
	if err != nil {
		t.Fatalf("second Up: %v", err)
	}

	secondIPs := s2status.TailscaleIPs
	t.Logf("IPs: %v", secondIPs)

	if !reflect.DeepEqual(firstIPs, secondIPs) {
		t.Fatalf("got %v but later %v", firstIPs, secondIPs)
	}
}

func TestFunnel(t *testing.T) {
	tstest.Shard(t)
	ctx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dialCancel()

	controlURL, _ := startControl(t)
	s1, _, _ := startServer(t, ctx, controlURL, "s1")
	s2, _, _ := startServer(t, ctx, controlURL, "s2")

	ln := must.Get(s1.ListenFunnel("tcp", ":443"))
	defer ln.Close()
	wantSrcAddrPort := netip.MustParseAddrPort("127.0.0.1:1234")
	wantTarget := ipn.HostPort("s1.tail-scale.ts.net:443")
	srv := &http.Server{
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			tc, ok := c.(*tls.Conn)
			if !ok {
				t.Errorf("ConnContext called with non-TLS conn: %T", c)
			}
			if fc, ok := tc.NetConn().(*ipn.FunnelConn); !ok {
				t.Errorf("ConnContext called with non-FunnelConn: %T", c)
			} else if fc.Src != wantSrcAddrPort {
				t.Errorf("ConnContext called with wrong SrcAddrPort; got %v, want %v", fc.Src, wantSrcAddrPort)
			} else if fc.Target != wantTarget {
				t.Errorf("ConnContext called with wrong Target; got %q, want %q", fc.Target, wantTarget)
			}
			return ctx
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "hello")
		}),
	}
	go srv.Serve(ln)

	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialIngressConn(s2, s1, addr)
			},
			TLSClientConfig: &tls.Config{
				RootCAs: testCertRoot.Pool(),
			},
		},
	}
	resp, err := c.Get("https://s1.tail-scale.ts.net:443")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("unexpected status code: %v", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Errorf("unexpected body: %q", body)
	}
}

// TestFunnelClose ensures that the listener returned by ListenFunnel cleans up
// after itself when closed. Specifically, changes made to the serve config
// should be cleared.
func TestFunnelClose(t *testing.T) {
	marshalServeConfig := func(t *testing.T, sc ipn.ServeConfigView) string {
		t.Helper()
		return string(must.Get(json.MarshalIndent(sc, "", "\t")))
	}

	t.Run("simple", func(t *testing.T) {
		controlURL, _ := startControl(t)
		s, _, _ := startServer(t, t.Context(), controlURL, "s")

		before := s.lb.ServeConfig()

		ln := must.Get(s.ListenFunnel("tcp", ":443"))
		ln.Close()

		after := s.lb.ServeConfig()
		if diff := cmp.Diff(marshalServeConfig(t, after), marshalServeConfig(t, before)); diff != "" {
			t.Fatalf("expected serve config to be unchanged after close (-got, +want):\n%s", diff)
		}
	})

	// Closing the listener shouldn't clear out config that predates it.
	t.Run("no_clobbering", func(t *testing.T) {
		controlURL, _ := startControl(t)
		s, _, _ := startServer(t, t.Context(), controlURL, "s")

		// To obtain config the listener might want to clobber, we:
		//  - run a listener
		//  - grab the config
		//  - close the listener (clearing config)
		ln := must.Get(s.ListenFunnel("tcp", ":443"))
		before := s.lb.ServeConfig()
		ln.Close()

		// Now we manually write the config to the local backend (it should have
		// been cleared), run the listener again, and close it again.
		must.Do(s.lb.SetServeConfig(before.AsStruct(), ""))
		ln = must.Get(s.ListenFunnel("tcp", ":443"))
		ln.Close()

		// The config should not have been cleared this time since it predated
		// the most recent run.
		after := s.lb.ServeConfig()
		if diff := cmp.Diff(marshalServeConfig(t, after), marshalServeConfig(t, before)); diff != "" {
			t.Fatalf("expected existing config to remain intact (-got, +want):\n%s", diff)
		}
	})

	// Closing one listener shouldn't affect config for another listener.
	t.Run("two_listeners", func(t *testing.T) {
		controlURL, _ := startControl(t)
		s, _, _ := startServer(t, t.Context(), controlURL, "s1")

		// Start a listener on 443.
		ln1 := must.Get(s.ListenFunnel("tcp", ":443"))
		defer ln1.Close()

		// Save the serve config for this original listener.
		before := s.lb.ServeConfig()

		// Now start and close a new listener on a different port.
		ln2 := must.Get(s.ListenFunnel("tcp", ":8080"))
		ln2.Close()

		// The serve config for the original listener should be intact.
		after := s.lb.ServeConfig()
		if diff := cmp.Diff(marshalServeConfig(t, after), marshalServeConfig(t, before)); diff != "" {
			t.Fatalf("expected existing config to remain intact (-got, +want):\n%s", diff)
		}
	})

	// It should be possible to close a listener and free system resources even
	// when the Server has been closed (or the listener should be automatically
	// closed).
	t.Run("after_server_close", func(t *testing.T) {
		controlURL, _ := startControl(t)
		s, _, _ := startServer(t, t.Context(), controlURL, "s")

		ln := must.Get(s.ListenFunnel("tcp", ":443"))

		// Close the server, then close the listener.
		must.Do(s.Close())
		// We don't care whether we get an error from the listener closing.
		ln.Close()

		// The listener should immediately return an error indicating closure.
		_, err := ln.Accept()
		// Looking for a string in the error sucks, but it's supposed to stay
		// consistent:
		// https://github.com/golang/go/blob/108b333d510c1f60877ac917375d7931791acfe6/src/internal/poll/fd.go#L20-L24
		if err == nil || !strings.Contains(err.Error(), "use of closed network connection") {
			t.Fatal("expected listener to be closed, got:", err)
		}
	})
}

func TestListenService(t *testing.T) {
	// First test an error case which doesn't require all of the fancy setup.
	t.Run("untagged_node_error", func(t *testing.T) {
		ctx := t.Context()

		controlURL, _ := startControl(t)
		serviceHost, _, _ := startServer(t, ctx, controlURL, "service-host")

		ln, err := serviceHost.ListenService("svc:foo", ServiceModeTCP{Port: 8080})
		if ln != nil {
			ln.Close()
		}
		if !errors.Is(err, ErrUntaggedServiceHost) {
			t.Fatalf("expected %v, got %v", ErrUntaggedServiceHost, err)
		}
	})

	// Now on to the fancier tests.

	type dialFn func(context.Context, string, string) (net.Conn, error)

	// TCP helpers
	acceptAndEcho := func(t *testing.T, ln net.Listener) {
		t.Helper()
		conn, err := ln.Accept()
		if err != nil {
			t.Error("accept error:", err)
			return
		}
		defer conn.Close()
		if _, err := io.Copy(conn, conn); err != nil {
			t.Error("copy error:", err)
		}
	}
	assertEcho := func(t *testing.T, conn net.Conn) {
		t.Helper()
		msg := "echo"
		buf := make([]byte, 1024)
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatal("write failed:", err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal("read failed:", err)
		}
		got := string(buf[:n])
		if got != msg {
			t.Fatalf("unexpected response:\n\twant: %s\n\tgot: %s", msg, got)
		}
	}

	// HTTP helpers
	checkAndEcho := func(t *testing.T, ln net.Listener, check func(r *http.Request)) {
		t.Helper()
		if check == nil {
			check = func(*http.Request) {}
		}
		http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			check(r)
			if _, err := io.Copy(w, r.Body); err != nil {
				t.Error("copy error:", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
	}
	assertEchoHTTP := func(t *testing.T, hostname, path string, dial dialFn) {
		t.Helper()
		c := http.Client{
			Transport: &http.Transport{
				DialContext: dial,
			},
		}
		msg := "echo"
		resp, err := c.Post("http://"+hostname+path, "text/plain", strings.NewReader(msg))
		if err != nil {
			t.Fatal("posting request:", err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal("reading body:", err)
		}
		got := string(b)
		if got != msg {
			t.Fatalf("unexpected response:\n\twant: %s\n\tgot: %s", msg, got)
		}
	}

	tests := []struct {
		name string

		// modes is used as input to [Server.ListenService].
		//
		// If this slice has multiple modes, then ListenService will be invoked
		// multiple times. The number of listeners provided to the run function
		// (below) will always match the number of elements in this slice.
		modes []ServiceMode

		extraSetup func(t *testing.T, control *testcontrol.Server)

		// run executes the test. This function does not need to close any of
		// the input resources, but it should close any new resources it opens.
		// listeners[i] corresponds to inputs[i].
		run func(t *testing.T, listeners []*ServiceListener, peer *Server)
	}{
		{
			name: "basic_TCP",
			modes: []ServiceMode{
				ServiceModeTCP{Port: 99},
			},
			run: func(t *testing.T, listeners []*ServiceListener, peer *Server) {
				go acceptAndEcho(t, listeners[0])

				target := fmt.Sprintf("%s:%d", listeners[0].FQDN, 99)
				conn := must.Get(peer.Dial(t.Context(), "tcp", target))
				defer conn.Close()

				assertEcho(t, conn)
			},
		},
		{
			name: "TLS_terminated_TCP",
			modes: []ServiceMode{
				ServiceModeTCP{
					TerminateTLS: true,
					Port:         443,
				},
			},
			run: func(t *testing.T, listeners []*ServiceListener, peer *Server) {
				go acceptAndEcho(t, listeners[0])

				target := fmt.Sprintf("%s:%d", listeners[0].FQDN, 443)
				conn := must.Get(peer.Dial(t.Context(), "tcp", target))
				defer conn.Close()

				assertEcho(t, tls.Client(conn, &tls.Config{
					ServerName: listeners[0].FQDN,
					RootCAs:    testCertRoot.Pool(),
				}))
			},
		},
		{
			name: "identity_headers",
			modes: []ServiceMode{
				ServiceModeHTTP{
					Port: 80,
				},
			},
			run: func(t *testing.T, listeners []*ServiceListener, peer *Server) {
				expectHeader := "Tailscale-User-Name"
				go checkAndEcho(t, listeners[0], func(r *http.Request) {
					if _, ok := r.Header[expectHeader]; !ok {
						t.Error("did not see expected header:", expectHeader)
					}
				})
				assertEchoHTTP(t, listeners[0].FQDN, "", peer.Dial)
			},
		},
		{
			name: "identity_headers_TLS",
			modes: []ServiceMode{
				ServiceModeHTTP{
					HTTPS: true,
					Port:  80,
				},
			},
			run: func(t *testing.T, listeners []*ServiceListener, peer *Server) {
				expectHeader := "Tailscale-User-Name"
				go checkAndEcho(t, listeners[0], func(r *http.Request) {
					if _, ok := r.Header[expectHeader]; !ok {
						t.Error("did not see expected header:", expectHeader)
					}
				})

				dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
					tcpConn, err := peer.Dial(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					return tls.Client(tcpConn, &tls.Config{
						ServerName: listeners[0].FQDN,
						RootCAs:    testCertRoot.Pool(),
					}), nil
				}

				assertEchoHTTP(t, listeners[0].FQDN, "", dial)
			},
		},
		{
			name: "app_capabilities",
			modes: []ServiceMode{
				ServiceModeHTTP{
					Port: 80,
					AcceptAppCaps: map[string][]string{
						"/":    {"example.com/cap/all-paths"},
						"/foo": {"example.com/cap/all-paths", "example.com/cap/foo"},
					},
				},
			},
			extraSetup: func(t *testing.T, control *testcontrol.Server) {
				control.SetGlobalAppCaps(tailcfg.PeerCapMap{
					"example.com/cap/all-paths": []tailcfg.RawMessage{`true`},
					"example.com/cap/foo":       []tailcfg.RawMessage{`true`},
				})
			},
			run: func(t *testing.T, listeners []*ServiceListener, peer *Server) {
				allPathsCap := "example.com/cap/all-paths"
				fooCap := "example.com/cap/foo"
				checkCaps := func(r *http.Request) {
					rawCaps, ok := r.Header["Tailscale-App-Capabilities"]
					if !ok {
						t.Error("no app capabilities header")
						return
					}
					if len(rawCaps) != 1 {
						t.Error("expected one app capabilities header value, got", len(rawCaps))
						return
					}
					var caps map[string][]any
					if err := json.Unmarshal([]byte(rawCaps[0]), &caps); err != nil {
						t.Error("error unmarshaling app caps:", err)
						return
					}
					if _, ok := caps[allPathsCap]; !ok {
						t.Errorf("got app caps, but %v is not present; saw:\n%v", allPathsCap, caps)
					}
					if strings.HasPrefix(r.URL.Path, "/foo") {
						if _, ok := caps[fooCap]; !ok {
							t.Errorf("%v should be present for /foo request; saw:\n%v", fooCap, caps)
						}
					} else {
						if _, ok := caps[fooCap]; ok {
							t.Errorf("%v should not be present for non-/foo request; saw:\n%v", fooCap, caps)
						}
					}
				}

				go checkAndEcho(t, listeners[0], checkCaps)
				assertEchoHTTP(t, listeners[0].FQDN, "", peer.Dial)
				assertEchoHTTP(t, listeners[0].FQDN, "/foo", peer.Dial)
				assertEchoHTTP(t, listeners[0].FQDN, "/foo/bar", peer.Dial)
			},
		},
		{
			name: "multiple_ports",
			modes: []ServiceMode{
				ServiceModeTCP{
					Port: 99,
				},
				ServiceModeHTTP{
					Port: 80,
				},
			},
			run: func(t *testing.T, listeners []*ServiceListener, peer *Server) {
				go acceptAndEcho(t, listeners[0])

				target := fmt.Sprintf("%s:%d", listeners[0].FQDN, 99)
				conn := must.Get(peer.Dial(t.Context(), "tcp", target))
				defer conn.Close()
				assertEcho(t, conn)

				go checkAndEcho(t, listeners[1], nil)
				assertEchoHTTP(t, listeners[1].FQDN, "", peer.Dial)
			},
		},
	}

	for _, tt := range tests {
		// Overview:
		// - start test control
		// - start 2 tsnet nodes:
		//     one to act as Service host and a second to act as a peer client
		// - configure necessary state on control mock
		// - start a Service listener from the host
		// - call tt.run with our test bed
		//
		// This ends up also testing the Service forwarding logic in
		// LocalBackend, but that's useful too.
		t.Run(tt.name, func(t *testing.T) {
			// We run each test with and without a TUN device ([Server.Tun]).
			// Note that this TUN device is distinct from TUN mode for Services.
			doTest := func(t *testing.T, withTUNDevice bool) {
				ctx := t.Context()

				lt := setupTwoClientTest(t, withTUNDevice)
				serviceHost := lt.s2
				serviceClient := lt.s1
				control := lt.control

				const serviceName = tailcfg.ServiceName("svc:foo")
				const serviceVIP = "100.11.22.33"

				// == Set up necessary state in our mock ==

				// The Service host must have the 'service-host' capability, which
				// is a mapping from the Service name to the Service VIP.
				var serviceHostCaps map[tailcfg.ServiceName]views.Slice[netip.Addr]
				mak.Set(&serviceHostCaps, serviceName, views.SliceOf([]netip.Addr{netip.MustParseAddr(serviceVIP)}))
				j := must.Get(json.Marshal(serviceHostCaps))
				cm := serviceHost.lb.NetMap().SelfNode.CapMap().AsMap()
				mak.Set(&cm, tailcfg.NodeAttrServiceHost, []tailcfg.RawMessage{tailcfg.RawMessage(j)})
				control.SetNodeCapMap(serviceHost.lb.NodeKey(), cm)

				// The Service host must be allowed to advertise the Service VIP.
				control.SetSubnetRoutes(serviceHost.lb.NodeKey(), []netip.Prefix{
					netip.MustParsePrefix(serviceVIP + `/32`),
				})

				// The Service host must be a tagged node (any tag will do).
				serviceHostNode := control.Node(serviceHost.lb.NodeKey())
				serviceHostNode.Tags = append(serviceHostNode.Tags, "some-tag")
				control.UpdateNode(serviceHostNode)

				// The service client must accept routes advertised by other nodes
				// (RouteAll is equivalent to --accept-routes).
				must.Get(serviceClient.localClient.EditPrefs(ctx, &ipn.MaskedPrefs{
					RouteAllSet: true,
					Prefs: ipn.Prefs{
						RouteAll: true,
					},
				}))

				// Set up DNS for our Service.
				control.AddDNSRecords(tailcfg.DNSRecord{
					Name:  serviceName.WithoutPrefix() + "." + control.MagicDNSDomain,
					Value: serviceVIP,
				})

				if tt.extraSetup != nil {
					tt.extraSetup(t, control)
				}

				// Wait until both nodes have up-to-date netmaps before
				// proceeding with the test.
				netmapUpToDate := func(s *Server) bool {
					nm := s.lb.NetMap()
					return slices.ContainsFunc(nm.DNS.ExtraRecords, func(r tailcfg.DNSRecord) bool {
						return r.Value == serviceVIP
					})
				}
				for !netmapUpToDate(serviceClient) {
					time.Sleep(10 * time.Millisecond)
				}
				for !netmapUpToDate(serviceHost) {
					time.Sleep(10 * time.Millisecond)
				}

				// == Done setting up mock state ==

				// Start the Service listeners.
				listeners := make([]*ServiceListener, 0, len(tt.modes))
				for _, input := range tt.modes {
					ln := must.Get(serviceHost.ListenService(serviceName.String(), input))
					defer ln.Close()
					listeners = append(listeners, ln)
				}

				tt.run(t, listeners, serviceClient)
			}

			t.Run("TUN", func(t *testing.T) { doTest(t, true) })
			t.Run("netstack", func(t *testing.T) { doTest(t, false) })
		})
	}
}

func TestListenerClose(t *testing.T) {
	tstest.Shard(t)
	ctx := context.Background()
	controlURL, _ := startControl(t)

	s1, _, _ := startServer(t, ctx, controlURL, "s1")

	ln, err := s1.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}

	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if c != nil {
			c.Close()
		}
		errc <- err
	}()

	ln.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for Accept to return")
	}
}

func dialIngressConn(from, to *Server, target string) (net.Conn, error) {
	toLC := must.Get(to.LocalClient())
	toStatus := must.Get(toLC.StatusWithoutPeers(context.Background()))
	peer6 := toStatus.Self.PeerAPIURL[1] // IPv6
	toPeerAPI, ok := strings.CutPrefix(peer6, "http://")
	if !ok {
		return nil, fmt.Errorf("unexpected PeerAPIURL %q", peer6)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	outConn, err := from.Dial(dialCtx, "tcp", toPeerAPI)
	dialCancel()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "/v0/ingress", nil)
	if err != nil {
		return nil, err
	}
	req.Host = toPeerAPI
	req.Header.Set("Tailscale-Ingress-Src", "127.0.0.1:1234")
	req.Header.Set("Tailscale-Ingress-Target", target)
	if err := req.Write(outConn); err != nil {
		return nil, err
	}

	br := bufio.NewReader(outConn)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close() // just to appease vet
	if res.StatusCode != 101 {
		return nil, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}
	return &bufferedConn{outConn, br}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func TestFallbackTCPHandler(t *testing.T) {
	tstest.Shard(t)
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)
	s1, s1ip, _ := startServer(t, ctx, controlURL, "s1")
	s2, _, _ := startServer(t, ctx, controlURL, "s2")

	lc2, err := s2.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	// ping to make sure the connection is up.
	res, err := lc2.Ping(ctx, s1ip, tailcfg.PingICMP)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ping success: %#+v", res)

	var s1TcpConnCount atomic.Int32
	deregister := s1.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		s1TcpConnCount.Add(1)
		return nil, false
	})

	if _, err := s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8081", s1ip)); err == nil {
		t.Fatal("Expected dial error because fallback handler did not intercept")
	}
	if got := s1TcpConnCount.Load(); got != 1 {
		t.Errorf("s1TcpConnCount = %d, want %d", got, 1)
	}
	deregister()
	if _, err := s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8081", s1ip)); err == nil {
		t.Fatal("Expected dial error because nothing would intercept")
	}
	if got := s1TcpConnCount.Load(); got != 1 {
		t.Errorf("s1TcpConnCount = %d, want %d", got, 1)
	}
}

func TestCapturePcap(t *testing.T) {
	tstest.Shard(t)
	const timeLimit = 120
	ctx, cancel := context.WithTimeout(context.Background(), timeLimit*time.Second)
	defer cancel()

	dir := t.TempDir()
	s1Pcap := filepath.Join(dir, "s1.pcap")
	s2Pcap := filepath.Join(dir, "s2.pcap")

	controlURL, _ := startControl(t)
	s1, s1ip, _ := startServer(t, ctx, controlURL, "s1")
	s2, _, _ := startServer(t, ctx, controlURL, "s2")
	s1.CapturePcap(ctx, s1Pcap)
	s2.CapturePcap(ctx, s2Pcap)

	lc2, err := s2.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	// send a packet which both nodes will capture
	res, err := lc2.Ping(ctx, s1ip, tailcfg.PingICMP)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ping success: %#+v", res)

	fileSize := func(name string) int64 {
		fi, err := os.Stat(name)
		if err != nil {
			return 0
		}
		return fi.Size()
	}

	const pcapHeaderSize = 24

	// there is a lag before the io.Copy writes a packet to the pcap files
	for range timeLimit * 10 {
		time.Sleep(100 * time.Millisecond)
		if (fileSize(s1Pcap) > pcapHeaderSize) && (fileSize(s2Pcap) > pcapHeaderSize) {
			break
		}
	}

	if got := fileSize(s1Pcap); got <= pcapHeaderSize {
		t.Errorf("s1 pcap file size = %d, want > pcapHeaderSize(%d)", got, pcapHeaderSize)
	}
	if got := fileSize(s2Pcap); got <= pcapHeaderSize {
		t.Errorf("s2 pcap file size = %d, want > pcapHeaderSize(%d)", got, pcapHeaderSize)
	}
}

func TestUDPConn(t *testing.T) {
	tstest.Shard(t)
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)
	s1, s1ip, _ := startServer(t, ctx, controlURL, "s1")
	s2, s2ip, _ := startServer(t, ctx, controlURL, "s2")

	lc2, err := s2.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	// ping to make sure the connection is up.
	res, err := lc2.Ping(ctx, s1ip, tailcfg.PingICMP)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ping success: %#+v", res)

	pc := must.Get(s1.ListenPacket("udp", fmt.Sprintf("%s:8081", s1ip)))
	defer pc.Close()

	// Dial to s1 from s2
	w, err := s2.Dial(ctx, "udp", fmt.Sprintf("%s:8081", s1ip))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Send a packet from s2 to s1
	want := "hello"
	if _, err := io.WriteString(w, want); err != nil {
		t.Fatal(err)
	}

	// Receive the packet on s1
	got := make([]byte, 1024)
	n, from, err := pc.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	got = got[:n]
	t.Logf("got: %q", got)
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if from.(*net.UDPAddr).AddrPort().Addr() != s2ip {
		t.Errorf("got from %v, want %v", from, s2ip)
	}

	// Write a response back to s2
	if _, err := pc.WriteTo([]byte("world"), from); err != nil {
		t.Fatal(err)
	}

	// Receive the response on s2
	got = make([]byte, 1024)
	n, err = w.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	got = got[:n]
	t.Logf("got: %q", got)
	if string(got) != "world" {
		t.Errorf("got %q, want world", got)
	}
}

func parseMetrics(m []byte) (map[string]float64, error) {
	metrics := make(map[string]float64)

	var parser expfmt.TextParser
	mf, err := parser.TextToMetricFamilies(bytes.NewReader(m))
	if err != nil {
		return nil, err
	}

	for _, f := range mf {
		for _, ff := range f.Metric {
			val := float64(0)

			switch f.GetType() {
			case dto.MetricType_COUNTER:
				val = ff.GetCounter().GetValue()
			case dto.MetricType_GAUGE:
				val = ff.GetGauge().GetValue()
			}

			metrics[f.GetName()+promMetricLabelsStr(ff.GetLabel())] = val
		}
	}

	return metrics, nil
}

func promMetricLabelsStr(labels []*dto.LabelPair) string {
	if len(labels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("{")
	for i, lb := range labels {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf("%s=%q", lb.GetName(), lb.GetValue()))
	}
	b.WriteString("}")
	return b.String()
}

// sendData sends a given amount of bytes from s1 to s2.
func sendData(logf func(format string, args ...any), ctx context.Context, bytesCount int, s1, s2 *Server, s1ip, s2ip netip.Addr) error {
	lb := must.Get(s1.Listen("tcp", fmt.Sprintf("%s:8081", s1ip)))
	defer lb.Close()

	// Dial to s1 from s2
	w, err := s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8081", s1ip))
	if err != nil {
		return err
	}
	defer w.Close()

	stopReceive := make(chan struct{})
	defer close(stopReceive)
	allReceived := make(chan error)
	defer close(allReceived)

	go func() {
		conn, err := lb.Accept()
		if err != nil {
			allReceived <- err
			return
		}
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

		total := 0
		recvStart := time.Now()
		for {
			got := make([]byte, bytesCount)
			n, err := conn.Read(got)
			if err != nil {
				allReceived <- fmt.Errorf("failed reading packet, %s", err)
				return
			}
			got = got[:n]

			select {
			case <-stopReceive:
				return
			default:
			}

			total += n
			logf("received %d/%d bytes, %.2f %%", total, bytesCount, (float64(total) / (float64(bytesCount)) * 100))

			// Validate the received bytes to be the same as the sent bytes.
			for _, b := range string(got) {
				if b != 'A' {
					allReceived <- fmt.Errorf("received unexpected byte: %c", b)
					return
				}
			}

			if total == bytesCount {
				break
			}
		}

		logf("all received, took: %s", time.Since(recvStart).String())
		allReceived <- nil
	}()

	sendStart := time.Now()
	w.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := w.Write(bytes.Repeat([]byte("A"), bytesCount)); err != nil {
		stopReceive <- struct{}{}
		return err
	}

	logf("all sent (%s), waiting for all packets (%d) to be received", time.Since(sendStart).String(), bytesCount)
	err, _ = <-allReceived
	if err != nil {
		return err
	}

	return nil
}

func TestUserMetricsByteCounters(t *testing.T) {
	tstest.Shard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)
	s1, s1ip, _ := startServer(t, ctx, controlURL, "s1")
	defer s1.Close()
	s2, s2ip, _ := startServer(t, ctx, controlURL, "s2")
	defer s2.Close()

	lc1, err := s1.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	lc2, err := s2.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	// Force an update to the netmap to ensure that the metrics are up-to-date.
	s1.lb.DebugForceNetmapUpdate()
	s2.lb.DebugForceNetmapUpdate()

	// Wait for both nodes to have a peer in their netmap.
	waitForCondition(t, "waiting for netmaps to contain peer", 90*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		status1, err := lc1.Status(ctx)
		if err != nil {
			t.Logf("getting status: %s", err)
			return false
		}
		status2, err := lc2.Status(ctx)
		if err != nil {
			t.Logf("getting status: %s", err)
			return false
		}
		return len(status1.Peers()) > 0 && len(status2.Peers()) > 0
	})

	// ping to make sure the connection is up.
	res, err := lc2.Ping(ctx, s1ip, tailcfg.PingICMP)
	if err != nil {
		t.Fatalf("pinging: %s", err)
	}
	t.Logf("ping success: %#+v", res)

	mustDirect(t, t.Logf, lc1, lc2)

	// 1 megabytes
	bytesToSend := 1 * 1024 * 1024

	// This asserts generates some traffic, it is factored out
	// of TestUDPConn.
	start := time.Now()
	err = sendData(t.Logf, ctx, bytesToSend, s1, s2, s1ip, s2ip)
	if err != nil {
		t.Fatalf("Failed to send packets: %v", err)
	}
	t.Logf("Sent %d bytes from s1 to s2 in %s", bytesToSend, time.Since(start).String())

	ctxLc, cancelLc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelLc()
	metrics1, err := lc1.UserMetrics(ctxLc)
	if err != nil {
		t.Fatal(err)
	}

	parsedMetrics1, err := parseMetrics(metrics1)
	if err != nil {
		t.Fatal(err)
	}

	// Allow the metrics for the bytes sent to be off by 15%.
	bytesSentTolerance := 1.15

	t.Logf("Metrics1:\n%s\n", metrics1)

	// Verify that the amount of data recorded in bytes is higher or equal to the data sent
	inboundBytes1 := parsedMetrics1[`tailscaled_inbound_bytes_total{path="direct_ipv4"}`]
	if inboundBytes1 < float64(bytesToSend) {
		t.Errorf(`metrics1, tailscaled_inbound_bytes_total{path="direct_ipv4"}: expected higher (or equal) than %d, got: %f`, bytesToSend, inboundBytes1)
	}

	// But ensure that it is not too much higher than the data sent.
	if inboundBytes1 > float64(bytesToSend)*bytesSentTolerance {
		t.Errorf(`metrics1, tailscaled_inbound_bytes_total{path="direct_ipv4"}: expected lower than %f, got: %f`, float64(bytesToSend)*bytesSentTolerance, inboundBytes1)
	}

	metrics2, err := lc2.UserMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}

	parsedMetrics2, err := parseMetrics(metrics2)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Metrics2:\n%s\n", metrics2)

	// Verify that the amount of data recorded in bytes is higher or equal than the data sent.
	outboundBytes2 := parsedMetrics2[`tailscaled_outbound_bytes_total{path="direct_ipv4"}`]
	if outboundBytes2 < float64(bytesToSend) {
		t.Errorf(`metrics2, tailscaled_outbound_bytes_total{path="direct_ipv4"}: expected higher (or equal) than %d, got: %f`, bytesToSend, outboundBytes2)
	}

	// But ensure that it is not too much higher than the data sent.
	if outboundBytes2 > float64(bytesToSend)*bytesSentTolerance {
		t.Errorf(`metrics2, tailscaled_outbound_bytes_total{path="direct_ipv4"}: expected lower than %f, got: %f`, float64(bytesToSend)*bytesSentTolerance, outboundBytes2)
	}
}

func TestUserMetricsRouteGauges(t *testing.T) {
	tstest.Shard(t)
	// Windows does not seem to support or report back routes when running in
	// userspace via tsnet. So, we skip this check on Windows.
	// TODO(kradalby): Figure out if this is correct.
	if runtime.GOOS == "windows" {
		t.Skipf("skipping on windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	controlURL, c := startControl(t)
	s1, _, s1PubKey := startServer(t, ctx, controlURL, "s1")
	defer s1.Close()
	s2, _, _ := startServer(t, ctx, controlURL, "s2")
	defer s2.Close()

	s1.lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.0.2.0/24"),
				netip.MustParsePrefix("192.0.3.0/24"),
				netip.MustParsePrefix("192.0.5.1/32"),
				netip.MustParsePrefix("0.0.0.0/0"),
			},
		},
		AdvertiseRoutesSet: true,
	})
	c.SetSubnetRoutes(s1PubKey, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.0.5.1/32"),
		netip.MustParsePrefix("0.0.0.0/0"),
	})

	lc1, err := s1.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	lc2, err := s2.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	// Force an update to the netmap to ensure that the metrics are up-to-date.
	s1.lb.DebugForceNetmapUpdate()
	s2.lb.DebugForceNetmapUpdate()

	wantRoutes := float64(2)

	// Wait for the routes to be propagated to node 1 to ensure
	// that the metrics are up-to-date.
	waitForCondition(t, "primary routes available for node1", 90*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		status1, err := lc1.Status(ctx)
		if err != nil {
			t.Logf("getting status: %s", err)
			return false
		}
		// Wait for the primary routes to reach our desired routes, which is wantRoutes + 1, because
		// the PrimaryRoutes list will contain a exit node route, which the metric does not count.
		return status1.Self.PrimaryRoutes != nil && status1.Self.PrimaryRoutes.Len() == int(wantRoutes)+1
	})

	ctxLc, cancelLc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelLc()
	metrics1, err := lc1.UserMetrics(ctxLc)
	if err != nil {
		t.Fatal(err)
	}

	parsedMetrics1, err := parseMetrics(metrics1)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Metrics1:\n%s\n", metrics1)

	// The node is advertising 4 routes:
	// - 192.0.2.0/24
	// - 192.0.3.0/24
	// - 192.0.5.1/32
	if got, want := parsedMetrics1["tailscaled_advertised_routes"], 3.0; got != want {
		t.Errorf("metrics1, tailscaled_advertised_routes: got %v, want %v", got, want)
	}

	// The control has approved 2 routes:
	// - 192.0.2.0/24
	// - 192.0.5.1/32
	if got, want := parsedMetrics1["tailscaled_approved_routes"], wantRoutes; got != want {
		t.Errorf("metrics1, tailscaled_approved_routes: got %v, want %v", got, want)
	}

	metrics2, err := lc2.UserMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}

	parsedMetrics2, err := parseMetrics(metrics2)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Metrics2:\n%s\n", metrics2)

	// The node is advertising 0 routes
	if got, want := parsedMetrics2["tailscaled_advertised_routes"], 0.0; got != want {
		t.Errorf("metrics2, tailscaled_advertised_routes: got %v, want %v", got, want)
	}

	// The control has approved 0 routes
	if got, want := parsedMetrics2["tailscaled_approved_routes"], 0.0; got != want {
		t.Errorf("metrics2, tailscaled_approved_routes: got %v, want %v", got, want)
	}
}

func waitForCondition(t *testing.T, msg string, waitTime time.Duration, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(waitTime); time.Now().Before(deadline); time.Sleep(1 * time.Second) {
		if f() {
			return
		}
	}
	t.Fatalf("waiting for condition: %s", msg)
}

// mustDirect ensures there is a direct connection between LocalClient 1 and 2
func mustDirect(t *testing.T, logf logger.Logf, lc1, lc2 *local.Client) {
	t.Helper()
	lastLog := time.Now().Add(-time.Minute)
	// See https://github.com/tailscale/tailscale/issues/654
	// and https://github.com/tailscale/tailscale/issues/3247 for discussions of this deadline.
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		status1, err := lc1.Status(ctx)
		if err != nil {
			continue
		}
		status2, err := lc2.Status(ctx)
		if err != nil {
			continue
		}
		pst := status1.Peer[status2.Self.PublicKey]
		if pst.CurAddr != "" {
			logf("direct link %s->%s found with addr %s", status1.Self.HostName, status2.Self.HostName, pst.CurAddr)
			return
		}
		if now := time.Now(); now.Sub(lastLog) > time.Second {
			logf("no direct path %s->%s yet, addrs %v", status1.Self.HostName, status2.Self.HostName, pst.Addrs)
			lastLog = now
		}
	}
	t.Error("magicsock did not find a direct path from lc1 to lc2")
}

// chanTUN is a tun.Device for testing that uses channels for packet I/O.
// Inbound receives packets written to the TUN (from the perspective of the network stack).
// Outbound is for injecting packets to be read from the TUN.
type chanTUN struct {
	Inbound  chan []byte // packets written to TUN
	Outbound chan []byte // packets to read from TUN
	closed   chan struct{}
	events   chan tun.Event
}

func newChanTUN() *chanTUN {
	t := &chanTUN{
		Inbound:  make(chan []byte, 10),
		Outbound: make(chan []byte, 10),
		closed:   make(chan struct{}),
		events:   make(chan tun.Event, 1),
	}
	t.events <- tun.EventUp
	return t
}

func (t *chanTUN) File() *os.File { panic("not implemented") }

func (t *chanTUN) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
		close(t.Inbound)
	}
	return nil
}

func (t *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, io.EOF
	case pkt := <-t.Outbound:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (t *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}
		select {
		case <-t.closed:
			return 0, errors.New("closed")
		case t.Inbound <- slices.Clone(pkt):
		}
	}
	return len(bufs), nil
}

func (t *chanTUN) MTU() (int, error)        { return 1280, nil }
func (t *chanTUN) Name() (string, error)    { return "chantun", nil }
func (t *chanTUN) Events() <-chan tun.Event { return t.events }
func (t *chanTUN) BatchSize() int           { return 1 }

// listenTest provides common setup for listener and TUN tests.
type listenTest struct {
	control      *testcontrol.Server
	s1, s2       *Server
	s1ip4, s1ip6 netip.Addr
	s2ip4, s2ip6 netip.Addr
	tun          *chanTUN // nil for netstack mode
}

// setupTwoClientTest creates two tsnet servers for testing.
// If useTUN is true, s2 uses a chanTUN; otherwise it uses netstack only.
func setupTwoClientTest(t *testing.T, useTUN bool) *listenTest {
	t.Helper()
	tstest.Shard(t)
	tstest.ResourceCheck(t)
	ctx := t.Context()
	controlURL, control := startControl(t)
	s1, _, _ := startServer(t, ctx, controlURL, "s1")

	tmp := filepath.Join(t.TempDir(), "s2")
	must.Do(os.MkdirAll(tmp, 0755))
	s2 := &Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   "s2",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}

	var tun *chanTUN
	if useTUN {
		tun = newChanTUN()
		s2.Tun = tun
	}

	if *verboseNodes {
		s2.Logf = t.Logf
	}
	t.Cleanup(func() { s2.Close() })

	s2status, err := s2.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s2.lb.ConfigureCertsForTest(testCertRoot.getCert)

	s1ip4, s1ip6 := s1.TailscaleIPs()
	s2ip4 := s2status.TailscaleIPs[0]
	var s2ip6 netip.Addr
	if len(s2status.TailscaleIPs) > 1 {
		s2ip6 = s2status.TailscaleIPs[1]
	}

	lc1 := must.Get(s1.LocalClient())
	must.Get(lc1.Ping(ctx, s2ip4, tailcfg.PingTSMP))

	return &listenTest{
		control: control,
		s1:      s1,
		s2:      s2,
		s1ip4:   s1ip4,
		s1ip6:   s1ip6,
		s2ip4:   s2ip4,
		s2ip6:   s2ip6,
		tun:     tun,
	}
}

// echoUDP returns an IP packet with src/dst and ports swapped, with checksums recomputed.
func echoUDP(pkt []byte) []byte {
	var p packet.Parsed
	p.Decode(pkt)
	if p.IPProto != ipproto.UDP {
		return nil
	}
	switch p.IPVersion {
	case 4:
		h := p.UDP4Header()
		h.ToResponse()
		return packet.Generate(h, p.Payload())
	case 6:
		h := packet.UDP6Header{
			IP6Header: p.IP6Header(),
			SrcPort:   p.Src.Port(),
			DstPort:   p.Dst.Port(),
		}
		h.ToResponse()
		return packet.Generate(h, p.Payload())
	}
	return nil
}

func TestTUN(t *testing.T) {
	tt := setupTwoClientTest(t, true)

	go func() {
		for pkt := range tt.tun.Inbound {
			var p packet.Parsed
			p.Decode(pkt)
			if p.Dst.Port() == 9999 {
				tt.tun.Outbound <- echoUDP(pkt)
			}
		}
	}()

	test := func(t *testing.T, s2ip netip.Addr) {
		conn, err := tt.s1.Dial(t.Context(), "udp", netip.AddrPortFrom(s2ip, 9999).String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		want := "hello from s1"
		if _, err := conn.Write([]byte(want)); err != nil {
			t.Fatal(err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 1024)
		n, err := conn.Read(got)
		if err != nil {
			t.Fatalf("reading echo response: %v", err)
		}
		if string(got[:n]) != want {
			t.Errorf("got %q, want %q", got[:n], want)
		}
	}

	t.Run("IPv4", func(t *testing.T) { test(t, tt.s2ip4) })
	t.Run("IPv6", func(t *testing.T) { test(t, tt.s2ip6) })
}

// TestTUNDNS tests that a TUN can send DNS queries to quad-100 and receive
// responses. This verifies that handleLocalPackets intercepts outbound traffic
// to the service IP.
func TestTUNDNS(t *testing.T) {
	tt := setupTwoClientTest(t, true)

	test := func(t *testing.T, srcIP netip.Addr, serviceIP netip.Addr) {
		tt.tun.Outbound <- buildDNSQuery("s2", srcIP)

		ipVersion := uint8(4)
		if srcIP.Is6() {
			ipVersion = 6
		}
		for {
			select {
			case pkt := <-tt.tun.Inbound:
				var p packet.Parsed
				p.Decode(pkt)
				if p.IPVersion != ipVersion || p.IPProto != ipproto.UDP {
					continue
				}
				if p.Src.Addr() == serviceIP && p.Src.Port() == 53 {
					if len(p.Payload()) < 12 {
						t.Fatalf("DNS response too short: %d bytes", len(p.Payload()))
					}
					return // success
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for DNS response")
			}
		}
	}

	t.Run("IPv4", func(t *testing.T) {
		test(t, tt.s2ip4, netip.MustParseAddr("100.100.100.100"))
	})
	t.Run("IPv6", func(t *testing.T) {
		test(t, tt.s2ip6, netip.MustParseAddr("fd7a:115c:a1e0::53"))
	})
}

// TestListenPacket tests UDP listeners (ListenPacket) in both netstack and TUN modes.
func TestListenPacket(t *testing.T) {
	testListenPacket := func(t *testing.T, lt *listenTest, listenIP netip.Addr) {
		pc, err := lt.s2.ListenPacket("udp", netip.AddrPortFrom(listenIP, 0).String())
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()

		echoErr := make(chan error, 1)
		go func() {
			buf := make([]byte, 1500)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				echoErr <- err
				return
			}
			_, err = pc.WriteTo(buf[:n], addr)
			if err != nil {
				echoErr <- err
				return
			}
		}()

		conn, err := lt.s1.Dial(t.Context(), "udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		want := "hello udp"
		if _, err := conn.Write([]byte(want)); err != nil {
			t.Fatal(err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 1024)
		n, err := conn.Read(got)
		if err != nil {
			select {
			case e := <-echoErr:
				t.Fatalf("echo error: %v; read error: %v", e, err)
			default:
				t.Fatalf("Read failed: %v", err)
			}
		}

		if string(got[:n]) != want {
			t.Errorf("got %q, want %q", got[:n], want)
		}
	}

	t.Run("Netstack", func(t *testing.T) {
		lt := setupTwoClientTest(t, false)
		t.Run("IPv4", func(t *testing.T) { testListenPacket(t, lt, lt.s2ip4) })
		t.Run("IPv6", func(t *testing.T) { testListenPacket(t, lt, lt.s2ip6) })
	})

	t.Run("TUN", func(t *testing.T) {
		lt := setupTwoClientTest(t, true)
		t.Run("IPv4", func(t *testing.T) { testListenPacket(t, lt, lt.s2ip4) })
		t.Run("IPv6", func(t *testing.T) { testListenPacket(t, lt, lt.s2ip6) })
	})
}

// TestListenTCP tests TCP listeners with concrete addresses in both netstack
// and TUN modes.
func TestListenTCP(t *testing.T) {
	testListenTCP := func(t *testing.T, lt *listenTest, listenIP netip.Addr) {
		ln, err := lt.s2.Listen("tcp", netip.AddrPortFrom(listenIP, 0).String())
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		echoErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				echoErr <- err
				return
			}
			defer conn.Close()
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				echoErr <- err
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				echoErr <- err
				return
			}
		}()

		conn, err := lt.s1.Dial(t.Context(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		want := "hello tcp"
		if _, err := conn.Write([]byte(want)); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 1024)
		n, err := conn.Read(got)
		if err != nil {
			select {
			case e := <-echoErr:
				t.Fatalf("echo error: %v; read error: %v", e, err)
			default:
				t.Fatalf("Read failed: %v", err)
			}
		}

		if string(got[:n]) != want {
			t.Errorf("got %q, want %q", got[:n], want)
		}
	}

	t.Run("Netstack", func(t *testing.T) {
		lt := setupTwoClientTest(t, false)
		t.Run("IPv4", func(t *testing.T) { testListenTCP(t, lt, lt.s2ip4) })
		t.Run("IPv6", func(t *testing.T) { testListenTCP(t, lt, lt.s2ip6) })
	})

	t.Run("TUN", func(t *testing.T) {
		lt := setupTwoClientTest(t, true)
		t.Run("IPv4", func(t *testing.T) { testListenTCP(t, lt, lt.s2ip4) })
		t.Run("IPv6", func(t *testing.T) { testListenTCP(t, lt, lt.s2ip6) })
	})
}

// TestListenTCPDualStack tests TCP listeners with wildcard addresses (dual-stack)
// in both netstack and TUN modes.
func TestListenTCPDualStack(t *testing.T) {
	testListenTCPDualStack := func(t *testing.T, lt *listenTest, dialIP netip.Addr) {
		ln, err := lt.s2.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		_, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("parsing listener address %q: %v", ln.Addr().String(), err)
		}

		echoErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				echoErr <- err
				return
			}
			defer conn.Close()
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				echoErr <- err
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				echoErr <- err
				return
			}
		}()

		dialAddr := net.JoinHostPort(dialIP.String(), portStr)
		conn, err := lt.s1.Dial(t.Context(), "tcp", dialAddr)
		if err != nil {
			t.Fatalf("Dial(%q) failed: %v", dialAddr, err)
		}
		defer conn.Close()

		want := "hello tcp dualstack"
		if _, err := conn.Write([]byte(want)); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 1024)
		n, err := conn.Read(got)
		if err != nil {
			select {
			case e := <-echoErr:
				t.Fatalf("echo error: %v; read error: %v", e, err)
			default:
				t.Fatalf("Read failed: %v", err)
			}
		}

		if string(got[:n]) != want {
			t.Errorf("got %q, want %q", got[:n], want)
		}
	}

	t.Run("Netstack", func(t *testing.T) {
		lt := setupTwoClientTest(t, false)
		t.Run("DialIPv4", func(t *testing.T) { testListenTCPDualStack(t, lt, lt.s2ip4) })
		t.Run("DialIPv6", func(t *testing.T) { testListenTCPDualStack(t, lt, lt.s2ip6) })
	})

	t.Run("TUN", func(t *testing.T) {
		lt := setupTwoClientTest(t, true)
		t.Run("DialIPv4", func(t *testing.T) { testListenTCPDualStack(t, lt, lt.s2ip4) })
		t.Run("DialIPv6", func(t *testing.T) { testListenTCPDualStack(t, lt, lt.s2ip6) })
	})
}

// TestDialTCP tests TCP dialing from s2 to s1 in both netstack and TUN modes.
// In TUN mode, this verifies that outbound TCP connections and their replies
// are handled by netstack without packets escaping to the TUN.
func TestDialTCP(t *testing.T) {
	testDialTCP := func(t *testing.T, lt *listenTest, listenIP netip.Addr) {
		ln, err := lt.s1.Listen("tcp", netip.AddrPortFrom(listenIP, 0).String())
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		echoErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				echoErr <- err
				return
			}
			defer conn.Close()
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				echoErr <- err
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				echoErr <- err
				return
			}
		}()

		conn, err := lt.s2.Dial(t.Context(), "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		want := "hello tcp dial"
		if _, err := conn.Write([]byte(want)); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 1024)
		n, err := conn.Read(got)
		if err != nil {
			select {
			case e := <-echoErr:
				t.Fatalf("echo error: %v; read error: %v", e, err)
			default:
				t.Fatalf("Read failed: %v", err)
			}
		}

		if string(got[:n]) != want {
			t.Errorf("got %q, want %q", got[:n], want)
		}
	}

	t.Run("Netstack", func(t *testing.T) {
		lt := setupTwoClientTest(t, false)
		t.Run("IPv4", func(t *testing.T) { testDialTCP(t, lt, lt.s1ip4) })
		t.Run("IPv6", func(t *testing.T) { testDialTCP(t, lt, lt.s1ip6) })
	})

	t.Run("TUN", func(t *testing.T) {
		lt := setupTwoClientTest(t, true)

		var escapedTCPPackets atomic.Int32
		var wg sync.WaitGroup
		wg.Go(func() {
			for pkt := range lt.tun.Inbound {
				var p packet.Parsed
				p.Decode(pkt)
				if p.IPProto == ipproto.TCP {
					escapedTCPPackets.Add(1)
					t.Logf("TCP packet escaped to TUN: %v -> %v", p.Src, p.Dst)
				}
			}
		})

		t.Run("IPv4", func(t *testing.T) { testDialTCP(t, lt, lt.s1ip4) })
		t.Run("IPv6", func(t *testing.T) { testDialTCP(t, lt, lt.s1ip6) })

		lt.tun.Close()
		wg.Wait()
		if escaped := escapedTCPPackets.Load(); escaped > 0 {
			t.Errorf("%d TCP packets escaped to TUN", escaped)
		}
	})
}

// TestDialUDP tests UDP dialing from s2 to s1 in both netstack and TUN modes.
// In TUN mode, this verifies that outbound UDP connections register endpoints
// with gVisor, allowing reply packets to be routed through netstack instead of
// escaping to the TUN.
func TestDialUDP(t *testing.T) {
	testDialUDP := func(t *testing.T, lt *listenTest, listenIP netip.Addr) {
		pc, err := lt.s1.ListenPacket("udp", netip.AddrPortFrom(listenIP, 0).String())
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()

		echoErr := make(chan error, 1)
		go func() {
			buf := make([]byte, 1500)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				echoErr <- err
				return
			}
			_, err = pc.WriteTo(buf[:n], addr)
			if err != nil {
				echoErr <- err
				return
			}
		}()

		conn, err := lt.s2.Dial(t.Context(), "udp", pc.LocalAddr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		want := "hello udp dial"
		if _, err := conn.Write([]byte(want)); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 1024)
		n, err := conn.Read(got)
		if err != nil {
			select {
			case e := <-echoErr:
				t.Fatalf("echo error: %v; read error: %v", e, err)
			default:
				t.Fatalf("Read failed: %v", err)
			}
		}

		if string(got[:n]) != want {
			t.Errorf("got %q, want %q", got[:n], want)
		}
	}

	t.Run("Netstack", func(t *testing.T) {
		lt := setupTwoClientTest(t, false)
		t.Run("IPv4", func(t *testing.T) { testDialUDP(t, lt, lt.s1ip4) })
		t.Run("IPv6", func(t *testing.T) { testDialUDP(t, lt, lt.s1ip6) })
	})

	t.Run("TUN", func(t *testing.T) {
		lt := setupTwoClientTest(t, true)

		var escapedUDPPackets atomic.Int32
		var wg sync.WaitGroup
		wg.Go(func() {
			for pkt := range lt.tun.Inbound {
				var p packet.Parsed
				p.Decode(pkt)
				if p.IPProto == ipproto.UDP {
					escapedUDPPackets.Add(1)
					t.Logf("UDP packet escaped to TUN: %v -> %v", p.Src, p.Dst)
				}
			}
		})

		t.Run("IPv4", func(t *testing.T) { testDialUDP(t, lt, lt.s1ip4) })
		t.Run("IPv6", func(t *testing.T) { testDialUDP(t, lt, lt.s1ip6) })

		lt.tun.Close()
		wg.Wait()
		if escaped := escapedUDPPackets.Load(); escaped > 0 {
			t.Errorf("%d UDP packets escaped to TUN", escaped)
		}
	})
}

// buildDNSQuery builds a UDP/IP packet containing a DNS query for name to the
// Tailscale service IP (100.100.100.100 for IPv4, fd7a:115c:a1e0::53 for IPv6).
func buildDNSQuery(name string, srcIP netip.Addr) []byte {
	qtype := byte(0x01) // Type A for IPv4
	if srcIP.Is6() {
		qtype = 0x1c // Type AAAA for IPv6
	}
	dns := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: standard query, recursion desired
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT, ARCOUNT
	}
	for _, label := range strings.Split(name, ".") {
		dns = append(dns, byte(len(label)))
		dns = append(dns, label...)
	}
	dns = append(dns, 0x00, 0x00, qtype, 0x00, 0x01) // null, Type A/AAAA, Class IN

	if srcIP.Is4() {
		h := packet.UDP4Header{
			IP4Header: packet.IP4Header{
				Src: srcIP,
				Dst: netip.MustParseAddr("100.100.100.100"),
			},
			SrcPort: 12345,
			DstPort: 53,
		}
		return packet.Generate(h, dns)
	}
	h := packet.UDP6Header{
		IP6Header: packet.IP6Header{
			Src: srcIP,
			Dst: netip.MustParseAddr("fd7a:115c:a1e0::53"),
		},
		SrcPort: 12345,
		DstPort: 53,
	}
	return packet.Generate(h, dns)
}

func TestDeps(t *testing.T) {
	tstest.Shard(t)
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		OnDep: func(dep string) {
			if strings.Contains(dep, "portlist") {
				t.Errorf("unexpected dep: %q", dep)
			}
		},
	}.Check(t)
}

func TestResolveAuthKey(t *testing.T) {
	tests := []struct {
		name            string
		authKey         string
		clientSecret    string
		clientID        string
		idToken         string
		audience        string
		oauthAvailable  bool
		wifAvailable    bool
		resolveViaOAuth func(ctx context.Context, clientSecret string, tags []string) (string, error)
		resolveViaWIF   func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error)
		wantAuthKey     string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:           "successful resolution via OAuth client secret",
			clientSecret:   "tskey-client-secret-123",
			oauthAvailable: true,
			resolveViaOAuth: func(ctx context.Context, clientSecret string, tags []string) (string, error) {
				if clientSecret != "tskey-client-secret-123" {
					return "", fmt.Errorf("unexpected client secret: %s", clientSecret)
				}
				return "tskey-auth-via-oauth", nil
			},
			wantAuthKey:     "tskey-auth-via-oauth",
			wantErrContains: "",
		},
		{
			name:           "failing resolution via OAuth client secret",
			clientSecret:   "tskey-client-secret-123",
			oauthAvailable: true,
			resolveViaOAuth: func(ctx context.Context, clientSecret string, tags []string) (string, error) {
				return "", fmt.Errorf("resolution failed")
			},
			wantErrContains: "resolution failed",
		},
		{
			name:         "successful resolution via federated ID token",
			clientID:     "client-id-123",
			idToken:      "id-token-456",
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				if clientID != "client-id-123" {
					return "", fmt.Errorf("unexpected client ID: %s", clientID)
				}
				if idToken != "id-token-456" {
					return "", fmt.Errorf("unexpected ID token: %s", idToken)
				}
				return "tskey-auth-via-wif", nil
			},
			wantAuthKey:     "tskey-auth-via-wif",
			wantErrContains: "",
		},
		{
			name:         "successful resolution via federated audience",
			clientID:     "client-id-123",
			audience:     "api.tailscale.com",
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				if clientID != "client-id-123" {
					return "", fmt.Errorf("unexpected client ID: %s", clientID)
				}
				if audience != "api.tailscale.com" {
					return "", fmt.Errorf("unexpected ID token: %s", idToken)
				}
				return "tskey-auth-via-wif", nil
			},
			wantAuthKey:     "tskey-auth-via-wif",
			wantErrContains: "",
		},
		{
			name:         "failing resolution via federated ID token",
			clientID:     "client-id-123",
			idToken:      "id-token-456",
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				return "", fmt.Errorf("resolution failed")
			},
			wantErrContains: "resolution failed",
		},
		{
			name:         "empty client ID with ID token",
			clientID:     "",
			idToken:      "id-token-456",
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				return "", fmt.Errorf("should not be called")
			},
			wantErrContains: "empty",
		},
		{
			name:         "empty client ID with audience",
			clientID:     "",
			audience:     "api.tailscale.com",
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				return "", fmt.Errorf("should not be called")
			},
			wantErrContains: "empty",
		},
		{
			name:         "empty ID token",
			clientID:     "client-id-123",
			idToken:      "",
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				return "", fmt.Errorf("should not be called")
			},
			wantErrContains: "empty",
		},
		{
			name:         "audience with ID token",
			clientID:     "client-id-123",
			idToken:      "id-token-456",
			audience:     "api.tailscale.com",
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				return "", fmt.Errorf("should not be called")
			},
			wantErrContains: "only one of ID token and audience",
		},
		{
			name:           "workload identity resolution skipped if resolution via OAuth token succeeds",
			clientSecret:   "tskey-client-secret-123",
			oauthAvailable: true,
			resolveViaOAuth: func(ctx context.Context, clientSecret string, tags []string) (string, error) {
				if clientSecret != "tskey-client-secret-123" {
					return "", fmt.Errorf("unexpected client secret: %s", clientSecret)
				}
				return "tskey-auth-via-oauth", nil
			},
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				return "", fmt.Errorf("should not be called")
			},
			wantAuthKey:     "tskey-auth-via-oauth",
			wantErrContains: "",
		},
		{
			name:           "workload identity resolution skipped if resolution via OAuth token fails",
			clientID:       "tskey-client-id-123",
			idToken:        "",
			oauthAvailable: true,
			resolveViaOAuth: func(ctx context.Context, clientSecret string, tags []string) (string, error) {
				return "", fmt.Errorf("resolution failed")
			},
			wifAvailable: true,
			resolveViaWIF: func(ctx context.Context, baseURL, clientID, idToken, audience string, tags []string) (string, error) {
				return "", fmt.Errorf("should not be called")
			},
			wantErrContains: "failed",
		},
		{
			name:            "authkey set and no resolution available",
			authKey:         "tskey-auth-123",
			oauthAvailable:  false,
			wifAvailable:    false,
			wantAuthKey:     "tskey-auth-123",
			wantErrContains: "",
		},
		{
			name:            "no authkey set and no resolution available",
			oauthAvailable:  false,
			wifAvailable:    false,
			wantAuthKey:     "",
			wantErrContains: "",
		},
		{
			name:           "authkey is client secret and resolution via OAuth client secret succeeds",
			authKey:        "tskey-client-secret-123",
			oauthAvailable: true,
			resolveViaOAuth: func(ctx context.Context, clientSecret string, tags []string) (string, error) {
				if clientSecret != "tskey-client-secret-123" {
					return "", fmt.Errorf("unexpected client secret: %s", clientSecret)
				}
				return "tskey-auth-via-oauth", nil
			},
			wantAuthKey:     "tskey-auth-via-oauth",
			wantErrContains: "",
		},
		{
			name:           "authkey is client secret but resolution via OAuth client secret fails",
			authKey:        "tskey-client-secret-123",
			oauthAvailable: true,
			resolveViaOAuth: func(ctx context.Context, clientSecret string, tags []string) (string, error) {
				return "", fmt.Errorf("resolution failed")
			},
			wantErrContains: "resolution failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.oauthAvailable {
				t.Cleanup(tailscale.HookResolveAuthKey.SetForTest(tt.resolveViaOAuth))
			}

			if tt.wifAvailable {
				t.Cleanup(tailscale.HookResolveAuthKeyViaWIF.SetForTest(tt.resolveViaWIF))
			}

			s := &Server{
				AuthKey:      tt.authKey,
				ClientSecret: tt.clientSecret,
				ClientID:     tt.clientID,
				IDToken:      tt.idToken,
				Audience:     tt.audience,
				ControlURL:   "https://control.example.com",
			}
			s.shutdownCtx = context.Background()

			gotAuthKey, err := s.resolveAuthKey()

			if tt.wantErrContains != "" {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("expected error containing %q but got error: %v", tt.wantErrContains, err)
				}
				return
			}

			if err != nil {
				t.Errorf("resolveAuthKey expected no error but got error: %v", err)
				return
			}

			if gotAuthKey != tt.wantAuthKey {
				t.Errorf("resolveAuthKey() = %q, want %q", gotAuthKey, tt.wantAuthKey)
			}
		})
	}
}

// TestSelfDial verifies that a single tsnet.Server can Dial its own Listen
// address. This is a regression test for a bug where self-addressed TCP SYN
// packets were sent to WireGuard (which has no peer for the node's own IP)
// and silently dropped, causing Dial to hang indefinitely.
func TestSelfDial(t *testing.T) {
	tstest.Shard(t)
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, _ := startControl(t)
	s1, s1ip, _ := startServer(t, ctx, controlURL, "s1")

	ln, err := s1.Listen("tcp", ":8081")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	connc := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		connc <- c
	}()

	// Self-dial: the same server dials its own Tailscale IP.
	w, err := s1.Dial(ctx, "tcp", fmt.Sprintf("%s:8081", s1ip))
	if err != nil {
		t.Fatalf("self-dial failed: %v", err)
	}
	defer w.Close()

	var accepted net.Conn
	select {
	case accepted = <-connc:
	case err := <-errc:
		t.Fatalf("accept failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for accept")
	}
	defer accepted.Close()

	// Verify bidirectional data exchange.
	want := "hello self"
	if _, err := io.WriteString(w, want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(accepted, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("client->server: got %q, want %q", got, want)
	}

	reply := "hello back"
	if _, err := io.WriteString(accepted, reply); err != nil {
		t.Fatal(err)
	}
	gotReply := make([]byte, len(reply))
	if _, err := io.ReadFull(w, gotReply); err != nil {
		t.Fatal(err)
	}
	if string(gotReply) != reply {
		t.Errorf("server->client: got %q, want %q", gotReply, reply)
	}
}
