// Copyright (c) Tailscale Inc & AUTHORS
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"golang.org/x/net/proxy"
	"tailscale.com/client/tailscale"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
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
	certs map[string]*tls.Certificate

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
		certs:   make(map[string]*tls.Certificate),
		root:    rootCA,
		rootKey: rootKey,
	}
}

func (tci *testCertIssuer) getCert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	tci.mu.Lock()
	defer tci.mu.Unlock()
	cert, ok := tci.certs[chi.ServerName]
	if ok {
		return cert, nil
	}

	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{chi.ServerName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, tci.root, &certPrivKey.PublicKey, tci.rootKey)
	if err != nil {
		return nil, err
	}
	cert = &tls.Certificate{
		Certificate: [][]byte{certDER, tci.root.Raw},
		PrivateKey:  certPrivKey,
	}
	tci.certs[chi.ServerName] = cert
	return cert, nil
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
		Dir:               tmp,
		ControlURL:        controlURL,
		Hostname:          hostname,
		Store:             new(mem.Store),
		Ephemeral:         true,
		getCertForTesting: testCertRoot.getCert,
	}
	if *verboseNodes {
		s.Logf = log.Printf
	}
	t.Cleanup(func() { s.Close() })

	status, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s, status.TailscaleIPs[0], status.Self.PublicKey
}

func TestConn(t *testing.T) {
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	controlURL, c := startControl(t)
	s1, s1ip, s1PubKey := startServer(t, ctx, controlURL, "s1")
	s2, _, _ := startServer(t, ctx, controlURL, "s2")

	s1.lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		},
		AdvertiseRoutesSet: true,
	})
	c.SetSubnetRoutes(s1PubKey, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})

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

	// pass some data through TCP.
	ln, err := s1.Listen("tcp", ":8081")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	w, err := s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8081", s1ip))
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

	_, err = s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8082", s1ip)) // some random port
	if err == nil {
		t.Fatalf("unexpected success; should have seen a connection refused error")
	}

	// s1 is a subnet router for TEST-NET-1 (192.0.2.0/24). Lets dial to that
	// subnet from s2 to ensure a listener without an IP address (i.e. ":8081")
	// only matches destination IPs corresponding to the node's IP, and not
	// to any random IP a subnet is routing.
	_, err = s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8081", "192.0.2.1"))
	if err == nil {
		t.Fatalf("unexpected success; should have seen a connection refused error")
	}
}

func TestLoopbackLocalAPI(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/8557")
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
}

// tests https://github.com/tailscale/tailscale/issues/6973 -- that we can start a tsnet server,
// stop it, and restart it, even on Windows.
func TestStartStopStartGetsSameIP(t *testing.T) {
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
	for i, l := range labels {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf("%s=%q", l.GetName(), l.GetValue()))
	}
	b.WriteString("}")
	return b.String()
}

// sendData sends a given amount of bytes from s1 to s2.
func sendData(logf func(format string, args ...any), ctx context.Context, bytesCount int, s1, s2 *Server, s1ip, s2ip netip.Addr) error {
	l := must.Get(s1.Listen("tcp", fmt.Sprintf("%s:8081", s1ip)))
	defer l.Close()

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
		conn, err := l.Accept()
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
func mustDirect(t *testing.T, logf logger.Logf, lc1, lc2 *tailscale.LocalClient) {
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
