// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"bufio"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/proxy"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/health"
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
			Logf:       logger.TestLogger(t),
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

func TestUserMetrics(t *testing.T) {
	tstest.ResourceCheck(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// testWarnable is a Warnable that is used within this package for testing purposes only.
	var testWarnable = health.Register(&health.Warnable{
		Code:     "test-warnable-tsnet",
		Title:    "Test warnable",
		Severity: health.SeverityLow,
		Text: func(args health.Args) string {
			return args[health.ArgError]
		},
	})

	controlURL, c := startControl(t)
	s1, _, s1PubKey := startServer(t, ctx, controlURL, "s1")

	s1.lb.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.0.2.0/24"),
				netip.MustParsePrefix("192.0.3.0/24"),
			},
		},
		AdvertiseRoutesSet: true,
	})
	c.SetSubnetRoutes(s1PubKey, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})

	lc1, err := s1.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	ht := s1.lb.HealthTracker()
	ht.SetUnhealthy(testWarnable, health.Args{"Text": "Hello world 1"})

	metrics1, err := lc1.UserMetrics(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Note that this test will check for two warnings because the health
	// tracker will have two warnings: one from the testWarnable, added in
	// this test, and one because we are running the dev/unstable version
	// of tailscale.
	want := `# TYPE tailscaled_advertised_routes gauge
# HELP tailscaled_advertised_routes Number of advertised network routes (e.g. by a subnet router)
tailscaled_advertised_routes 2
# TYPE tailscaled_health_messages gauge
# HELP tailscaled_health_messages Number of health messages broken down by type.
tailscaled_health_messages{type="warning"} 2
# TYPE tailscaled_inbound_dropped_packets_total counter
# HELP tailscaled_inbound_dropped_packets_total Counts the number of dropped packets received by the node from other peers
# TYPE tailscaled_outbound_dropped_packets_total counter
# HELP tailscaled_outbound_dropped_packets_total Counts the number of packets dropped while being sent to other peers
`

	if diff := cmp.Diff(want, string(metrics1)); diff != "" {
		t.Fatalf("unexpected metrics (-want +got):\n%s", diff)
	}
}
