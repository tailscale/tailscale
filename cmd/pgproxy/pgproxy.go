// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The pgproxy server is a proxy for the Postgres wire protocol.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/metrics"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
	"tailscale.com/types/logger"
)

var (
	hostname     = flag.String("hostname", "", "Tailscale hostname to serve on")
	port         = flag.Int("port", 5432, "Listening port for client connections")
	debugPort    = flag.Int("debug-port", 80, "Listening port for debug/metrics endpoint")
	upstreamAddr = flag.String("upstream-addr", "", "Address of the upstream Postgres server, in host:port format")
	upstreamCA   = flag.String("upstream-ca-file", "", "File containing the PEM-encoded CA certificate for the upstream server")
	tailscaleDir = flag.String("state-dir", "", "Directory in which to store the Tailscale auth state")
)

func main() {
	flag.Parse()
	if *hostname == "" {
		log.Fatal("missing --hostname")
	}
	if *upstreamAddr == "" {
		log.Fatal("missing --upstream-addr")
	}
	if *upstreamCA == "" {
		log.Fatal("missing --upstream-ca-file")
	}
	if *tailscaleDir == "" {
		log.Fatal("missing --state-dir")
	}

	ts := &tsnet.Server{
		Dir:      *tailscaleDir,
		Hostname: *hostname,
		// Make the stdout logs a clean audit log of connections.
		Logf: logger.Discard,
	}

	if os.Getenv("TS_AUTHKEY") == "" {
		log.Print("Note: you need to run this with TS_AUTHKEY=... the first time, to join your tailnet of choice.")
	}

	tsclient, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("getting tsnet API client: %v", err)
	}

	p, err := newProxy(*upstreamAddr, *upstreamCA, tsclient)
	if err != nil {
		log.Fatal(err)
	}
	expvar.Publish("pgproxy", p.Expvar())

	if *debugPort != 0 {
		mux := http.NewServeMux()
		tsweb.Debugger(mux)
		srv := &http.Server{
			Handler: mux,
		}
		dln, err := ts.Listen("tcp", fmt.Sprintf(":%d", *debugPort))
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			log.Fatal(srv.Serve(dln))
		}()
	}

	ln, err := ts.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving access to %s on port %d", *upstreamAddr, *port)
	log.Fatal(p.Serve(ln))
}

// proxy is a postgres wire protocol proxy, which strictly enforces
// the security of the TLS connection to its upstream regardless of
// what the client's TLS configuration is.
type proxy struct {
	upstreamAddr     string // "my.database.com:5432"
	upstreamHost     string // "my.database.com"
	upstreamCertPool *x509.CertPool
	downstreamCert   []tls.Certificate
	client           *tailscale.LocalClient

	activeSessions  expvar.Int
	startedSessions expvar.Int
	errors          metrics.LabelMap
}

// newProxy returns a proxy that forwards connections to
// upstreamAddr. The upstream's TLS session is verified using the CA
// cert(s) in upstreamCAPath.
func newProxy(upstreamAddr, upstreamCAPath string, client *tailscale.LocalClient) (*proxy, error) {
	bs, err := os.ReadFile(upstreamCAPath)
	if err != nil {
		return nil, err
	}
	upstreamCertPool := x509.NewCertPool()
	if !upstreamCertPool.AppendCertsFromPEM(bs) {
		return nil, fmt.Errorf("invalid CA cert in %q", upstreamCAPath)
	}

	h, _, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		return nil, err
	}
	downstreamCert, err := mkSelfSigned(h)
	if err != nil {
		return nil, err
	}

	return &proxy{
		upstreamAddr:     upstreamAddr,
		upstreamHost:     h,
		upstreamCertPool: upstreamCertPool,
		downstreamCert:   []tls.Certificate{downstreamCert},
		client:           client,
		errors:           metrics.LabelMap{Label: "kind"},
	}, nil
}

// Expvar returns p's monitoring metrics.
func (p *proxy) Expvar() expvar.Var {
	ret := &metrics.Set{}
	ret.Set("sessions_active", &p.activeSessions)
	ret.Set("sessions_started", &p.startedSessions)
	ret.Set("session_errors", &p.errors)
	return ret
}

// Serve accepts postgres client connections on ln and proxies them to
// the configured upstream. ln can be any net.Listener, but all client
// connections must originate from tailscale IPs that can be verified
// with WhoIs.
func (p *proxy) Serve(ln net.Listener) error {
	var lastSessionID int64
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		id := time.Now().UnixNano()
		if id == lastSessionID {
			// Bluntly enforce SID uniqueness, even if collisions are
			// fantastically unlikely (but OSes vary in how much timer
			// precision they expose to the OS, so id might be rounded
			// e.g. to the same millisecond)
			id++
		}
		lastSessionID = id
		go func(sessionID int64) {
			if err := p.serve(sessionID, c); err != nil {
				log.Printf("%d: session ended with error: %v", sessionID, err)
			}
		}(id)
	}
}

var (
	// sslStart is the magic bytes that postgres clients use to indicate
	// that they want to do a TLS handshake. Servers should respond with
	// the single byte "S" before starting a normal TLS handshake.
	sslStart = [8]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	// plaintextStart is the magic bytes that postgres clients use to
	// indicate that they're starting a plaintext authentication
	// handshake.
	plaintextStart = [8]byte{0, 0, 0, 86, 0, 3, 0, 0}
)

// serve proxies the postgres client on c to the proxy's upstream,
// enforcing strict TLS to the upstream.
func (p *proxy) serve(sessionID int64, c net.Conn) error {
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	whois, err := p.client.WhoIs(ctx, c.RemoteAddr().String())
	if err != nil {
		p.errors.Add("whois-failed", 1)
		return fmt.Errorf("getting client identity: %v", err)
	}

	// Before anything else, log the connection attempt.
	user, machine := "", ""
	if whois.Node != nil {
		if whois.Node.Hostinfo.ShareeNode() {
			machine = "external-device"
		} else {
			machine = strings.TrimSuffix(whois.Node.Name, ".")
		}
	}
	if whois.UserProfile != nil {
		user = whois.UserProfile.LoginName
		if user == "tagged-devices" && whois.Node != nil {
			user = strings.Join(whois.Node.Tags, ",")
		}
	}
	if user == "" || machine == "" {
		p.errors.Add("no-ts-identity", 1)
		return fmt.Errorf("couldn't identify source user and machine (user %q, machine %q)", user, machine)
	}
	log.Printf("%d: session start, from %s (machine %s, user %s)", sessionID, c.RemoteAddr(), machine, user)
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		log.Printf("%d: session end, from %s (machine %s, user %s), lasted %s", sessionID, c.RemoteAddr(), machine, user, elapsed.Round(time.Millisecond))
	}()

	// Read the client's opening message, to figure out if it's trying
	// to TLS or not.
	var buf [8]byte
	if _, err := io.ReadFull(c, buf[:len(sslStart)]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("initial magic read: %v", err)
	}
	var clientIsTLS bool
	switch {
	case buf == sslStart:
		clientIsTLS = true
	case buf == plaintextStart:
		clientIsTLS = false
	default:
		p.errors.Add("client-bad-protocol", 1)
		return fmt.Errorf("unrecognized initial packet = % 02x", buf)
	}

	// Dial & verify upstream connection.
	var d net.Dialer
	d.Timeout = 10 * time.Second
	upc, err := d.Dial("tcp", p.upstreamAddr)
	if err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("upstream dial: %v", err)
	}
	defer upc.Close()
	if _, err := upc.Write(sslStart[:]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("upstream write of start-ssl magic: %v", err)
	}
	if _, err := io.ReadFull(upc, buf[:1]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("reading upstream start-ssl response: %v", err)
	}
	if buf[0] != 'S' {
		p.errors.Add("upstream-bad-protocol", 1)
		return fmt.Errorf("upstream didn't acknowldge start-ssl, said %q", buf[0])
	}
	tlsConf := &tls.Config{
		ServerName: p.upstreamHost,
		RootCAs:    p.upstreamCertPool,
		MinVersion: tls.VersionTLS12,
	}
	uptc := tls.Client(upc, tlsConf)
	if err = uptc.HandshakeContext(ctx); err != nil {
		p.errors.Add("upstream-tls", 1)
		return fmt.Errorf("upstream TLS handshake: %v", err)
	}

	// Accept the client conn and set it up the way the client wants.
	var clientConn net.Conn
	if clientIsTLS {
		io.WriteString(c, "S") // yeah, we're good to speak TLS
		s := tls.Server(c, &tls.Config{
			ServerName:   p.upstreamHost,
			Certificates: p.downstreamCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err = uptc.HandshakeContext(ctx); err != nil {
			p.errors.Add("client-tls", 1)
			return fmt.Errorf("client TLS handshake: %v", err)
		}
		clientConn = s
	} else {
		// Repeat the header we read earlier up to the server.
		if _, err := uptc.Write(plaintextStart[:]); err != nil {
			p.errors.Add("network-error", 1)
			return fmt.Errorf("sending initial client bytes to upstream: %v", err)
		}
		clientConn = c
	}

	// Finally, proxy the client to the upstream.
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(uptc, clientConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, uptc)
		errc <- err
	}()
	if err := <-errc; err != nil {
		// Don't increment error counts here, because the most common
		// cause of termination is client or server closing the
		// connection normally, and it'll obscure "interesting"
		// handshake errors.
		return fmt.Errorf("session terminated with error: %v", err)
	}
	return nil
}

// mkSelfSigned creates and returns a self-signed TLS certificate for
// hostname.
func mkSelfSigned(hostname string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	pub := priv.Public()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"pgproxy"},
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(crand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        cert,
	}, nil
}
