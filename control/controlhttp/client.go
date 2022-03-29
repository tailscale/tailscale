// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js
// +build !js

// Package controlhttp implements the Tailscale 2021 control protocol
// base transport over HTTP.
//
// This tunnels the protocol in control/controlbase over HTTP with a
// variety of compatibility fallbacks for handling picky or deep
// inspecting proxies.
//
// In the happy path, a client makes a single cleartext HTTP request
// to the server, the server responds with 101 Switching Protocols,
// and the control base protocol takes place over plain TCP.
//
// In the compatibility path, the client does the above over HTTPS,
// resulting in double encryption (once for the control transport, and
// once for the outer TLS layer).
package controlhttp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/types/key"
)

// Dial connects to the HTTP server at host:httpPort, requests to switch to the
// Tailscale control protocol, and returns an established control
// protocol connection.
//
// If Dial fails to connect using addr, it also tries to tunnel over
// TLS to host:httpsPort as a compatibility fallback.
//
// The provided ctx is only used for the initial connection, until
// Dial returns. It does not affect the connection once established.
func Dial(ctx context.Context, host string, httpPort string, httpsPort string, machineKey key.MachinePrivate, controlKey key.MachinePublic, protocolVersion uint16, dialer dnscache.DialContextFunc) (*controlbase.Conn, error) {
	a := &dialParams{
		host:       host,
		httpPort:   httpPort,
		httpsPort:  httpsPort,
		machineKey: machineKey,
		controlKey: controlKey,
		version:    protocolVersion,
		proxyFunc:  tshttpproxy.ProxyFromEnvironment,
		dialer:     dialer,
	}
	return a.dial(ctx)
}

type dialParams struct {
	host       string
	httpPort   string
	httpsPort  string
	machineKey key.MachinePrivate
	controlKey key.MachinePublic
	version    uint16
	proxyFunc  func(*http.Request) (*url.URL, error) // or nil
	dialer     dnscache.DialContextFunc

	// For tests only
	insecureTLS       bool
	testFallbackDelay time.Duration
}

// httpsFallbackDelay is how long we'll wait for a.httpPort to work before
// starting to try a.httpsPort.
func (a *dialParams) httpsFallbackDelay() time.Duration {
	if v := a.testFallbackDelay; v != 0 {
		return v
	}
	return 500 * time.Millisecond
}

func (a *dialParams) dial(ctx context.Context) (*controlbase.Conn, error) {
	// Create one shared context used by both port 80 and port 443 dials.
	// If port 80 is still in flight when 443 returns, this deferred cancel
	// will stop the port 80 dial.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// u80 and u443 are the URLs we'll try to hit over HTTP or HTTPS,
	// respectively, in order to do the HTTP upgrade to a net.Conn over which
	// we'll speak Noise.
	u80 := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(a.host, a.httpPort),
		Path:   serverUpgradePath,
	}
	u443 := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(a.host, a.httpsPort),
		Path:   serverUpgradePath,
	}

	type tryURLRes struct {
		u    *url.URL          // input (the URL conn+err are for/from)
		conn *controlbase.Conn // result (mutually exclusive with err)
		err  error
	}
	ch := make(chan tryURLRes) // must be unbuffered
	try := func(u *url.URL) {
		cbConn, err := a.dialURL(ctx, u)
		select {
		case ch <- tryURLRes{u, cbConn, err}:
		case <-ctx.Done():
			if cbConn != nil {
				cbConn.Close()
			}
		}
	}

	// Start the plaintext HTTP attempt first.
	go try(u80)

	// In case outbound port 80 blocked or MITM'ed poorly, start a backup timer
	// to dial port 443 if port 80 doesn't either succeed or fail quickly.
	try443Timer := time.AfterFunc(a.httpsFallbackDelay(), func() { try(u443) })
	defer try443Timer.Stop()

	var err80, err443 error
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("connection attempts aborted by context: %w", ctx.Err())
		case res := <-ch:
			if res.err == nil {
				return res.conn, nil
			}
			switch res.u {
			case u80:
				// Connecting over plain HTTP failed; assume it's an HTTP proxy
				// being difficult and see if we can get through over HTTPS.
				err80 = res.err
				// Stop the fallback timer and run it immediately. We don't use
				// Timer.Reset(0) here because on AfterFuncs, that can run it
				// again.
				if try443Timer.Stop() {
					go try(u443)
				} // else we lost the race and it started already which is what we want
			case u443:
				err443 = res.err
			default:
				panic("invalid")
			}
			if err80 != nil && err443 != nil {
				return nil, fmt.Errorf("all connection attempts failed (HTTP: %v, HTTPS: %v)", err80, err443)
			}
		}
	}
}

// dialURL attempts to connect to the given URL.
func (a *dialParams) dialURL(ctx context.Context, u *url.URL) (*controlbase.Conn, error) {
	init, cont, err := controlbase.ClientDeferred(a.machineKey, a.controlKey, a.version)
	if err != nil {
		return nil, err
	}
	netConn, err := a.tryURLUpgrade(ctx, u, init)
	if err != nil {
		return nil, err
	}
	cbConn, err := cont(ctx, netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return cbConn, nil
}

// tryURLUpgrade connects to u, and tries to upgrade it to a net.Conn.
//
// Only the provided ctx is used, not a.ctx.
func (a *dialParams) tryURLUpgrade(ctx context.Context, u *url.URL, init []byte) (net.Conn, error) {
	dns := &dnscache.Resolver{
		Forward:          dnscache.Get().Forward,
		LookupIPFallback: dnsfallback.Lookup,
		UseLastGood:      true,
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	defer tr.CloseIdleConnections()
	tr.Proxy = a.proxyFunc
	tshttpproxy.SetTransportGetProxyConnectHeader(tr)
	tr.DialContext = dnscache.Dialer(a.dialer, dns)
	// Disable HTTP2, since h2 can't do protocol switching.
	tr.TLSClientConfig.NextProtos = []string{}
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tr.TLSClientConfig = tlsdial.Config(a.host, tr.TLSClientConfig)
	if a.insecureTLS {
		tr.TLSClientConfig.InsecureSkipVerify = true
		tr.TLSClientConfig.VerifyConnection = nil
	}
	tr.DialTLSContext = dnscache.TLSDialer(a.dialer, dns, tr.TLSClientConfig)
	tr.DisableCompression = true

	// (mis)use httptrace to extract the underlying net.Conn from the
	// transport. We make exactly 1 request using this transport, so
	// there will be exactly 1 GotConn call. Additionally, the
	// transport handles 101 Switching Protocols correctly, such that
	// the Conn will not be reused or kept alive by the transport once
	// the response has been handed back from RoundTrip.
	//
	// In theory, the machinery of net/http should make it such that
	// the trace callback happens-before we get the response, but
	// there's no promise of that. So, to make sure, we use a buffered
	// channel as a synchronization step to avoid data races.
	//
	// Note that even though we're able to extract a net.Conn via this
	// mechanism, we must still keep using the eventual resp.Body to
	// read from, because it includes a buffer we can't get rid of. If
	// the server never sends any data after sending the HTTP
	// response, we could get away with it, but violating this
	// assumption leads to very mysterious transport errors (lockups,
	// unexpected EOFs...), and we're bound to forget someday and
	// introduce a protocol optimization at a higher level that starts
	// eagerly transmitting from the server.
	connCh := make(chan net.Conn, 1)
	trace := httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			connCh <- info.Conn
		},
	}
	ctx = httptrace.WithClientTrace(ctx, &trace)
	req := &http.Request{
		Method: "POST",
		URL:    u,
		Header: http.Header{
			"Upgrade":           []string{upgradeHeaderValue},
			"Connection":        []string{"upgrade"},
			handshakeHeaderName: []string{base64.StdEncoding.EncodeToString(init)},
		},
	}
	req = req.WithContext(ctx)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("unexpected HTTP response: %s", resp.Status)
	}

	// From here on, the underlying net.Conn is ours to use, but there
	// is still a read buffer attached to it within resp.Body. So, we
	// must direct I/O through resp.Body, but we can still use the
	// underlying net.Conn for stuff like deadlines.
	var switchedConn net.Conn
	select {
	case switchedConn = <-connCh:
	default:
	}
	if switchedConn == nil {
		resp.Body.Close()
		return nil, fmt.Errorf("httptrace didn't provide a connection")
	}

	if next := resp.Header.Get("Upgrade"); next != upgradeHeaderValue {
		resp.Body.Close()
		return nil, fmt.Errorf("server switched to unexpected protocol %q", next)
	}

	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		return nil, errors.New("http Transport did not provide a writable body")
	}

	return netutil.NewAltReadWriteCloserConn(rwc, switchedConn), nil
}
