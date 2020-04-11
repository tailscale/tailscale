// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package derphttp implements DERP-over-HTTP.
//
// This makes DERP look exactly like WebSockets.
// A server can implement DERP over HTTPS and even if the TLS connection
// intercepted using a fake root CA, unless the interceptor knows how to
// detect DERP packets, it will look like a web socket.
package derphttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/net/dnscache"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// Client is a DERP-over-HTTP client.
//
// It automatically reconnects on error retry. That is, a failed Send or
// Recv will report the error and not retry, but subsequent calls to
// Send/Recv will completely re-establish the connection (unless Close
// has been called).
type Client struct {
	TLSConfig *tls.Config        // for sever connection, optional, nil means default
	DNSCache  *dnscache.Resolver // optional; if nil, no caching

	privateKey key.Private
	logf       logger.Logf
	url        *url.URL

	ctx       context.Context // closed via cancelCtx in Client.Close
	cancelCtx context.CancelFunc

	mu        sync.Mutex
	preferred bool
	closed    bool
	netConn   io.Closer
	client    *derp.Client
}

// NewClient returns a new DERP-over-HTTP client. It connects lazily.
// To trigger a connection use Connect.
func NewClient(privateKey key.Private, serverURL string, logf logger.Logf) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("derphttp.NewClient: %v", err)
	}
	if urlPort(u) == "" {
		return nil, fmt.Errorf("derphttp.NewClient: invalid URL scheme %q", u.Scheme)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		privateKey: privateKey,
		logf:       logf,
		url:        u,
		ctx:        ctx,
		cancelCtx:  cancel,
	}
	return c, nil
}

// Connect connects or reconnects to the server, unless already connected.
// It returns nil if there was already a good connection, or if one was made.
func (c *Client) Connect(ctx context.Context) error {
	_, err := c.connect(ctx, "derphttp.Client.Connect")
	return err
}

func urlPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

func (c *Client) connect(ctx context.Context, caller string) (client *derp.Client, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrClientClosed
	}
	if c.client != nil {
		return c.client, nil
	}

	c.logf("%s: connecting to %v", caller, c.url)

	// timeout is the fallback maximum time (if ctx doesn't limit
	// it further) to do all of: DNS + TCP + TLS + HTTP Upgrade +
	// DERP upgrade.
	const timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	go func() {
		select {
		case <-ctx.Done():
			// Either timeout fired (handled below), or
			// we're returning via the defer cancel()
			// below.
		case <-c.ctx.Done():
			// Propagate a Client.Close call into
			// cancelling this context.
			cancel()
		}
	}()
	defer cancel()

	var tcpConn net.Conn
	defer func() {
		if err != nil {
			if ctx.Err() != nil {
				err = fmt.Errorf("%v: %v", ctx.Err(), err)
			}
			err = fmt.Errorf("%s connect to %v: %v", caller, c.url, err)
			if tcpConn != nil {
				go tcpConn.Close()
			}
		}
	}()

	host := c.url.Hostname()
	hostOrIP := host

	var d net.Dialer

	if c.DNSCache != nil {
		ip, err := c.DNSCache.LookupIP(ctx, host)
		if err != nil {
			return nil, err
		}
		hostOrIP = ip.String()
	}

	tcpConn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(hostOrIP, urlPort(c.url)))
	if err != nil {
		return nil, fmt.Errorf("dial of %q: %v", host, err)
	}

	// Now that we have a TCP connection, force close it.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			// Normal path. Upgrade occurred in time.
		case <-ctx.Done():
			select {
			case <-done:
				// Normal path. Upgrade occurred in time.
				// But the ctx.Done() is also done because
				// the "defer cancel()" above scheduled
				// before this goroutine.
			default:
				// The TLS or HTTP or DERP exchanges didn't complete
				// in time. Force close the TCP connection to force
				// them to fail quickly.
				tcpConn.Close()
			}
		}
	}()

	var httpConn net.Conn // a TCP conn or a TLS conn; what we speak HTTP to
	if c.url.Scheme == "https" {
		tlsConfig := &tls.Config{}
		if c.TLSConfig != nil {
			tlsConfig = c.TLSConfig.Clone()
		}
		tlsConfig.ServerName = c.url.Host
		httpConn = tls.Client(tcpConn, tlsConfig)
	} else {
		httpConn = tcpConn
	}

	brw := bufio.NewReadWriter(bufio.NewReader(httpConn), bufio.NewWriter(httpConn))

	req, err := http.NewRequest("GET", c.url.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Upgrade", "DERP")
	req.Header.Set("Connection", "Upgrade")

	if err := req.Write(brw); err != nil {
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(brw.Reader, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("GET failed: %v: %s", err, b)
	}

	derpClient, err := derp.NewClient(c.privateKey, httpConn, brw, c.logf)
	if err != nil {
		return nil, err
	}
	if c.preferred {
		if err := derpClient.NotePreferred(true); err != nil {
			go httpConn.Close()
			return nil, err
		}
	}

	c.client = derpClient
	c.netConn = tcpConn
	return c.client, nil
}

func (c *Client) Send(dstKey key.Public, b []byte) error {
	client, err := c.connect(context.TODO(), "derphttp.Client.Send")
	if err != nil {
		return err
	}
	if err := client.Send(dstKey, b); err != nil {
		c.closeForReconnect(client)
	}
	return err
}

// NotePreferred notes whether this Client is the caller's preferred
// (home) DERP node. It's only used for stats.
func (c *Client) NotePreferred(v bool) {
	c.mu.Lock()
	if c.preferred == v {
		c.mu.Unlock()
		return
	}
	c.preferred = v
	client := c.client
	c.mu.Unlock()

	if client != nil {
		if err := client.NotePreferred(v); err != nil {
			c.closeForReconnect(client)
		}
	}
}

func (c *Client) Recv(b []byte) (derp.ReceivedMessage, error) {
	client, err := c.connect(context.TODO(), "derphttp.Client.Recv")
	if err != nil {
		return nil, err
	}
	m, err := client.Recv(b)
	if err != nil {
		c.closeForReconnect(client)
	}
	return m, err
}

// Close closes the client. It will not automatically reconnect after
// being closed.
func (c *Client) Close() error {
	c.cancelCtx() // not in lock, so it can cancel Connect, which holds mu

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClientClosed
	}
	c.closed = true
	if c.netConn != nil {
		c.netConn.Close()
	}
	return nil
}

// closeForReconnect closes the underlying network connection and
// zeros out the client field so future calls to Connect will
// reconnect.
//
// The provided brokenClient is the client to forget. If current
// client is not brokenClient, closeForReconnect does nothing. (This
// prevents a send and receive goroutine from failing at the ~same
// time and both calling closeForReconnect and the caller goroutines
// forever calling closeForReconnect in lockstep endlessly;
// https://github.com/tailscale/tailscale/pull/264)
func (c *Client) closeForReconnect(brokenClient *derp.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != brokenClient {
		return
	}
	if c.netConn != nil {
		c.netConn.Close()
		c.netConn = nil
	}
	c.client = nil
}

var ErrClientClosed = errors.New("derphttp.Client closed")
