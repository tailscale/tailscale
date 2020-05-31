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

	"inet.af/netaddr"
	"tailscale.com/derp"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netns"
	"tailscale.com/net/tlsdial"
	"tailscale.com/tailcfg"
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
	TLSConfig *tls.Config        // optional; nil means default
	DNSCache  *dnscache.Resolver // optional; nil means no caching

	privateKey key.Private
	logf       logger.Logf

	// Either url or getRegion is non-nil:
	url       *url.URL
	getRegion func() *tailcfg.DERPRegion

	ctx       context.Context // closed via cancelCtx in Client.Close
	cancelCtx context.CancelFunc

	mu        sync.Mutex
	preferred bool
	closed    bool
	netConn   io.Closer
	client    *derp.Client
}

// NewRegionClient returns a new DERP-over-HTTP client. It connects lazily.
// To trigger a connection, use Connect.
func NewRegionClient(privateKey key.Private, logf logger.Logf, getRegion func() *tailcfg.DERPRegion) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		privateKey: privateKey,
		logf:       logf,
		getRegion:  getRegion,
		ctx:        ctx,
		cancelCtx:  cancel,
	}
	return c
}

// NewNetcheckClient returns a Client that's only able to have its DialRegion method called.
// It's used by the netcheck package.
func NewNetcheckClient(logf logger.Logf) *Client {
	return &Client{logf: logf}
}

// NewClient returns a new DERP-over-HTTP client. It connects lazily.
// To trigger a connection, use Connect.
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

type dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
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

func (c *Client) targetString(reg *tailcfg.DERPRegion) string {
	if c.url != nil {
		return c.url.String()
	}
	return fmt.Sprintf("region %d (%v)", reg.RegionID, reg.RegionCode)
}

func (c *Client) useHTTPS() bool {
	if c.url != nil && c.url.Scheme == "http" {
		return false
	}
	return true
}

// tlsServerName returns which TLS cert name to expect for the given node.
func (c *Client) tlsServerName(node *tailcfg.DERPNode) string {
	if c.url != nil {
		return c.url.Host
	}
	if node.CertName != "" {
		return node.CertName
	}
	return node.HostName
}

func (c *Client) urlString(node *tailcfg.DERPNode) string {
	if c.url != nil {
		return c.url.String()
	}
	return fmt.Sprintf("https://%s/derp", node.HostName)
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

	var reg *tailcfg.DERPRegion // nil when using c.url to dial
	if c.getRegion != nil {
		reg = c.getRegion()
		if reg == nil {
			return nil, errors.New("DERP region not available")
		}
	}

	var tcpConn net.Conn

	defer func() {
		if err != nil {
			if ctx.Err() != nil {
				err = fmt.Errorf("%v: %v", ctx.Err(), err)
			}
			err = fmt.Errorf("%s connect to %v: %v", caller, c.targetString(reg), err)
			if tcpConn != nil {
				go tcpConn.Close()
			}
		}
	}()

	var node *tailcfg.DERPNode // nil when using c.url to dial
	if c.url != nil {
		c.logf("%s: connecting to %v", caller, c.url)
		tcpConn, err = c.dialURL(ctx)
	} else {
		c.logf("%s: connecting to derp-%d (%v)", caller, reg.RegionID, reg.RegionCode)
		tcpConn, node, err = c.dialRegion(ctx, reg)
	}
	if err != nil {
		return nil, err
	}

	// Now that we have a TCP connection, force close it if the
	// TLS handshake + DERP setup takes too long.
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
	if c.useHTTPS() {
		httpConn = c.tlsClient(tcpConn, node)
	} else {
		httpConn = tcpConn
	}

	brw := bufio.NewReadWriter(bufio.NewReader(httpConn), bufio.NewWriter(httpConn))

	req, err := http.NewRequest("GET", c.urlString(node), nil)
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

func (c *Client) dialURL(ctx context.Context) (net.Conn, error) {
	host := c.url.Hostname()
	hostOrIP := host

	var stdDialer dialer = netns.Dialer()
	var dialer = stdDialer
	if wrapDialer != nil {
		dialer = wrapDialer(dialer)
	}

	if c.DNSCache != nil {
		ip, err := c.DNSCache.LookupIP(ctx, host)
		if err == nil {
			hostOrIP = ip.String()
		}
		if err != nil && dialer == stdDialer {
			// Return an error if we're not using a dial
			// proxy that can do DNS lookups for us.
			return nil, err
		}
	}

	tcpConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(hostOrIP, urlPort(c.url)))
	if err != nil {
		return nil, fmt.Errorf("dial of %v: %v", host, err)
	}
	return tcpConn, nil
}

// dialRegion returns a TCP connection to the provided region, trying
// each node in order (with dialNode) until one connects or ctx is
// done.
func (c *Client) dialRegion(ctx context.Context, reg *tailcfg.DERPRegion) (net.Conn, *tailcfg.DERPNode, error) {
	if len(reg.Nodes) == 0 {
		return nil, nil, fmt.Errorf("no nodes for %s", c.targetString(reg))
	}
	var firstErr error
	for _, n := range reg.Nodes {
		if n.STUNOnly {
			continue
		}
		c, err := c.dialNode(ctx, n)
		if err == nil {
			return c, n, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, nil, firstErr
}

func (c *Client) tlsClient(nc net.Conn, node *tailcfg.DERPNode) *tls.Conn {
	tlsConf := tlsdial.Config(c.tlsServerName(node), c.TLSConfig)
	if node != nil && node.DERPTestPort != 0 {
		tlsConf.InsecureSkipVerify = true
	}
	return tls.Client(nc, tlsConf)
}

func (c *Client) DialRegionTLS(ctx context.Context, reg *tailcfg.DERPRegion) (tlsConn *tls.Conn, connClose io.Closer, err error) {
	tcpConn, node, err := c.dialRegion(ctx, reg)
	if err != nil {
		return nil, nil, err
	}
	done := make(chan bool) // unbufferd
	defer close(done)

	tlsConn = c.tlsClient(tcpConn, node)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			tcpConn.Close()
		}
	}()
	err = tlsConn.Handshake()
	if err != nil {
		return nil, nil, err
	}
	select {
	case done <- true:
		return tlsConn, tcpConn, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (c *Client) dialContext(ctx context.Context, proto, addr string) (net.Conn, error) {
	var stdDialer dialer = netns.Dialer()
	var dialer = stdDialer
	if wrapDialer != nil {
		dialer = wrapDialer(dialer)
	}
	return dialer.DialContext(ctx, proto, addr)
}

// shouldDialProto reports whether an explicitly provided IPv4 or IPv6
// address (given in s) is valid. An empty value means to dial, but to
// use DNS. The predicate function reports whether the non-empty
// string s contained a valid IP address of the right family.
func shouldDialProto(s string, pred func(netaddr.IP) bool) bool {
	if s == "" {
		return true
	}
	ip, _ := netaddr.ParseIP(s)
	return pred(ip)
}

const dialNodeTimeout = 1500 * time.Millisecond

// dialNode returns a TCP connection to node n, racing IPv4 and IPv6
// (both as applicable) against each other.
// A node is only given dialNodeTimeout to connect.
//
// TODO(bradfitz): longer if no options remain perhaps? ...  Or longer
// overall but have dialRegion start overlapping races?
func (c *Client) dialNode(ctx context.Context, n *tailcfg.DERPNode) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	resc := make(chan res) // must be unbuffered
	ctx, cancel := context.WithTimeout(ctx, dialNodeTimeout)
	defer cancel()

	nwait := 0
	startDial := func(dstPrimary, proto string) {
		nwait++
		go func() {
			dst := dstPrimary
			if dst == "" {
				dst = n.HostName
			}
			port := "443"
			if n.DERPTestPort != 0 {
				port = fmt.Sprint(n.DERPTestPort)
			}
			c, err := c.dialContext(ctx, proto, net.JoinHostPort(dst, port))
			select {
			case resc <- res{c, err}:
			case <-ctx.Done():
				if c != nil {
					c.Close()
				}
			}
		}()
	}
	if shouldDialProto(n.IPv4, netaddr.IP.Is4) {
		startDial(n.IPv4, "tcp4")
	}
	if shouldDialProto(n.IPv6, netaddr.IP.Is6) {
		startDial(n.IPv6, "tcp6")
	}
	if nwait == 0 {
		return nil, errors.New("both IPv4 and IPv6 are explicitly disabled for node")
	}

	var firstErr error
	for {
		select {
		case res := <-resc:
			nwait--
			if res.err == nil {
				return res.c, nil
			}
			if firstErr == nil {
				firstErr = res.err
			}
			if nwait == 0 {
				return nil, firstErr
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
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

// wrapDialer, if non-nil, specifies a function to wrap a dialer in a
// SOCKS-using dialer. It's set conditionally by socks.go.
var wrapDialer func(dialer) dialer
