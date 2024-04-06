// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package derphttp implements DERP-over-HTTP.
//
// This makes DERP look exactly like WebSockets.
// A server can implement DERP over HTTPS and even if the TLS connection
// intercepted using a fake root CA, unless the interceptor knows how to
// detect DERP packets, it will look like a web socket.
package derphttp

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/envknob"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/sockstats"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
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
	MeshKey   string             // optional; for trusted clients
	IsProber  bool               // optional; for probers to optional declare themselves as such

	// WatchConnectionChanges is whether the client wishes to subscribe to
	// notifications about clients connecting & disconnecting.
	//
	// Only trusted connections (using MeshKey) are allowed to use this.
	WatchConnectionChanges bool

	// BaseContext, if non-nil, returns the base context to use for dialing a
	// new derp server. If nil, context.Background is used.
	// In either case, additional timeouts may be added to the base context.
	BaseContext func() context.Context

	privateKey key.NodePrivate
	logf       logger.Logf
	netMon     *netmon.Monitor // optional; nil means interfaces will be looked up on-demand
	dialer     func(ctx context.Context, network, addr string) (net.Conn, error)

	// Either url or getRegion is non-nil:
	url       *url.URL
	getRegion func() *tailcfg.DERPRegion

	ctx       context.Context // closed via cancelCtx in Client.Close
	cancelCtx context.CancelFunc

	// addrFamSelAtomic is the last AddressFamilySelector set
	// by SetAddressFamilySelector. It's an atomic because it needs
	// to be accessed by multiple racing routines started while
	// Client.conn holds mu.
	addrFamSelAtomic syncs.AtomicValue[AddressFamilySelector]

	mu           sync.Mutex
	atomicState  syncs.AtomicValue[ConnectedState] // hold mu to write
	started      bool                              // true upon first connect, never transitions to false
	preferred    bool
	canAckPings  bool
	closed       bool
	netConn      io.Closer
	client       *derp.Client
	connGen      int // incremented once per new connection; valid values are >0
	serverPubKey key.NodePublic
	tlsState     *tls.ConnectionState
	pingOut      map[derp.PingMessage]chan<- bool // chan to send to on pong
	clock        tstime.Clock
}

// ConnectedState describes the state of a derphttp Client.
type ConnectedState struct {
	Connected  bool
	Connecting bool
	Closed     bool
	LocalAddr  netip.AddrPort // if Connected
}

func (c *Client) String() string {
	return fmt.Sprintf("<derphttp_client.Client %s url=%s>", c.ServerPublicKey().ShortString(), c.url)
}

// NewRegionClient returns a new DERP-over-HTTP client. It connects lazily.
// To trigger a connection, use Connect.
// The netMon parameter is optional; if non-nil it's used to do faster interface lookups.
func NewRegionClient(privateKey key.NodePrivate, logf logger.Logf, netMon *netmon.Monitor, getRegion func() *tailcfg.DERPRegion) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		privateKey: privateKey,
		logf:       logf,
		netMon:     netMon,
		getRegion:  getRegion,
		ctx:        ctx,
		cancelCtx:  cancel,
		clock:      tstime.StdClock{},
	}
	return c
}

// NewNetcheckClient returns a Client that's only able to have its DialRegionTLS method called.
// It's used by the netcheck package.
func NewNetcheckClient(logf logger.Logf) *Client {
	return &Client{logf: logf, clock: tstime.StdClock{}}
}

// NewClient returns a new DERP-over-HTTP client. It connects lazily.
// To trigger a connection, use Connect.
func NewClient(privateKey key.NodePrivate, serverURL string, logf logger.Logf) (*Client, error) {
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
		clock:      tstime.StdClock{},
	}
	return c, nil
}

// isStarted reports whether this client has been used yet.
//
// If if reports false, it may still have its exported fields configured.
func (c *Client) isStarted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

// Connect connects or reconnects to the server, unless already connected.
// It returns nil if there was already a good connection, or if one was made.
func (c *Client) Connect(ctx context.Context) error {
	_, _, err := c.connect(ctx, "derphttp.Client.Connect")
	return err
}

// newContext returns a new context for setting up a new DERP connection.
// It uses either c.BaseContext or returns context.Background.
func (c *Client) newContext() context.Context {
	if c.BaseContext != nil {
		ctx := c.BaseContext()
		if ctx == nil {
			panic("BaseContext returned nil")
		}
		return ctx
	}
	return context.Background()
}

// TLSConnectionState returns the last TLS connection state, if any.
// The client must already be connected.
func (c *Client) TLSConnectionState() (_ *tls.ConnectionState, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.client == nil {
		return nil, false
	}
	return c.tlsState, c.tlsState != nil
}

// ServerPublicKey returns the server's public key.
//
// It only returns a non-zero value once a connection has succeeded
// from an earlier call.
func (c *Client) ServerPublicKey() key.NodePublic {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverPubKey
}

// SelfPublicKey returns our own public key.
func (c *Client) SelfPublicKey() key.NodePublic {
	return c.privateKey.Public()
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

// debugDERPUseHTTP tells clients to connect to DERP via HTTP on port
// 3340 instead of HTTPS on 443.
var debugUseDERPHTTP = envknob.RegisterBool("TS_DEBUG_USE_DERP_HTTP")

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
	if debugUseDERPHTTP() {
		return false
	}

	return true
}

// tlsServerName returns the tls.Config.ServerName value (for the TLS ClientHello).
func (c *Client) tlsServerName(node *tailcfg.DERPNode) string {
	if c.url != nil {
		return c.url.Hostname()
	}
	return node.HostName
}

func (c *Client) urlString(node *tailcfg.DERPNode) string {
	if c.url != nil {
		return c.url.String()
	}
	proto := "https"
	if debugUseDERPHTTP() {
		proto = "http"
	}
	return fmt.Sprintf("%s://%s/derp", proto, node.HostName)
}

// AddressFamilySelector decides whether IPv6 is preferred for
// outbound dials.
type AddressFamilySelector interface {
	// PreferIPv6 reports whether IPv4 dials should be slightly
	// delayed to give IPv6 a better chance of winning dial races.
	// Implementations should only return true if IPv6 is expected
	// to succeed. (otherwise delaying IPv4 will delay the
	// connection overall)
	PreferIPv6() bool
}

// SetAddressFamilySelector sets the AddressFamilySelector that this
// connection will use. It should be called before any dials.
// The value must not be nil. If called more than once, s must
// be the same concrete type as any prior calls.
func (c *Client) SetAddressFamilySelector(s AddressFamilySelector) {
	c.addrFamSelAtomic.Store(s)
}

func (c *Client) preferIPv6() bool {
	if s, ok := c.addrFamSelAtomic.Load().(AddressFamilySelector); ok {
		return s.PreferIPv6()
	}
	return false
}

// dialWebsocketFunc is non-nil (set by websocket.go's init) when compiled in.
var dialWebsocketFunc func(ctx context.Context, urlStr string) (net.Conn, error)

func useWebsockets() bool {
	if runtime.GOOS == "js" {
		return true
	}
	if dialWebsocketFunc != nil {
		return envknob.Bool("TS_DEBUG_DERP_WS_CLIENT")
	}
	return false
}

func (c *Client) connect(ctx context.Context, caller string) (client *derp.Client, connGen int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started = true
	if c.closed {
		return nil, 0, ErrClientClosed
	}
	if c.client != nil {
		return c.client, c.connGen, nil
	}
	c.atomicState.Store(ConnectedState{Connecting: true})
	defer func() {
		if err != nil {
			c.atomicState.Store(ConnectedState{Connecting: false})
		}
	}()

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
			return nil, 0, errors.New("DERP region not available")
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
	switch {
	case useWebsockets():
		var urlStr string
		if c.url != nil {
			urlStr = c.url.String()
		} else {
			urlStr = c.urlString(reg.Nodes[0])
		}
		c.logf("%s: connecting websocket to %v", caller, urlStr)
		conn, err := dialWebsocketFunc(ctx, urlStr)
		if err != nil {
			c.logf("%s: websocket to %v error: %v", caller, urlStr, err)
			return nil, 0, err
		}
		brw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		derpClient, err := derp.NewClient(c.privateKey, conn, brw, c.logf,
			derp.MeshKey(c.MeshKey),
			derp.CanAckPings(c.canAckPings),
			derp.IsProber(c.IsProber),
		)
		if err != nil {
			return nil, 0, err
		}
		if c.preferred {
			if err := derpClient.NotePreferred(true); err != nil {
				go conn.Close()
				return nil, 0, err
			}
		}
		c.serverPubKey = derpClient.ServerPublicKey()
		c.client = derpClient
		c.netConn = conn
		c.connGen++
		return c.client, c.connGen, nil
	case c.url != nil:
		c.logf("%s: connecting to %v", caller, c.url)
		tcpConn, err = c.dialURL(ctx)
	default:
		c.logf("%s: connecting to derp-%d (%v)", caller, reg.RegionID, reg.RegionCode)
		tcpConn, node, err = c.dialRegion(ctx, reg)
	}
	if err != nil {
		return nil, 0, err
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

	var httpConn net.Conn        // a TCP conn or a TLS conn; what we speak HTTP to
	var serverPub key.NodePublic // or zero if unknown (if not using TLS or TLS middlebox eats it)
	var serverProtoVersion int
	var tlsState *tls.ConnectionState
	if c.useHTTPS() {
		tlsConn := c.tlsClient(tcpConn, node)
		httpConn = tlsConn

		// Force a handshake now (instead of waiting for it to
		// be done implicitly on read/write) so we can check
		// the ConnectionState.
		if err := tlsConn.Handshake(); err != nil {
			return nil, 0, err
		}

		// We expect to be using TLS 1.3 to our own servers, and only
		// starting at TLS 1.3 are the server's returned certificates
		// encrypted, so only look for and use our "meta cert" if we're
		// using TLS 1.3. If we're not using TLS 1.3, it might be a user
		// running cmd/derper themselves with a different configuration,
		// in which case we can avoid this fast-start optimization.
		// (If a corporate proxy is MITM'ing TLS 1.3 connections with
		// corp-mandated TLS root certs than all bets are off anyway.)
		// Note that we're not specifically concerned about TLS downgrade
		// attacks. TLS handles that fine:
		// https://blog.gypsyengineer.com/en/security/how-does-tls-1-3-protect-against-downgrade-attacks.html
		cs := tlsConn.ConnectionState()
		tlsState = &cs
		if cs.Version >= tls.VersionTLS13 {
			serverPub, serverProtoVersion = parseMetaCert(cs.PeerCertificates)
		}
	} else {
		httpConn = tcpConn
	}

	brw := bufio.NewReadWriter(bufio.NewReader(httpConn), bufio.NewWriter(httpConn))
	var derpClient *derp.Client

	req, err := http.NewRequest("GET", c.urlString(node), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Upgrade", "DERP")
	req.Header.Set("Connection", "Upgrade")

	if !serverPub.IsZero() && serverProtoVersion != 0 {
		// parseMetaCert found the server's public key (no TLS
		// middlebox was in the way), so skip the HTTP upgrade
		// exchange.  See https://github.com/tailscale/tailscale/issues/693
		// for an overview. We still send the HTTP request
		// just to get routed into the server's HTTP Handler so it
		// can Hijack the request, but we signal with a special header
		// that we don't want to deal with its HTTP response.
		req.Header.Set(fastStartHeader, "1") // suppresses the server's HTTP response
		if err := req.Write(brw); err != nil {
			return nil, 0, err
		}
		// No need to flush the HTTP request. the derp.Client's initial
		// client auth frame will flush it.
	} else {
		if err := req.Write(brw); err != nil {
			return nil, 0, err
		}
		if err := brw.Flush(); err != nil {
			return nil, 0, err
		}

		resp, err := http.ReadResponse(brw.Reader, req)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, 0, fmt.Errorf("GET failed: %v: %s", err, b)
		}
	}
	derpClient, err = derp.NewClient(c.privateKey, httpConn, brw, c.logf,
		derp.MeshKey(c.MeshKey),
		derp.ServerPublicKey(serverPub),
		derp.CanAckPings(c.canAckPings),
		derp.IsProber(c.IsProber),
	)
	if err != nil {
		return nil, 0, err
	}
	if c.preferred {
		if err := derpClient.NotePreferred(true); err != nil {
			go httpConn.Close()
			return nil, 0, err
		}
	}

	if c.WatchConnectionChanges {
		if err := derpClient.WatchConnectionChanges(); err != nil {
			go httpConn.Close()
			return nil, 0, err
		}
	}

	c.serverPubKey = derpClient.ServerPublicKey()
	c.client = derpClient
	c.netConn = tcpConn
	c.tlsState = tlsState
	c.connGen++

	localAddr, _ := c.client.LocalAddr()
	c.atomicState.Store(ConnectedState{
		Connected: true,
		LocalAddr: localAddr,
	})
	return c.client, c.connGen, nil
}

// SetURLDialer sets the dialer to use for dialing URLs.
// This dialer is only use for clients created with NewClient, not NewRegionClient.
// If unset or nil, the default dialer is used.
//
// The primary use for this is the derper mesh mode to connect to each
// other over a VPC network.
func (c *Client) SetURLDialer(dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
	c.dialer = dialer
}

func (c *Client) dialURL(ctx context.Context) (net.Conn, error) {
	host := c.url.Hostname()
	if c.dialer != nil {
		return c.dialer(ctx, "tcp", net.JoinHostPort(host, urlPort(c.url)))
	}
	hostOrIP := host
	dialer := netns.NewDialer(c.logf, c.netMon)

	if c.DNSCache != nil {
		ip, _, _, err := c.DNSCache.LookupIP(ctx, host)
		if err == nil {
			hostOrIP = ip.String()
		}
		if err != nil && netns.IsSOCKSDialer(dialer) {
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
			if firstErr == nil {
				firstErr = fmt.Errorf("no non-STUNOnly nodes for %s", c.targetString(reg))
			}
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
	if node != nil {
		if node.InsecureForTests {
			tlsConf.InsecureSkipVerify = true
			tlsConf.VerifyConnection = nil
		}
		if node.CertName != "" {
			tlsdial.SetConfigExpectedCert(tlsConf, node.CertName)
		}
	}
	return tls.Client(nc, tlsConf)
}

// DialRegionTLS returns a TLS connection to a DERP node in the given region.
//
// DERP nodes for a region are tried in sequence according to their order
// in the DERP map. TLS is initiated on the first node where a socket is
// established.
func (c *Client) DialRegionTLS(ctx context.Context, reg *tailcfg.DERPRegion) (tlsConn *tls.Conn, connClose io.Closer, node *tailcfg.DERPNode, err error) {
	tcpConn, node, err := c.dialRegion(ctx, reg)
	if err != nil {
		return nil, nil, nil, err
	}
	done := make(chan bool) // unbuffered
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
		return nil, nil, nil, err
	}
	select {
	case done <- true:
		return tlsConn, tcpConn, node, nil
	case <-ctx.Done():
		return nil, nil, nil, ctx.Err()
	}
}

func (c *Client) dialContext(ctx context.Context, proto, addr string) (net.Conn, error) {
	return netns.NewDialer(c.logf, c.netMon).DialContext(ctx, proto, addr)
}

// shouldDialProto reports whether an explicitly provided IPv4 or IPv6
// address (given in s) is valid. An empty value means to dial, but to
// use DNS. The predicate function reports whether the non-empty
// string s contained a valid IP address of the right family.
func shouldDialProto(s string, pred func(netip.Addr) bool) bool {
	if s == "" {
		return true
	}
	ip, _ := netip.ParseAddr(s)
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
	// First see if we need to use an HTTP proxy.
	proxyReq := &http.Request{
		Method: "GET", // doesn't really matter
		URL: &url.URL{
			Scheme: "https",
			Host:   c.tlsServerName(n),
			Path:   "/", // unused
		},
	}
	if proxyURL, err := tshttpproxy.ProxyFromEnvironment(proxyReq); err == nil && proxyURL != nil {
		return c.dialNodeUsingProxy(ctx, n, proxyURL)
	}

	type res struct {
		c   net.Conn
		err error
	}
	resc := make(chan res) // must be unbuffered
	ctx, cancel := context.WithTimeout(ctx, dialNodeTimeout)
	defer cancel()

	ctx = sockstats.WithSockStats(ctx, sockstats.LabelDERPHTTPClient, c.logf)

	nwait := 0
	startDial := func(dstPrimary, proto string) {
		nwait++
		go func() {
			if proto == "tcp4" && c.preferIPv6() {
				t, tChannel := c.clock.NewTimer(200 * time.Millisecond)
				select {
				case <-ctx.Done():
					// Either user canceled original context,
					// it timed out, or the v6 dial succeeded.
					t.Stop()
					return
				case <-tChannel:
					// Start v4 dial
				}
			}
			dst := cmp.Or(dstPrimary, n.HostName)
			port := "443"
			if n.DERPPort != 0 {
				port = fmt.Sprint(n.DERPPort)
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
	if shouldDialProto(n.IPv4, netip.Addr.Is4) {
		startDial(n.IPv4, "tcp4")
	}
	if shouldDialProto(n.IPv6, netip.Addr.Is6) {
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

func firstStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// dialNodeUsingProxy connects to n using a CONNECT to the HTTP(s) proxy in proxyURL.
func (c *Client) dialNodeUsingProxy(ctx context.Context, n *tailcfg.DERPNode, proxyURL *url.URL) (_ net.Conn, err error) {
	pu := proxyURL
	var proxyConn net.Conn
	if pu.Scheme == "https" {
		var d tls.Dialer
		proxyConn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(pu.Hostname(), firstStr(pu.Port(), "443")))
	} else {
		var d net.Dialer
		proxyConn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(pu.Hostname(), firstStr(pu.Port(), "80")))
	}
	defer func() {
		if err != nil && proxyConn != nil {
			// In a goroutine in case it's a *tls.Conn (that can block on Close)
			// TODO(bradfitz): track the underlying tcp.Conn and just close that instead.
			go proxyConn.Close()
		}
	}()
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-ctx.Done():
			proxyConn.Close()
		}
	}()

	target := net.JoinHostPort(n.HostName, "443")

	var authHeader string
	if v, err := tshttpproxy.GetAuthHeader(pu); err != nil {
		c.logf("derphttp: error getting proxy auth header for %v: %v", proxyURL, err)
	} else if v != "" {
		authHeader = fmt.Sprintf("Proxy-Authorization: %s\r\n", v)
	}

	if _, err := fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, authHeader); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}

	br := bufio.NewReader(proxyConn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c.logf("derphttp: CONNECT dial to %s: %v", target, err)
		return nil, err
	}
	c.logf("derphttp: CONNECT dial to %s: %v", target, res.Status)
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("invalid response status from HTTP proxy %s on CONNECT to %s: %v", pu, target, res.Status)
	}
	return proxyConn, nil
}

func (c *Client) Send(dstKey key.NodePublic, b []byte) error {
	client, _, err := c.connect(c.newContext(), "derphttp.Client.Send")
	if err != nil {
		return err
	}
	if err := client.Send(dstKey, b); err != nil {
		c.closeForReconnect(client)
	}
	return err
}

func (c *Client) registerPing(m derp.PingMessage, ch chan<- bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pingOut == nil {
		c.pingOut = map[derp.PingMessage]chan<- bool{}
	}
	c.pingOut[m] = ch
}

func (c *Client) unregisterPing(m derp.PingMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pingOut, m)
}

func (c *Client) handledPong(m derp.PongMessage) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := derp.PingMessage(m)
	if ch, ok := c.pingOut[k]; ok {
		ch <- true
		delete(c.pingOut, k)
		return true
	}
	return false
}

// Ping sends a ping to the peer and waits for it either to be
// acknowledged (in which case Ping returns nil) or waits for ctx to
// be over and returns an error. It will wait at most 5 seconds
// before returning an error.
//
// Another goroutine must be in a loop calling Recv or
// RecvDetail or ping responses won't be handled.
func (c *Client) Ping(ctx context.Context) error {
	maxDL := time.Now().Add(5 * time.Second)
	if dl, ok := ctx.Deadline(); !ok || dl.After(maxDL) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, maxDL)
		defer cancel()
	}
	var data derp.PingMessage
	rand.Read(data[:])
	gotPing := make(chan bool, 1)
	c.registerPing(data, gotPing)
	defer c.unregisterPing(data)
	if err := c.SendPing(data); err != nil {
		return err
	}
	select {
	case <-gotPing:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SendPing writes a ping message, without any implicit connect or
// reconnect. This is a lower-level interface that writes a frame
// without any implicit handling of the response pong, if any. For a
// higher-level interface, use Ping.
func (c *Client) SendPing(data [8]byte) error {
	c.mu.Lock()
	closed, client := c.closed, c.client
	c.mu.Unlock()
	if closed {
		return ErrClientClosed
	}
	if client == nil {
		return errors.New("client not connected")
	}
	return client.SendPing(data)
}

// LocalAddr reports c's local TCP address, without any implicit
// connect or reconnect.
func (c *Client) LocalAddr() (netip.AddrPort, error) {
	st := c.atomicState.Load()
	if st.Closed {
		return netip.AddrPort{}, ErrClientClosed
	}
	la := st.LocalAddr
	if !st.Connected && !la.IsValid() {
		return netip.AddrPort{}, errors.New("client not connected")
	}
	return la, nil
}

func (c *Client) ForwardPacket(from, to key.NodePublic, b []byte) error {
	client, _, err := c.connect(c.newContext(), "derphttp.Client.ForwardPacket")
	if err != nil {
		return err
	}
	if err := client.ForwardPacket(from, to, b); err != nil {
		c.closeForReconnect(client)
	}
	return err
}

// SendPong sends a reply to a ping, with the ping's provided
// challenge/identifier data.
//
// Unlike other send methods, SendPong makes no attempt to connect or
// reconnect to the peer. It's best effort. If there's a connection
// problem, the server will choose to hang up on us if we're not
// replying.
func (c *Client) SendPong(data [8]byte) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClientClosed
	}
	if c.client == nil {
		c.mu.Unlock()
		return errors.New("not connected")
	}
	dc := c.client
	c.mu.Unlock()

	return dc.SendPong(data)
}

// SetCanAckPings sets whether this client will reply to ping requests from the server.
//
// This only affects future connections.
func (c *Client) SetCanAckPings(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.canAckPings = v
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

// ClosePeer asks the server to close target's TCP connection.
//
// Only trusted connections (using MeshKey) are allowed to use this.
func (c *Client) ClosePeer(target key.NodePublic) error {
	client, _, err := c.connect(c.newContext(), "derphttp.Client.ClosePeer")
	if err != nil {
		return err
	}
	err = client.ClosePeer(target)
	if err != nil {
		c.closeForReconnect(client)
	}
	return err
}

// Recv reads a message from c. The returned message may alias memory from Client.
// The message should only be used until the next Client call.
func (c *Client) Recv() (derp.ReceivedMessage, error) {
	m, _, err := c.RecvDetail()
	return m, err
}

// RecvDetail is like Recv, but additional returns the connection generation on each message.
// The connGen value is incremented every time the derphttp.Client reconnects to the server.
func (c *Client) RecvDetail() (m derp.ReceivedMessage, connGen int, err error) {
	client, connGen, err := c.connect(c.newContext(), "derphttp.Client.Recv")
	if err != nil {
		return nil, 0, err
	}
	for {
		m, err = client.Recv()
		switch m := m.(type) {
		case derp.PongMessage:
			if c.handledPong(m) {
				continue
			}
		}
		if err != nil {
			c.closeForReconnect(client)
			if c.isClosed() {
				err = ErrClientClosed
			}
		}
		return m, connGen, err
	}
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Close closes the client. It will not automatically reconnect after
// being closed.
func (c *Client) Close() error {
	if c.cancelCtx != nil {
		c.cancelCtx() // not in lock, so it can cancel Connect, which holds mu
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClientClosed
	}
	c.closed = true
	if c.netConn != nil {
		c.netConn.Close()
	}
	c.atomicState.Store(ConnectedState{Closed: true})
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

func parseMetaCert(certs []*x509.Certificate) (serverPub key.NodePublic, serverProtoVersion int) {
	for _, cert := range certs {
		// Look for derpkey prefix added by initMetacert() on the server side.
		if pubHex, ok := strings.CutPrefix(cert.Subject.CommonName, "derpkey"); ok {
			var err error
			serverPub, err = key.ParseNodePublicUntyped(mem.S(pubHex))
			if err == nil && cert.SerialNumber.BitLen() <= 8 { // supports up to version 255
				return serverPub, int(cert.SerialNumber.Int64())
			}
		}
	}
	return key.NodePublic{}, 0
}
