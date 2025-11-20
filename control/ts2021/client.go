// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ts2021

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"tailscale.com/control/controlhttp"
	"tailscale.com/health"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// Client provides a http.Client to connect to tailcontrol over
// the ts2021 protocol.
type Client struct {
	// Client is an HTTP client to talk to the coordination server.
	// It automatically makes a new Noise connection as needed.
	*http.Client

	logf      logger.Logf // non-nil
	opts      ClientOpts
	host      string // the host part of serverURL
	httpPort  string // the default port to dial
	httpsPort string // the fallback Noise-over-https port or empty if none

	// mu protects the following
	mu       sync.Mutex
	closed   bool
	connPool set.HandleSet[*Conn] // all live connections
}

// ClientOpts contains options for the [NewClient] function. All fields are
// required unless otherwise specified.
type ClientOpts struct {
	// ServerURL is the URL of the server to connect to.
	ServerURL string

	// PrivKey is this node's private key.
	PrivKey key.MachinePrivate

	// ServerPubKey is the public key of the server.
	// It is of the form https://<host>:<port> (no trailing slash).
	ServerPubKey key.MachinePublic

	// Dialer's SystemDial function is used to connect to the server.
	Dialer *tsdial.Dialer

	// Optional fields follow

	// Logf is the log function to use.
	// If nil, log.Printf is used.
	Logf logger.Logf

	// NetMon is the network monitor that will be used to get the
	// network interface state. This field can be nil; if so, the current
	// state will be looked up dynamically.
	NetMon *netmon.Monitor

	// DNSCache is the caching Resolver to use to connect to the server.
	//
	// This field can be nil.
	DNSCache *dnscache.Resolver

	// HealthTracker, if non-nil, is the health tracker to use.
	HealthTracker *health.Tracker

	// DialPlan, if set, is a function that should return an explicit plan
	// on how to connect to the server.
	DialPlan func() *tailcfg.ControlDialPlan

	// ProtocolVersion, if non-zero, specifies an alternate
	// protocol version to use instead of the default,
	// of [tailcfg.CurrentCapabilityVersion].
	ProtocolVersion uint16
}

// NewClient returns a new noiseClient for the provided server and machine key.
//
// netMon may be nil, if non-nil it's used to do faster interface lookups.
// dialPlan may be nil
func NewClient(opts ClientOpts) (*Client, error) {
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	if opts.ServerURL == "" {
		return nil, errors.New("ServerURL is required")
	}
	if opts.PrivKey.IsZero() {
		return nil, errors.New("PrivKey is required")
	}
	if opts.ServerPubKey.IsZero() {
		return nil, errors.New("ServerPubKey is required")
	}
	if opts.Dialer == nil {
		return nil, errors.New("Dialer is required")
	}

	u, err := url.Parse(opts.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ClientOpts.ServerURL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("invalid ServerURL scheme, must be http or https")
	}

	httpPort, httpsPort := "80", "443"
	addr, _ := netip.ParseAddr(u.Hostname())
	isPrivateHost := addr.IsPrivate() || addr.IsLoopback() || u.Hostname() == "localhost"
	if port := u.Port(); port != "" {
		// If there is an explicit port specified, entirely rely on the scheme,
		// unless it's http with a private host in which case we never try using HTTPS.
		if u.Scheme == "https" {
			httpPort = ""
			httpsPort = port
		} else if u.Scheme == "http" {
			httpPort = port
			httpsPort = "443"
			if isPrivateHost {
				logf("setting empty HTTPS port with http scheme and private host %s", u.Hostname())
				httpsPort = ""
			}
		}
	} else if u.Scheme == "http" && isPrivateHost {
		// Whenever the scheme is http and the hostname is an IP address, do not set the HTTPS port,
		// as there cannot be a TLS certificate issued for an IP, unless it's a public IP.
		httpPort = "80"
		httpsPort = ""
	}

	np := &Client{
		opts:      opts,
		host:      u.Hostname(),
		httpPort:  httpPort,
		httpsPort: httpsPort,
		logf:      logf,
	}

	tr := &http.Transport{
		Protocols:       new(http.Protocols),
		MaxConnsPerHost: 1,
	}
	// We force only HTTP/2 for this transport, which is what the control server
	// speaks inside the ts2021 Noise encryption. But Go doesn't know about that,
	// so we use "SetUnencryptedHTTP2" even though it's actually encrypted.
	tr.Protocols.SetUnencryptedHTTP2(true)
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return np.dial(ctx)
	}

	np.Client = &http.Client{Transport: tr}
	return np, nil
}

// Close closes all the underlying noise connections.
// It is a no-op and returns nil if the connection is already closed.
func (nc *Client) Close() error {
	nc.mu.Lock()
	live := nc.connPool
	nc.closed = true
	nc.connPool = nil // stop noteConnClosed from mutating it as we loop over it (in live) below
	nc.mu.Unlock()

	for _, c := range live {
		c.Close()
	}
	nc.Client.CloseIdleConnections()

	return nil
}

// dial opens a new connection to tailcontrol, fetching the server noise key
// if not cached.
func (nc *Client) dial(ctx context.Context) (*Conn, error) {
	if tailcfg.CurrentCapabilityVersion > math.MaxUint16 {
		// Panic, because a test should have started failing several
		// thousand version numbers before getting to this point.
		panic("capability version is too high to fit in the wire protocol")
	}

	var dialPlan *tailcfg.ControlDialPlan
	if nc.opts.DialPlan != nil {
		dialPlan = nc.opts.DialPlan()
	}

	// If we have a dial plan, then set our timeout as slightly longer than
	// the maximum amount of time contained therein; we assume that
	// explicit instructions on timeouts are more useful than a single
	// hard-coded timeout.
	//
	// The default value of 5 is chosen so that, when there's no dial plan,
	// we retain the previous behaviour of 10 seconds end-to-end timeout.
	timeoutSec := 5.0
	if dialPlan != nil {
		for _, c := range dialPlan.Candidates {
			if v := c.DialStartDelaySec + c.DialTimeoutSec; v > timeoutSec {
				timeoutSec = v
			}
		}
	}

	// After we establish a connection, we need some time to actually
	// upgrade it into a Noise connection. With a ballpark worst-case RTT
	// of 1000ms, give ourselves an extra 5 seconds to complete the
	// handshake.
	timeoutSec += 5

	// Be extremely defensive and ensure that the timeout is in the range
	// [5, 60] seconds (e.g. if we accidentally get a negative number).
	if timeoutSec > 60 {
		timeoutSec = 60
	} else if timeoutSec < 5 {
		timeoutSec = 5
	}

	timeout := time.Duration(timeoutSec * float64(time.Second))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	chd := &controlhttp.Dialer{
		Hostname:        nc.host,
		HTTPPort:        nc.httpPort,
		HTTPSPort:       cmp.Or(nc.httpsPort, controlhttp.NoPort),
		MachineKey:      nc.opts.PrivKey,
		ControlKey:      nc.opts.ServerPubKey,
		ProtocolVersion: cmp.Or(nc.opts.ProtocolVersion, uint16(tailcfg.CurrentCapabilityVersion)),
		Dialer:          nc.opts.Dialer.SystemDial,
		DNSCache:        nc.opts.DNSCache,
		DialPlan:        dialPlan,
		Logf:            nc.logf,
		NetMon:          nc.opts.NetMon,
		HealthTracker:   nc.opts.HealthTracker,
		Clock:           tstime.StdClock{},
	}
	clientConn, err := chd.Dial(ctx)
	if err != nil {
		return nil, err
	}

	nc.mu.Lock()

	handle := set.NewHandle()
	ncc := NewConn(clientConn.Conn, func() { nc.noteConnClosed(handle) })
	mak.Set(&nc.connPool, handle, ncc)

	if nc.closed {
		nc.mu.Unlock()
		ncc.Close() // Needs to be called without holding the lock.
		return nil, errors.New("noise client closed")
	}

	defer nc.mu.Unlock()
	return ncc, nil
}

// noteConnClosed notes that the *Conn with the given handle has closed and
// should be removed from the live connPool (which is usually of size 0 or 1,
// except perhaps briefly 2 during a network failure and reconnect).
func (nc *Client) noteConnClosed(handle set.Handle) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.connPool.Delete(handle)
}

// post does a POST to the control server at the given path, JSON-encoding body.
// The provided nodeKey is an optional load balancing hint.
func (nc *Client) Post(ctx context.Context, path string, nodeKey key.NodePublic, body any) (*http.Response, error) {
	return nc.DoWithBody(ctx, "POST", path, nodeKey, body)
}

func (nc *Client) DoWithBody(ctx context.Context, method, path string, nodeKey key.NodePublic, body any) (*http.Response, error) {
	jbody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+nc.host+path, bytes.NewReader(jbody))
	if err != nil {
		return nil, err
	}
	AddLBHeader(req, nodeKey)
	req.Header.Set("Content-Type", "application/json")
	return nc.Do(req)
}

// AddLBHeader adds the load balancer header to req if nodeKey is non-zero.
func AddLBHeader(req *http.Request, nodeKey key.NodePublic) {
	if !nodeKey.IsZero() {
		req.Header.Add(tailcfg.LBHeader, nodeKey.String())
	}
}
