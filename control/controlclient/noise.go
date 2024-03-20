// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
	"tailscale.com/util/singleflight"
)

// noiseConn is a wrapper around controlbase.Conn.
// It allows attaching an ID to a connection to allow
// cleaning up references in the pool when the connection
// is closed.
type noiseConn struct {
	*controlbase.Conn
	id   int
	pool *NoiseClient
	h2cc *http2.ClientConn

	readHeaderOnce    sync.Once     // guards init of reader field
	reader            io.Reader     // (effectively Conn.Reader after header)
	earlyPayloadReady chan struct{} // closed after earlyPayload is set (including set to nil)
	earlyPayload      *tailcfg.EarlyNoise
	earlyPayloadErr   error
}

func (c *noiseConn) RoundTrip(r *http.Request) (*http.Response, error) {
	return c.h2cc.RoundTrip(r)
}

// getEarlyPayload waits for the early noise payload to arrive.
// It may return (nil, nil) if the server begins HTTP/2 without one.
func (c *noiseConn) getEarlyPayload(ctx context.Context) (*tailcfg.EarlyNoise, error) {
	select {
	case <-c.earlyPayloadReady:
		return c.earlyPayload, c.earlyPayloadErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// The first 9 bytes from the server to client over Noise are either an HTTP/2
// settings frame (a normal HTTP/2 setup) or, as we added later, an "early payload"
// header that's also 9 bytes long: 5 bytes (earlyPayloadMagic) followed by 4 bytes
// of length. Then that many bytes of JSON-encoded tailcfg.EarlyNoise.
// The early payload is optional. Some servers may not send it.
const (
	hdrLen            = 9 // http2 frame header size; also size of our early payload size header
	earlyPayloadMagic = "\xff\xff\xffTS"
)

// returnErrReader is an io.Reader that always returns an error.
type returnErrReader struct {
	err error // the error to return
}

func (r returnErrReader) Read([]byte) (int, error) { return 0, r.err }

// Read is basically the same as controlbase.Conn.Read, but it first reads the
// "early payload" header from the server which may or may not be present,
// depending on the server.
func (c *noiseConn) Read(p []byte) (n int, err error) {
	c.readHeaderOnce.Do(c.readHeader)
	return c.reader.Read(p)
}

// readHeader reads the optional "early payload" from the server that arrives
// after the Noise handshake but before the HTTP/2 session begins.
//
// readHeader is responsible for reading the header (if present), initializing
// c.earlyPayload, closing c.earlyPayloadReady, and initializing c.reader for
// future reads.
func (c *noiseConn) readHeader() {
	defer close(c.earlyPayloadReady)

	setErr := func(err error) {
		c.reader = returnErrReader{err}
		c.earlyPayloadErr = err
	}

	var hdr [hdrLen]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		setErr(err)
		return
	}
	if string(hdr[:len(earlyPayloadMagic)]) != earlyPayloadMagic {
		// No early payload. We have to return the 9 bytes read we already
		// consumed.
		c.reader = io.MultiReader(bytes.NewReader(hdr[:]), c.Conn)
		return
	}
	epLen := binary.BigEndian.Uint32(hdr[len(earlyPayloadMagic):])
	if epLen > 10<<20 {
		setErr(errors.New("invalid early payload length"))
		return
	}
	payBuf := make([]byte, epLen)
	if _, err := io.ReadFull(c.Conn, payBuf); err != nil {
		setErr(err)
		return
	}
	if err := json.Unmarshal(payBuf, &c.earlyPayload); err != nil {
		setErr(err)
		return
	}
	c.reader = c.Conn
}

func (c *noiseConn) Close() error {
	if err := c.Conn.Close(); err != nil {
		return err
	}
	c.pool.connClosed(c.id)
	return nil
}

// NoiseClient provides a http.Client to connect to tailcontrol over
// the ts2021 protocol.
type NoiseClient struct {
	// Client is an HTTP client to talk to the coordination server.
	// It automatically makes a new Noise connection as needed.
	// It does not support node key proofs. To do that, call
	// noiseClient.getConn instead to make a connection.
	*http.Client

	// h2t is the HTTP/2 transport we use a bit to create new
	// *http2.ClientConns. We don't use its connection pool and we don't use its
	// dialing. We use it for exactly one reason: its idle timeout that can only
	// be configured via the HTTP/1 config. And then we call NewClientConn (with
	// an existing Noise connection) on the http2.Transport which sets up an
	// http2.ClientConn using that idle timeout from an http1.Transport.
	h2t *http2.Transport

	// sfDial ensures that two concurrent requests for a noise connection only
	// produce one shared one between the two callers.
	sfDial singleflight.Group[struct{}, *noiseConn]

	dialer       *tsdial.Dialer
	dnsCache     *dnscache.Resolver
	privKey      key.MachinePrivate
	serverPubKey key.MachinePublic
	host         string // the host part of serverURL
	httpPort     string // the default port to call
	httpsPort    string // the fallback Noise-over-https port

	// dialPlan optionally returns a ControlDialPlan previously received
	// from the control server; either the function or the return value can
	// be nil.
	dialPlan func() *tailcfg.ControlDialPlan

	logf   logger.Logf
	netMon *netmon.Monitor

	// mu only protects the following variables.
	mu       sync.Mutex
	closed   bool
	last     *noiseConn // or nil
	nextID   int
	connPool map[int]*noiseConn // active connections not yet closed; see noiseConn.Close
}

// NoiseOpts contains options for the NewNoiseClient function. All fields are
// required unless otherwise specified.
type NoiseOpts struct {
	// PrivKey is this node's private key.
	PrivKey key.MachinePrivate
	// ServerPubKey is the public key of the server.
	ServerPubKey key.MachinePublic
	// ServerURL is the URL of the server to connect to.
	ServerURL string
	// Dialer's SystemDial function is used to connect to the server.
	Dialer *tsdial.Dialer
	// DNSCache is the caching Resolver to use to connect to the server.
	//
	// This field can be nil.
	DNSCache *dnscache.Resolver
	// Logf is the log function to use. This field can be nil.
	Logf logger.Logf
	// NetMon is the network monitor that, if set, will be used to get the
	// network interface state. This field can be nil; if so, the current
	// state will be looked up dynamically.
	NetMon *netmon.Monitor
	// DialPlan, if set, is a function that should return an explicit plan
	// on how to connect to the server.
	DialPlan func() *tailcfg.ControlDialPlan
}

// NewNoiseClient returns a new noiseClient for the provided server and machine key.
// serverURL is of the form https://<host>:<port> (no trailing slash).
//
// netMon may be nil, if non-nil it's used to do faster interface lookups.
// dialPlan may be nil
func NewNoiseClient(opts NoiseOpts) (*NoiseClient, error) {
	u, err := url.Parse(opts.ServerURL)
	if err != nil {
		return nil, err
	}
	var httpPort string
	var httpsPort string
	if u.Port() != "" {
		// If there is an explicit port specified, trust the scheme and hope for the best
		if u.Scheme == "http" {
			httpPort = u.Port()
			httpsPort = "443"
		} else {
			httpPort = "80"
			httpsPort = u.Port()
		}
	} else {
		// Otherwise, use the standard ports
		httpPort = "80"
		httpsPort = "443"
	}

	np := &NoiseClient{
		serverPubKey: opts.ServerPubKey,
		privKey:      opts.PrivKey,
		host:         u.Hostname(),
		httpPort:     httpPort,
		httpsPort:    httpsPort,
		dialer:       opts.Dialer,
		dnsCache:     opts.DNSCache,
		dialPlan:     opts.DialPlan,
		logf:         opts.Logf,
		netMon:       opts.NetMon,
	}

	// Create the HTTP/2 Transport using a net/http.Transport
	// (which only does HTTP/1) because it's the only way to
	// configure certain properties on the http2.Transport. But we
	// never actually use the net/http.Transport for any HTTP/1
	// requests.
	h2Transport, err := http2.ConfigureTransports(&http.Transport{
		IdleConnTimeout: time.Minute,
	})
	if err != nil {
		return nil, err
	}
	np.h2t = h2Transport

	np.Client = &http.Client{Transport: np}
	return np, nil
}

// GetSingleUseRoundTripper returns a RoundTripper that can be only be used once
// (and must be used once) to make a single HTTP request over the noise channel
// to the coordination server.
//
// In addition to the RoundTripper, it returns the HTTP/2 channel's early noise
// payload, if any.
func (nc *NoiseClient) GetSingleUseRoundTripper(ctx context.Context) (http.RoundTripper, *tailcfg.EarlyNoise, error) {
	for tries := 0; tries < 3; tries++ {
		conn, err := nc.getConn(ctx)
		if err != nil {
			return nil, nil, err
		}
		earlyPayloadMaybeNil, err := conn.getEarlyPayload(ctx)
		if err != nil {
			return nil, nil, err
		}
		if conn.h2cc.ReserveNewRequest() {
			return conn, earlyPayloadMaybeNil, nil
		}
	}
	return nil, nil, errors.New("[unexpected] failed to reserve a request on a connection")
}

// contextErr is an error that wraps another error and is used to indicate that
// the error was because a context expired.
type contextErr struct {
	err error
}

func (e contextErr) Error() string {
	return e.err.Error()
}

func (e contextErr) Unwrap() error {
	return e.err
}

// getConn returns a noiseConn that can be used to make requests to the
// coordination server. It may return a cached connection or create a new one.
// Dials are singleflighted, so concurrent calls to getConn may only dial once.
// As such, context values may not be respected as there are no guarantees that
// the context passed to getConn is the same as the context passed to dial.
func (nc *NoiseClient) getConn(ctx context.Context) (*noiseConn, error) {
	nc.mu.Lock()
	if last := nc.last; last != nil && last.canTakeNewRequest() {
		nc.mu.Unlock()
		return last, nil
	}
	nc.mu.Unlock()

	for {
		// We singeflight the dial to avoid making multiple connections, however
		// that means that we can't simply cancel the dial if the context is
		// canceled. Instead, we have to additionally check that the context
		// which was canceled is our context and retry if our context is still
		// valid.
		conn, err, _ := nc.sfDial.Do(struct{}{}, func() (*noiseConn, error) {
			c, err := nc.dial(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil, contextErr{ctx.Err()}
				}
				return nil, err
			}
			return c, nil
		})
		var ce contextErr
		if err == nil || !errors.As(err, &ce) {
			return conn, err
		}
		if ctx.Err() == nil {
			// The dial failed because of a context error, but our context
			// is still valid. Retry.
			continue
		}
		// The dial failed because our context was canceled. Return the
		// underlying error.
		return nil, ce.Unwrap()
	}
}

func (nc *NoiseClient) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	conn, err := nc.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return conn.RoundTrip(req)
}

// connClosed removes the connection with the provided ID from the pool
// of active connections.
func (nc *NoiseClient) connClosed(id int) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	conn := nc.connPool[id]
	if conn != nil {
		delete(nc.connPool, id)
		if nc.last == conn {
			nc.last = nil
		}
	}
}

// Close closes all the underlying noise connections.
// It is a no-op and returns nil if the connection is already closed.
func (nc *NoiseClient) Close() error {
	nc.mu.Lock()
	nc.closed = true
	conns := nc.connPool
	nc.connPool = nil
	nc.mu.Unlock()

	var errors []error
	for _, c := range conns {
		if err := c.Close(); err != nil {
			errors = append(errors, err)
		}
	}
	return multierr.New(errors...)
}

// dial opens a new connection to tailcontrol, fetching the server noise key
// if not cached.
func (nc *NoiseClient) dial(ctx context.Context) (*noiseConn, error) {
	nc.mu.Lock()
	connID := nc.nextID
	nc.nextID++
	nc.mu.Unlock()

	if tailcfg.CurrentCapabilityVersion > math.MaxUint16 {
		// Panic, because a test should have started failing several
		// thousand version numbers before getting to this point.
		panic("capability version is too high to fit in the wire protocol")
	}

	var dialPlan *tailcfg.ControlDialPlan
	if nc.dialPlan != nil {
		dialPlan = nc.dialPlan()
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

	clientConn, err := (&controlhttp.Dialer{
		Hostname:        nc.host,
		HTTPPort:        nc.httpPort,
		HTTPSPort:       nc.httpsPort,
		MachineKey:      nc.privKey,
		ControlKey:      nc.serverPubKey,
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
		Dialer:          nc.dialer.SystemDial,
		DNSCache:        nc.dnsCache,
		DialPlan:        dialPlan,
		Logf:            nc.logf,
		NetMon:          nc.netMon,
		Clock:           tstime.StdClock{},
	}).Dial(ctx)
	if err != nil {
		return nil, err
	}

	ncc := &noiseConn{
		Conn:              clientConn.Conn,
		id:                connID,
		pool:              nc,
		earlyPayloadReady: make(chan struct{}),
	}

	h2cc, err := nc.h2t.NewClientConn(ncc)
	if err != nil {
		return nil, err
	}
	ncc.h2cc = h2cc

	nc.mu.Lock()
	if nc.closed {
		nc.mu.Unlock()
		ncc.Close() // Needs to be called without holding the lock.
		return nil, errors.New("noise client closed")
	}
	defer nc.mu.Unlock()
	mak.Set(&nc.connPool, ncc.id, ncc)
	nc.last = ncc
	return ncc, nil
}

// post does a POST to the control server at the given path, JSON-encoding body.
// The provided nodeKey is an optional load balancing hint.
func (nc *NoiseClient) post(ctx context.Context, path string, nodeKey key.NodePublic, body any) (*http.Response, error) {
	jbody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+nc.host+path, bytes.NewReader(jbody))
	if err != nil {
		return nil, err
	}
	addLBHeader(req, nodeKey)
	req.Header.Set("Content-Type", "application/json")

	conn, err := nc.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return conn.h2cc.RoundTrip(req)
}

func (c *noiseConn) canTakeNewRequest() bool {
	return c.h2cc.CanTakeNewRequest()
}
