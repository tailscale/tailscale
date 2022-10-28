// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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
	pool *noiseClient
	h2cc *http2.ClientConn
}

func (c *noiseConn) Close() error {
	if err := c.Conn.Close(); err != nil {
		return err
	}
	c.pool.connClosed(c.id)
	return nil
}

// noiseClient provides a http.Client to connect to tailcontrol over
// the ts2021 protocol.
type noiseClient struct {
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
	privKey      key.MachinePrivate
	serverPubKey key.MachinePublic
	host         string // the host part of serverURL
	httpPort     string // the default port to call
	httpsPort    string // the fallback Noise-over-https port

	// dialPlan optionally returns a ControlDialPlan previously received
	// from the control server; either the function or the return value can
	// be nil.
	dialPlan func() *tailcfg.ControlDialPlan

	// mu only protects the following variables.
	mu       sync.Mutex
	last     *noiseConn // or nil
	nextID   int
	connPool map[int]*noiseConn // active connections not yet closed; see noiseConn.Close
}

// newNoiseClient returns a new noiseClient for the provided server and machine key.
// serverURL is of the form https://<host>:<port> (no trailing slash).
//
// dialPlan may be nil
func newNoiseClient(priKey key.MachinePrivate, serverPubKey key.MachinePublic, serverURL string, dialer *tsdial.Dialer, dialPlan func() *tailcfg.ControlDialPlan) (*noiseClient, error) {
	u, err := url.Parse(serverURL)
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
	np := &noiseClient{
		serverPubKey: serverPubKey,
		privKey:      priKey,
		host:         u.Hostname(),
		httpPort:     httpPort,
		httpsPort:    httpsPort,
		dialer:       dialer,
		dialPlan:     dialPlan,
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

func (nc *noiseClient) getConn(ctx context.Context) (*noiseConn, error) {
	nc.mu.Lock()
	if last := nc.last; last != nil && last.canTakeNewRequest() {
		nc.mu.Unlock()
		return last, nil
	}
	nc.mu.Unlock()

	conn, err, _ := nc.sfDial.Do(struct{}{}, nc.dial)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (nc *noiseClient) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	conn, err := nc.getConn(ctx)
	if err != nil {
		return nil, err
	}
	return conn.h2cc.RoundTrip(req)
}

// connClosed removes the connection with the provided ID from the pool
// of active connections.
func (nc *noiseClient) connClosed(id int) {
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
func (nc *noiseClient) Close() error {
	nc.mu.Lock()
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
func (nc *noiseClient) dial() (*noiseConn, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	clientConn, err := (&controlhttp.Dialer{
		Hostname:        nc.host,
		HTTPPort:        nc.httpPort,
		HTTPSPort:       nc.httpsPort,
		MachineKey:      nc.privKey,
		ControlKey:      nc.serverPubKey,
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
		Dialer:          nc.dialer.SystemDial,
		DialPlan:        dialPlan,
	}).Dial(ctx)
	if err != nil {
		return nil, err
	}

	ncc := &noiseConn{
		Conn: clientConn.Conn,
		id:   connID,
		pool: nc,
	}

	// TODO(bradfitz): wrap clientConn in a type that sniffs the leading bytes
	// from the server to see if it has early post-Noise, pre-H2 data for us.

	h2cc, err := nc.h2t.NewClientConn(ncc)
	if err != nil {
		return nil, err
	}
	ncc.h2cc = h2cc

	nc.mu.Lock()
	defer nc.mu.Unlock()
	mak.Set(&nc.connPool, ncc.id, ncc)
	nc.last = ncc
	return ncc, nil
}

func (nc *noiseClient) post(ctx context.Context, path string, body any) (*http.Response, error) {
	jbody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+nc.host+path, bytes.NewReader(jbody))
	if err != nil {
		return nil, err
	}
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
