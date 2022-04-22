// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
)

// noiseConn is a wrapper around controlbase.Conn.
// It allows attaching an ID to a connection to allow
// cleaning up references in the pool when the connection
// is closed.
type noiseConn struct {
	*controlbase.Conn
	id   int
	pool *noiseClient
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
	*http.Client // HTTP client used to talk to tailcontrol
	privKey      key.MachinePrivate
	serverPubKey key.MachinePublic
	serverHost   string // the host:port part of serverURL

	// mu only protects the following variables.
	mu       sync.Mutex
	nextID   int
	connPool map[int]*noiseConn // active connections not yet closed; see noiseConn.Close
}

// newNoiseClient returns a new noiseClient for the provided server and machine key.
// serverURL is of the form https://<host>:<port> (no trailing slash).
func newNoiseClient(priKey key.MachinePrivate, serverPubKey key.MachinePublic, serverURL string) (*noiseClient, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	var host string
	if u.Port() != "" {
		// If there is an explicit port specified use it.
		host = u.Host
	} else {
		// Otherwise, controlhttp.Dial expects an http endpoint.
		host = fmt.Sprintf("%v:80", u.Hostname())
	}
	np := &noiseClient{
		serverPubKey: serverPubKey,
		privKey:      priKey,
		serverHost:   host,
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

	// Let the HTTP/2 Transport think it's dialing out using TLS,
	// but it's actually our Noise dialer:
	h2Transport.DialTLS = np.dial

	// ConfigureTransports assumes it's being used to wire up an HTTP/1
	// and HTTP/2 Transport together, so its returned http2.Transport
	// has a ConnPool already initialized that's configured to not dial
	// (assuming it's only called from the HTTP/1 Transport). But we
	// want it to dial, so nil it out before use. On first use it has
	// a sync.Once that lazily initializes the ConnPool to its default
	// one that dials.
	h2Transport.ConnPool = nil

	np.Client = &http.Client{Transport: h2Transport}
	return np, nil
}

// connClosed removes the connection with the provided ID from the pool
// of active connections.
func (nc *noiseClient) connClosed(id int) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	delete(nc.connPool, id)
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
// if not cached. It implements the signature needed by http2.Transport.DialTLS
// but ignores all params as it only dials out to the server the noiseClient was
// created for.
func (nc *noiseClient) dial(_, _ string, _ *tls.Config) (net.Conn, error) {
	nc.mu.Lock()
	connID := nc.nextID
	nc.nextID++
	nc.mu.Unlock()

	// Timeout is a little arbitrary, but plenty long enough for even the
	// highest latency links.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if tailcfg.CurrentCapabilityVersion > math.MaxUint16 {
		// Panic, because a test should have started failing several
		// thousand version numbers before getting to this point.
		panic("capability version is too high to fit in the wire protocol")
	}
	conn, err := controlhttp.Dial(ctx, nc.serverHost, nc.privKey, nc.serverPubKey, uint16(tailcfg.CurrentCapabilityVersion))
	if err != nil {
		return nil, err
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()
	ncc := &noiseConn{Conn: conn, id: connID, pool: nc}
	mak.Set(&nc.connPool, ncc.id, ncc)
	return ncc, nil
}
