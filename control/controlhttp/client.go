// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

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
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netutil"
	"tailscale.com/net/sockstats"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/multierr"
)

var stdDialer net.Dialer

// Dial connects to the HTTP server at this Dialer's Host:HTTPPort, requests to
// switch to the Tailscale control protocol, and returns an established control
// protocol connection.
//
// If Dial fails to connect using HTTP, it also tries to tunnel over TLS to the
// Dialer's Host:HTTPSPort as a compatibility fallback.
//
// The provided ctx is only used for the initial connection, until
// Dial returns. It does not affect the connection once established.
func (a *Dialer) Dial(ctx context.Context) (*ClientConn, error) {
	if a.Hostname == "" {
		return nil, errors.New("required Dialer.Hostname empty")
	}
	return a.dial(ctx)
}

func (a *Dialer) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}

func (a *Dialer) getProxyFunc() func(*http.Request) (*url.URL, error) {
	if a.proxyFunc != nil {
		return a.proxyFunc
	}
	return tshttpproxy.ProxyFromEnvironment
}

// httpsFallbackDelay is how long we'll wait for a.HTTPPort to work before
// starting to try a.HTTPSPort.
func (a *Dialer) httpsFallbackDelay() time.Duration {
	if forceNoise443() {
		return time.Nanosecond
	}
	if v := a.testFallbackDelay; v != 0 {
		return v
	}
	return 500 * time.Millisecond
}

var _ = envknob.RegisterBool("TS_USE_CONTROL_DIAL_PLAN") // to record at init time whether it's in use

func (a *Dialer) dial(ctx context.Context) (*ClientConn, error) {
	// If we don't have a dial plan, just fall back to dialing the single
	// host we know about.
	useDialPlan := envknob.BoolDefaultTrue("TS_USE_CONTROL_DIAL_PLAN")
	if !useDialPlan || a.DialPlan == nil || len(a.DialPlan.Candidates) == 0 {
		return a.dialHost(ctx, netip.Addr{})
	}
	candidates := a.DialPlan.Candidates

	// Otherwise, we try dialing per the plan. Store the highest priority
	// in the list, so that if we get a connection to one of those
	// candidates we can return quickly.
	var highestPriority int = math.MinInt
	for _, c := range candidates {
		if c.Priority > highestPriority {
			highestPriority = c.Priority
		}
	}

	// This context allows us to cancel in-flight connections if we get a
	// highest-priority connection before we're all done.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Now, for each candidate, kick off a dial in parallel.
	type dialResult struct {
		conn     *ClientConn
		err      error
		addr     netip.Addr
		priority int
	}
	resultsCh := make(chan dialResult, len(candidates))

	var pending atomic.Int32
	pending.Store(int32(len(candidates)))
	for _, c := range candidates {
		go func(ctx context.Context, c tailcfg.ControlIPCandidate) {
			var (
				conn *ClientConn
				err  error
			)

			// Always send results back to our channel.
			defer func() {
				resultsCh <- dialResult{conn, err, c.IP, c.Priority}
				if pending.Add(-1) == 0 {
					close(resultsCh)
				}
			}()

			// If non-zero, wait the configured start timeout
			// before we do anything.
			if c.DialStartDelaySec > 0 {
				a.logf("[v2] controlhttp: waiting %.2f seconds before dialing %q @ %v", c.DialStartDelaySec, a.Hostname, c.IP)
				if a.Clock == nil {
					a.Clock = tstime.StdClock{}
				}
				tmr, tmrChannel := a.Clock.NewTimer(time.Duration(c.DialStartDelaySec * float64(time.Second)))
				defer tmr.Stop()
				select {
				case <-ctx.Done():
					err = ctx.Err()
					return
				case <-tmrChannel:
				}
			}

			// Now, create a sub-context with the given timeout and
			// try dialing the provided host.
			ctx, cancel := context.WithTimeout(ctx, time.Duration(c.DialTimeoutSec*float64(time.Second)))
			defer cancel()

			// This will dial, and the defer above sends it back to our parent.
			a.logf("[v2] controlhttp: trying to dial %q @ %v", a.Hostname, c.IP)
			conn, err = a.dialHost(ctx, c.IP)
		}(ctx, c)
	}

	var results []dialResult
	for res := range resultsCh {
		// If we get a response that has the highest priority, we don't
		// need to wait for any of the other connections to finish; we
		// can just return this connection.
		//
		// TODO(andrew): we could make this better by keeping track of
		// the highest remaining priority dynamically, instead of just
		// checking for the highest total
		if res.priority == highestPriority && res.conn != nil {
			a.logf("[v1] controlhttp: high-priority success dialing %q @ %v from dial plan", a.Hostname, res.addr)

			// Drain the channel and any existing connections in
			// the background.
			go func() {
				for _, res := range results {
					if res.conn != nil {
						res.conn.Close()
					}
				}
				for res := range resultsCh {
					if res.conn != nil {
						res.conn.Close()
					}
				}
				if a.drainFinished != nil {
					close(a.drainFinished)
				}
			}()
			return res.conn, nil
		}

		// This isn't a highest-priority result, so just store it until
		// we're done.
		results = append(results, res)
	}

	// After we finish this function, close any remaining open connections.
	defer func() {
		for _, result := range results {
			// Note: below, we nil out the returned connection (if
			// any) in the slice so we don't close it.
			if result.conn != nil {
				result.conn.Close()
			}
		}

		// We don't drain asynchronously after this point, so notify our
		// channel when we return.
		if a.drainFinished != nil {
			close(a.drainFinished)
		}
	}()

	// Sort by priority, then take the first non-error response.
	sort.Slice(results, func(i, j int) bool {
		// NOTE: intentionally inverted so that the highest priority
		// item comes first
		return results[i].priority > results[j].priority
	})

	var (
		conn *ClientConn
		errs []error
	)
	for i, result := range results {
		if result.err != nil {
			errs = append(errs, result.err)
			continue
		}

		a.logf("[v1] controlhttp: succeeded dialing %q @ %v from dial plan", a.Hostname, result.addr)
		conn = result.conn
		results[i].conn = nil // so we don't close it in the defer
		return conn, nil
	}
	merr := multierr.New(errs...)

	// If we get here, then we didn't get anywhere with our dial plan; fall back to just using DNS.
	a.logf("controlhttp: failed dialing using DialPlan, falling back to DNS; errs=%s", merr.Error())
	return a.dialHost(ctx, netip.Addr{})
}

// The TS_FORCE_NOISE_443 envknob forces the controlclient noise dialer to
// always use port 443 HTTPS connections to the controlplane and not try the
// port 80 HTTP fast path.
//
// This is currently (2023-01-17) needed for Docker Desktop's "VPNKit" proxy
// that breaks port 80 for us post-Noise-handshake, causing us to never try port
// 443. Until one of Docker's proxy and/or this package's port 443 fallback is
// fixed, this is a workaround. It might also be useful for future debugging.
var forceNoise443 = envknob.RegisterBool("TS_FORCE_NOISE_443")

var debugNoiseDial = envknob.RegisterBool("TS_DEBUG_NOISE_DIAL")

// dialHost connects to the configured Dialer.Hostname and upgrades the
// connection into a controlbase.Conn. If addr is valid, then no DNS is used
// and the connection will be made to the provided address.
func (a *Dialer) dialHost(ctx context.Context, addr netip.Addr) (*ClientConn, error) {
	// Create one shared context used by both port 80 and port 443 dials.
	// If port 80 is still in flight when 443 returns, this deferred cancel
	// will stop the port 80 dial.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = sockstats.WithSockStats(ctx, sockstats.LabelControlClientDialer, a.logf)

	// u80 and u443 are the URLs we'll try to hit over HTTP or HTTPS,
	// respectively, in order to do the HTTP upgrade to a net.Conn over which
	// we'll speak Noise.
	u80 := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(a.Hostname, strDef(a.HTTPPort, "80")),
		Path:   serverUpgradePath,
	}
	u443 := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(a.Hostname, strDef(a.HTTPSPort, "443")),
		Path:   serverUpgradePath,
	}

	type tryURLRes struct {
		u    *url.URL    // input (the URL conn+err are for/from)
		conn *ClientConn // result (mutually exclusive with err)
		err  error
	}
	ch := make(chan tryURLRes) // must be unbuffered
	try := func(u *url.URL) {
		if debugNoiseDial() {
			a.logf("trying noise dial (%v, %v) ...", u, addr)
		}
		cbConn, err := a.dialURL(ctx, u, addr)
		if debugNoiseDial() {
			a.logf("noise dial (%v, %v) = (%v, %v)", u, addr, cbConn, err)
		}
		select {
		case ch <- tryURLRes{u, cbConn, err}:
		case <-ctx.Done():
			if cbConn != nil {
				cbConn.Close()
			}
		}
	}

	// Start the plaintext HTTP attempt first, unless disabled by the envknob.
	if !forceNoise443() {
		go try(u80)
	}

	// In case outbound port 80 blocked or MITM'ed poorly, start a backup timer
	// to dial port 443 if port 80 doesn't either succeed or fail quickly.
	if a.Clock == nil {
		a.Clock = tstime.StdClock{}
	}
	try443Timer := a.Clock.AfterFunc(a.httpsFallbackDelay(), func() { try(u443) })
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
func (a *Dialer) dialURL(ctx context.Context, u *url.URL, addr netip.Addr) (*ClientConn, error) {
	init, cont, err := controlbase.ClientDeferred(a.MachineKey, a.ControlKey, a.ProtocolVersion)
	if err != nil {
		return nil, err
	}
	netConn, err := a.tryURLUpgrade(ctx, u, addr, init)
	if err != nil {
		return nil, err
	}
	cbConn, err := cont(ctx, netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return &ClientConn{
		Conn: cbConn,
	}, nil
}

// resolver returns a.DNSCache if non-nil or a new *dnscache.Resolver
// otherwise.
func (a *Dialer) resolver() *dnscache.Resolver {
	if a.DNSCache != nil {
		return a.DNSCache
	}

	return &dnscache.Resolver{
		Forward:          dnscache.Get().Forward,
		LookupIPFallback: dnsfallback.MakeLookupFunc(a.logf, a.NetMon),
		UseLastGood:      true,
		Logf:             a.Logf, // not a.logf method; we want to propagate nil-ness
	}
}

func isLoopback(a net.Addr) bool {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP.IsLoopback()
	}
	return false
}

var macOSScreenTime = health.Register(&health.Warnable{
	Code:     "macos-screen-time",
	Severity: health.SeverityHigh,
	Title:    "Tailscale blocked by Screen Time",
	Text: func(args health.Args) string {
		return "macOS Screen Time seems to be blocking Tailscale. Try disabling Screen Time in System Settings > Screen Time > Content & Privacy > Access to Web Content."
	},
	ImpactsConnectivity: true,
})

// tryURLUpgrade connects to u, and tries to upgrade it to a net.Conn. If addr
// is valid, then no DNS is used and the connection will be made to the
// provided address.
//
// Only the provided ctx is used, not a.ctx.
func (a *Dialer) tryURLUpgrade(ctx context.Context, u *url.URL, addr netip.Addr, init []byte) (_ net.Conn, retErr error) {
	var dns *dnscache.Resolver

	// If we were provided an address to dial, then create a resolver that just
	// returns that value; otherwise, fall back to DNS.
	if addr.IsValid() {
		dns = &dnscache.Resolver{
			SingleHostStaticResult: []netip.Addr{addr},
			SingleHost:             u.Hostname(),
			Logf:                   a.Logf, // not a.logf method; we want to propagate nil-ness
		}
	} else {
		dns = a.resolver()
	}

	var dialer dnscache.DialContextFunc
	if a.Dialer != nil {
		dialer = a.Dialer
	} else {
		dialer = stdDialer.DialContext
	}

	// On macOS, see if Screen Time is blocking things.
	if runtime.GOOS == "darwin" {
		var proxydIntercepted atomic.Bool // intercepted by macOS webfilterproxyd
		origDialer := dialer
		dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := origDialer(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if isLoopback(c.LocalAddr()) && isLoopback(c.RemoteAddr()) {
				proxydIntercepted.Store(true)
			}
			return c, nil
		}
		defer func() {
			if retErr != nil && proxydIntercepted.Load() {
				a.HealthTracker.SetUnhealthy(macOSScreenTime, nil)
				retErr = fmt.Errorf("macOS Screen Time is blocking network access: %w", retErr)
			} else {
				a.HealthTracker.SetHealthy(macOSScreenTime)
			}
		}()
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	defer tr.CloseIdleConnections()
	tr.Proxy = a.getProxyFunc()
	tshttpproxy.SetTransportGetProxyConnectHeader(tr)
	tr.DialContext = dnscache.Dialer(dialer, dns)
	// Disable HTTP2, since h2 can't do protocol switching.
	tr.TLSClientConfig.NextProtos = []string{}
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tr.TLSClientConfig = tlsdial.Config(a.Hostname, a.HealthTracker, tr.TLSClientConfig)
	if !tr.TLSClientConfig.InsecureSkipVerify {
		panic("unexpected") // should be set by tlsdial.Config
	}
	verify := tr.TLSClientConfig.VerifyConnection
	if verify == nil {
		panic("unexpected") // should be set by tlsdial.Config
	}
	// Demote all cert verification errors to log messages. We don't actually
	// care about the TLS security (because we just do the Noise crypto atop whatever
	// connection we get, including HTTP port 80 plaintext) so this permits
	// middleboxes to MITM their users. All they'll see is some Noise.
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := verify(cs); err != nil && a.Logf != nil && !a.omitCertErrorLogging {
			a.Logf("warning: TLS cert verificication for %q failed: %v", a.Hostname, err)
		}
		return nil // regardless
	}

	tr.DialTLSContext = dnscache.TLSDialer(dialer, dns, tr.TLSClientConfig)
	tr.DisableCompression = true

	// (mis)use httptrace to extract the underlying net.Conn from the
	// transport. The transport handles 101 Switching Protocols correctly,
	// such that the Conn will not be reused or kept alive by the transport
	// once the response has been handed back from RoundTrip.
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
	var lastConn syncs.AtomicValue[net.Conn]
	trace := httptrace.ClientTrace{
		// Even though we only make a single HTTP request which should
		// require a single connection, the context (with the attached
		// trace configuration) might be used by our custom dialer to
		// make other HTTP requests (e.g. BootstrapDNS). We only care
		// about the last connection made, which should be the one to
		// the control server.
		GotConn: func(info httptrace.GotConnInfo) {
			lastConn.Store(info.Conn)
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
	switchedConn := lastConn.Load()
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
