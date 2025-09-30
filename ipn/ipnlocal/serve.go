// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

// TODO: move this whole file to its own package, out of ipnlocal.

package ipnlocal

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go4.org/mem"
	"tailscale.com/ipn"
	"tailscale.com/net/netutil"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/ctxkey"
	"tailscale.com/util/mak"
	"tailscale.com/util/slicesx"
	"tailscale.com/version"
)

func init() {
	hookServeTCPHandlerForVIPService.Set((*LocalBackend).tcpHandlerForVIPService)
	hookTCPHandlerForServe.Set((*LocalBackend).tcpHandlerForServe)
	hookServeUpdateServeTCPPortNetMapAddrListenersLocked.Set((*LocalBackend).updateServeTCPPortNetMapAddrListenersLocked)

	hookServeSetTCPPortsInterceptedFromNetmapAndPrefsLocked.Set(serveSetTCPPortsInterceptedFromNetmapAndPrefsLocked)
	hookServeClearVIPServicesTCPPortsInterceptedLocked.Set(func(b *LocalBackend) {
		b.setVIPServicesTCPPortsInterceptedLocked(nil)
	})

	RegisterC2N("GET /vip-services", handleC2NVIPServicesGet)
}

const (
	contentTypeHeader   = "Content-Type"
	grpcBaseContentType = "application/grpc"
)

// ErrETagMismatch signals that the given
// If-Match header does not match with the
// current etag of a resource.
var ErrETagMismatch = errors.New("etag mismatch")

var serveHTTPContextKey ctxkey.Key[*serveHTTPContext]

type serveHTTPContext struct {
	SrcAddr       netip.AddrPort
	ForVIPService tailcfg.ServiceName // "" means local
	DestPort      uint16

	// provides funnel-specific context, nil if not funneled
	Funnel *funnelFlow
}

// funnelFlow represents a funneled connection initiated via IngressPeer
// to Host.
type funnelFlow struct {
	Host        string
	IngressPeer tailcfg.NodeView
}

// localListener is the state of host-level net.Listen for a specific (Tailscale IP, port)
// combination. If there are two TailscaleIPs (v4 and v6) and three ports being served,
// then there will be six of these active and looping in their Run method.
//
// This is not used in userspace-networking mode.
//
// localListener is used by tailscale serve (TCP only), the built-in web client and Taildrive.
// Most serve traffic and peer traffic for the web client are intercepted by netstack.
// This listener exists purely for connections from the machine itself, as that goes via the kernel,
// so we need to be in the kernel's listening/routing tables.
type localListener struct {
	b      *LocalBackend
	ap     netip.AddrPort
	ctx    context.Context    // valid while listener is desired
	cancel context.CancelFunc // for ctx, to close listener
	logf   logger.Logf
	bo     *backoff.Backoff // for retrying failed Listen calls

	handler       func(net.Conn) error            // handler for inbound connections
	closeListener syncs.AtomicValue[func() error] // Listener's Close method, if any
}

func (b *LocalBackend) newServeListener(ctx context.Context, ap netip.AddrPort, logf logger.Logf) *localListener {
	ctx, cancel := context.WithCancel(ctx)
	return &localListener{
		b:      b,
		ap:     ap,
		ctx:    ctx,
		cancel: cancel,
		logf:   logf,

		handler: func(conn net.Conn) error {
			srcAddr := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
			handler := b.tcpHandlerForServe(ap.Port(), srcAddr, nil)
			if handler == nil {
				b.logf("[unexpected] local-serve: no handler for %v to port %v", srcAddr, ap.Port())
				conn.Close()
				return nil
			}
			return handler(conn)
		},
		bo: backoff.NewBackoff("serve-listener", logf, 30*time.Second),
	}

}

// Close cancels the context and closes the listener, if any.
func (s *localListener) Close() error {
	s.cancel()
	if close, ok := s.closeListener.LoadOk(); ok {
		s.closeListener.Store(nil)
		close()
	}
	return nil
}

// Run starts a net.Listen for the localListener's address and port.
// If unable to listen, it retries with exponential backoff.
// Listen is retried until the context is canceled.
func (s *localListener) Run() {
	for {
		ip := s.ap.Addr()
		ipStr := ip.String()

		var lc net.ListenConfig
		if initListenConfig != nil {
			// On macOS, this sets the lc.Control hook to
			// setsockopt the interface index to bind to. This is
			// required by the network sandbox to allow binding to
			// a specific interface. Without this hook, the system
			// chooses a default interface to bind to.
			if err := initListenConfig(&lc, ip, s.b.prevIfState, s.b.dialer.TUNName()); err != nil {
				s.logf("localListener failed to init listen config %v, backing off: %v", s.ap, err)
				s.bo.BackOff(s.ctx, err)
				continue
			}
			// On macOS (AppStore or macsys) and if we're binding to a privileged port,
			if version.IsSandboxedMacOS() && s.ap.Port() < 1024 {
				// On macOS, we need to bind to ""/all-interfaces due to
				// the network sandbox. Ideally we would only bind to the
				// Tailscale interface, but macOS errors out if we try to
				// to listen on privileged ports binding only to a specific
				// interface. (#6364)
				ipStr = ""
			}
		}

		tcp4or6 := "tcp4"
		if ip.Is6() {
			tcp4or6 = "tcp6"
		}

		// while we were backing off and trying again, the context got canceled
		// so don't bind, just return, because otherwise there will be no way
		// to close this listener
		if s.ctx.Err() != nil {
			s.logf("localListener context closed before binding")
			return
		}

		ln, err := lc.Listen(s.ctx, tcp4or6, net.JoinHostPort(ipStr, fmt.Sprint(s.ap.Port())))
		if err != nil {
			if s.shouldWarnAboutListenError(err) {
				s.logf("localListener failed to listen on %v, backing off: %v", s.ap, err)
			}
			s.bo.BackOff(s.ctx, err)
			continue
		}
		s.closeListener.Store(ln.Close)

		s.logf("listening on %v", s.ap)
		err = s.handleListenersAccept(ln)
		if s.ctx.Err() != nil {
			// context canceled, we're done
			return
		}
		if err != nil {
			s.logf("localListener accept error, retrying: %v", err)
		}
	}
}

func (s *localListener) shouldWarnAboutListenError(err error) bool {
	if !s.b.sys.NetMon.Get().InterfaceState().HasIP(s.ap.Addr()) {
		// Machine likely doesn't have IPv6 enabled (or the IP is still being
		// assigned). No need to warn. Notably, WSL2 (Issue 6303).
		return false
	}
	// TODO(bradfitz): check errors.Is(err, syscall.EADDRNOTAVAIL) etc? Let's
	// see what happens in practice.
	return true
}

// handleListenersAccept accepts connections for the Listener. It calls the
// handler in a new goroutine for each accepted connection. This is used to
// handle local "tailscale serve" and web client traffic originating from the
// machine itself.
func (s *localListener) handleListenersAccept(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handler(conn)
	}
}

// updateServeTCPPortNetMapAddrListenersLocked starts a net.Listen for configured
// Serve ports on all the node's addresses.
// Existing Listeners are closed if port no longer in incoming ports list.
//
// b.mu must be held.
func (b *LocalBackend) updateServeTCPPortNetMapAddrListenersLocked(ports []uint16) {
	if b.sys.IsNetstack() {
		// don't listen on netmap addresses if we're in userspace mode
		return
	}
	// close existing listeners where port
	// is no longer in incoming ports list
	for ap, sl := range b.serveListeners {
		if !slices.Contains(ports, ap.Port()) {
			b.logf("closing listener %v", ap)
			sl.Close()
			delete(b.serveListeners, ap)
		}
	}

	nm := b.NetMap()
	if nm == nil {
		b.logf("netMap is nil")
		return
	}
	if !nm.SelfNode.Valid() {
		b.logf("netMap SelfNode is nil")
		return
	}

	addrs := nm.GetAddresses()
	for _, a := range addrs.All() {
		for _, p := range ports {
			addrPort := netip.AddrPortFrom(a.Addr(), p)
			if _, ok := b.serveListeners[addrPort]; ok {
				continue // already listening
			}

			sl := b.newServeListener(context.Background(), addrPort, b.logf)
			mak.Set(&b.serveListeners, addrPort, sl)

			go sl.Run()
		}
	}
}

// SetServeConfig establishes or replaces the current serve config.
// ETag is an optional parameter to enforce Optimistic Concurrency Control.
// If it is an empty string, then the config will be overwritten.
func (b *LocalBackend) SetServeConfig(config *ipn.ServeConfig, etag string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.setServeConfigLocked(config, etag)
}

func (b *LocalBackend) setServeConfigLocked(config *ipn.ServeConfig, etag string) error {
	prefs := b.pm.CurrentPrefs()
	if config.IsFunnelOn() && prefs.ShieldsUp() {
		return errors.New("Unable to turn on Funnel while shields-up is enabled")
	}
	if b.isConfigLocked_Locked() {
		return errors.New("can't reconfigure tailscaled when using a config file; config file is locked")
	}

	if config != nil {
		if err := config.CheckValidServicesConfig(); err != nil {
			return err
		}
	}

	nm := b.NetMap()
	if nm == nil {
		return errors.New("netMap is nil")
	}
	if !nm.SelfNode.Valid() {
		return errors.New("netMap SelfNode is nil")
	}

	// If etag is present, check that it has
	// not changed from the last config.
	prevConfig := b.serveConfig
	if etag != "" {
		// Note that we marshal b.serveConfig
		// and not use b.lastServeConfJSON as that might
		// be a Go nil value, which produces a different
		// checksum from a JSON "null" value.
		prevBytes, err := json.Marshal(prevConfig)
		if err != nil {
			return fmt.Errorf("error encoding previous config: %w", err)
		}
		sum := sha256.Sum256(prevBytes)
		previousEtag := hex.EncodeToString(sum[:])
		if etag != previousEtag {
			return ErrETagMismatch
		}
	}

	var bs []byte
	if config != nil {
		j, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("encoding serve config: %w", err)
		}
		bs = j
	}

	profileID := b.pm.CurrentProfile().ID()
	confKey := ipn.ServeConfigKey(profileID)
	if err := b.store.WriteState(confKey, bs); err != nil {
		return fmt.Errorf("writing ServeConfig to StateStore: %w", err)
	}

	b.setTCPPortsInterceptedFromNetmapAndPrefsLocked(b.pm.CurrentPrefs())

	// clean up and close all previously open foreground sessions
	// if the current ServeConfig has overwritten them.
	if prevConfig.Valid() {
		has := func(string) bool { return false }
		if b.serveConfig.Valid() {
			has = b.serveConfig.Foreground().Contains
		}
		for k := range prevConfig.Foreground().All() {
			if !has(k) {
				for _, sess := range b.notifyWatchers {
					if sess.sessionID == k {
						sess.cancel()
					}
				}
			}
		}
	}

	return nil
}

// ServeConfig provides a view of the current serve mappings.
// If serving is not configured, the returned view is not Valid.
func (b *LocalBackend) ServeConfig() ipn.ServeConfigView {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.serveConfig
}

// DeleteForegroundSession deletes a ServeConfig's foreground session
// in the LocalBackend if it exists. It also ensures check, delete, and
// set operations happen within the same mutex lock to avoid any races.
func (b *LocalBackend) DeleteForegroundSession(sessionID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.serveConfig.Valid() || !b.serveConfig.Foreground().Contains(sessionID) {
		return nil
	}
	sc := b.serveConfig.AsStruct()
	delete(sc.Foreground, sessionID)
	return b.setServeConfigLocked(sc, "")
}

// HandleIngressTCPConn handles a TCP connection initiated by the ingressPeer
// proxied to the local node over the PeerAPI.
// Target represents the destination HostPort of the conn.
// srcAddr represents the source AddrPort and not that of the ingressPeer.
// getConnOrReset is a callback to get the connection, or reset if the connection
// is no longer available.
// sendRST is a callback to send a TCP RST to the ingressPeer indicating that
// the connection was not accepted.
func (b *LocalBackend) HandleIngressTCPConn(ingressPeer tailcfg.NodeView, target ipn.HostPort, srcAddr netip.AddrPort, getConnOrReset func() (net.Conn, bool), sendRST func()) {
	b.mu.Lock()
	sc := b.serveConfig
	b.mu.Unlock()

	// TODO(maisem,bradfitz): make this not alloc for every conn.
	logf := logger.WithPrefix(b.logf, "handleIngress: ")

	if !sc.Valid() {
		logf("got ingress conn w/o serveConfig; rejecting")
		sendRST()
		return
	}

	if !sc.HasFunnelForTarget(target) {
		logf("got ingress conn for unconfigured %q; rejecting", target)
		sendRST()
		return
	}

	host, port, err := net.SplitHostPort(string(target))
	if err != nil {
		logf("got ingress conn for bad target %q; rejecting", target)
		sendRST()
		return
	}
	port16, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		logf("got ingress conn for bad target %q; rejecting", target)
		sendRST()
		return
	}
	dport := uint16(port16)
	if b.getTCPHandlerForFunnelFlow != nil {
		handler := b.getTCPHandlerForFunnelFlow(srcAddr, dport)
		if handler != nil {
			c, ok := getConnOrReset()
			if !ok {
				logf("getConn didn't complete from %v to port %v", srcAddr, dport)
				return
			}
			handler(c)
			return
		}
	}
	handler := b.tcpHandlerForServe(dport, srcAddr, &funnelFlow{
		Host:        host,
		IngressPeer: ingressPeer,
	})
	if handler == nil {
		logf("[unexpected] no matching ingress serve handler for %v to port %v", srcAddr, dport)
		sendRST()
		return
	}
	c, ok := getConnOrReset()
	if !ok {
		logf("getConn didn't complete from %v to port %v", srcAddr, dport)
		return
	}
	handler(c)
}

func (b *LocalBackend) vipServicesFromPrefsLocked(prefs ipn.PrefsView) []*tailcfg.VIPService {
	// keyed by service name
	var services map[tailcfg.ServiceName]*tailcfg.VIPService
	if b.serveConfig.Valid() {
		for svc, config := range b.serveConfig.Services().All() {
			mak.Set(&services, svc, &tailcfg.VIPService{
				Name:  svc,
				Ports: config.ServicePortRange(),
			})
		}
	}

	for _, s := range prefs.AdvertiseServices().All() {
		sn := tailcfg.ServiceName(s)
		if services == nil || services[sn] == nil {
			mak.Set(&services, sn, &tailcfg.VIPService{
				Name: sn,
			})
		}
		services[sn].Active = true
	}

	servicesList := slicesx.MapValues(services)
	// [slicesx.MapValues] provides the values in an indeterminate order, but since we'll
	// be hashing a representation of this list later we want it to be in a consistent
	// order.
	slices.SortFunc(servicesList, func(a, b *tailcfg.VIPService) int {
		return strings.Compare(a.Name.String(), b.Name.String())
	})
	return servicesList
}

// tcpHandlerForVIPService returns a handler for a TCP connection to a VIP service
// that is being served via the ipn.ServeConfig. It returns nil if the destination
// address is not a VIP service or if the VIP service does not have a TCP handler set.
func (b *LocalBackend) tcpHandlerForVIPService(dstAddr, srcAddr netip.AddrPort) (handler func(net.Conn) error) {
	b.mu.Lock()
	sc := b.serveConfig
	ipVIPServiceMap := b.ipVIPServiceMap
	b.mu.Unlock()

	if !sc.Valid() {
		return nil
	}

	dport := dstAddr.Port()

	dstSvc, ok := ipVIPServiceMap[dstAddr.Addr()]
	if !ok {
		return nil
	}

	tcph, ok := sc.FindServiceTCP(dstSvc, dstAddr.Port())
	if !ok {
		b.logf("The destination service doesn't have a TCP handler set.")
		return nil
	}

	if tcph.HTTPS() || tcph.HTTP() {
		hs := &http.Server{
			Handler: http.HandlerFunc(b.serveWebHandler),
			BaseContext: func(_ net.Listener) context.Context {
				return serveHTTPContextKey.WithValue(context.Background(), &serveHTTPContext{
					SrcAddr:       srcAddr,
					ForVIPService: dstSvc,
					DestPort:      dport,
				})
			},
		}
		if tcph.HTTPS() {
			// TODO(kevinliang10): just leaving this TLS cert creation as if we don't have other
			// hostnames, but for services this getTLSServeCetForPort will need a version that also take
			// in the hostname. How to store the TLS cert is still being discussed.
			hs.TLSConfig = &tls.Config{
				GetCertificate: b.getTLSServeCertForPort(dport, dstSvc),
			}
			return func(c net.Conn) error {
				return hs.ServeTLS(netutil.NewOneConnListener(c, nil), "", "")
			}
		}

		return func(c net.Conn) error {
			return hs.Serve(netutil.NewOneConnListener(c, nil))
		}
	}

	if backDst := tcph.TCPForward(); backDst != "" {
		return func(conn net.Conn) error {
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			backConn, err := b.dialer.SystemDial(ctx, "tcp", backDst)
			cancel()
			if err != nil {
				b.logf("localbackend: failed to TCP proxy port %v (from %v) to %s: %v", dport, srcAddr, backDst, err)
				return nil
			}
			defer backConn.Close()
			if sni := tcph.TerminateTLS(); sni != "" {
				conn = tls.Server(conn, &tls.Config{
					GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
						ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
						defer cancel()
						pair, err := b.GetCertPEM(ctx, sni)
						if err != nil {
							return nil, err
						}
						cert, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
						if err != nil {
							return nil, err
						}
						return &cert, nil
					},
				})
			}

			errc := make(chan error, 1)
			go func() {
				_, err := io.Copy(backConn, conn)
				errc <- err
			}()
			go func() {
				_, err := io.Copy(conn, backConn)
				errc <- err
			}()
			return <-errc
		}
	}

	return nil
}

// tcpHandlerForServe returns a handler for a TCP connection to be served via
// the ipn.ServeConfig. The funnelFlow can be nil if this is not a funneled
// connection.
func (b *LocalBackend) tcpHandlerForServe(dport uint16, srcAddr netip.AddrPort, f *funnelFlow) (handler func(net.Conn) error) {
	b.mu.Lock()
	sc := b.serveConfig
	b.mu.Unlock()

	if !sc.Valid() {
		return nil
	}

	tcph, ok := sc.FindTCP(dport)
	if !ok {
		return nil
	}

	if tcph.HTTPS() || tcph.HTTP() {
		hs := &http.Server{
			Handler: http.HandlerFunc(b.serveWebHandler),
			BaseContext: func(_ net.Listener) context.Context {
				return serveHTTPContextKey.WithValue(context.Background(), &serveHTTPContext{
					Funnel:   f,
					SrcAddr:  srcAddr,
					DestPort: dport,
				})
			},
		}
		if tcph.HTTPS() {
			hs.TLSConfig = &tls.Config{
				GetCertificate: b.getTLSServeCertForPort(dport, ""),
			}
			return func(c net.Conn) error {
				return hs.ServeTLS(netutil.NewOneConnListener(c, nil), "", "")
			}
		}

		return func(c net.Conn) error {
			return hs.Serve(netutil.NewOneConnListener(c, nil))
		}
	}

	if backDst := tcph.TCPForward(); backDst != "" {
		return func(conn net.Conn) error {
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			backConn, err := b.dialer.SystemDial(ctx, "tcp", backDst)
			cancel()
			if err != nil {
				b.logf("localbackend: failed to TCP proxy port %v (from %v) to %s: %v", dport, srcAddr, backDst, err)
				return nil
			}
			defer backConn.Close()
			if sni := tcph.TerminateTLS(); sni != "" {
				conn = tls.Server(conn, &tls.Config{
					GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
						ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
						defer cancel()
						pair, err := b.GetCertPEM(ctx, sni)
						if err != nil {
							return nil, err
						}
						cert, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
						if err != nil {
							return nil, err
						}
						return &cert, nil
					},
				})
			}

			// TODO(bradfitz): do the RegisterIPPortIdentity and
			// UnregisterIPPortIdentity stuff that netstack does
			errc := make(chan error, 1)
			go func() {
				_, err := io.Copy(backConn, conn)
				errc <- err
			}()
			go func() {
				_, err := io.Copy(conn, backConn)
				errc <- err
			}()
			return <-errc
		}
	}

	return nil
}

func (b *LocalBackend) getServeHandler(r *http.Request) (_ ipn.HTTPHandlerView, at string, ok bool) {
	var z ipn.HTTPHandlerView // zero value

	hostname := r.Host
	if r.TLS == nil {
		tcd := "." + b.CurrentProfile().NetworkProfile().MagicDNSName
		if host, _, err := net.SplitHostPort(hostname); err == nil {
			hostname = host
		}
		if !strings.HasSuffix(hostname, tcd) {
			hostname += tcd
		}
	} else {
		hostname = r.TLS.ServerName
	}

	sctx, ok := serveHTTPContextKey.ValueOk(r.Context())
	if !ok {
		b.logf("[unexpected] localbackend: no serveHTTPContext in request")
		return z, "", false
	}
	wsc, ok := b.webServerConfig(hostname, sctx.ForVIPService, sctx.DestPort)
	if !ok {
		return z, "", false
	}

	if h, ok := wsc.Handlers().GetOk(r.URL.Path); ok {
		return h, r.URL.Path, true
	}
	pth := path.Clean(r.URL.Path)
	for {
		withSlash := pth + "/"
		if h, ok := wsc.Handlers().GetOk(withSlash); ok {
			return h, withSlash, true
		}
		if h, ok := wsc.Handlers().GetOk(pth); ok {
			return h, pth, true
		}
		if pth == "/" {
			return z, "", false
		}
		pth = path.Dir(pth)
	}
}

// proxyHandlerForBackend creates a new HTTP reverse proxy for a particular backend that
// we serve requests for. `backend` is a HTTPHandler.Proxy string (url, hostport or just port).
func (b *LocalBackend) proxyHandlerForBackend(backend string) (http.Handler, error) {
	targetURL, insecure := expandProxyArg(backend)
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url %s: %w", targetURL, err)
	}
	p := &reverseProxy{
		logf:     b.logf,
		url:      u,
		insecure: insecure,
		backend:  backend,
		lb:       b,
	}
	return p, nil
}

// reverseProxy is a proxy that forwards a request to a backend host
// (preconfigured via ipn.ServeConfig). If the host is configured with
// http+insecure prefix, connection between proxy and backend will be over
// insecure TLS. If the backend host has a http prefix and the incoming request
// has application/grpc content type header, the connection will be over h2c.
// Otherwise standard Go http transport will be used.
type reverseProxy struct {
	logf logger.Logf
	url  *url.URL
	// insecure tracks whether the connection to an https backend should be
	// insecure (i.e because we cannot verify its CA).
	insecure      bool
	backend       string
	lb            *LocalBackend
	httpTransport lazy.SyncValue[*http.Transport] // transport for non-h2c backends
	h2cTransport  lazy.SyncValue[*http.Transport] // transport for h2c backends
	// closed tracks whether proxy is closed/currently closing.
	closed atomic.Bool
}

// close ensures that any open backend connections get closed.
func (rp *reverseProxy) close() {
	rp.closed.Store(true)
	if h2cT := rp.h2cTransport.Get(func() *http.Transport { return nil }); h2cT != nil {
		h2cT.CloseIdleConnections()
	}
	if httpTransport := rp.httpTransport.Get(func() *http.Transport {
		return nil
	}); httpTransport != nil {
		httpTransport.CloseIdleConnections()
	}
}

func (rp *reverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if closed := rp.closed.Load(); closed {
		rp.logf("received a request for a proxy that's being closed or has been closed")
		http.Error(w, "proxy is closed", http.StatusServiceUnavailable)
		return
	}
	p := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		oldOutPath := r.Out.URL.Path
		r.SetURL(rp.url)

		// If mount point matches the request path exactly, the outbound
		// request URL was set to empty string in serveWebHandler which
		// would have resulted in the outbound path set to <proxy path>
		// + '/' in SetURL. In that case, if the proxy path was set, we
		// want to send the request to the <proxy path> (without the
		// '/') .
		if oldOutPath == "" && rp.url.Path != "" {
			r.Out.URL.Path = rp.url.Path
			r.Out.URL.RawPath = rp.url.RawPath
		}

		r.Out.Host = r.In.Host
		addProxyForwardedHeaders(r)
		rp.lb.addTailscaleIdentityHeaders(r)
	}}

	// There is no way to autodetect h2c as per RFC 9113
	// https://datatracker.ietf.org/doc/html/rfc9113#name-starting-http-2.
	// However, we assume that http:// proxy prefix in combination with the
	// protoccol being HTTP/2 is sufficient to detect h2c for our needs. Only use this for
	// gRPC to fix a known problem of plaintext gRPC backends
	if rp.shouldProxyViaH2C(r) {
		rp.logf("received a proxy request for plaintext gRPC")
		p.Transport = rp.getH2CTransport()
	} else {
		p.Transport = rp.getTransport()
	}
	p.ServeHTTP(w, r)
}

// getTransport returns the Transport used for regular (non-GRPC) requests
// to the backend. The Transport gets created lazily, at most once.
func (rp *reverseProxy) getTransport() *http.Transport {
	return rp.httpTransport.Get(func() *http.Transport {
		return &http.Transport{
			DialContext: rp.lb.dialer.SystemDial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: rp.insecure,
			},
			// Values for the following parameters have been copied from http.DefaultTransport.
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	})
}

// getH2CTransport returns the Transport used for GRPC requests to the backend.
// The Transport gets created lazily, at most once.
func (rp *reverseProxy) getH2CTransport() http.RoundTripper {
	return rp.h2cTransport.Get(func() *http.Transport {
		var p http.Protocols
		p.SetUnencryptedHTTP2(true)
		tr := &http.Transport{
			Protocols: &p,
			DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return rp.lb.dialer.SystemDial(ctx, "tcp", rp.url.Host)
			},
		}
		return tr
	})
}

// This is not a generally reliable way how to determine whether a request is
// for a h2c server, but sufficient for our particular use case.
func (rp *reverseProxy) shouldProxyViaH2C(r *http.Request) bool {
	contentType := r.Header.Get(contentTypeHeader)
	return r.ProtoMajor == 2 && strings.HasPrefix(rp.backend, "http://") && isGRPCContentType(contentType)
}

// isGRPC accepts an HTTP request's content type header value and determines
// whether this is gRPC content. grpc-go considers a value that equals
// application/grpc or has a prefix of application/grpc+ or application/grpc; a
// valid grpc content type header.
// https://github.com/grpc/grpc-go/blob/v1.60.0-dev/internal/grpcutil/method.go#L41-L78
func isGRPCContentType(contentType string) bool {
	s, ok := strings.CutPrefix(contentType, grpcBaseContentType)
	return ok && (len(s) == 0 || s[0] == '+' || s[0] == ';')
}

func addProxyForwardedHeaders(r *httputil.ProxyRequest) {
	r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
	if r.In.TLS != nil {
		r.Out.Header.Set("X-Forwarded-Proto", "https")
	}
	if c, ok := serveHTTPContextKey.ValueOk(r.Out.Context()); ok {
		r.Out.Header.Set("X-Forwarded-For", c.SrcAddr.Addr().String())
	}
}

func (b *LocalBackend) addTailscaleIdentityHeaders(r *httputil.ProxyRequest) {
	// Clear any incoming values squatting in the headers.
	r.Out.Header.Del("Tailscale-User-Login")
	r.Out.Header.Del("Tailscale-User-Name")
	r.Out.Header.Del("Tailscale-User-Profile-Pic")
	r.Out.Header.Del("Tailscale-Funnel-Request")
	r.Out.Header.Del("Tailscale-Headers-Info")

	c, ok := serveHTTPContextKey.ValueOk(r.Out.Context())
	if !ok {
		return
	}
	if c.Funnel != nil {
		r.Out.Header.Set("Tailscale-Funnel-Request", "?1")
		return
	}
	node, user, ok := b.WhoIs("tcp", c.SrcAddr)
	if !ok {
		return // traffic from outside of Tailnet (funneled or local machine)
	}
	if node.IsTagged() {
		// 2023-06-14: Not setting identity headers for tagged nodes.
		// Only currently set for nodes with user identities.
		return
	}
	r.Out.Header.Set("Tailscale-User-Login", encTailscaleHeaderValue(user.LoginName))
	r.Out.Header.Set("Tailscale-User-Name", encTailscaleHeaderValue(user.DisplayName))
	r.Out.Header.Set("Tailscale-User-Profile-Pic", user.ProfilePicURL)
	r.Out.Header.Set("Tailscale-Headers-Info", "https://tailscale.com/s/serve-headers")
}

// encTailscaleHeaderValue cleans or encodes as necessary v, to be suitable in
// an HTTP header value. See
// https://github.com/tailscale/tailscale/issues/11603.
//
// If v is not a valid UTF-8 string, it returns an empty string.
// If v is a valid ASCII string, it returns v unmodified.
// If v is a valid UTF-8 string with non-ASCII characters, it returns a
// RFC 2047 Q-encoded string.
func encTailscaleHeaderValue(v string) string {
	if !utf8.ValidString(v) {
		return ""
	}
	return mime.QEncoding.Encode("utf-8", v)
}

// serveWebHandler is an http.HandlerFunc that maps incoming requests to the
// correct *http.
func (b *LocalBackend) serveWebHandler(w http.ResponseWriter, r *http.Request) {
	h, mountPoint, ok := b.getServeHandler(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if s := h.Text(); s != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, s)
		return
	}
	if v := h.Path(); v != "" {
		b.serveFileOrDirectory(w, r, v, mountPoint)
		return
	}
	if v := h.Proxy(); v != "" {
		p, ok := b.serveProxyHandlers.Load(v)
		if !ok {
			http.Error(w, "unknown proxy destination", http.StatusInternalServerError)
			return
		}
		h := p.(http.Handler)
		// Trim the mount point from the URL path before proxying. (#6571)
		if r.URL.Path != "/" {
			h = http.StripPrefix(strings.TrimSuffix(mountPoint, "/"), h)
		}
		h.ServeHTTP(w, r)
		return
	}

	http.Error(w, "empty handler", 500)
}

func (b *LocalBackend) serveFileOrDirectory(w http.ResponseWriter, r *http.Request, fileOrDir, mountPoint string) {
	fi, err := os.Stat(fileOrDir)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		b.logf("error calling stat on %s: %v", fileOrDir, err)
		http.Error(w, "an error occurred reading the file or directory", 500)
		return
	}
	if fi.Mode().IsRegular() {
		if mountPoint != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(fileOrDir)
		if err != nil {
			b.logf("error opening %s: %v", fileOrDir, err)
			http.Error(w, "an error occurred reading the file or directory", 500)
			return
		}
		defer f.Close()
		http.ServeContent(w, r, path.Base(mountPoint), fi.ModTime(), f)
		return
	}
	if !fi.IsDir() {
		http.Error(w, "not a file or directory", 500)
		return
	}
	if len(r.URL.Path) < len(mountPoint) && r.URL.Path+"/" == mountPoint {
		http.Redirect(w, r, mountPoint, http.StatusFound)
		return
	}

	var fs http.Handler = http.FileServer(http.Dir(fileOrDir))
	if mountPoint != "/" {
		fs = http.StripPrefix(strings.TrimSuffix(mountPoint, "/"), fs)
	}
	fs.ServeHTTP(&fixLocationHeaderResponseWriter{
		ResponseWriter: w,
		mountPoint:     mountPoint,
	}, r)
}

// fixLocationHeaderResponseWriter is an http.ResponseWriter wrapper that, upon
// flushing HTTP headers, prefixes any Location header with the mount point.
type fixLocationHeaderResponseWriter struct {
	http.ResponseWriter
	mountPoint string
	fixOnce    sync.Once // guards call to fix
}

func (w *fixLocationHeaderResponseWriter) fix() {
	h := w.ResponseWriter.Header()
	if v := h.Get("Location"); v != "" {
		h.Set("Location", w.mountPoint+v)
	}
}

func (w *fixLocationHeaderResponseWriter) WriteHeader(code int) {
	w.fixOnce.Do(w.fix)
	w.ResponseWriter.WriteHeader(code)
}

func (w *fixLocationHeaderResponseWriter) Write(p []byte) (int, error) {
	w.fixOnce.Do(w.fix)
	return w.ResponseWriter.Write(p)
}

// expandProxyArg returns a URL from s, where s can be of form:
//
// * port number ("8080")
// * host:port ("localhost:8080")
// * full URL ("http://localhost:8080", in which case it's returned unchanged)
// * insecure TLS ("https+insecure://127.0.0.1:4430")
func expandProxyArg(s string) (targetURL string, insecureSkipVerify bool) {
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s, false
	}
	if rest, ok := strings.CutPrefix(s, "https+insecure://"); ok {
		return "https://" + rest, true
	}
	if allNumeric(s) {
		return "http://127.0.0.1:" + s, false
	}
	return "http://" + s, false
}

func allNumeric(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func (b *LocalBackend) webServerConfig(hostname string, forVIPService tailcfg.ServiceName, port uint16) (c ipn.WebServerConfigView, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.serveConfig.Valid() {
		return c, false
	}
	if forVIPService != "" {
		magicDNSSuffix := b.currentNode().NetMap().MagicDNSSuffix()
		fqdn := strings.Join([]string{forVIPService.WithoutPrefix(), magicDNSSuffix}, ".")
		key := ipn.HostPort(net.JoinHostPort(fqdn, fmt.Sprintf("%d", port)))
		return b.serveConfig.FindServiceWeb(forVIPService, key)
	}
	key := ipn.HostPort(net.JoinHostPort(hostname, fmt.Sprintf("%d", port)))
	return b.serveConfig.FindWeb(key)
}

func (b *LocalBackend) getTLSServeCertForPort(port uint16, forVIPService tailcfg.ServiceName) func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hi == nil || hi.ServerName == "" {
			return nil, errors.New("no SNI ServerName")
		}
		_, ok := b.webServerConfig(hi.ServerName, forVIPService, port)
		if !ok {
			return nil, errors.New("no webserver configured for name/port")
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		pair, err := b.GetCertPEM(ctx, hi.ServerName)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(pair.CertPEM, pair.KeyPEM)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
}

// setServeProxyHandlersLocked ensures there is an http proxy handler for each
// backend specified in serveConfig. It expects serveConfig to be valid and
// up-to-date, so should be called after reloadServeConfigLocked.
func (b *LocalBackend) setServeProxyHandlersLocked() {
	if !b.serveConfig.Valid() {
		return
	}
	var backends map[string]bool
	for _, conf := range b.serveConfig.Webs() {
		for _, h := range conf.Handlers().All() {
			backend := h.Proxy()
			if backend == "" {
				// Only create proxy handlers for servers with a proxy backend.
				continue
			}
			mak.Set(&backends, backend, true)
			if _, ok := b.serveProxyHandlers.Load(backend); ok {
				continue
			}

			b.logf("serve: creating a new proxy handler for %s", backend)
			p, err := b.proxyHandlerForBackend(backend)
			if err != nil {
				// The backend endpoint (h.Proxy) should have been validated by expandProxyTarget
				// in the CLI, so just log the error here.
				b.logf("[unexpected] could not create proxy for %v: %s", backend, err)
				continue
			}
			b.serveProxyHandlers.Store(backend, p)
		}
	}

	// Clean up handlers for proxy backends that are no longer present
	// in configuration.
	b.serveProxyHandlers.Range(func(key, value any) bool {
		backend := key.(string)
		if !backends[backend] {
			b.logf("serve: closing idle connections to %s", backend)
			b.serveProxyHandlers.Delete(backend)
			value.(*reverseProxy).close()
		}
		return true
	})
}

// VIPServices returns the list of tailnet services that this node
// is serving as a destination for.
// The returned memory is owned by the caller.
func (b *LocalBackend) VIPServices() []*tailcfg.VIPService {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.vipServicesFromPrefsLocked(b.pm.CurrentPrefs())
}

func handleC2NVIPServicesGet(b *LocalBackend, w http.ResponseWriter, r *http.Request) {
	b.logf("c2n: GET /vip-services received")
	var res tailcfg.C2NVIPServicesResponse
	res.VIPServices = b.VIPServices()
	res.ServicesHash = b.vipServiceHash(res.VIPServices)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

var metricIngressCalls = clientmetric.NewCounter("peerapi_ingress")

func init() {
	RegisterPeerAPIHandler("/v0/ingress", handleServeIngress)

}

func handleServeIngress(ph PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	h := ph.(*peerAPIHandler)
	metricIngressCalls.Add(1)

	// http.Errors only useful if hitting endpoint manually
	// otherwise rely on log lines when debugging ingress connections
	// as connection is hijacked for bidi and is encrypted tls
	if !h.canIngress() {
		h.logf("ingress: denied; no ingress cap from %v", h.remoteAddr)
		http.Error(w, "denied; no ingress cap", http.StatusForbidden)
		return
	}
	logAndError := func(code int, publicMsg string) {
		h.logf("ingress: bad request from %v: %s", h.remoteAddr, publicMsg)
		http.Error(w, publicMsg, code)
	}
	bad := func(publicMsg string) {
		logAndError(http.StatusBadRequest, publicMsg)
	}
	if r.Method != "POST" {
		logAndError(http.StatusMethodNotAllowed, "only POST allowed")
		return
	}
	srcAddrStr := r.Header.Get("Tailscale-Ingress-Src")
	if srcAddrStr == "" {
		bad("Tailscale-Ingress-Src header not set")
		return
	}
	srcAddr, err := netip.ParseAddrPort(srcAddrStr)
	if err != nil {
		bad("Tailscale-Ingress-Src header invalid; want ip:port")
		return
	}
	target := ipn.HostPort(r.Header.Get("Tailscale-Ingress-Target"))
	if target == "" {
		bad("Tailscale-Ingress-Target header not set")
		return
	}
	if _, _, err := net.SplitHostPort(string(target)); err != nil {
		bad("Tailscale-Ingress-Target header invalid; want host:port")
		return
	}

	getConnOrReset := func() (net.Conn, bool) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			h.logf("ingress: failed hijacking conn")
			http.Error(w, "failed hijacking conn", http.StatusInternalServerError)
			return nil, false
		}
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
		return &ipn.FunnelConn{
			Conn:   conn,
			Src:    srcAddr,
			Target: target,
		}, true
	}
	sendRST := func() {
		http.Error(w, "denied", http.StatusForbidden)
	}

	h.ps.b.HandleIngressTCPConn(h.peerNode, target, srcAddr, getConnOrReset, sendRST)
}

// wantIngressLocked reports whether this node has ingress configured. This bool
// is sent to the coordination server (in Hostinfo.WireIngress) as an
// optimization hint to know primarily which nodes are NOT using ingress, to
// avoid doing work for regular nodes.
//
// Even if the user's ServeConfig.AllowFunnel map was manually edited in raw
// mode and contains map entries with false values, sending true (from Len > 0)
// is still fine. This is only an optimization hint for the control plane and
// doesn't affect security or correctness. And we also don't expect people to
// modify their ServeConfig in raw mode.
func (b *LocalBackend) wantIngressLocked() bool {
	return b.serveConfig.Valid() && b.serveConfig.HasAllowFunnel()
}

// hasIngressEnabledLocked reports whether the node has any funnel endpoint enabled. This bool is sent to control (in
// Hostinfo.IngressEnabled) to determine whether 'Funnel' badge should be displayed on this node in the admin panel.
func (b *LocalBackend) hasIngressEnabledLocked() bool {
	return b.serveConfig.Valid() && b.serveConfig.IsFunnelOn()
}

// shouldWireInactiveIngressLocked reports whether the node is in a state where funnel is not actively enabled, but it
// seems that it is intended to be used with funnel.
func (b *LocalBackend) shouldWireInactiveIngressLocked() bool {
	return b.serveConfig.Valid() && !b.hasIngressEnabledLocked() && b.wantIngressLocked()
}

func serveSetTCPPortsInterceptedFromNetmapAndPrefsLocked(b *LocalBackend, prefs ipn.PrefsView) (handlePorts []uint16) {
	var vipServicesPorts map[tailcfg.ServiceName][]uint16

	b.reloadServeConfigLocked(prefs)
	if b.serveConfig.Valid() {
		servePorts := make([]uint16, 0, 3)
		for port := range b.serveConfig.TCPs() {
			if port > 0 {
				servePorts = append(servePorts, uint16(port))
			}
		}
		handlePorts = append(handlePorts, servePorts...)

		for svc, cfg := range b.serveConfig.Services().All() {
			servicePorts := make([]uint16, 0, 3)
			for port := range cfg.TCP().All() {
				if port > 0 {
					servicePorts = append(servicePorts, uint16(port))
				}
			}
			if _, ok := vipServicesPorts[svc]; !ok {
				mak.Set(&vipServicesPorts, svc, servicePorts)
			} else {
				mak.Set(&vipServicesPorts, svc, append(vipServicesPorts[svc], servicePorts...))
			}
		}

		b.setServeProxyHandlersLocked()

		// don't listen on netmap addresses if we're in userspace mode
		if !b.sys.IsNetstack() {
			b.updateServeTCPPortNetMapAddrListenersLocked(servePorts)
		}
	}

	b.setVIPServicesTCPPortsInterceptedLocked(vipServicesPorts)

	return handlePorts
}

// reloadServeConfigLocked reloads the serve config from the store or resets the
// serve config to nil if not logged in. The "changed" parameter, when false, instructs
// the method to only run the reset-logic and not reload the store from memory to ensure
// foreground sessions are not removed if they are not saved on disk.
func (b *LocalBackend) reloadServeConfigLocked(prefs ipn.PrefsView) {
	if !b.currentNode().Self().Valid() || !prefs.Valid() || b.pm.CurrentProfile().ID() == "" {
		// We're not logged in, so we don't have a profile.
		// Don't try to load the serve config.
		b.lastServeConfJSON = mem.B(nil)
		b.serveConfig = ipn.ServeConfigView{}
		return
	}

	confKey := ipn.ServeConfigKey(b.pm.CurrentProfile().ID())
	// TODO(maisem,bradfitz): prevent reading the config from disk
	// if the profile has not changed.
	confj, err := b.store.ReadState(confKey)
	if err != nil {
		b.lastServeConfJSON = mem.B(nil)
		b.serveConfig = ipn.ServeConfigView{}
		return
	}
	if b.lastServeConfJSON.Equal(mem.B(confj)) {
		return
	}
	b.lastServeConfJSON = mem.B(confj)
	var conf ipn.ServeConfig
	if err := json.Unmarshal(confj, &conf); err != nil {
		b.logf("invalid ServeConfig %q in StateStore: %v", confKey, err)
		b.serveConfig = ipn.ServeConfigView{}
		return
	}

	// remove inactive sessions
	maps.DeleteFunc(conf.Foreground, func(sessionID string, sc *ipn.ServeConfig) bool {
		_, ok := b.notifyWatchers[sessionID]
		return !ok
	})

	b.serveConfig = conf.View()
}

func (b *LocalBackend) setVIPServicesTCPPortsInterceptedLocked(svcPorts map[tailcfg.ServiceName][]uint16) {
	if len(svcPorts) == 0 {
		b.shouldInterceptVIPServicesTCPPortAtomic.Store(func(netip.AddrPort) bool { return false })
		return
	}
	nm := b.currentNode().NetMap()
	if nm == nil {
		b.logf("can't set intercept function for Service TCP Ports, netMap is nil")
		return
	}
	vipServiceIPMap := nm.GetVIPServiceIPMap()
	if len(vipServiceIPMap) == 0 {
		// No approved VIP Services
		return
	}

	svcAddrPorts := make(map[netip.Addr]func(uint16) bool)
	// Only set the intercept function if the service has been assigned a VIP.
	for svcName, ports := range svcPorts {
		addrs, ok := vipServiceIPMap[svcName]
		if !ok {
			continue
		}
		interceptFn := generateInterceptTCPPortFunc(ports)
		for _, addr := range addrs {
			svcAddrPorts[addr] = interceptFn
		}
	}

	b.shouldInterceptVIPServicesTCPPortAtomic.Store(generateInterceptVIPServicesTCPPortFunc(svcAddrPorts))
}
