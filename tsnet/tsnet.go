// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsnet provides Tailscale as a library.
//
// It is an experimental work in progress.
package tsnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/ipn/store"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/logtail/filch"
	"tailscale.com/net/nettest"
	"tailscale.com/net/tsdial"
	"tailscale.com/smallzstd"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/netstack"
)

// Server is an embedded Tailscale server.
//
// Its exported fields may be changed until the first call to Listen.
type Server struct {
	// Dir specifies the name of the directory to use for
	// state. If empty, a directory is selected automatically
	// under os.UserConfigDir (https://golang.org/pkg/os/#UserConfigDir).
	// based on the name of the binary.
	Dir string

	// Store specifies the state store to use.
	//
	// If nil, a new FileStore is initialized at `Dir/tailscaled.state`.
	// See tailscale.com/ipn/store for supported stores.
	//
	// Logs will automatically be uploaded to uploaded to log.tailscale.io,
	// where the configuration file for logging will be saved at
	// `Dir/tailscaled.log.conf`.
	Store ipn.StateStore

	// Hostname is the hostname to present to the control server.
	// If empty, the binary name is used.
	Hostname string

	// Logf, if non-nil, specifies the logger to use. By default,
	// log.Printf is used.
	Logf logger.Logf

	// Ephemeral, if true, specifies that the instance should register
	// as an Ephemeral node (https://tailscale.com/kb/1111/ephemeral-nodes/).
	Ephemeral bool

	// AuthKey, if non-empty, is the auth key to create the node
	// and will be preferred over the TS_AUTHKEY environment
	// variable. If the node is already created (from state
	// previously stored in in Store), then this field is not
	// used.
	AuthKey string

	// ControlURL optionally specifies the coordination server URL.
	// If empty, the Tailscale default is used.
	ControlURL string

	initOnce         sync.Once
	initErr          error
	lb               *ipnlocal.LocalBackend
	netstack         *netstack.Impl
	linkMon          *monitor.Mon
	localAPIListener net.Listener
	rootPath         string // the state directory
	hostname         string
	shutdownCtx      context.Context
	shutdownCancel   context.CancelFunc
	localClient      *tailscale.LocalClient
	logbuffer        *filch.Filch
	logtail          *logtail.Logger

	mu        sync.Mutex
	listeners map[listenKey]*listener
	dialer    *tsdial.Dialer
}

// Dial connects to the address on the tailnet.
// It will start the server if it has not been started yet.
func (s *Server) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	return s.dialer.UserDial(ctx, network, address)
}

// LocalClient returns a LocalClient that speaks to s.
//
// It will start the server if it has not been started yet. If the server's
// already been started successfully, it doesn't return an error.
func (s *Server) LocalClient() (*tailscale.LocalClient, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	return s.localClient, nil
}

// Start connects the server to the tailnet.
// Optional: any calls to Dial/Listen will also call Start.
func (s *Server) Start() error {
	hostinfo.SetPackage("tsnet")
	s.initOnce.Do(s.doInit)
	return s.initErr
}

// Close stops the server.
//
// It must not be called before or concurrently with Start.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Perform a best-effort final flush.
		s.logtail.Shutdown(ctx)
		s.logbuffer.Close()
	}()

	if _, isMemStore := s.Store.(*mem.Store); isMemStore && s.Ephemeral {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Perform a best-effort logout.
			s.lb.LogoutSync(ctx)
		}()
	}

	if s.netstack != nil {
		s.netstack.Close()
		s.netstack = nil
	}
	s.shutdownCancel()
	s.lb.Shutdown()
	s.linkMon.Close()
	s.dialer.Close()
	s.localAPIListener.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ln := range s.listeners {
		ln.Close()
	}
	s.listeners = nil

	wg.Wait()
	return nil
}

func (s *Server) doInit() {
	s.shutdownCtx, s.shutdownCancel = context.WithCancel(context.Background())
	if err := s.start(); err != nil {
		s.initErr = fmt.Errorf("tsnet: %w", err)
	}
}

func (s *Server) getAuthKey() string {
	if v := s.AuthKey; v != "" {
		return v
	}
	return os.Getenv("TS_AUTHKEY")
}

func (s *Server) start() (reterr error) {
	var closePool closeOnErrorPool
	defer closePool.closeAllIfError(&reterr)

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	prog := strings.TrimSuffix(strings.ToLower(filepath.Base(exe)), ".exe")

	s.hostname = s.Hostname
	if s.hostname == "" {
		s.hostname = prog
	}

	s.rootPath = s.Dir
	if s.Store != nil {
		_, isMemStore := s.Store.(*mem.Store)
		if isMemStore && !s.Ephemeral {
			return fmt.Errorf("in-memory store is only supported for Ephemeral nodes")
		}
	}

	logf := s.logf

	if s.rootPath == "" {
		confDir, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		s.rootPath, err = getTSNetDir(logf, confDir, prog)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(s.rootPath, 0700); err != nil {
			return err
		}
	}
	if fi, err := os.Stat(s.rootPath); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("%v is not a directory", s.rootPath)
	}

	cfgPath := filepath.Join(s.rootPath, "tailscaled.log.conf")

	lpc, err := logpolicy.ConfigFromFile(cfgPath)
	switch {
	case os.IsNotExist(err):
		lpc = logpolicy.NewConfig(logtail.CollectionNode)
		if err := lpc.Save(cfgPath); err != nil {
			return fmt.Errorf("logpolicy.Config.Save for %v: %w", cfgPath, err)
		}
	case err != nil:
		return fmt.Errorf("logpolicy.LoadConfig for %v: %w", cfgPath, err)
	}
	if err := lpc.Validate(logtail.CollectionNode); err != nil {
		return fmt.Errorf("logpolicy.Config.Validate for %v: %w", cfgPath, err)
	}
	logid := lpc.PublicID.String()

	s.logbuffer, err = filch.New(filepath.Join(s.rootPath, "tailscaled"), filch.Options{ReplaceStderr: false})
	if err != nil {
		return fmt.Errorf("error creating filch: %w", err)
	}
	closePool.add(s.logbuffer)
	c := logtail.Config{
		Collection: lpc.Collection,
		PrivateID:  lpc.PrivateID,
		Stderr:     io.Discard, // log everything to Buffer
		Buffer:     s.logbuffer,
		NewZstdEncoder: func() logtail.Encoder {
			w, err := smallzstd.NewEncoder(nil)
			if err != nil {
				panic(err)
			}
			return w
		},
		HTTPC: &http.Client{Transport: logpolicy.NewLogtailTransport(logtail.DefaultHost)},
	}
	s.logtail = logtail.NewLogger(c, logf)
	closePool.addFunc(func() { s.logtail.Shutdown(context.Background()) })

	s.linkMon, err = monitor.New(logf)
	if err != nil {
		return err
	}
	closePool.add(s.linkMon)

	s.dialer = &tsdial.Dialer{Logf: logf} // mutated below (before used)
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		ListenPort:  0,
		LinkMonitor: s.linkMon,
		Dialer:      s.dialer,
	})
	if err != nil {
		return err
	}
	closePool.add(s.dialer)

	tunDev, magicConn, dns, ok := eng.(wgengine.InternalsGetter).GetInternals()
	if !ok {
		return fmt.Errorf("%T is not a wgengine.InternalsGetter", eng)
	}

	ns, err := netstack.Create(logf, tunDev, eng, magicConn, s.dialer, dns)
	if err != nil {
		return fmt.Errorf("netstack.Create: %w", err)
	}
	ns.ProcessLocalIPs = true
	ns.ForwardTCPIn = s.forwardTCP
	if err := ns.Start(); err != nil {
		return fmt.Errorf("failed to start netstack: %w", err)
	}
	s.netstack = ns
	s.dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		_, ok := eng.PeerForIP(ip)
		return ok
	}
	s.dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	if s.Store == nil {
		stateFile := filepath.Join(s.rootPath, "tailscaled.state")
		logf("tsnet running state path %s", stateFile)
		s.Store, err = store.New(logf, stateFile)
		if err != nil {
			return err
		}
	}

	loginFlags := controlclient.LoginDefault
	if s.Ephemeral {
		loginFlags = controlclient.LoginEphemeral
	}
	lb, err := ipnlocal.NewLocalBackend(logf, logid, s.Store, "", s.dialer, eng, loginFlags)
	if err != nil {
		return fmt.Errorf("NewLocalBackend: %v", err)
	}
	lb.SetVarRoot(s.rootPath)
	logf("tsnet starting with hostname %q, varRoot %q", s.hostname, s.rootPath)
	s.lb = lb
	closePool.addFunc(func() { s.lb.Shutdown() })
	lb.SetDecompressor(func() (controlclient.Decompressor, error) {
		return smallzstd.NewDecoder(nil)
	})
	prefs := ipn.NewPrefs()
	prefs.Hostname = s.hostname
	prefs.WantRunning = true
	prefs.ControlURL = s.ControlURL
	authKey := s.getAuthKey()
	err = lb.Start(ipn.Options{
		UpdatePrefs: prefs,
		AuthKey:     authKey,
	})
	if err != nil {
		return fmt.Errorf("starting backend: %w", err)
	}
	st := lb.State()
	if st == ipn.NeedsLogin || envknob.Bool("TSNET_FORCE_LOGIN") {
		logf("LocalBackend state is %v; running StartLoginInteractive...", st)
		s.lb.StartLoginInteractive()
	} else if authKey != "" {
		logf("Authkey is set; but state is %v. Ignoring authkey. Re-run with TSNET_FORCE_LOGIN=1 to force use of authkey.", st)
	}
	go s.printAuthURLLoop()

	// Run the localapi handler, to allow fetching LetsEncrypt certs.
	lah := localapi.NewHandler(lb, logf, logid)
	lah.PermitWrite = true
	lah.PermitRead = true

	// Create an in-process listener.
	// nettest.Listen provides a in-memory pipe based implementation for net.Conn.
	// TODO(maisem): Rename nettest package to remove "test".
	lal := nettest.Listen("local-tailscaled.sock:80")
	s.localAPIListener = lal
	s.localClient = &tailscale.LocalClient{Dial: lal.Dial}
	go func() {
		if err := http.Serve(lal, lah); err != nil {
			logf("localapi serve error: %v", err)
		}
	}()
	closePool.add(s.localAPIListener)
	return nil
}

type closeOnErrorPool []func()

func (p *closeOnErrorPool) add(c io.Closer)   { *p = append(*p, func() { c.Close() }) }
func (p *closeOnErrorPool) addFunc(fn func()) { *p = append(*p, fn) }
func (p closeOnErrorPool) closeAllIfError(errp *error) {
	if *errp != nil {
		for _, closeFn := range p {
			closeFn()
		}
	}
}

func (s *Server) logf(format string, a ...interface{}) {
	if s.logtail != nil {
		s.logtail.Logf(format, a...)
	}
	if s.Logf != nil {
		s.Logf(format, a...)
		return
	}
	log.Printf(format, a...)
}

// printAuthURLLoop loops once every few seconds while the server is still running and
// is in NeedsLogin state, printing out the auth URL.
func (s *Server) printAuthURLLoop() {
	for {
		if s.shutdownCtx.Err() != nil {
			return
		}
		if st := s.lb.State(); st != ipn.NeedsLogin {
			s.logf("printAuthURLLoop: state is %v; stopping", st)
			return
		}
		st := s.lb.StatusWithoutPeers()
		if st.AuthURL != "" {
			s.logf("To start this tsnet server, restart with TS_AUTHKEY set, or go to: %s", st.AuthURL)
		}
		select {
		case <-time.After(5 * time.Second):
		case <-s.shutdownCtx.Done():
			return
		}
	}
}

func (s *Server) forwardTCP(c net.Conn, port uint16) {
	s.mu.Lock()
	ln, ok := s.listeners[listenKey{"tcp", "", port}]
	s.mu.Unlock()
	if !ok {
		c.Close()
		return
	}
	t := time.NewTimer(time.Second)
	defer t.Stop()
	select {
	case ln.conn <- c:
	case <-t.C:
		c.Close()
	}
}

// getTSNetDir usually just returns filepath.Join(confDir, "tsnet-"+prog)
// with no error.
//
// One special case is that it renames old "tslib-" directories to
// "tsnet-", and that rename might return an error.
//
// TODO(bradfitz): remove this maybe 6 months after 2022-03-17,
// once people (notably Tailscale corp services) have updated.
func getTSNetDir(logf logger.Logf, confDir, prog string) (string, error) {
	oldPath := filepath.Join(confDir, "tslib-"+prog)
	newPath := filepath.Join(confDir, "tsnet-"+prog)

	fi, err := os.Lstat(oldPath)
	if os.IsNotExist(err) {
		// Common path.
		return newPath, nil
	}
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("expected old tslib path %q to be a directory; got %v", oldPath, fi.Mode())
	}

	// At this point, oldPath exists and is a directory. But does
	// the new path exist?

	fi, err = os.Lstat(newPath)
	if err == nil && fi.IsDir() {
		// New path already exists somehow. Ignore the old one and
		// don't try to migrate it.
		return newPath, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(oldPath, newPath); err != nil {
		return "", err
	}
	logf("renamed old tsnet state storage directory %q to %q", oldPath, newPath)
	return newPath, nil
}

// APIClient returns a tailscale.Client that can be used to make authenticated
// requests to the Tailscale control server.
// It requires the user to set tailscale.I_Acknowledge_This_API_Is_Unstable.
func (s *Server) APIClient() (*tailscale.Client, error) {
	if !tailscale.I_Acknowledge_This_API_Is_Unstable {
		return nil, errors.New("use of Client without setting I_Acknowledge_This_API_Is_Unstable")
	}
	if err := s.Start(); err != nil {
		return nil, err
	}

	c := tailscale.NewClient("-", nil)
	c.HTTPClient = &http.Client{Transport: s.lb.KeyProvingNoiseRoundTripper()}
	return c, nil
}

// Listen announces only on the Tailscale network.
// It will start the server if it has not been started yet.
func (s *Server) Listen(network, addr string) (net.Listener, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("unsupported network type")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("tsnet: %w", err)
	}
	port, err := net.LookupPort(network, portStr)
	if err != nil || port < 0 || port > math.MaxUint16 {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	if err := s.Start(); err != nil {
		return nil, err
	}

	key := listenKey{network, host, uint16(port)}
	ln := &listener{
		s:    s,
		key:  key,
		addr: addr,

		conn: make(chan net.Conn),
	}
	s.mu.Lock()
	if _, ok := s.listeners[key]; ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("tsnet: listener already open for %s, %s", network, addr)
	}
	mak.Set(&s.listeners, key, ln)
	s.mu.Unlock()
	return ln, nil
}

type listenKey struct {
	network string
	host    string
	port    uint16
}

type listener struct {
	s    *Server
	key  listenKey
	addr string
	conn chan net.Conn
}

func (ln *listener) Accept() (net.Conn, error) {
	c, ok := <-ln.conn
	if !ok {
		return nil, fmt.Errorf("tsnet: %w", net.ErrClosed)
	}
	return c, nil
}

func (ln *listener) Addr() net.Addr { return addr{ln} }
func (ln *listener) Close() error {
	ln.s.mu.Lock()
	defer ln.s.mu.Unlock()
	if v, ok := ln.s.listeners[ln.key]; ok && v == ln {
		delete(ln.s.listeners, ln.key)
		close(ln.conn)
	}
	return nil
}

// Server returns the tsnet Server associated with the listener.
func (ln *listener) Server() *Server { return ln.s }

type addr struct{ ln *listener }

func (a addr) Network() string { return a.ln.key.network }
func (a addr) String() string  { return a.ln.addr }
