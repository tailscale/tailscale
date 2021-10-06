// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsnet provides Tailscale as a library.
//
// It is an experimental work in progress.
package tsnet

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/nettest"
	"tailscale.com/smallzstd"
	"tailscale.com/types/logger"
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

	// Hostname is the hostname to present to the control server.
	// If empty, the binary name is used.
	Hostname string

	// Logf, if non-nil, specifies the logger to use. By default,
	// log.Printf is used.
	Logf logger.Logf

	initOnce sync.Once
	initErr  error
	lb       *ipnlocal.LocalBackend
	// the state directory
	dir      string
	hostname string

	mu        sync.Mutex
	listeners map[listenKey]*listener
}

func (s *Server) doInit() {
	if err := s.start(); err != nil {
		s.initErr = fmt.Errorf("tsnet: %w", err)
	}
}

func (s *Server) start() error {
	if v, _ := strconv.ParseBool(os.Getenv("TAILSCALE_USE_WIP_CODE")); !v {
		return errors.New("code disabled without environment variable TAILSCALE_USE_WIP_CODE set true")
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	prog := strings.TrimSuffix(strings.ToLower(filepath.Base(exe)), ".exe")

	s.hostname = s.Hostname
	if s.hostname == "" {
		s.hostname = prog
	}

	s.dir = s.Dir
	if s.dir == "" {
		confDir, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		s.dir = filepath.Join(confDir, "tslib-"+prog)
		if err := os.MkdirAll(s.dir, 0700); err != nil {
			return err
		}
	}
	if fi, err := os.Stat(s.dir); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("%v is not a directory", s.dir)
	}

	logf := s.Logf
	if logf == nil {
		logf = log.Printf
	}

	// TODO(bradfitz): start logtail? don't use filch, perhaps?
	// only upload plumbed Logf?

	linkMon, err := monitor.New(logf)
	if err != nil {
		return err
	}

	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		ListenPort:  0,
		LinkMonitor: linkMon,
	})
	if err != nil {
		return err
	}

	tunDev, magicConn, ok := eng.(wgengine.InternalsGetter).GetInternals()
	if !ok {
		return fmt.Errorf("%T is not a wgengine.InternalsGetter", eng)
	}

	ns, err := netstack.Create(logf, tunDev, eng, magicConn, false)
	if err != nil {
		return fmt.Errorf("netstack.Create: %w", err)
	}
	ns.ForwardTCPIn = s.forwardTCP
	if err := ns.Start(); err != nil {
		return fmt.Errorf("failed to start netstack: %w", err)
	}

	statePath := filepath.Join(s.dir, "tailscaled.state")
	store, err := ipn.NewFileStore(statePath)
	if err != nil {
		return err
	}
	logid := "tslib-TODO"

	lb, err := ipnlocal.NewLocalBackend(logf, logid, store, eng)
	if err != nil {
		return fmt.Errorf("NewLocalBackend: %v", err)
	}
	s.lb = lb
	lb.SetDecompressor(func() (controlclient.Decompressor, error) {
		return smallzstd.NewDecoder(nil)
	})
	prefs := ipn.NewPrefs()
	prefs.Hostname = s.hostname
	prefs.WantRunning = true
	err = lb.Start(ipn.Options{
		StateKey:    ipn.GlobalDaemonStateKey,
		UpdatePrefs: prefs,
		AuthKey:     os.Getenv("TS_AUTHKEY"),
	})
	if err != nil {
		return fmt.Errorf("starting backend: %w", err)
	}
	if os.Getenv("TS_LOGIN") == "1" || os.Getenv("TS_AUTHKEY") != "" {
		s.lb.StartLoginInteractive()
	}

	// Run the localapi handler, to allow fetching LetsEncrypt certs.
	lah := localapi.NewHandler(lb, logf, logid)
	lah.PermitWrite = true
	lah.PermitRead = true

	// Create an in-process listener.
	// nettest.Listen provides a in-memory pipe based implementation for net.Conn.
	// TODO(maisem): Rename nettest package to remove "test".
	lal := nettest.Listen("local-tailscaled.sock:80")

	// Override the Tailscale client to use the in-process listener.
	tailscale.TailscaledDialer = lal.Dial
	go func() {
		if err := http.Serve(lal, lah); err != nil {
			logf("localapi serve error: %v", err)
		}
	}()
	return nil
}

func (s *Server) forwardTCP(c net.Conn, port uint16) {
	s.mu.Lock()
	ln, ok := s.listeners[listenKey{"tcp", "", fmt.Sprint(port)}]
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

func (s *Server) Listen(network, addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("tsnet: %w", err)
	}

	s.initOnce.Do(s.doInit)
	if s.initErr != nil {
		return nil, s.initErr
	}

	key := listenKey{network, host, port}
	ln := &listener{
		s:    s,
		key:  key,
		addr: addr,

		conn: make(chan net.Conn),
	}
	s.mu.Lock()
	if s.listeners == nil {
		s.listeners = map[listenKey]*listener{}
	}
	if _, ok := s.listeners[key]; ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("tsnet: listener already open for %s, %s", network, addr)
	}
	s.listeners[key] = ln
	s.mu.Unlock()
	return ln, nil
}

type listenKey struct {
	network string
	host    string
	port    string
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

type addr struct{ ln *listener }

func (a addr) Network() string { return a.ln.key.network }
func (a addr) String() string  { return a.ln.addr }
