// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnserver

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/logtail/backoff"
	"tailscale.com/safesocket"
	"tailscale.com/smallzstd"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine"
)

// Options is the configuration of the Tailscale node agent.
type Options struct {
	// SocketPath, on unix systems, is the unix socket path to listen
	// on for frontend connections.
	SocketPath string

	// Port, on windows, is the localhost TCP port to listen on for
	// frontend connections.
	Port int

	// StatePath is the path to the stored agent state.
	StatePath string

	// AutostartStateKey, if non-empty, immediately starts the agent
	// using the given StateKey. If empty, the agent stays idle and
	// waits for a frontend to start it.
	AutostartStateKey ipn.StateKey

	// LegacyConfigPath optionally specifies the old-style relaynode
	// relay.conf location. If both LegacyConfigPath and
	// AutostartStateKey are specified and the requested state doesn't
	// exist in the backend store, the backend migrates the config
	// from LegacyConfigPath.
	//
	// TODO(danderson): remove some time after the transition to
	// tailscaled is done.
	LegacyConfigPath string

	// SurviveDisconnects specifies how the server reacts to its
	// frontend disconnecting. If true, the server keeps running on
	// its existing state, and accepts new frontend connections. If
	// false, the server dumps its state and becomes idle.
	//
	// To support CLI connections (notably, "tailscale status"),
	// the actual definition of "disconnect" is when the
	// connection count transitions from 1 to 0.
	SurviveDisconnects bool

	// DebugMux, if non-nil, specifies an HTTP ServeMux in which
	// to register a debug handler.
	DebugMux *http.ServeMux
}

// server is an IPN backend and its set of 0 or more active connections
// talking to an IPN backend.
type server struct {
	resetOnZero bool // call bs.Reset on transition from 1->0 connections

	bsMu sync.Mutex // lock order: bsMu, then mu
	bs   *ipn.BackendServer

	mu      sync.Mutex
	clients map[net.Conn]bool
}

func (s *server) serveConn(ctx context.Context, c net.Conn, logf logger.Logf) {
	s.addConn(c)
	logf("incoming control connection")
	defer s.removeAndCloseConn(c)
	for ctx.Err() == nil {
		msg, err := ipn.ReadMsg(c)
		if err != nil {
			if ctx.Err() == nil {
				logf("ReadMsg: %v", err)
			}
			return
		}
		s.bsMu.Lock()
		if err := s.bs.GotCommandMsg(msg); err != nil {
			logf("GotCommandMsg: %v", err)
		}
		gotQuit := s.bs.GotQuit
		s.bsMu.Unlock()
		if gotQuit {
			return
		}
	}
}

func (s *server) addConn(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clients == nil {
		s.clients = map[net.Conn]bool{}
	}
	s.clients[c] = true
}

func (s *server) removeAndCloseConn(c net.Conn) {
	s.mu.Lock()
	delete(s.clients, c)
	remain := len(s.clients)
	s.mu.Unlock()

	if remain == 0 && s.resetOnZero {
		s.bsMu.Lock()
		s.bs.Reset()
		s.bsMu.Unlock()
	}
	c.Close()
}

func (s *server) stopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		safesocket.ConnCloseRead(c)
		safesocket.ConnCloseWrite(c)
	}
	s.clients = nil
}

func (s *server) writeToClients(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		ipn.WriteMsg(c, b)
	}
}

// Run runs a Tailscale backend service.
// The getEngine func is called repeatedly, once per connection, until it returns an engine successfully.
func Run(ctx context.Context, logf logger.Logf, logid string, getEngine func() (wgengine.Engine, error), opts Options) error {
	runDone := make(chan struct{})
	defer close(runDone)

	listen, _, err := safesocket.Listen(opts.SocketPath, uint16(opts.Port))
	if err != nil {
		return fmt.Errorf("safesocket.Listen: %v", err)
	}

	server := &server{
		resetOnZero: !opts.SurviveDisconnects,
	}

	// When the context is closed or when we return, whichever is first, close our listner
	// and all open connections.
	go func() {
		select {
		case <-ctx.Done():
		case <-runDone:
		}
		server.stopAll()
		listen.Close()
	}()
	logf("Listening on %v", listen.Addr())

	bo := backoff.NewBackoff("ipnserver", logf)

	eng, err := getEngine()
	if err != nil {
		logf("Initial getEngine call: %v", err)
		for i := 1; ctx.Err() == nil; i++ {
			s, err := listen.Accept()
			if err != nil {
				logf("%d: Accept: %v", i, err)
				bo.BackOff(ctx, err)
				continue
			}
			logf("%d: trying getEngine again...", i)
			//lint:ignore SA4006 staticcheck is wrong
			eng, err = getEngine()
			if err == nil {
				logf("%d: GetEngine worked; exiting failure loop", i)
				break
			}
			logf("%d: getEngine failed again: %v", i, err)
			errMsg := err.Error()
			go func() {
				defer s.Close()
				serverToClient := func(b []byte) { ipn.WriteMsg(s, b) }
				bs := ipn.NewBackendServer(logf, nil, serverToClient)
				bs.SendErrorMessage(errMsg)
				s.Read(make([]byte, 1))
			}()
		}
		return ctx.Err()
	}

	var store ipn.StateStore
	if opts.StatePath != "" {
		store, err = ipn.NewFileStore(opts.StatePath)
		if err != nil {
			return fmt.Errorf("ipn.NewFileStore(%q): %v", opts.StatePath, err)
		}
	} else {
		store = &ipn.MemoryStore{}
	}

	b, err := ipn.NewLocalBackend(logf, logid, store, eng)
	if err != nil {
		return fmt.Errorf("NewLocalBackend: %v", err)
	}
	defer b.Shutdown()
	b.SetDecompressor(func() (controlclient.Decompressor, error) {
		return smallzstd.NewDecoder(nil)
	})

	if opts.DebugMux != nil {
		opts.DebugMux.HandleFunc("/debug/ipn", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			st := b.Status()
			// TODO(bradfitz): add LogID and opts to st?
			st.WriteHTML(w)
		})
	}

	server.bs = ipn.NewBackendServer(logf, b, server.writeToClients)

	if opts.AutostartStateKey != "" {
		server.bs.GotCommand(&ipn.Command{
			Version: version.LONG,
			Start: &ipn.StartArgs{
				Opts: ipn.Options{
					StateKey:         opts.AutostartStateKey,
					LegacyConfigPath: opts.LegacyConfigPath,
				},
			},
		})
	}

	for i := 1; ctx.Err() == nil; i++ {
		c, err := listen.Accept()
		if err != nil {
			if ctx.Err() == nil {
				logf("ipnserver: Accept: %v", err)
				bo.BackOff(ctx, err)
			}
			continue
		}
		go server.serveConn(ctx, c, logger.WithPrefix(logf, fmt.Sprintf("ipnserver: conn%d: ", i)))
	}
	return ctx.Err()
}

func BabysitProc(ctx context.Context, args []string, logf logger.Logf) {

	executable, err := os.Executable()
	if err != nil {
		panic("cannot determine executable: " + err.Error())
	}

	var proc struct {
		mu sync.Mutex
		p  *os.Process
	}

	done := make(chan struct{})
	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		var sig os.Signal
		select {
		case sig = <-interrupt:
			logf("BabysitProc: got signal: %v", sig)
			close(done)
		case <-ctx.Done():
			logf("BabysitProc: context done")
			sig = os.Kill
			close(done)
		}

		proc.mu.Lock()
		proc.p.Signal(sig)
		proc.mu.Unlock()
	}()

	bo := backoff.NewBackoff("BabysitProc", logf)

	for {
		startTime := time.Now()
		log.Printf("exec: %#v %v", executable, args)
		cmd := exec.Command(executable, args...)

		// Create a pipe object to use as the subproc's stdin.
		// When the writer goes away, the reader gets EOF.
		// A subproc can watch its stdin and exit when it gets EOF;
		// this is a very reliable way to have a subproc die when
		// its parent (us) disappears.
		// We never need to actually write to wStdin.
		rStdin, wStdin, err := os.Pipe()
		if err != nil {
			log.Printf("os.Pipe 1: %v", err)
			return
		}

		// Create a pipe object to use as the subproc's stdout/stderr.
		// We'll read from this pipe and send it to logf, line by line.
		// We can't use os.exec's io.Writer for this because it
		// doesn't care about lines, and thus ends up merging multiple
		// log lines into one or splitting one line into multiple
		// logf() calls. bufio is more appropriate.
		rStdout, wStdout, err := os.Pipe()
		if err != nil {
			log.Printf("os.Pipe 2: %v", err)
		}
		go func(r *os.File) {
			defer r.Close()
			rb := bufio.NewReader(r)
			for {
				s, err := rb.ReadString('\n')
				if s != "" {
					logf("%s", s)
				}
				if err != nil {
					break
				}
			}
		}(rStdout)

		cmd.Stdin = rStdin
		cmd.Stdout = wStdout
		cmd.Stderr = wStdout
		err = cmd.Start()

		// Now that the subproc is started, get rid of our copy of the
		// pipe reader. Bad things happen on Windows if more than one
		// process owns the read side of a pipe.
		rStdin.Close()
		wStdout.Close()

		if err != nil {
			log.Printf("starting subprocess failed: %v", err)
		} else {
			proc.mu.Lock()
			proc.p = cmd.Process
			proc.mu.Unlock()

			err = cmd.Wait()
			log.Printf("subprocess exited: %v", err)
		}

		// If the process finishes, clean up the write side of the
		// pipe. We'll make a new one when we restart the subproc.
		wStdin.Close()

		if time.Since(startTime) < 60*time.Second {
			bo.BackOff(ctx, fmt.Errorf("subproc early exit: %v", err))
		} else {
			// Reset the timeout, since the process ran for a while.
			bo.BackOff(ctx, nil)
		}

		select {
		case <-done:
			return
		default:
		}
	}
}

// FixedEngine returns a func that returns eng and a nil error.
func FixedEngine(eng wgengine.Engine) func() (wgengine.Engine, error) {
	return func() (wgengine.Engine, error) { return eng, nil }
}
