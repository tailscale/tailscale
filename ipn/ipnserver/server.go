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
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/klauspost/compress/zstd"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/logtail/backoff"
	"tailscale.com/safesocket"
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
	SurviveDisconnects bool
}

func pump(logf logger.Logf, ctx context.Context, bs *ipn.BackendServer, s net.Conn) {
	defer logf("Control connection done.\n")

	for ctx.Err() == nil && !bs.GotQuit {
		msg, err := ipn.ReadMsg(s)
		if err != nil {
			logf("ReadMsg: %v\n", err)
			break
		}
		err = bs.GotCommandMsg(msg)
		if err != nil {
			logf("GotCommandMsg: %v\n", err)
			break
		}
	}
}

func Run(rctx context.Context, logf logger.Logf, logid string, opts Options, e wgengine.Engine) error {
	bo := backoff.Backoff{Name: "ipnserver"}

	listen, _, err := safesocket.Listen(opts.SocketPath, uint16(opts.Port))
	if err != nil {
		return fmt.Errorf("safesocket.Listen: %v", err)
	}
	// Go listeners can't take a context, close it instead.
	go func() {
		<-rctx.Done()
		listen.Close()
	}()
	logf("Listening on %v\n", listen.Addr())

	var store ipn.StateStore
	if opts.StatePath != "" {
		store, err = ipn.NewFileStore(opts.StatePath)
		if err != nil {
			return fmt.Errorf("ipn.NewFileStore(%q): %v", opts.StatePath, err)
		}
	} else {
		store = &ipn.MemoryStore{}
	}

	b, err := ipn.NewLocalBackend(logf, logid, store, e)
	if err != nil {
		return fmt.Errorf("NewLocalBackend: %v", err)
	}
	b.SetDecompressor(func() (controlclient.Decompressor, error) {
		return zstd.NewReader(nil)
	})
	b.SetCmpDiff(func(x, y interface{}) string { return cmp.Diff(x, y) })

	var s net.Conn
	serverToClient := func(b []byte) {
		if s != nil {
			ipn.WriteMsg(s, b)
		}
	}

	bs := ipn.NewBackendServer(logf, b, serverToClient)

	if opts.AutostartStateKey != "" {
		bs.GotCommand(&ipn.Command{
			Version: version.LONG,
			Start: &ipn.StartArgs{
				Opts: ipn.Options{
					StateKey:         opts.AutostartStateKey,
					LegacyConfigPath: opts.LegacyConfigPath,
				},
			},
		})
	}

	var oldS net.Conn
	//lint:ignore SA4006 ctx is never used, but has to be defined so
	// that it can be assigned to in the following for loop. It's a
	// bit of necessary code convolution to work around Go's variable
	// shadowing rules.
	ctx, cancel := context.WithCancel(rctx)

	stopAll := func() {
		// Currently we only support one client connection at a time.
		// Theoretically we could allow multiple clients, by passing
		// notifications to all of them and accepting commands from
		// any of them, but there doesn't seem to be much need for
		// that right now.
		if oldS != nil {
			cancel()
			safesocket.ConnCloseRead(oldS)
			safesocket.ConnCloseWrite(oldS)
		}
	}

	for i := 1; rctx.Err() == nil; i++ {
		s, err = listen.Accept()
		if err != nil {
			logf("%d: Accept: %v\n", i, err)
			bo.BackOff(rctx, err)
			continue
		}
		logf("%d: Incoming control connection.\n", i)
		stopAll()

		ctx, cancel = context.WithCancel(context.Background())
		oldS = s

		go func(ctx context.Context, bs *ipn.BackendServer, s net.Conn, i int) {
			si := fmt.Sprintf("%d: ", i)
			pump(func(fmt string, args ...interface{}) {
				logf(si+fmt, args...)
			}, ctx, bs, s)
			if !opts.SurviveDisconnects || bs.GotQuit {
				bs.Reset()
				s.Close()
			}
			// Quitting not allowed, just keep going.
			bs.GotQuit = false
		}(ctx, bs, s, i)

		bo.BackOff(ctx, nil)
	}
	stopAll()

	return rctx.Err()
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
			logf("BabysitProc: got signal: %v\n", sig)
			close(done)
		case <-ctx.Done():
			logf("BabysitProc: context done\n")
			sig = os.Kill
			close(done)
		}

		proc.mu.Lock()
		proc.p.Signal(sig)
		proc.mu.Unlock()
	}()

	bo := backoff.Backoff{Name: "BabysitProc"}

	for {
		startTime := time.Now()
		log.Printf("exec: %#v %v\n", executable, args)
		cmd := exec.Command(executable, args...)

		// Create a pipe object to use as the subproc's stdin.
		// When the writer goes away, the reader gets EOF.
		// A subproc can watch its stdin and exit when it gets EOF;
		// this is a very reliable way to have a subproc die when
		// its parent (us) disappears.
		// We never need to actually write to wStdin.
		rStdin, wStdin, err := os.Pipe()
		if err != nil {
			log.Printf("os.Pipe 1: %v\n", err)
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
			log.Printf("os.Pipe 2: %v\n", err)
		}
		go func(r *os.File) {
			defer r.Close()
			rb := bufio.NewReader(r)
			for {
				s, err := rb.ReadString('\n')
				if s != "" {
					logf("%s\n", strings.TrimSuffix(s, "\n"))
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
