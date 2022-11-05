// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tswrap binary runs a child process and makes it accessible over
// Tailscale.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/portlist"
	"tailscale.com/syncs"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

var (
	tsDir   = flag.String("state-dir", "", "Directory in which to store the Tailscale auth state")
	verbose = flag.Bool("verbose", false, "Output tailscaled logs to stderr")
)

func main() {
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, syscall.SIGTERM)

	flag.Parse()

	argv := flag.Args()

	if len(argv) < 2 {
		log.Fatalf("Usage: %s tailscale-host:port child-cmd...", os.Args[0])
	}

	p := proxy{
		ListenAddr: argv[0],
		Command:    argv[1:],
		AuthKey:    os.Getenv("TS_AUTHKEY"),
		Dir:        *tsDir,
		Verbose:    *verbose,
	}

	if err := p.Start(); err != nil {
		log.Fatalf("Failed to start tswrap: %v", err)
	}
	go func() {
		<-sigch
		p.Stop()
	}()

	p.Wait()
}

type proxy struct {
	ListenAddr string
	Command    []string
	AuthKey    string
	Dir        string
	Verbose    bool

	shutdownCtx   context.Context
	startShutdown context.CancelFunc
	srv           *tsnet.Server
	client        *tailscale.LocalClient
	ln            net.Listener
	cmd           *exec.Cmd
	ports         syncs.AtomicValue[[]int]
}

func (p *proxy) Start() error {
	host, port, err := net.SplitHostPort(p.ListenAddr)
	if err != nil {
		return fmt.Errorf("parsing %q: %v", p.ListenAddr, err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("parsing port number %q: %v", port, err)
	}

	if p.Dir == "" && p.AuthKey == "" {
		return errors.New("must provide either a TS_AUTHKEY or a state storage dir")
	}

	p.srv = &tsnet.Server{
		Hostname: host,
		AuthKey:  p.AuthKey,
		Logf:     logger.Discard,
		Dir:      p.Dir,
	}
	if p.Dir == "" {
		p.srv.Store = new(mem.Store)
		p.srv.Ephemeral = true
	}
	if p.Verbose {
		p.srv.Logf = log.Printf
	}

	p.shutdownCtx, p.startShutdown = context.WithCancel(context.Background())

	p.client, err = p.srv.LocalClient()
	if err != nil {
		return fmt.Errorf("starting tsnet server failed: %v", err)
	}

	var (
		looped       = false
		authURLShown = false
		status       *ipnstate.Status
	)
loginLoop:
	for {
		if looped {
			time.Sleep(100 * time.Millisecond)
		}
		looped = true

		status, err = p.client.Status(context.Background())
		if err != nil {
			return fmt.Errorf("getting tsnet status: %v", err)
		}

		switch status.BackendState {
		case "Running":
			if status.Self == nil || status.Self.DNSName == "" {
				// No known DNS name yet, keep going
				continue
			}
			break loginLoop
		case "NeedsLogin":
			if status.AuthURL != "" && p.AuthKey != "" {
				return errors.New("failed to auth with provided authkey")
			}
			if status.AuthURL != "" && !authURLShown {
				log.Printf("To log into Tailscale, please visit: %s", status.AuthURL)
				authURLShown = true
			}
		default:
			// Just keep trying, eventually we should get into either
			// NeedsLogin or Running.
		}
	}

	addr := ":" + port
	p.ln, err = p.srv.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tailscale listen on %q: %v", addr, err)
	}

	log.Printf("Listening on %s:%s", status.Self.DNSName, port)

	p.cmd = exec.Command(p.Command[0], p.Command[1:]...)
	p.cmd.Stdin = os.Stdin
	p.cmd.Stdout = os.Stdout
	p.cmd.Stderr = os.Stderr
	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("starting child failed: %v", err)
	}

	go p.listen()
	go p.waitForChildExit()
	go p.monitorChildPorts()
	return nil
}

func (p *proxy) Stop() {
	p.startShutdown()
}

func (p *proxy) Wait() {
	<-p.shutdownCtx.Done()
	p.cmd.Process.Signal(syscall.SIGTERM)
	p.ln.Close()
	if p.srv.Ephemeral {
		p.client.Logout(context.Background())
	}
}

func (p *proxy) listen() {
	for {
		conn, err := p.ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		} else if err != nil {
			log.Printf("accept: %v", err)
			p.startShutdown()
			return
		}

		go func() {
			if err := p.proxy(conn); err != nil {
				log.Printf("proxying %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func (p *proxy) proxy(conn net.Conn) error {
	defer conn.Close()
	ports, err := p.getPorts()
	if err != nil {
		return err
	}

	if len(ports) > 1 {
		log.Printf("warning: multiple listening ports found on child, proxying to lowest one (%d)", ports[0])
	}

	prox, err := net.Dial("tcp", net.JoinHostPort("localhost", strconv.Itoa(ports[0])))
	if err != nil {
		return fmt.Errorf("dialing child port %d: %v", ports[0], err)
	}
	defer prox.Close()

	errc := make(chan error, 1)
	go proxyCopy(errc, conn, prox)
	go proxyCopy(errc, prox, conn)
	<-errc
	return nil
}

func (p *proxy) getPorts() ([]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for ctx.Err() == nil {
		if ports := p.ports.Load(); len(ports) > 0 {
			return ports, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil, errors.New("timed out waiting for child listening ports")
}

func (p *proxy) waitForChildExit() {
	if err := p.cmd.Wait(); err != nil {
		log.Printf("child exited with error: %v", err)
	} else {
		log.Printf("child exited, shutting down")
	}
	p.startShutdown()
}

func (p *proxy) monitorChildPorts() {
	for p.shutdownCtx.Err() == nil {
		ports, err := portsOfCmd(p.cmd)
		if err == nil {
			p.ports.Store(ports)
		}
		select {
		case <-time.After(time.Second):
		case <-p.shutdownCtx.Done():
			return
		}
	}
}

func proxyCopy(errc chan<- error, dst, src net.Conn) {
	// TODO: still need the unwrap hack from tcpproxy? Or is io.Copy
	// smart now?
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Print(err)
	}
	errc <- err
}

func portsOfCmd(cmd *exec.Cmd) (ports []int, err error) {
	if cmd == nil || cmd.Process == nil {
		return nil, errors.New("no process")
	}
	pid := cmd.Process.Pid

	poller, err := portlist.NewPoller()
	if err != nil {
		return nil, fmt.Errorf("creating port poller: %w", err)
	}
	defer poller.Close()
	// TODO(raggi): timeout?
	go poller.Run(context.Background())

	c := poller.Updates()
	for list := range c {
		for _, p := range list {
			if p.Pid == pid {
				ports = append(ports, int(p.Port))
			}
		}
		if len(ports) > 0 {
			break
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("no listening ports found")
	}

	sort.Ints(ports)
	return ports, nil
}
