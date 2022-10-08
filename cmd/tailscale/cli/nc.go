// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn/ipnstate"
)

var ncCmd = &ffcli.Command{
	Name:       "nc",
	ShortUsage: "nc <hostname-or-IP> <port>\n  nc -l",
	ShortHelp:  "Connect to a port on a host, connected to stdin/stdout",
	Exec:       runNC,
	FlagSet: func() *flag.FlagSet {
		fs := flag.NewFlagSet("nc", flag.ExitOnError)
		fs.BoolVar(&ncArgs.listen, "l", false, "whether to listen for incoming connections (\"Tailpipe\")")
		return fs
	}(),
}

var ncArgs struct {
	listen bool
}

func runNC(ctx context.Context, args []string) error {
	if ncArgs.listen {
		if len(args) != 0 {
			return errors.New("no arguments supported with -l")
		}
		return runNCListen(ctx)
	}

	if len(args) != 2 {
		return errors.New("usage: nc <hostname-or-IP> <port>")
	}

	if _, err := checkRunning(ctx); err != nil {
		return err
	}
	hostOrIP, portStr := args[0], args[1]

	var c net.Conn
	var err error
	if strings.HasPrefix(portStr, "tailpipe-") {
		c, err = localClient.DialTCPNamedPort(ctx, hostOrIP, portStr)
	} else {
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port number %q", portStr)
		}
		// TODO(bradfitz): also add UDP too, via flag?
		c, err = localClient.DialTCP(ctx, hostOrIP, uint16(port))
	}
	if err != nil {
		return fmt.Errorf("Dial(%q, %v): %w", hostOrIP, portStr, err)
	}
	defer c.Close()
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(os.Stdout, c)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(c, os.Stdin)
		errc <- err
	}()
	return <-errc
}

func checkRunning(ctx context.Context) (*ipnstate.Status, error) {
	st, err := localClient.Status(ctx)
	if err != nil {
		return nil, fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}
	return st, err
}

// runNCLIsten opens a tailpipe.
func runNCListen(ctx context.Context) error {
	st, err := checkRunning(ctx)
	if err != nil {
		return err
	}
	portName, accept, err := localClient.ListenNewRandomPortName(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(Stderr, "Port opened. Connect with: nc %v %v\n", st.Self.Addrs[0], portName)
	c, err := accept(ctx)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(Stdout, c)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(c, Stdin)
		errc <- err
	}()
	return <-errc
}
