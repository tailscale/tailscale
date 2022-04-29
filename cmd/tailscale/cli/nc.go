// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var ncCmd = &ffcli.Command{
	Name:       "nc",
	ShortUsage: "nc <hostname-or-IP> <port>",
	ShortHelp:  "Connect to a port on a host, connected to stdin/stdout",
	Exec:       runNC,
}

func runNC(ctx context.Context, args []string) error {
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		printf("%s\n", description)
		os.Exit(1)
	}

	if len(args) != 2 {
		return errors.New("usage: nc <hostname-or-IP> <port>")
	}

	hostOrIP, portStr := args[0], args[1]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port number %q", portStr)
	}

	// TODO(bradfitz): also add UDP too, via flag?
	c, err := localClient.DialTCP(ctx, hostOrIP, uint16(port))
	if err != nil {
		return fmt.Errorf("Dial(%q, %v): %w", hostOrIP, port, err)
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
