// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
)

var ncCmd = &ffcli.Command{
	Name:       "nc",
	ShortUsage: "tailscale nc <hostname-or-IP> <port>",
	ShortHelp:  "Connect to a port on a host, connected to stdin/stdout",
	Exec:       runNC,
}

func init() {
	ffcomplete.Args(ncCmd, func(args []string) ([]string, ffcomplete.ShellCompDirective, error) {
		if len(args) > 1 {
			return nil, ffcomplete.ShellCompDirectiveNoFileComp, nil
		}
		return completeHostOrIP(ffcomplete.LastArg(args))
	})
}

func completeHostOrIP(arg string) ([]string, ffcomplete.ShellCompDirective, error) {
	st, err := localClient.Status(context.Background())
	if err != nil {
		return nil, 0, err
	}
	nodes := make([]string, 0, len(st.Peer))
	for _, node := range st.Peer {
		nodes = append(nodes, strings.TrimSuffix(node.DNSName, "."))
	}
	return nodes, ffcomplete.ShellCompDirectiveNoFileComp, nil
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
		return errors.New("usage: tailscale nc <hostname-or-IP> <port>")
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
