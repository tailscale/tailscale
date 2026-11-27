// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/cmd/tailscale/cli/ffcomplete"
	"tailscale.com/types/nettype"
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
	return pipeStdio(c, os.Stdin, os.Stdout)
}

// pipeStdio copies stdin to c and c to stdout.
//
// When c reaches EOF, it closes stdout if it's an [io.Closer].
// When stdin reaches EOF, it half-closes c so that the peer sees EOF but
// can still reply, and when the peer half-closes its side, it keeps
// sending stdin (tailscale/tailscale#22637). It returns when both
// directions are done or either fails. If c can't be half-closed, it
// returns as soon as stdin reaches EOF.
func pipeStdio(c net.Conn, stdin io.Reader, stdout io.Writer) error {
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(stdout, c)
		if err == nil {
			// The peer is done sending; tell whoever reads our output.
			if cl, ok := stdout.(io.Closer); ok {
				cl.Close()
			}
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(c, stdin)
		if err == nil {
			cw, ok := c.(nettype.TCPWriteCloser)
			if !ok || cw.CloseWrite() != nil {
				err = errNoHalfClose
			}
		}
		errc <- err
	}()
	for range 2 {
		if err := <-errc; err != nil {
			if err == errNoHalfClose {
				return nil
			}
			return err
		}
	}
	return nil
}

// errNoHalfClose is sent by pipeStdio's stdin copier when stdin reached EOF
// but the connection can't be half-closed.
var errNoHalfClose = errors.New("connection can't be half-closed")
