// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_relayserver

package cli

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/net/udprelay/status"
)

func init() {
	debugPeerRelayCmd = mkDebugPeerRelaySessionsCmd
}

func mkDebugPeerRelaySessionsCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "peer-relay-sessions",
		ShortUsage: "tailscale debug peer-relay-sessions",
		Exec:       runPeerRelaySessions,
		ShortHelp:  "Print the current set of active peer relay sessions relayed through this node",
	}
}

func runPeerRelaySessions(ctx context.Context, args []string) error {
	srv, err := localClient.DebugPeerRelaySessions(ctx)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	f := func(format string, a ...any) { fmt.Fprintf(&buf, format, a...) }

	valid_state := false
	f("Server status  : ")
	switch srv.State {
	case status.Disabled:
		f("disabled (via node capability attribute 'disable-relay-server')")
	case status.ShutDown:
		f("shut down")
	case status.NotConfigured:
		f("not configured (you can configure the port with 'sudo tailscale set --relay-server-port=<PORT>')")
	case status.Uninitialized:
		valid_state = true
		f("listening on port %v", srv.UDPPort)
	case status.Running:
		valid_state = true
		f("running on port %v", srv.UDPPort)
	default:
		panic(fmt.Sprintf("unexpected status.ServerState: %#v", srv.State))
	}

	f("\n")
	if !valid_state {
		Stdout.Write(buf.Bytes())
		return nil
	}

	f("Active sessions: %d\n", len(srv.Sessions))
	if len(srv.Sessions) == 0 {
		Stdout.Write(buf.Bytes())
		return nil
	}

	slices.SortFunc(srv.Sessions, func(s1, s2 status.ServerSession) int { return cmp.Compare(s1.VNI, s2.VNI) })
	f("\n%-8s %-41s %-55s %-55s\n", "VNI", "Server", "Client 1", "Client 2")
	for _, s := range srv.Sessions {
		f("%-8d %-41s %-55s %-55s\n",
			s.VNI,
			s.Server.String(),
			s.Client1.String(),
			s.Client2.String(),
		)
	}

	Stdout.Write(buf.Bytes())
	return nil
}
