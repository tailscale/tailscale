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

	f("Server port: ")
	if srv.UDPPort == nil {
		f("not configured (you can configure the port with 'tailscale set --relay-server-port=<PORT>')")
	} else {
		f("%d", *srv.UDPPort)
	}
	f("\n")
	f("Sessions count: %d\n", len(srv.Sessions))
	if len(srv.Sessions) == 0 {
		Stdout.Write(buf.Bytes())
		return nil
	}

	fmtClientInfo := func(info status.ClientInfo) string {
		addrPort := "<no handshake>"
		if info.Endpoint.IsValid() {
			addrPort = info.Endpoint.String()
		}
		return fmt.Sprintf("%s(%v)", info.ShortDisco, addrPort)
	}

	slices.SortFunc(srv.Sessions, func(s1, s2 status.ServerSession) int { return cmp.Compare(s1.VNI, s2.VNI) })
	f("\n%-8s %-67s %-20s %-67s %-20s\n", "VNI", "Client1", "Client1 Bytes", "Client2", "Client2 Bytes")
	for _, s := range srv.Sessions {
		f("%-8d %-67s %-20d %-67s %-20d\n",
			s.VNI,
			fmtClientInfo(s.Client1),
			s.Client1.BytesTx,
			fmtClientInfo(s.Client2),
			s.Client2.BytesTx,
		)
	}

	Stdout.Write(buf.Bytes())
	return nil
}
