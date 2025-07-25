// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_relayserver

package cli

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"net/netip"
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

	fmtSessionDirection := func(a, z status.ClientInfo) string {
		fmtEndpoint := func(ap netip.AddrPort) string {
			if ap.IsValid() {
				return ap.String()
			}
			return "<no handshake>"
		}
		return fmt.Sprintf("%s(%s) --> %s(%s), Packets: %d Bytes: %d",
			fmtEndpoint(a.Endpoint), a.ShortDisco,
			fmtEndpoint(z.Endpoint), z.ShortDisco,
			a.PacketsTx, a.BytesTx)
	}

	f("\n")
	slices.SortFunc(srv.Sessions, func(s1, s2 status.ServerSession) int { return cmp.Compare(s1.VNI, s2.VNI) })
	for _, s := range srv.Sessions {
		f("VNI: %d\n", s.VNI)
		f("  %s\n", fmtSessionDirection(s.Client1, s.Client2))
		f("  %s\n", fmtSessionDirection(s.Client2, s.Client1))
	}
	Stdout.Write(buf.Bytes())
	return nil
}
