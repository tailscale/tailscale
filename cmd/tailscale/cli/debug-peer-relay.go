// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_relayserver

package cli

import (
	"context"

	"github.com/peterbourgon/ff/v3/ffcli"
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
	v, err := localClient.DebugPeerRelaySessions(ctx)
	if err != nil {
		return err
	}

	if len(v) == 0 {
		println("This peer relay server is not relaying any sessions.")
		return nil
	}

	println("Sessions relayed by this peer relay server:")
	for _, s := range v {
		printf("- Session %v: %v <-> %v <-> %v\n", s.VNI, s.ClientEndpoint[0], s.ServerEndpoint, s.ClientEndpoint[1])
		printf("    Server  : disco=%v | endpoint=%v | status=%v\n", s.ServerShortDisco, s.ServerEndpoint, s.Status.OverallStatus)
		printf("    Client 1: disco=%v | endpoint=%v | status=%v, %v\n", s.ClientShortDisco[0], s.ClientEndpoint[0], s.Status.ClientBindStatus[0], s.Status.ClientPingStatus[0])
		printf("    Client 2: disco=%v | endpoint=%v | status=%v, %v\n", s.ClientShortDisco[1], s.ClientEndpoint[1], s.Status.ClientBindStatus[1], s.Status.ClientPingStatus[1])
	}

	return nil
}
