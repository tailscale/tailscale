// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

var joinStatusArgs struct {
	json bool
}

var joinStatusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "tailscale join status [--json]",
	ShortHelp:  "Show the projected blueprint configuration on this node",
	LongHelp: strings.TrimSpace(`
"tailscale join status" displays the configuration projected onto
this node by its bound Blueprint, plus the set of peers visible to
this node that are bound to the same Blueprint.

Peer visibility is determined by the tailnet's policy; peers whose
binding is not visible to this node will not appear in the output.
"No other peers bound to bp:<id> are visible to this node." means
just that -- it does not mean there are no other bound peers.
`),
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("join status")
		fs.BoolVar(&joinStatusArgs.json, "json", false, "output in JSON format (WARNING: format subject to change)")
		return fs
	})(),
	Exec: runJoinStatus,
}

// joinStatusJSON is the documented (but unstable) JSON shape emitted
// by `tailscale join status --json`. Mirrors `tailscale status --json`'s
// "format may change between releases" contract.
type joinStatusJSON struct {
	BlueprintID     string                   `json:"BlueprintID"`
	BlueprintConfig *tailcfg.BlueprintConfig `json:"BlueprintConfig,omitempty"`
	BoundPeers      []boundPeerJSON          `json:"BoundPeers"`
}

type boundPeerJSON struct {
	HostName     string       `json:"HostName"`
	TailscaleIPs []netip.Addr `json:"TailscaleIPs"`
}

func runJoinStatus(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unexpected positional arguments: %q", args)
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if st == nil || st.Self == nil || st.Self.BlueprintID == "" {
		fmt.Fprintln(os.Stderr, "this node is not blueprint-bound; run 'tailscale join --blueprint=<id> --auth-key=...' to bind it")
		os.Exit(1)
	}
	if joinStatusArgs.json {
		renderJoinStatusJSON(os.Stdout, st)
	} else {
		renderJoinStatus(os.Stdout, st)
	}
	return nil
}

// renderJoinStatus writes the text representation of st's blueprint
// state to w and returns 0. The caller is responsible for checking
// whether the node is bound before calling; see runJoinStatus.
// Pure: no I/O beyond w.
func renderJoinStatus(w io.Writer, st *ipnstate.Status) int {
	id := st.Self.BlueprintID
	renderBlueprintConfig(w, id, st.Self.BlueprintConfig)

	type peerRow struct {
		host string
		ip   string
	}
	var rows []peerRow
	for _, p := range st.Peer {
		if p == nil || p.BlueprintID != id {
			continue
		}
		ip := ""
		if len(p.TailscaleIPs) > 0 {
			ip = p.TailscaleIPs[0].String()
		}
		rows = append(rows, peerRow{host: p.HostName, ip: ip})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].host < rows[j].host })

	if len(rows) == 0 {
		fmt.Fprintf(w, "No other peers bound to bp:%s are visible to this node.\n", id)
		return 0
	}
	fmt.Fprintf(w, "Peers bound to bp:%s (%d visible):\n", id, len(rows))
	for _, r := range rows {
		fmt.Fprintf(w, "  %-12s %s\n", r.host, r.ip)
	}
	return 0
}

// renderJoinStatusJSON writes the JSON shape to w; returns 0. The caller
// is responsible for checking whether the node is bound before calling;
// see runJoinStatus.
func renderJoinStatusJSON(w io.Writer, st *ipnstate.Status) int {
	out := joinStatusJSON{
		BlueprintID:     st.Self.BlueprintID,
		BlueprintConfig: st.Self.BlueprintConfig,
		BoundPeers:      []boundPeerJSON{},
	}
	for _, p := range st.Peer {
		if p == nil || p.BlueprintID != st.Self.BlueprintID {
			continue
		}
		out.BoundPeers = append(out.BoundPeers, boundPeerJSON{
			HostName:     p.HostName,
			TailscaleIPs: p.TailscaleIPs,
		})
	}
	sort.Slice(out.BoundPeers, func(i, j int) bool {
		return out.BoundPeers[i].HostName < out.BoundPeers[j].HostName
	})
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
	return 0
}
