// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var whoamiCmd = &ffcli.Command{
	Name:       "whoami",
	ShortUsage: "tailscale whoami [--json]",
	ShortHelp:  "Show the machine and user identity of the current machine",
	LongHelp: strings.TrimSpace(`
	'tailscale whoami' shows the machine and user identity of the current machine.
	It is equivalent to running 'tailscale whois' against one of the current machine's own Tailscale IP addresses.
	`),
	Exec: runWhoami,
	FlagSet: func() *flag.FlagSet {
		fs := newFlagSet("whoami")
		fs.BoolVar(&whoamiArgs.json, "json", false, "output in JSON format")
		return fs
	}(),
}

var whoamiArgs struct {
	json bool // output in JSON format
}

func runWhoami(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("too many arguments, expected none")
	}
	st, err := localClient.StatusWithoutPeers(ctx)
	if err != nil {
		return err
	}
	if len(st.TailscaleIPs) == 0 {
		return fmt.Errorf("no current Tailscale IP address; state: %v", st.BackendState)
	}
	who, err := localClient.WhoIsProto(ctx, "", st.TailscaleIPs[0].String())
	if err != nil {
		return err
	}
	return printWhoIs(who, whoamiArgs.json)
}
