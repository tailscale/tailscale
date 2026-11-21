// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_wakeonlan

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
)

func init() {
	maybeWakeOnLANCmd = wakeOnLANCmd
}

var wakeOnLANCmd = func() *ffcli.Command {
	return &ffcli.Command{
		Name:       "wol",
		ShortUsage: "tailscale wol [--via=<device>] <device|MAC>",
		ShortHelp:  "Wake a sleeping machine with Wake-on-LAN",
		LongHelp: strings.TrimSpace(`
"tailscale wol" sends a Wake-on-LAN magic packet to wake a sleeping machine.

The target is either a MAC address or the name or Tailscale IP of a device in
your tailnet. To wake a tailnet device by name, it must advertise its MAC
addresses, which it does when its tailscaled runs with TS_WAKE_MAC=auto (or
TS_WAKE_MAC=<mac>).

Wake-on-LAN packets only travel within a LAN. By default they are broadcast
from this machine. If the sleeping machine is elsewhere, use --via to name an
awake device on its LAN; that device broadcasts the packets for you. The relay
device must be owned by you, or grant you the Wake-on-LAN peer capability.

Examples:

  tailscale wol --via=nas desktop
  tailscale wol --via=100.101.102.103 aa:bb:cc:dd:ee:ff
  tailscale wol aa:bb:cc:dd:ee:ff
`),
		Exec: runWakeOnLAN,
		FlagSet: func() *flag.FlagSet {
			fs := newFlagSet("wol")
			fs.StringVar(&wolArgs.via, "via", "", "name or Tailscale IP of an awake device on the target's LAN to send the packets from (default: this machine)")
			fs.BoolVar(&wolArgs.json, "json", false, "output in JSON format")
			return fs
		}(),
	}
}

var wolArgs struct {
	via  string
	json bool
}

func runWakeOnLAN(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tailscale wol [--via=<device>] <device|MAC>")
	}
	res, err := localClient.WakeOnLAN(ctx, args[0], wolArgs.via)
	if err != nil {
		return err
	}
	if wolArgs.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	for _, e := range res.Errors {
		printf("warning: %s\n", e)
	}
	if len(res.SentTo) == 0 {
		return fmt.Errorf("no Wake-on-LAN packets were sent from %s", res.Via)
	}
	printf("Sent Wake-on-LAN packet for %s from %s on %s\n",
		strings.Join(res.MACs, ", "), res.Via, strings.Join(res.SentTo, ", "))
	return nil
}
