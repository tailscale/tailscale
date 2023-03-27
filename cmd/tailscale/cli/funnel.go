// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/util/mak"
)

var funnelCmd = newFunnelCommand(&serveEnv{lc: &localClient})

// newFunnelCommand returns a new "funnel" subcommand using e as its environment.
// The funnel subcommand is used to turn on/off the Funnel service.
// Funnel is off by default.
// Funnel allows you to publish a 'tailscale serve' server publicly, open to the
// entire internet.
// newFunnelCommand shares the same serveEnv as the "serve" subcommand. See
// newServeCommand and serve.go for more details.
func newFunnelCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:      "funnel",
		ShortHelp: "[BETA] turn Tailscale Funnel on or off",
		ShortUsage: strings.TrimSpace(`
funnel <serve-port> {on|off}
  funnel status [--json]
`),
		LongHelp: strings.Join([]string{
			"Funnel allows you to publish a 'tailscale serve'",
			"server publicly, open to the entire internet.",
			"",
			"Turning off Funnel only turns off serving to the internet.",
			"It does not affect serving to your tailnet.",
		}, "\n"),
		Exec:      e.runFunnel,
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "show current serve/funnel status",
				FlagSet: e.newFlags("funnel-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
		},
	}
}

// runFunnel is the entry point for the "tailscale funnel" subcommand and
// manages turning on/off funnel. Funnel is off by default.
//
// Note: funnel is only supported on single DNS name for now. (2022-11-15)
func (e *serveEnv) runFunnel(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return flag.ErrHelp
	}

	var on bool
	switch args[1] {
	case "on", "off":
		on = args[1] == "on"
	default:
		return flag.ErrHelp
	}
	sc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	st, err := e.getLocalClientStatus(ctx)
	if err != nil {
		return fmt.Errorf("getting client status: %w", err)
	}

	port64, err := strconv.ParseUint(args[0], 10, 16)
	if err != nil {
		return err
	}
	port := uint16(port64)

	if err := ipn.CheckFunnelAccess(port, st.Self.Capabilities); err != nil {
		return err
	}
	dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
	hp := ipn.HostPort(dnsName + ":" + strconv.Itoa(int(port)))
	if on == sc.AllowFunnel[hp] {
		printFunnelWarning(sc)
		// Nothing to do.
		return nil
	}
	if on {
		mak.Set(&sc.AllowFunnel, hp, true)
	} else {
		delete(sc.AllowFunnel, hp)
		// clear map mostly for testing
		if len(sc.AllowFunnel) == 0 {
			sc.AllowFunnel = nil
		}
	}
	if err := e.lc.SetServeConfig(ctx, sc); err != nil {
		return err
	}
	printFunnelWarning(sc)
	return nil
}

// printFunnelWarning prints a warning if the Funnel is on but there is no serve
// config for its host:port.
func printFunnelWarning(sc *ipn.ServeConfig) {
	var warn bool
	for hp, a := range sc.AllowFunnel {
		if !a {
			continue
		}
		_, portStr, _ := net.SplitHostPort(string(hp))
		p, _ := strconv.ParseUint(portStr, 10, 16)
		if _, ok := sc.TCP[uint16(p)]; !ok {
			warn = true
			fmt.Fprintf(os.Stderr, "Warning: funnel=on for %s, but no serve config\n", hp)
		}
	}
	if warn {
		fmt.Fprintf(os.Stderr, "         run: `tailscale serve --help` to see how to configure handlers\n")
	}
}
