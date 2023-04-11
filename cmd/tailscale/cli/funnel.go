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
		ShortHelp: "Turn on/off Funnel service",
		ShortUsage: strings.TrimSpace(`
funnel <serve-port> {on|off}
  funnel status [--json]
  funnel https:<port> <mount-point> <source> [off]
`),
		LongHelp: strings.TrimSpace(`
*** BETA; all of this is subject to change ***

Funnel allows you to publish a Tailscale Serve
server publicly, open to the entire internet.

EXAMPLES
  - To toggle Funnel on HTTPS port 443 (default):
    $ tailscale funnel 443 on
    $ tailscale funnel 443 off

    Turning off Funnel only turns off serving to the internet.
    It does not affect serving to your tailnet.

  - To proxy requests to a web server at 127.0.0.1:3000:
    $ tailscale funnel https:443 / http://127.0.0.1:3000

    Or, using the default port:
    $ tailscale funnel https / http://127.0.0.1:3000

  - To serve a single file or a directory of files:
    $ tailscale funnel https / /home/alice/blog/index.html
    $ tailscale funnel https /images/ /home/alice/blog/images
`),
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
// handles the following cases:
//
// 1. `tailscale funnel status`
//   - Prints the current status of the Funnel service.
//
// 2. `tailscale funnel <serve-port> {on|off}`
//   - Turns the Funnel service on or off.
//
// 3. `tailsclae funnel https(:<serve-port>) <mount-point> <source>`
//   - Starts a serve command and turns the Funnel service on.
//
// Note: funnel is only supported on single DNS name for now. (2022-11-15)
func (e *serveEnv) runFunnel(ctx context.Context, args []string) error {
	if len(args) == 2 {
		switch args[1] {
		case "on", "off":
			return e.doToggleFunnel(ctx, args)
		default:
			return flag.ErrHelp
		}
	}

	if len(args) > 2 {
		if err := serveCmd.Exec(ctx, args); err != nil {
			return err
		}
		_, portStr, _ := strings.Cut(args[0], ":")
		if portStr == "" {
			portStr = "443"
		}
		onOrOff := args[len(args)-1]
		if onOrOff != "off" {
			onOrOff = "on"
		}

		return e.doToggleFunnel(ctx, []string{portStr, onOrOff})
	}

	return flag.ErrHelp
}

// doToggleFunnel is the handler for "funnel <serve-port> {on|off}". It sets the
// Funnel service to on or off for the given port.
func (e *serveEnv) doToggleFunnel(ctx context.Context, args []string) error {
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
