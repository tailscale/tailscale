// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tailscale command is the Tailscale command-line client. It interacts
// with the tailscaled node agent.
package main // import "tailscale.com/cmd/tailscale"

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/apenwarr/fixconsole"
	"github.com/peterbourgon/ff/v2/ffcli"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/ipn"
	"tailscale.com/logpolicy"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
)

// globalStateKey is the ipn.StateKey that tailscaled loads on
// startup.
//
// We have to support multiple state keys for other OSes (Windows in
// particular), but right now Unix daemons run with a single
// node-global state. To keep open the option of having per-user state
// later, the global state key doesn't look like a username.
const globalStateKey = "_daemon"

// pump receives backend messages on conn and pushes them into bc.
func pump(ctx context.Context, bc *ipn.BackendClient, conn net.Conn) {
	defer log.Printf("Control connection done.\n")
	defer conn.Close()
	for ctx.Err() == nil {
		msg, err := ipn.ReadMsg(conn)
		if err != nil {
			log.Printf("ReadMsg: %v\n", err)
			break
		}
		bc.GotNotifyMsg(msg)
	}
}

func main() {
	err := fixconsole.FixConsoleIfNeeded()
	if err != nil {
		log.Printf("fixConsoleOutput: %v\n", err)
	}

	upf := flag.NewFlagSet("up", flag.ExitOnError)
	upf.StringVar(&upArgs.socket, "socket", paths.DefaultTailscaledSocket(), "path to tailscaled's unix socket")
	upf.StringVar(&upArgs.server, "login-server", "https://login.tailscale.com", "base URL of control server")
	upf.BoolVar(&upArgs.acceptRoutes, "accept-routes", false, "accept routes advertised by other Tailscale nodes")
	upf.BoolVar(&upArgs.noSingleRoutes, "no-single-routes", false, "don't install routes to single nodes")
	upf.BoolVar(&upArgs.noPacketFilter, "no-packet-filter", false, "disable packet filter")
	upf.StringVar(&upArgs.advertiseRoutes, "advertise-routes", "", "routes to advertise to other nodes (comma-separated, e.g. 10.0.0.0/8,192.168.0.0/24)")
	upCmd := &ffcli.Command{
		Name:       "up",
		ShortUsage: "up [flags]",
		ShortHelp:  "Connect to your Tailscale network",

		LongHelp: strings.TrimSpace(`
"tailscale up" connects this machine to your Tailscale network,
triggering authentication if necessary.

The flags passed to this command set tailscaled options that are
specific to this machine, such as whether to advertise some routes to
other nodes in the Tailscale network. If you don't specify any flags,
options are reset to their default.
`),
		FlagSet: upf,
		Exec:    runUp,
	}

	netcheckCmd := &ffcli.Command{
		Name:       "netcheck",
		ShortUsage: "netcheck",
		ShortHelp:  "Print an analysis of local network conditions",
		Exec:       runNetcheck,
	}

	rootCmd := &ffcli.Command{
		Name:       "tailscale",
		ShortUsage: "tailscale subcommand [flags]",
		ShortHelp:  "The easiest, most secure way to use WireGuard.",
		LongHelp: strings.TrimSpace(`
This CLI is still under active development. Commands and flags will
change in the future.
`),
		Subcommands: []*ffcli.Command{
			upCmd,
			netcheckCmd,
		},
		Exec: func(context.Context, []string) error { return flag.ErrHelp },
	}

	if err := rootCmd.ParseAndRun(context.Background(), os.Args[1:]); err != nil && err != flag.ErrHelp {
		log.Fatal(err)
	}
}

var upArgs = struct {
	socket          string
	server          string
	acceptRoutes    bool
	noSingleRoutes  bool
	noPacketFilter  bool
	advertiseRoutes string
}{}

func runUp(ctx context.Context, args []string) error {
	pol := logpolicy.New("tailnode.log.tailscale.io")
	if len(args) > 0 {
		log.Fatalf("too many non-flag arguments: %q", args)
	}

	defer pol.Close()

	var adv []wgcfg.CIDR
	if upArgs.advertiseRoutes != "" {
		advroutes := strings.Split(upArgs.advertiseRoutes, ",")
		for _, s := range advroutes {
			cidr, err := wgcfg.ParseCIDR(s)
			if err != nil {
				log.Fatalf("%q is not a valid CIDR prefix: %v", s, err)
			}
			adv = append(adv, *cidr)
		}
	}

	// TODO(apenwarr): fix different semantics between prefs and uflags
	// TODO(apenwarr): allow setting/using CorpDNS
	prefs := ipn.NewPrefs()
	prefs.ControlURL = upArgs.server
	prefs.WantRunning = true
	prefs.RouteAll = upArgs.acceptRoutes
	prefs.AllowSingleHosts = !upArgs.noSingleRoutes
	prefs.UsePacketFilter = !upArgs.noPacketFilter
	prefs.AdvertiseRoutes = adv

	c, err := safesocket.Connect(upArgs.socket, 41112)
	if err != nil {
		log.Fatalf("Failed to connect to connect to tailscaled. (safesocket.Connect: %v)\n", err)
	}
	clientToServer := func(b []byte) {
		ipn.WriteMsg(c, b)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-interrupt
		c.Close()
	}()

	bc := ipn.NewBackendClient(log.Printf, clientToServer)
	bc.SetPrefs(prefs)
	opts := ipn.Options{
		StateKey: globalStateKey,
		Notify: func(n ipn.Notify) {
			if n.ErrMessage != nil {
				log.Fatalf("backend error: %v\n", *n.ErrMessage)
			}
			if s := n.State; s != nil {
				switch *s {
				case ipn.NeedsLogin:
					bc.StartLoginInteractive()
				case ipn.NeedsMachineAuth:
					fmt.Fprintf(os.Stderr, "\nTo authorize your machine, visit (as admin):\n\n\t%s/admin/machines\n\n", upArgs.server)
				case ipn.Starting, ipn.Running:
					// Done full authentication process
					fmt.Fprintf(os.Stderr, "\ntailscaled is authenticated, nothing more to do.\n\n")
					cancel()
				}
			}
			if url := n.BrowseToURL; url != nil {
				fmt.Fprintf(os.Stderr, "\nTo authenticate, visit:\n\n\t%s\n\n", *url)
			}
		},
	}
	// We still have to Start right now because it's the only way to
	// set up notifications and whatnot. This causes a bunch of churn
	// every time the CLI touches anything.
	//
	// TODO(danderson): redo the frontend/backend API to assume
	// ephemeral frontends that read/modify/write state, once
	// Windows/Mac state is moved into backend.
	bc.Start(opts)
	pump(ctx, bc, c)

	return nil
}
