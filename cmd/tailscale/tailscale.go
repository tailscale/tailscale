// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tailscale command is the Tailscale command-line client. It interacts
// with the tailscaled node agent.
package main // import "tailscale.com/cmd/tailscale"

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/apenwarr/fixconsole"
	"github.com/pborman/getopt/v2"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/ipn"
	"tailscale.com/logpolicy"
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

	socket := getopt.StringLong("socket", 0, "/run/tailscale/tailscaled.sock", "path of tailscaled's unix socket")
	server := getopt.StringLong("server", 's', "https://login.tailscale.com", "URL to tailcontrol server")
	nuroutes := getopt.BoolLong("no-single-routes", 'N', "disallow (non-subnet) routes to single nodes")
	routeall := getopt.BoolLong("remote-routes", 'R', "accept routes advertised by remote nodes")
	nopf := getopt.BoolLong("no-packet-filter", 'F', "disable packet filter")
	advroutes := getopt.ListLong("routes", 'r', "routes to advertise to other nodes (comma-separated, e.g. 10.0.0.0/8,192.168.1.0/24)")
	getopt.Parse()
	pol := logpolicy.New("tailnode.log.tailscale.io")
	if len(getopt.Args()) > 0 {
		log.Fatalf("too many non-flag arguments: %#v", getopt.Args()[0])
	}

	defer pol.Close()

	var adv []wgcfg.CIDR
	for _, s := range *advroutes {
		cidr, err := wgcfg.ParseCIDR(s)
		if err != nil {
			log.Fatalf("%q is not a valid CIDR prefix: %v", s, err)
		}
		adv = append(adv, *cidr)
	}

	// TODO(apenwarr): fix different semantics between prefs and uflags
	// TODO(apenwarr): allow setting/using CorpDNS
	prefs := ipn.Prefs{
		ControlURL:       *server,
		WantRunning:      true,
		RouteAll:         *routeall,
		AllowSingleHosts: !*nuroutes,
		UsePacketFilter:  !*nopf,
		AdvertiseRoutes:  adv,
	}

	c, err := safesocket.Connect(*socket, 0)
	if err != nil {
		log.Fatalf("safesocket.Connect: %v\n", err)
	}
	clientToServer := func(b []byte) {
		ipn.WriteMsg(c, b)
	}

	ctx, cancel := context.WithCancel(context.Background())
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
					fmt.Fprintf(os.Stderr, "\nTo authorize your machine, visit (as admin):\n\n\t%s/admin/machines\n\n", *server)
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
}
