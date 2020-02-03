// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tailscale command is the Tailscale command-line client. It interacts
// with the tailscaled client daemon.
package main // import "tailscale.com/cmd/tailscale"

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/apenwarr/fixconsole"
	"github.com/pborman/getopt/v2"
	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
	"tailscale.com/logpolicy"
	"tailscale.com/safesocket"
)

func pump(ctx context.Context, bc *ipn.BackendClient, c net.Conn) {
	defer log.Printf("Control connection done.\n")
	defer c.Close()
	for ctx.Err() == nil {
		msg, err := ipn.ReadMsg(c)
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
	config := getopt.StringLong("config", 'f', "", "path to config file")
	statekey := getopt.StringLong("statekey", 0, "", "state key for daemon-side config")
	server := getopt.StringLong("server", 's', "https://login.tailscale.com", "URL to tailcontrol server")
	nuroutes := getopt.BoolLong("no-single-routes", 'N', "disallow (non-subnet) routes to single nodes")
	rroutes := getopt.BoolLong("remote-routes", 'R', "allow routing subnets to remote nodes")
	droutes := getopt.BoolLong("default-routes", 'D', "allow default route on remote node")
	getopt.Parse()
	if *config == "" && *statekey == "" {
		logpolicy.New("tailnode.log.tailscale.io", "tailscale")
		log.Fatal("no --config or --statekey provided")
	}
	if len(getopt.Args()) > 0 {
		log.Fatalf("too many non-flag arguments: %#v", getopt.Args()[0])
	}

	pol := logpolicy.New("tailnode.log.tailscale.io", *config)
	defer pol.Close()

	var prefs *ipn.Prefs
	if *config != "" {
		localCfg, err := loadConfig(*config)
		if err != nil {
			log.Fatal(err)
		}

		// TODO(apenwarr): fix different semantics between prefs and uflags
		// TODO(apenwarr): allow setting/using CorpDNS
		prefs = &localCfg
		prefs.WantRunning = true
		prefs.RouteAll = *rroutes || *droutes
		prefs.AllowSingleHosts = !*nuroutes
	}

	c, err := safesocket.Connect("", "Tailscale", "tailscaled", 41112)
	if err != nil {
		log.Fatalf("safesocket.Connect: %v\n", err)
	}
	clientToServer := func(b []byte) {
		ipn.WriteMsg(c, b)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-interrupt
		c.Close()
	}()

	bc := ipn.NewBackendClient(log.Printf, clientToServer)
	opts := ipn.Options{
		StateKey:  ipn.StateKey(*statekey),
		Prefs:     prefs,
		ServerURL: *server,
		Notify: func(n ipn.Notify) {
			log.Printf("Notify: %v\n", n)
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
					cancel()
				}
			}
			if url := n.BrowseToURL; url != nil {
				fmt.Fprintf(os.Stderr, "\nTo authenticate, visit:\n\n\t%s\n\n", *url)
			}
			if p := n.Prefs; p != nil {
				prefs = p
				saveConfig(*config, *p)
			}
		},
	}
	bc.Start(opts)
	pump(ctx, bc, c)
}

func loadConfig(path string) (ipn.Prefs, error) {
	b, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		log.Printf("config %s does not exist", path)
		return ipn.NewPrefs(), nil
	}
	return ipn.PrefsFromBytes(b, false)
}

func saveConfig(path string, prefs ipn.Prefs) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(prefs, "", "\t")
	if err != nil {
		return fmt.Errorf("save config: %v", err)
	}
	if err := atomicfile.WriteFile(path, b, 0666); err != nil {
		return fmt.Errorf("save config: %v", err)
	}
	return nil
}
