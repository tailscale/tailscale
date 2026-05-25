// Server tsmultiserve is a TCP proxy that can register and listen on multiple tailscale addresses
// using tsnet.
//
// The main motivation for this is to run multiple services on the same host, but give
// them memorable names and use canonical ports.
//
// Usage:
//
//	tsmultiserve [ts-node:ts-port:dst-host:dst-port ...]
//
// For example:
//
//	tsmultiserve cameras:http:localhost:8001 cameras:rtsp:localhost:rtsp phone:sip:localhost:sip
//
// This will register two nodes on your tailnet, "cameras" and "phone". On cameras it will forward
// port 80 to localhost:8001 and port 554 (rtsp) to localhost:554, and on phone it will forward port
// 5060 (sip) to localhost:5060.
//
// You can get the same effect if you:
//  1. Run multiple tailscaleds in separate network namespaces or containers, but that can get complicated.
//  2. Use the caddy-tailscale extension, but that's HTTP only.
//  2. Use an HTTP proxy & vitual hosts, but now you have to set your own DNS. Also HTTP (or TLS) only.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

var logf = func(string, ...any) {}

var (
	statedir string
	verbose  bool
)

func authkeyForHost(h string) string {
	authkey := os.Getenv("TS_AUTHKEY_" + h)
	if authkey != "" {
		log.Printf("%v: using authkey from $TS_AUTHKEY_%s", h, h)
		return authkey
	}
	authkey = os.Getenv("TS_AUTHKEY")
	if authkey != "" {
		log.Printf("%v: using authkey from $TS_AUTHKEY", h)
		return authkey
	}
	return ""
}

func up(node string, cfg *ipn.ServeConfig) {
	ctx := context.Background()
	statedir := filepath.Join(statedir, node)

	err := os.MkdirAll(statedir, 0770)
	if err != nil {
		log.Fatalf("%v: could not make state directory (%s): %v", node, statedir, err)
	}
	srv := &tsnet.Server{
		Hostname: node,
		Dir:      statedir,
		Logf:     logf,
		AuthKey:  authkeyForHost(node),
	}
	defer srv.Close()

	lc, err := srv.LocalClient()
	if err != nil {
		log.Fatalf("%v: could not get local client: %v", node, err)
	}

	watcher, err := lc.WatchIPNBus(ctx, ipn.NotifyWatchEngineUpdates|ipn.NotifyInitialState|ipn.NotifyNoPrivateKeys)
	if err != nil {
		log.Fatalf("%v: %v", node, err)
	}
	defer watcher.Close()
login:
	for {
		n, err := watcher.Next()
		if err != nil {
			log.Fatalf("%v: %v", node, err)
		}
		if n.ErrMessage != nil {
			log.Fatalf("%v: %v", node, err)
		}
		if state := n.State; state != nil {
			switch *state {
			case ipn.Running:
				break login
			case ipn.NeedsLogin:
				if srv.AuthKey == "" {
					status, err := lc.Status(ctx)
					if err != nil {
						log.Fatalf("%v: %v", node, err)
					}
					// TODO figure out why this doesn't work without polling. AuthURL isn't always set
					// immediately after NeedsLogin, possibly a race?
					for status.AuthURL == "" {
						time.Sleep(100 * time.Millisecond)
						status, err = lc.Status(ctx)
						if err != nil {
							log.Fatalf("%v: %v", node, err)
						}
					}
					log.Printf("%v login: %s", node, status.AuthURL)
				}
			}
		}
	}

	err = lc.SetServeConfig(ctx, cfg)
	if err != nil {
		log.Fatalf("%v: could not set serve config: %v", node, err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "\ttsmultiserve tailscale-host:tailscale-port:target-host:target-port ...\n\n")
	fmt.Fprintf(os.Stderr, "flags:\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	flag.Usage = usage
	configdir, _ := os.UserConfigDir() // Ignore error. Empty string means we fall back to current directory.
	flag.StringVar(&statedir, "state-dir", filepath.Join(configdir, "tsmultiserve"), "directory to keep tailscale state")
	flag.BoolVar(&verbose, "verbose", false, "be verbose")
	flag.Parse()

	if verbose {
		logf = log.Printf
	}

	if flag.NArg() == 0 {
		usage()
	}

	nodes := map[string]*ipn.ServeConfig{}
	for _, arg := range flag.Args() {
		parts := strings.Split(arg, ":")
		if len(parts) != 4 {
			log.Fatalf("could not parse proxy directive")
		}
		host, port, dst := parts[0], parts[1], parts[2]+":"+parts[3]

		p, err := net.LookupPort("tcp", port)
		if err != nil {
			log.Fatalf("could not lookup port (%v): %v", port, err)
		}

		if nodes[host] == nil {
			nodes[host] = &ipn.ServeConfig{TCP: map[uint16]*ipn.TCPPortHandler{}}
		}

		nodes[host].TCP[uint16(p)] = &ipn.TCPPortHandler{TCPForward: dst}
	}

	for n, cfg := range nodes {
		up(n, cfg)
	}

	select {}
}
