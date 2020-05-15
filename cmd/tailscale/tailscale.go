// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tailscale command is the Tailscale command-line client. It interacts
// with the tailscaled node agent.
package main // import "tailscale.com/cmd/tailscale"

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/apenwarr/fixconsole"
	"github.com/peterbourgon/ff/v2/ffcli"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/ipn"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/router"
)

// globalStateKey is the ipn.StateKey that tailscaled loads on
// startup.
//
// We have to support multiple state keys for other OSes (Windows in
// particular), but right now Unix daemons run with a single
// node-global state. To keep open the option of having per-user state
// later, the global state key doesn't look like a username.
const globalStateKey = "_daemon"

var rootArgs struct {
	socket string
}

func main() {
	err := fixconsole.FixConsoleIfNeeded()
	if err != nil {
		log.Printf("fixConsoleOutput: %v\n", err)
	}

	upf := flag.NewFlagSet("up", flag.ExitOnError)
	upf.StringVar(&upArgs.server, "login-server", "https://login.tailscale.com", "base URL of control server")
	upf.BoolVar(&upArgs.acceptRoutes, "accept-routes", false, "accept routes advertised by other Tailscale nodes")
	upf.BoolVar(&upArgs.noSingleRoutes, "no-single-routes", false, "don't install routes to single nodes")
	upf.BoolVar(&upArgs.shieldsUp, "shields-up", false, "don't allow incoming connections")
	upf.StringVar(&upArgs.advertiseTags, "advertise-tags", "", "ACL tags to request (comma-separated, e.g. eng,montreal,ssh)")
	upf.StringVar(&upArgs.authKey, "authkey", "", "node authorization key")
	if runtime.GOOS == "linux" {
		upf.StringVar(&upArgs.advertiseRoutes, "advertise-routes", "", "routes to advertise to other nodes (comma-separated, e.g. 10.0.0.0/8,192.168.0.0/24)")
		upf.BoolVar(&upArgs.noSNAT, "no-snat", false, "disable SNAT of traffic to local routes advertised with -advertise-routes")
		upf.StringVar(&upArgs.netfilterMode, "netfilter-mode", "on", "netfilter mode (one of on, nodivert, off)")
	}
	upCmd := &ffcli.Command{
		Name:       "up",
		ShortUsage: "up [flags]",
		ShortHelp:  "Connect to your Tailscale network",

		LongHelp: strings.TrimSpace(`
"tailscale up" connects this machine to your Tailscale network,
triggering authentication if necessary.

The flags passed to this command are specific to this machine. If you don't
specify any flags, options are reset to their default.
`),
		FlagSet: upf,
		Exec:    runUp,
	}

	rootfs := flag.NewFlagSet("tailscale", flag.ExitOnError)
	rootfs.StringVar(&rootArgs.socket, "socket", paths.DefaultTailscaledSocket(), "path to tailscaled's unix socket")

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
			statusCmd,
		},
		FlagSet: rootfs,
		Exec:    func(context.Context, []string) error { return flag.ErrHelp },
	}

	if err := rootCmd.ParseAndRun(context.Background(), os.Args[1:]); err != nil && err != flag.ErrHelp {
		log.Fatal(err)
	}
}

var upArgs struct {
	server          string
	acceptRoutes    bool
	noSingleRoutes  bool
	shieldsUp       bool
	advertiseRoutes string
	advertiseTags   string
	noSNAT          bool
	netfilterMode   string
	authKey         string
}

// parseIPOrCIDR parses an IP address or a CIDR prefix. If the input
// is an IP address, it is returned in CIDR form with a /32 mask for
// IPv4 or a /128 mask for IPv6.
func parseIPOrCIDR(s string) (wgcfg.CIDR, bool) {
	if strings.Contains(s, "/") {
		ret, err := wgcfg.ParseCIDR(s)
		if err != nil {
			return wgcfg.CIDR{}, false
		}
		return ret, true
	}

	ip, ok := wgcfg.ParseIP(s)
	if !ok {
		return wgcfg.CIDR{}, false
	}
	if ip.Is4() {
		return wgcfg.CIDR{ip, 32}, true
	} else {
		return wgcfg.CIDR{ip, 128}, true
	}
}

func warning(format string, args ...interface{}) {
	fmt.Printf("Warning: "+format+"\n", args...)
}

// checkIPForwarding prints warnings on linux if IP forwarding is not
// enabled, or if we were unable to verify the state of IP forwarding.
func checkIPForwarding() {
	if runtime.GOOS != "linux" {
		return
	}
	bs, err := ioutil.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		warning("couldn't check if IP forwarding is enabled (%v). IP forwarding must be enabled for subnet routes to work.", err)
		return
	}
	on, err := strconv.ParseBool(string(bytes.TrimSpace(bs)))
	if err != nil {
		warning("couldn't check if IP forwarding is enabled (%v). IP forwarding must be enabled for subnet routes to work.", err)
		return
	}
	if !on {
		warning("IP forwarding is disabled, subnet routes will not work.")
	}
}

func runUp(ctx context.Context, args []string) error {
	if len(args) > 0 {
		log.Fatalf("too many non-flag arguments: %q", args)
	}

	var routes []wgcfg.CIDR
	if upArgs.advertiseRoutes != "" {
		checkIPForwarding()
		advroutes := strings.Split(upArgs.advertiseRoutes, ",")
		for _, s := range advroutes {
			cidr, ok := parseIPOrCIDR(s)
			if !ok {
				log.Fatalf("%q is not a valid IP address or CIDR prefix", s)
			}
			routes = append(routes, cidr)
		}
	}

	var tags []string
	if upArgs.advertiseTags != "" {
		tags = strings.Split(upArgs.advertiseTags, ",")
		for _, tag := range tags {
			err := tailcfg.CheckTag(tag)
			if err != nil {
				log.Fatalf("tag: %q: %s", tag, err)
			}
		}
	}

	// TODO(apenwarr): fix different semantics between prefs and uflags
	// TODO(apenwarr): allow setting/using CorpDNS
	prefs := ipn.NewPrefs()
	prefs.ControlURL = upArgs.server
	prefs.WantRunning = true
	prefs.RouteAll = upArgs.acceptRoutes
	prefs.AllowSingleHosts = !upArgs.noSingleRoutes
	prefs.ShieldsUp = upArgs.shieldsUp
	prefs.AdvertiseRoutes = routes
	prefs.AdvertiseTags = tags
	prefs.NoSNAT = upArgs.noSNAT
	if runtime.GOOS == "linux" {
		switch upArgs.netfilterMode {
		case "on":
			prefs.NetfilterMode = router.NetfilterOn
		case "nodivert":
			prefs.NetfilterMode = router.NetfilterNoDivert
			warning("netfilter in nodivert mode, you must add calls to Tailscale netfilter chains manually")
		case "off":
			prefs.NetfilterMode = router.NetfilterOff
			warning("netfilter management disabled, you must write a secure packet filter yourself")
		default:
			log.Fatalf("invalid value --netfilter-mode: %q", upArgs.netfilterMode)
		}
	}

	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	bc.SetPrefs(prefs)
	opts := ipn.Options{
		StateKey: globalStateKey,
		AuthKey:  upArgs.authKey,
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
					fmt.Fprintf(os.Stderr, "tailscaled is authenticated, nothing more to do.\n")
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

func connect(ctx context.Context) (net.Conn, *ipn.BackendClient, context.Context, context.CancelFunc) {
	c, err := safesocket.Connect(rootArgs.socket, 41112)
	if err != nil {
		if runtime.GOOS != "windows" && rootArgs.socket == "" {
			log.Fatalf("--socket cannot be empty")
		}
		log.Fatalf("Failed to connect to connect to tailscaled. (safesocket.Connect: %v)\n", err)
	}
	clientToServer := func(b []byte) {
		ipn.WriteMsg(c, b)
	}

	ctx, cancel := context.WithCancel(ctx)

	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-interrupt
		c.Close()
		cancel()
	}()

	bc := ipn.NewBackendClient(log.Printf, clientToServer)
	return c, bc, ctx, cancel
}

// pump receives backend messages on conn and pushes them into bc.
func pump(ctx context.Context, bc *ipn.BackendClient, conn net.Conn) {
	defer conn.Close()
	for ctx.Err() == nil {
		msg, err := ipn.ReadMsg(conn)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("ReadMsg: %v\n", err)
			break
		}
		bc.GotNotifyMsg(msg)
	}
}
