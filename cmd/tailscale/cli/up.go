// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v2/ffcli"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/ipn"
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

var upCmd = &ffcli.Command{
	Name:       "up",
	ShortUsage: "up [flags]",
	ShortHelp:  "Connect to your Tailscale network",

	LongHelp: strings.TrimSpace(`
"tailscale up" connects this machine to your Tailscale network,
triggering authentication if necessary.

The flags passed to this command are specific to this machine. If you don't
specify any flags, options are reset to their default.
`),
	FlagSet: (func() *flag.FlagSet {
		upf := flag.NewFlagSet("up", flag.ExitOnError)
		upf.StringVar(&upArgs.server, "login-server", "https://login.tailscale.com", "base URL of control server")
		upf.BoolVar(&upArgs.acceptRoutes, "accept-routes", false, "accept routes advertised by other Tailscale nodes")
		upf.BoolVar(&upArgs.singleRoutes, "host-routes", true, "install host routes to other Tailscale nodes")
		upf.BoolVar(&upArgs.shieldsUp, "shields-up", false, "don't allow incoming connections")
		upf.StringVar(&upArgs.advertiseTags, "advertise-tags", "", "ACL tags to request (comma-separated, e.g. eng,montreal,ssh)")
		upf.StringVar(&upArgs.authKey, "authkey", "", "node authorization key")
		upf.StringVar(&upArgs.hostname, "hostname", "", "hostname to use instead of the one provided by the OS")
		upf.BoolVar(&upArgs.enableDERP, "enable-derp", true, "enable the use of DERP servers")
		if runtime.GOOS == "linux" || isBSD(runtime.GOOS) {
			upf.StringVar(&upArgs.advertiseRoutes, "advertise-routes", "", "routes to advertise to other nodes (comma-separated, e.g. 10.0.0.0/8,192.168.0.0/24)")
		}
		if runtime.GOOS == "linux" {
			upf.BoolVar(&upArgs.snat, "snat-subnet-routes", true, "source NAT traffic to local routes advertised with -advertise-routes")
			upf.StringVar(&upArgs.netfilterMode, "netfilter-mode", "on", "netfilter mode (one of on, nodivert, off)")
		}
		return upf
	})(),
	Exec: runUp,
}

var upArgs struct {
	server          string
	acceptRoutes    bool
	singleRoutes    bool
	shieldsUp       bool
	advertiseRoutes string
	advertiseTags   string
	enableDERP      bool
	snat            bool
	netfilterMode   string
	authKey         string
	hostname        string
}

// validateHostname checks that name is a valid domain name label
// pursuant to https://tools.ietf.org/html/rfc1034#section-3.1.
func validateHostname(name string) error {
	switch {
	// Empty string is treated as missing hostname and replaced downstream.
	case len(name) == 0:
		return nil
	case len(name) > 63:
		return fmt.Errorf("longer than 63 characters")
	}

	name = strings.ToLower(name)
	first, last := name[0], name[len(name)-1]

	// This is more obviously correct than using package unicode,
	// though that can work too if we ensure that characters are below MaxASCII.
	if !('a' <= first && first <= 'z') {
		return fmt.Errorf("does not start with a letter")
	}
	if !(('a' <= last && last <= 'z') || ('0' <= last && last <= '9')) {
		return fmt.Errorf("does not end with a letter or digit")
	}
	for i, c := range name {
		if !(('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || (c == '-')) {
			return fmt.Errorf("[%d] = %c is not a letter, digit or hyphen", i, c)
		}
	}

	return nil
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

func isBSD(s string) bool {
	return s == "dragonfly" || s == "freebsd" || s == "netbsd" || s == "openbsd"
}

func warning(format string, args ...interface{}) {
	fmt.Printf("Warning: "+format+"\n", args...)
}

// checkIPForwarding prints warnings on linux if IP forwarding is not
// enabled, or if we were unable to verify the state of IP forwarding.
func checkIPForwarding() {
	var key string

	if runtime.GOOS == "linux" {
		key = "net.ipv4.ip_forward"
	} else if isBSD(runtime.GOOS) {
		key = "net.inet.ip.forwarding"
	} else {
		return
	}

	bs, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		warning("couldn't check %s (%v).\nSubnet routes won't work without IP forwarding.", key, err)
		return
	}
	on, err := strconv.ParseBool(string(bytes.TrimSpace(bs)))
	if err != nil {
		warning("couldn't parse %s (%v).\nSubnet routes won't work without IP forwarding.", key, err)
		return
	}
	if !on {
		warning("%s is disabled. Subnet routes won't work.", key)
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

	if err := validateHostname(upArgs.hostname); err != nil {
		log.Fatalf("illegal hostname: %v", err)
	}

	// TODO(apenwarr): fix different semantics between prefs and uflags
	// TODO(apenwarr): allow setting/using CorpDNS
	prefs := ipn.NewPrefs()
	prefs.ControlURL = upArgs.server
	prefs.WantRunning = true
	prefs.RouteAll = upArgs.acceptRoutes
	prefs.AllowSingleHosts = upArgs.singleRoutes
	prefs.ShieldsUp = upArgs.shieldsUp
	prefs.AdvertiseRoutes = routes
	prefs.AdvertiseTags = tags
	prefs.NoSNAT = !upArgs.snat
	prefs.DisableDERP = !upArgs.enableDERP
	prefs.Hostname = upArgs.hostname
	if runtime.GOOS == "linux" {
		switch upArgs.netfilterMode {
		case "on":
			prefs.NetfilterMode = router.NetfilterOn
		case "nodivert":
			prefs.NetfilterMode = router.NetfilterNoDivert
			warning("netfilter=nodivert; add iptables calls to ts-* chains manually.")
		case "off":
			prefs.NetfilterMode = router.NetfilterOff
			warning("netfilter=off; configure iptables yourself.")
		default:
			log.Fatalf("invalid value --netfilter-mode: %q", upArgs.netfilterMode)
		}
	}

	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	var printed bool

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
					printed = true
					bc.StartLoginInteractive()
				case ipn.NeedsMachineAuth:
					printed = true
					fmt.Fprintf(os.Stderr, "\nTo authorize your machine, visit (as admin):\n\n\t%s/admin/machines\n\n", upArgs.server)
				case ipn.Starting, ipn.Running:
					// Done full authentication process
					if printed {
						// Only need to print an update if we printed the "please click" message earlier.
						fmt.Fprintf(os.Stderr, "Success.\n")
					}
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
