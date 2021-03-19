// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/peterbourgon/ff/v2/ffcli"
	"inet.af/netaddr"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/preftype"
	"tailscale.com/version/distro"
)

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
		upf.BoolVar(&upArgs.acceptDNS, "accept-dns", true, "accept DNS configuration from the admin panel")
		upf.BoolVar(&upArgs.singleRoutes, "host-routes", true, "install host routes to other Tailscale nodes")
		upf.StringVar(&upArgs.exitNodeIP, "exit-node", "", "Tailscale IP of the exit node for internet traffic")
		upf.BoolVar(&upArgs.shieldsUp, "shields-up", false, "don't allow incoming connections")
		upf.BoolVar(&upArgs.forceReauth, "force-reauth", false, "force reauthentication")
		upf.StringVar(&upArgs.advertiseTags, "advertise-tags", "", "ACL tags to request (comma-separated, e.g. eng,montreal,ssh)")
		upf.StringVar(&upArgs.authKey, "authkey", "", "node authorization key")
		upf.StringVar(&upArgs.hostname, "hostname", "", "hostname to use instead of the one provided by the OS")
		if runtime.GOOS == "linux" || isBSD(runtime.GOOS) {
			upf.StringVar(&upArgs.advertiseRoutes, "advertise-routes", "", "routes to advertise to other nodes (comma-separated, e.g. 10.0.0.0/8,192.168.0.0/24)")
			upf.BoolVar(&upArgs.advertiseDefaultRoute, "advertise-exit-node", false, "offer to be an exit node for internet traffic for the tailnet")
		}
		if runtime.GOOS == "linux" {
			upf.BoolVar(&upArgs.snat, "snat-subnet-routes", true, "source NAT traffic to local routes advertised with --advertise-routes")
			upf.StringVar(&upArgs.netfilterMode, "netfilter-mode", defaultNetfilterMode(), "netfilter mode (one of on, nodivert, off)")
		}
		return upf
	})(),
	Exec: runUp,
}

func defaultNetfilterMode() string {
	if distro.Get() == distro.Synology {
		return "off"
	}
	return "on"
}

var upArgs struct {
	server                string
	acceptRoutes          bool
	acceptDNS             bool
	singleRoutes          bool
	exitNodeIP            string
	shieldsUp             bool
	forceReauth           bool
	advertiseRoutes       string
	advertiseDefaultRoute bool
	advertiseTags         string
	snat                  bool
	netfilterMode         string
	authKey               string
	hostname              string
}

func isBSD(s string) bool {
	return s == "dragonfly" || s == "freebsd" || s == "netbsd" || s == "openbsd"
}

func warnf(format string, args ...interface{}) {
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
		warnf("couldn't check %s (%v).\nSubnet routes won't work without IP forwarding.", key, err)
		return
	}
	on, err := strconv.ParseBool(string(bytes.TrimSpace(bs)))
	if err != nil {
		warnf("couldn't parse %s (%v).\nSubnet routes won't work without IP forwarding.", key, err)
		return
	}
	if !on {
		warnf("%s is disabled. Subnet routes won't work.", key)
	}
}

var (
	ipv4default = netaddr.MustParseIPPrefix("0.0.0.0/0")
	ipv6default = netaddr.MustParseIPPrefix("::/0")
)

func runUp(ctx context.Context, args []string) error {
	if len(args) > 0 {
		log.Fatalf("too many non-flag arguments: %q", args)
	}

	if distro.Get() == distro.Synology {
		notSupported := "not yet supported on Synology; see https://github.com/tailscale/tailscale/issues/451"
		if upArgs.advertiseRoutes != "" {
			return errors.New("--advertise-routes is " + notSupported)
		}
		if upArgs.acceptRoutes {
			return errors.New("--accept-routes is " + notSupported)
		}
		if upArgs.exitNodeIP != "" {
			return errors.New("--exit-node is " + notSupported)
		}
		if upArgs.netfilterMode != "off" {
			return errors.New("--netfilter-mode values besides \"off\" " + notSupported)
		}
	}

	routeMap := map[netaddr.IPPrefix]bool{}
	var default4, default6 bool
	if upArgs.advertiseRoutes != "" {
		advroutes := strings.Split(upArgs.advertiseRoutes, ",")
		for _, s := range advroutes {
			ipp, err := netaddr.ParseIPPrefix(s)
			if err != nil {
				fatalf("%q is not a valid IP address or CIDR prefix", s)
			}
			if ipp != ipp.Masked() {
				fatalf("%s has non-address bits set; expected %s", ipp, ipp.Masked())
			}
			if ipp == ipv4default {
				default4 = true
			} else if ipp == ipv6default {
				default6 = true
			}
			routeMap[ipp] = true
		}
		if default4 && !default6 {
			fatalf("%s advertised without its IPv6 counterpart, please also advertise %s", ipv4default, ipv6default)
		} else if default6 && !default4 {
			fatalf("%s advertised without its IPv6 counterpart, please also advertise %s", ipv6default, ipv4default)
		}
	}
	if upArgs.advertiseDefaultRoute {
		routeMap[netaddr.MustParseIPPrefix("0.0.0.0/0")] = true
		routeMap[netaddr.MustParseIPPrefix("::/0")] = true
	}
	if len(routeMap) > 0 {
		checkIPForwarding()
		if isBSD(runtime.GOOS) {
			warnf("Subnet routing and exit nodes only work with additional manual configuration on %v, and is not currently officially supported.", runtime.GOOS)
		}
	}
	routes := make([]netaddr.IPPrefix, 0, len(routeMap))
	for r := range routeMap {
		routes = append(routes, r)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Bits != routes[j].Bits {
			return routes[i].Bits < routes[j].Bits
		}
		return routes[i].IP.Less(routes[j].IP)
	})

	var exitNodeIP netaddr.IP
	if upArgs.exitNodeIP != "" {
		var err error
		exitNodeIP, err = netaddr.ParseIP(upArgs.exitNodeIP)
		if err != nil {
			fatalf("invalid IP address %q for --exit-node: %v", upArgs.exitNodeIP, err)
		}
	}

	var tags []string
	if upArgs.advertiseTags != "" {
		tags = strings.Split(upArgs.advertiseTags, ",")
		for _, tag := range tags {
			err := tailcfg.CheckTag(tag)
			if err != nil {
				fatalf("tag: %q: %s", tag, err)
			}
		}
	}

	if len(upArgs.hostname) > 256 {
		fatalf("hostname too long: %d bytes (max 256)", len(upArgs.hostname))
	}

	prefs := ipn.NewPrefs()
	prefs.ControlURL = upArgs.server
	prefs.WantRunning = true
	prefs.RouteAll = upArgs.acceptRoutes
	prefs.ExitNodeIP = exitNodeIP
	prefs.CorpDNS = upArgs.acceptDNS
	prefs.AllowSingleHosts = upArgs.singleRoutes
	prefs.ShieldsUp = upArgs.shieldsUp
	prefs.AdvertiseRoutes = routes
	prefs.AdvertiseTags = tags
	prefs.NoSNAT = !upArgs.snat
	prefs.Hostname = upArgs.hostname
	prefs.ForceDaemon = (runtime.GOOS == "windows")

	if runtime.GOOS == "linux" {
		switch upArgs.netfilterMode {
		case "on":
			prefs.NetfilterMode = preftype.NetfilterOn
		case "nodivert":
			prefs.NetfilterMode = preftype.NetfilterNoDivert
			warnf("netfilter=nodivert; add iptables calls to ts-* chains manually.")
		case "off":
			prefs.NetfilterMode = preftype.NetfilterOff
			warnf("netfilter=off; configure iptables yourself.")
		default:
			fatalf("invalid value --netfilter-mode: %q", upArgs.netfilterMode)
		}
	}

	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	if !prefs.ExitNodeIP.IsZero() {
		st, err := tailscale.Status(ctx)
		if err != nil {
			fatalf("can't fetch status from tailscaled: %v", err)
		}
		for _, ip := range st.TailscaleIPs {
			if prefs.ExitNodeIP == ip {
				fatalf("cannot use %s as the exit node as it is a local IP address to this machine, did you mean --advertise-exit-node?", ip)
			}
		}
	}

	var printed bool
	var loginOnce sync.Once
	startLoginInteractive := func() { loginOnce.Do(func() { bc.StartLoginInteractive() }) }

	bc.SetPrefs(prefs)

	opts := ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
		AuthKey:  upArgs.authKey,
		Notify: func(n ipn.Notify) {
			if n.ErrMessage != nil {
				msg := *n.ErrMessage
				if msg == ipn.ErrMsgPermissionDenied {
					switch runtime.GOOS {
					case "windows":
						msg += " (Tailscale service in use by other user?)"
					default:
						msg += " (try 'sudo tailscale up [...]')"
					}
				}
				fatalf("backend error: %v\n", msg)
			}
			if s := n.State; s != nil {
				switch *s {
				case ipn.NeedsLogin:
					printed = true
					startLoginInteractive()
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

	// On Windows, we still run in mostly the "legacy" way that
	// predated the server's StateStore. That is, we send an empty
	// StateKey and send the prefs directly. Although the Windows
	// supports server mode, though, the transition to StateStore
	// is only half complete. Only server mode uses it, and the
	// Windows service (~tailscaled) is the one that computes the
	// StateKey based on the connection identity. So for now, just
	// do as the Windows GUI's always done:
	if runtime.GOOS == "windows" {
		// The Windows service will set this as needed based
		// on our connection's identity.
		opts.StateKey = ""
		opts.Prefs = prefs
	}

	// We still have to Start right now because it's the only way to
	// set up notifications and whatnot. This causes a bunch of churn
	// every time the CLI touches anything.
	//
	// TODO(danderson): redo the frontend/backend API to assume
	// ephemeral frontends that read/modify/write state, once
	// Windows/Mac state is moved into backend.
	bc.Start(opts)
	if upArgs.forceReauth {
		printed = true
		startLoginInteractive()
	}
	pump(ctx, bc, c)

	return nil
}
