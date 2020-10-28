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
	"strconv"
	"strings"
	"sync"

	"github.com/peterbourgon/ff/v2/ffcli"
	"github.com/tailscale/wireguard-go/wgcfg"
	"inet.af/netaddr"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine/router"
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
		upf.BoolVar(&upArgs.shieldsUp, "shields-up", false, "don't allow incoming connections")
		upf.BoolVar(&upArgs.forceReauth, "force-reauth", false, "force reauthentication")
		upf.StringVar(&upArgs.advertiseTags, "advertise-tags", "", "ACL tags to request (comma-separated, e.g. eng,montreal,ssh)")
		upf.StringVar(&upArgs.authKey, "authkey", "", "node authorization key")
		upf.StringVar(&upArgs.hostname, "hostname", "", "hostname to use instead of the one provided by the OS")
		if runtime.GOOS == "linux" || isBSD(runtime.GOOS) || version.OS() == "macOS" {
			upf.StringVar(&upArgs.advertiseRoutes, "advertise-routes", "", "routes to advertise to other nodes (comma-separated, e.g. 10.0.0.0/8,192.168.0.0/24)")
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
	server          string
	acceptRoutes    bool
	acceptDNS       bool
	singleRoutes    bool
	shieldsUp       bool
	forceReauth     bool
	advertiseRoutes string
	advertiseTags   string
	snat            bool
	netfilterMode   string
	authKey         string
	hostname        string
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
		return wgcfg.CIDR{IP: ip, Mask: 32}, true
	} else {
		return wgcfg.CIDR{IP: ip, Mask: 128}, true
	}
}

func isBSD(s string) bool {
	return s == "dragonfly" || s == "freebsd" || s == "netbsd" || s == "openbsd"
}

func warnf(format string, args ...interface{}) {
	fmt.Printf("Warning: "+format+"\n", args...)
}

// checkIPForwarding prints warnings if IP forwarding is not
// enabled, or if we were unable to verify the state of IP forwarding.
func checkIPForwarding() {
	var key string

	if runtime.GOOS == "linux" {
		key = "net.ipv4.ip_forward"
	} else if isBSD(runtime.GOOS) || version.OS() == "macOS" {
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
		if upArgs.netfilterMode != "off" {
			return errors.New("--netfilter-mode values besides \"off\" " + notSupported)
		}
	}

	var routes []wgcfg.CIDR
	if upArgs.advertiseRoutes != "" {
		advroutes := strings.Split(upArgs.advertiseRoutes, ",")
		for _, s := range advroutes {
			cidr, ok := parseIPOrCIDR(s)
			ipp, err := netaddr.ParseIPPrefix(s) // parse it with other pawith both packages
			if !ok || err != nil {
				fatalf("%q is not a valid IP address or CIDR prefix", s)
			}
			if ipp != ipp.Masked() {
				fatalf("%s has non-address bits set; expected %s", ipp, ipp.Masked())
			}
			routes = append(routes, cidr)
		}
		checkIPForwarding()
	}

	var tags []string
	if upArgs.advertiseTags != "" {
		tags = strings.Split(upArgs.advertiseTags, ",")
		for i, tag := range tags {
			if strings.HasPrefix(tag, "tag:") {
				// Accept fully-qualified tags (starting with
				// "tag:"), as we do in the ACL file.
				err := tailcfg.CheckTag(tag)
				if err != nil {
					fatalf("tag: %q: %v", tag, err)
				}
			} else if err := tailcfg.CheckTagSuffix(tag); err != nil {
				fatalf("tag: %q: %v", tag, err)
			}
			tags[i] = "tag:" + tag
		}
	}

	if len(upArgs.hostname) > 256 {
		fatalf("hostname too long: %d bytes (max 256)", len(upArgs.hostname))
	}

	// TODO(apenwarr): fix different semantics between prefs and uflags
	prefs := ipn.NewPrefs()
	prefs.ControlURL = upArgs.server
	prefs.WantRunning = true
	prefs.RouteAll = upArgs.acceptRoutes
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
			prefs.NetfilterMode = router.NetfilterOn
		case "nodivert":
			prefs.NetfilterMode = router.NetfilterNoDivert
			warnf("netfilter=nodivert; add iptables calls to ts-* chains manually.")
		case "off":
			prefs.NetfilterMode = router.NetfilterOff
			warnf("netfilter=off; configure iptables yourself.")
		default:
			fatalf("invalid value --netfilter-mode: %q", upArgs.netfilterMode)
		}
	}

	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	var printed bool
	var loginOnce sync.Once
	startLoginInteractive := func() { loginOnce.Do(func() { bc.StartLoginInteractive() }) }

	bc.SetPrefs(prefs)

	opts := ipn.Options{
		StateKey: ipn.GlobalDaemonStateKey,
		AuthKey:  upArgs.authKey,
		Notify: func(n ipn.Notify) {
			if n.ErrMessage != nil {
				fatalf("backend error: %v\n", *n.ErrMessage)
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
	// StateKey based on the connection idenity. So for now, just
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
