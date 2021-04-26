// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	shellquote "github.com/kballard/go-shellquote"
	"github.com/peterbourgon/ff/v2/ffcli"
	"inet.af/netaddr"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/preftype"
	"tailscale.com/version/distro"
)

var upCmd = &ffcli.Command{
	Name:       "up",
	ShortUsage: "up [flags]",
	ShortHelp:  "Connect to Tailscale, logging in if needed",

	LongHelp: strings.TrimSpace(`
"tailscale up" connects this machine to your Tailscale network,
triggering authentication if necessary.

With no flags, "tailscale up" brings the network online without
changing any settings. (That is, it's the opposite of "tailscale
down").

If flags are specified, the flags must be the complete set of desired
settings. An error is returned if any setting would be changed as a
result of an unspecified flag's default value, unless the --reset
flag is also used.
`),
	FlagSet: upFlagSet,
	Exec:    runUp,
}

var upFlagSet = (func() *flag.FlagSet {
	upf := flag.NewFlagSet("up", flag.ExitOnError)

	upf.BoolVar(&upArgs.forceReauth, "force-reauth", false, "force reauthentication")
	upf.BoolVar(&upArgs.reset, "reset", false, "reset unspecified settings to their default values")

	upf.StringVar(&upArgs.server, "login-server", ipn.DefaultControlURL, "base URL of control server")
	upf.BoolVar(&upArgs.acceptRoutes, "accept-routes", false, "accept routes advertised by other Tailscale nodes")
	upf.BoolVar(&upArgs.acceptDNS, "accept-dns", true, "accept DNS configuration from the admin panel")
	upf.BoolVar(&upArgs.singleRoutes, "host-routes", true, "install host routes to other Tailscale nodes")
	upf.StringVar(&upArgs.exitNodeIP, "exit-node", "", "Tailscale IP of the exit node for internet traffic")
	upf.BoolVar(&upArgs.exitNodeAllowLANAccess, "exit-node-allow-lan-access", false, "Allow direct access to the local network when routing traffic via an exit node")
	upf.BoolVar(&upArgs.shieldsUp, "shields-up", false, "don't allow incoming connections")
	upf.StringVar(&upArgs.advertiseTags, "advertise-tags", "", "comma-separated ACL tags to request; each must start with \"tag:\" (e.g. \"tag:eng,tag:montreal,tag:ssh\")")
	upf.StringVar(&upArgs.authKey, "authkey", "", "node authorization key")
	upf.StringVar(&upArgs.hostname, "hostname", "", "hostname to use instead of the one provided by the OS")
	upf.StringVar(&upArgs.advertiseRoutes, "advertise-routes", "", "routes to advertise to other nodes (comma-separated, e.g. \"10.0.0.0/8,192.168.0.0/24\")")
	upf.BoolVar(&upArgs.advertiseDefaultRoute, "advertise-exit-node", false, "offer to be an exit node for internet traffic for the tailnet")
	if safesocket.PlatformUsesPeerCreds() {
		upf.StringVar(&upArgs.opUser, "operator", "", "Unix username to allow to operate on tailscaled without sudo")
	}
	if runtime.GOOS == "linux" {
		upf.BoolVar(&upArgs.snat, "snat-subnet-routes", true, "source NAT traffic to local routes advertised with --advertise-routes")
		upf.StringVar(&upArgs.netfilterMode, "netfilter-mode", defaultNetfilterMode(), "netfilter mode (one of on, nodivert, off)")
	}
	if runtime.GOOS == "windows" {
		upf.BoolVar(&upArgs.forceDaemon, "unattended", false, "run in \"Unattended Mode\" where Tailscale keeps running even after the current GUI user logs out (Windows-only)")
	}
	return upf
})()

func defaultNetfilterMode() string {
	if distro.Get() == distro.Synology {
		return "off"
	}
	return "on"
}

type upArgsT struct {
	reset                  bool
	server                 string
	acceptRoutes           bool
	acceptDNS              bool
	singleRoutes           bool
	exitNodeIP             string
	exitNodeAllowLANAccess bool
	shieldsUp              bool
	forceReauth            bool
	forceDaemon            bool
	advertiseRoutes        string
	advertiseDefaultRoute  bool
	advertiseTags          string
	snat                   bool
	netfilterMode          string
	authKey                string
	hostname               string
	opUser                 string
}

var upArgs upArgsT

func warnf(format string, args ...interface{}) {
	fmt.Printf("Warning: "+format+"\n", args...)
}

var (
	ipv4default = netaddr.MustParseIPPrefix("0.0.0.0/0")
	ipv6default = netaddr.MustParseIPPrefix("::/0")
)

// prefsFromUpArgs returns the ipn.Prefs for the provided args.
//
// Note that the parameters upArgs and warnf are named intentionally
// to shadow the globals to prevent accidental misuse of them. This
// function exists for testing and should have no side effects or
// outside interactions (e.g. no making Tailscale local API calls).
func prefsFromUpArgs(upArgs upArgsT, warnf logger.Logf, st *ipnstate.Status, goos string) (*ipn.Prefs, error) {
	routeMap := map[netaddr.IPPrefix]bool{}
	var default4, default6 bool
	if upArgs.advertiseRoutes != "" {
		advroutes := strings.Split(upArgs.advertiseRoutes, ",")
		for _, s := range advroutes {
			ipp, err := netaddr.ParseIPPrefix(s)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid IP address or CIDR prefix", s)
			}
			if ipp != ipp.Masked() {
				return nil, fmt.Errorf("%s has non-address bits set; expected %s", ipp, ipp.Masked())
			}
			if ipp == ipv4default {
				default4 = true
			} else if ipp == ipv6default {
				default6 = true
			}
			routeMap[ipp] = true
		}
		if default4 && !default6 {
			return nil, fmt.Errorf("%s advertised without its IPv6 counterpart, please also advertise %s", ipv4default, ipv6default)
		} else if default6 && !default4 {
			return nil, fmt.Errorf("%s advertised without its IPv6 counterpart, please also advertise %s", ipv6default, ipv4default)
		}
	}
	if upArgs.advertiseDefaultRoute {
		routeMap[netaddr.MustParseIPPrefix("0.0.0.0/0")] = true
		routeMap[netaddr.MustParseIPPrefix("::/0")] = true
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
			return nil, fmt.Errorf("invalid IP address %q for --exit-node: %v", upArgs.exitNodeIP, err)
		}
	} else if upArgs.exitNodeAllowLANAccess {
		return nil, fmt.Errorf("--exit-node-allow-lan-access can only be used with --exit-node")
	}

	if upArgs.exitNodeIP != "" {
		for _, ip := range st.TailscaleIPs {
			if exitNodeIP == ip {
				return nil, fmt.Errorf("cannot use %s as the exit node as it is a local IP address to this machine, did you mean --advertise-exit-node?", upArgs.exitNodeIP)
			}
		}
	}

	var tags []string
	if upArgs.advertiseTags != "" {
		tags = strings.Split(upArgs.advertiseTags, ",")
		for _, tag := range tags {
			err := tailcfg.CheckTag(tag)
			if err != nil {
				return nil, fmt.Errorf("tag: %q: %s", tag, err)
			}
		}
	}

	if len(upArgs.hostname) > 256 {
		return nil, fmt.Errorf("hostname too long: %d bytes (max 256)", len(upArgs.hostname))
	}

	prefs := ipn.NewPrefs()
	prefs.ControlURL = upArgs.server
	prefs.WantRunning = true
	prefs.RouteAll = upArgs.acceptRoutes
	prefs.ExitNodeIP = exitNodeIP
	prefs.ExitNodeAllowLANAccess = upArgs.exitNodeAllowLANAccess
	prefs.CorpDNS = upArgs.acceptDNS
	prefs.AllowSingleHosts = upArgs.singleRoutes
	prefs.ShieldsUp = upArgs.shieldsUp
	prefs.AdvertiseRoutes = routes
	prefs.AdvertiseTags = tags
	prefs.NoSNAT = !upArgs.snat
	prefs.Hostname = upArgs.hostname
	prefs.ForceDaemon = upArgs.forceDaemon
	prefs.OperatorUser = upArgs.opUser

	if goos == "linux" {
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
			return nil, fmt.Errorf("invalid value --netfilter-mode=%q", upArgs.netfilterMode)
		}
	}
	return prefs, nil
}

func runUp(ctx context.Context, args []string) error {
	if len(args) > 0 {
		fatalf("too many non-flag arguments: %q", args)
	}

	st, err := tailscale.Status(ctx)
	if err != nil {
		fatalf("can't fetch status from tailscaled: %v", err)
	}
	origAuthURL := st.AuthURL

	// printAuthURL reports whether we should print out the
	// provided auth URL from an IPN notify.
	printAuthURL := func(url string) bool {
		if upArgs.authKey != "" {
			// Issue 1755: when using an authkey, don't
			// show an authURL that might still be pending
			// from a previous non-completed interactive
			// login.
			return false
		}
		if upArgs.forceReauth && url == origAuthURL {
			return false
		}
		return true
	}

	if distro.Get() == distro.Synology {
		notSupported := "not yet supported on Synology; see https://github.com/tailscale/tailscale/issues/451"
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

	prefs, err := prefsFromUpArgs(upArgs, warnf, st, runtime.GOOS)
	if err != nil {
		fatalf("%s", err)
	}

	if len(prefs.AdvertiseRoutes) > 0 {
		if err := tailscale.CheckIPForwarding(context.Background()); err != nil {
			warnf("%v", err)
		}
	}

	curPrefs, err := tailscale.GetPrefs(ctx)
	if err != nil {
		return err
	}

	flagSet := map[string]bool{}
	mp := new(ipn.MaskedPrefs)
	mp.WantRunningSet = true
	mp.Prefs = *prefs
	upFlagSet.Visit(func(f *flag.Flag) {
		updateMaskedPrefsFromUpFlag(mp, f.Name)
		flagSet[f.Name] = true
	})

	if !upArgs.reset {
		if err := checkForAccidentalSettingReverts(flagSet, curPrefs, mp, os.Getenv("USER")); err != nil {
			fatalf("%s", err)
		}
	}

	controlURLChanged := curPrefs.ControlURL != prefs.ControlURL
	if controlURLChanged && st.BackendState == ipn.Running.String() && !upArgs.forceReauth {
		fatalf("can't change --login-server without --force-reauth")
	}

	// If we're already running and none of the flags require a
	// restart, we can just do an EditPrefs call and change the
	// prefs at runtime (e.g. changing hostname, changinged
	// advertised tags, routes, etc)
	justEdit := st.BackendState == ipn.Running.String() &&
		!upArgs.forceReauth &&
		!upArgs.reset &&
		upArgs.authKey == "" &&
		!controlURLChanged
	if justEdit {
		_, err := tailscale.EditPrefs(ctx, mp)
		return err
	}

	// simpleUp is whether we're running a simple "tailscale up"
	// to transition to running from a previously-logged-in but
	// down state, without changing any settings.
	simpleUp := len(flagSet) == 0 &&
		curPrefs.Persist != nil &&
		curPrefs.Persist.LoginName != "" &&
		st.BackendState != ipn.NeedsLogin.String()

	// At this point we need to subscribe to the IPN bus to watch
	// for state transitions and possible need to authenticate.
	c, bc, pumpCtx, cancel := connect(ctx)
	defer cancel()

	startingOrRunning := make(chan bool, 1) // gets value once starting or running
	gotEngineUpdate := make(chan bool, 1)   // gets value upon an engine update
	go pump(pumpCtx, bc, c)

	printed := !simpleUp
	var loginOnce sync.Once
	startLoginInteractive := func() { loginOnce.Do(func() { bc.StartLoginInteractive() }) }

	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.Engine != nil {
			select {
			case gotEngineUpdate <- true:
			default:
			}
		}
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
				select {
				case startingOrRunning <- true:
				default:
				}
				cancel()
			}
		}
		if url := n.BrowseToURL; url != nil && printAuthURL(*url) {
			printed = true
			fmt.Fprintf(os.Stderr, "\nTo authenticate, visit:\n\n\t%s\n\n", *url)
		}
	})
	// Wait for backend client to be connected so we know
	// we're subscribed to updates. Otherwise we can miss
	// an update upon its transition to running. Do so by causing some traffic
	// back to the bus that we then wait on.
	bc.RequestEngineStatus()
	select {
	case <-gotEngineUpdate:
	case <-pumpCtx.Done():
		return pumpCtx.Err()
	}

	// Special case: bare "tailscale up" means to just start
	// running, if there's ever been a login.
	if simpleUp {
		_, err := tailscale.EditPrefs(ctx, &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				WantRunning: true,
			},
			WantRunningSet: true,
		})
		if err != nil {
			return err
		}
	} else {
		bc.SetPrefs(prefs)

		opts := ipn.Options{
			StateKey: ipn.GlobalDaemonStateKey,
			AuthKey:  upArgs.authKey,
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

		bc.Start(opts)
		if upArgs.forceReauth {
			startLoginInteractive()
		}
	}

	select {
	case <-startingOrRunning:
		return nil
	case <-pumpCtx.Done():
		select {
		case <-startingOrRunning:
			return nil
		default:
		}
		return pumpCtx.Err()
	}
}

var (
	flagForPref = map[string]string{} // "ExitNodeIP" => "exit-node"
	prefsOfFlag = map[string][]string{}
)

func init() {
	addPrefFlagMapping("accept-dns", "CorpDNS")
	addPrefFlagMapping("accept-routes", "RouteAll")
	addPrefFlagMapping("advertise-routes", "AdvertiseRoutes")
	addPrefFlagMapping("advertise-tags", "AdvertiseTags")
	addPrefFlagMapping("host-routes", "AllowSingleHosts")
	addPrefFlagMapping("hostname", "Hostname")
	addPrefFlagMapping("login-server", "ControlURL")
	addPrefFlagMapping("netfilter-mode", "NetfilterMode")
	addPrefFlagMapping("shields-up", "ShieldsUp")
	addPrefFlagMapping("snat-subnet-routes", "NoSNAT")
	addPrefFlagMapping("exit-node", "ExitNodeIP", "ExitNodeID")
	addPrefFlagMapping("exit-node-allow-lan-access", "ExitNodeAllowLANAccess")
	addPrefFlagMapping("unattended", "ForceDaemon")
	addPrefFlagMapping("operator", "OperatorUser")
}

func addPrefFlagMapping(flagName string, prefNames ...string) {
	prefsOfFlag[flagName] = prefNames
	prefType := reflect.TypeOf(ipn.Prefs{})
	for _, pref := range prefNames {
		flagForPref[pref] = flagName

		// Crash at runtime if there's a typo in the prefName.
		if _, ok := prefType.FieldByName(pref); !ok {
			panic(fmt.Sprintf("invalid ipn.Prefs field %q", pref))
		}
	}
}

func updateMaskedPrefsFromUpFlag(mp *ipn.MaskedPrefs, flagName string) {
	if prefs, ok := prefsOfFlag[flagName]; ok {
		for _, pref := range prefs {
			reflect.ValueOf(mp).Elem().FieldByName(pref + "Set").SetBool(true)
		}
		return
	}
	switch flagName {
	case "authkey", "force-reauth", "reset":
		// Not pref-related flags.
	case "advertise-exit-node":
		// This pref is a shorthand for advertise-routes.
	default:
		panic(fmt.Sprintf("internal error: unhandled flag %q", flagName))
	}
}

const accidentalUpPrefix = "Error: changing settings via 'tailscale up' requires mentioning all\n" +
	"non-default flags. To proceed, either re-run your command with --reset or\n" +
	"specify use the command below to explicitly mention the current value of\n" +
	"all non-default settings:\n\n" +
	"\ttailscale up"

// checkForAccidentalSettingReverts checks for people running
// "tailscale up" with a subset of the flags they originally ran it
// with.
//
// For example, in Tailscale 1.6 and prior, a user might've advertised
// a tag, but later tried to change just one other setting and forgot
// to mention the tag later and silently wiped it out. We now
// require --reset to change preferences to flag default values when
// the flag is not mentioned on the command line.
//
// curPrefs is what's currently active on the server.
//
// mp is the mask of settings actually set, where mp.Prefs is the new
// preferences to set, including any values set from implicit flags.
func checkForAccidentalSettingReverts(flagSet map[string]bool, curPrefs *ipn.Prefs, mp *ipn.MaskedPrefs, curUser string) error {
	if len(flagSet) == 0 {
		// A bare "tailscale up" is a special case to just
		// mean bringing the network up without any changes.
		return nil
	}
	if curPrefs.ControlURL == "" {
		// Don't validate things on initial "up" before a control URL has been set.
		return nil
	}
	curWithExplicitEdits := curPrefs.Clone()
	curWithExplicitEdits.ApplyEdits(mp)

	prefType := reflect.TypeOf(ipn.Prefs{})

	// Explicit values (current + explicit edit):
	ev := reflect.ValueOf(curWithExplicitEdits).Elem()
	// Implicit values (what we'd get if we replaced everything with flag defaults):
	iv := reflect.ValueOf(&mp.Prefs).Elem()

	var missing []string
	flagExplicitValue := map[string]interface{}{} // e.g. "accept-dns" => true (from flagSet)
	for i := 0; i < prefType.NumField(); i++ {
		prefName := prefType.Field(i).Name
		if prefName == "Persist" {
			continue
		}
		flagName, hasFlag := flagForPref[prefName]

		// Special case for advertise-exit-node; which is a
		// flag but doesn't have a corresponding pref.  The
		// flag augments advertise-routes, so we have to infer
		// the imaginary pref's current value from the routes.
		if prefName == "AdvertiseRoutes" &&
			hasExitNodeRoutes(curPrefs.AdvertiseRoutes) &&
			!hasExitNodeRoutes(curWithExplicitEdits.AdvertiseRoutes) &&
			!flagSet["advertise-exit-node"] {
			missing = append(missing, "--advertise-exit-node")
		}

		if hasFlag && flagSet[flagName] {
			flagExplicitValue[flagName] = ev.Field(i).Interface()
			continue
		}
		// Get explicit value and implicit value
		ex, im := ev.Field(i), iv.Field(i)
		switch ex.Kind() {
		case reflect.String, reflect.Slice:
			if ex.Kind() == reflect.Slice && ex.Len() == 0 && im.Len() == 0 {
				// Treat nil and non-nil empty slices as equivalent.
				continue
			}
		}
		exi, imi := ex.Interface(), im.Interface()

		if reflect.DeepEqual(exi, imi) {
			continue
		}
		if flagName == "operator" && imi == "" && exi == curUser {
			// Don't require setting operator if the current user matches
			// the configured operator.
			continue
		}
		switch flagName {
		case "":
			return fmt.Errorf("'tailscale up' without --reset requires all preferences with changing values to be explicitly mentioned; this command would change the value of flagless pref %q", prefName)
		case "exit-node":
			if prefName == "ExitNodeIP" {
				missing = append(missing, fmtFlagValueArg("exit-node", fmtSettingVal(exi)))
			}
		default:
			missing = append(missing, fmtFlagValueArg(flagName, fmtSettingVal(exi)))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString(accidentalUpPrefix)

	var flagSetSorted []string
	for f := range flagSet {
		flagSetSorted = append(flagSetSorted, f)
	}
	sort.Strings(flagSetSorted)
	for _, flagName := range flagSetSorted {
		if ev, ok := flagExplicitValue[flagName]; ok {
			fmt.Fprintf(&sb, " %s", fmtFlagValueArg(flagName, fmtSettingVal(ev)))
		}
	}
	for _, a := range missing {
		fmt.Fprintf(&sb, " %s", a)
	}
	sb.WriteString("\n\n")
	return errors.New(sb.String())
}

func fmtFlagValueArg(flagName, val string) string {
	if val == "true" {
		// TODO: check flagName's type to see if its Pref is of type bool
		return "--" + flagName
	}
	if val == "" {
		return "--" + flagName + "="
	}
	return fmt.Sprintf("--%s=%v", flagName, shellquote.Join(val))
}

func fmtSettingVal(v interface{}) string {
	switch v := v.(type) {
	case bool:
		return strconv.FormatBool(v)
	case string:
		return v
	case preftype.NetfilterMode:
		return v.String()
	case []string:
		return strings.Join(v, ",")
	case []netaddr.IPPrefix:
		var sb strings.Builder
		for i, r := range v {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(r.String())
		}
		return sb.String()
	}
	return fmt.Sprint(v)
}

func hasExitNodeRoutes(rr []netaddr.IPPrefix) bool {
	var v4, v6 bool
	for _, r := range rr {
		if r.Bits == 0 {
			if r.IP.Is4() {
				v4 = true
			} else if r.IP.Is6() {
				v6 = true
			}
		}
	}
	return v4 && v6
}
