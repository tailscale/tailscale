// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/views"
)

var getCmd = &ffcli.Command{
	Name:       "get",
	ShortUsage: "tailscale get [flags] [setting-name | all]",
	ShortHelp:  "Show current preference values",
	LongHelp: `"tailscale get" shows the current value of one or all preferences.

With no argument or "all", all preferences are shown.
With a specific setting name, only that value is shown.

The setting names are the same flag names accepted by "tailscale set".`,
	FlagSet: getFlags,
	Exec:    runGet,
}

type getArgsT struct {
	json     bool
	setFlags bool
}

var getArgs getArgsT

var getFlags = newGetFlagSet(&getArgs)

func newGetFlagSet(args *getArgsT) *flag.FlagSet {
	fs := newFlagSet("get")
	fs.BoolVar(&args.json, "json", false, "output as JSON")
	fs.BoolVar(&args.setFlags, "set-flags", false, "output as \"tailscale set\" flag arguments")
	return fs
}

// getSetting is a single preference name-value pair.
type getSetting struct {
	name  string
	value any
}

func runGet(ctx context.Context, args []string) error {
	if len(args) > 1 {
		fatalf("too many arguments: %q", args)
	}

	wantAll := len(args) == 0 || args[0] == "all"
	var wantName string
	if !wantAll {
		wantName = args[0]
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return err
	}

	goos := effectiveGOOS()

	var settings []getSetting
	if wantAll {
		settings = getSettingsFromPrefs(prefs, st, goos, false)
	} else {
		// When querying a specific name, include hidden flags.
		all := getSettingsFromPrefs(prefs, st, goos, true)
		for _, s := range all {
			if s.name == wantName {
				settings = []getSetting{s}
				break
			}
		}
		if len(settings) == 0 {
			return fmt.Errorf("unknown setting %q; see \"tailscale set --help\" for valid settings", wantName)
		}
	}

	switch {
	case getArgs.json:
		return getOutputJSON(settings)
	case getArgs.setFlags:
		return getOutputSetFlags(settings)
	case !wantAll:
		// Single value: just print the raw value.
		outln(fmt.Sprint(settings[0].value))
		return nil
	default:
		return getOutputTable(settings)
	}
}

// getSettingsFromPrefs returns get-able settings derived from prefs,
// using the same flag names as "tailscale set".
// If includeHidden is false, flags with hidden usage strings are omitted.
func getSettingsFromPrefs(prefs *ipn.Prefs, st *ipnstate.Status, goos string, includeHidden bool) []getSetting {
	// Use the set command's flag set to get the canonical ordered list
	// of flag names and to determine OS applicability.
	var dummy setArgsT
	fs := newSetFlagSet(goos, &dummy)

	var settings []getSetting
	fs.VisitAll(func(f *flag.Flag) {
		if preflessFlag(f.Name) {
			return
		}
		if !includeHidden && strings.HasPrefix(f.Usage, hidden) {
			return
		}
		v := prefValue(f.Name, prefs, st)
		settings = append(settings, getSetting{name: f.Name, value: v})
	})
	return settings
}

// prefValue returns the current value of the preference corresponding to
// the given "tailscale set" flag name.
func prefValue(flagName string, prefs *ipn.Prefs, st *ipnstate.Status) any {
	switch flagName {
	case "accept-routes":
		return prefs.RouteAll
	case "accept-dns":
		return prefs.CorpDNS
	case "exit-node":
		if prefs.AutoExitNode.IsSet() {
			return ipn.AutoExitNodePrefix + string(prefs.AutoExitNode)
		}
		ip := exitNodeIP(prefs, st)
		if ip.IsValid() {
			return ip.String()
		}
		return ""
	case "exit-node-allow-lan-access":
		return prefs.ExitNodeAllowLANAccess
	case "shields-up":
		return prefs.ShieldsUp
	case "ssh":
		return prefs.RunSSH
	case "hostname":
		return prefs.Hostname
	case "advertise-routes":
		var sb strings.Builder
		for i, r := range tsaddr.WithoutExitRoutes(views.SliceOf(prefs.AdvertiseRoutes)).All() {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(r.String())
		}
		return sb.String()
	case "advertise-exit-node":
		return tsaddr.ContainsExitRoutes(views.SliceOf(prefs.AdvertiseRoutes))
	case "advertise-connector":
		return prefs.AppConnector.Advertise
	case "nickname":
		return prefs.ProfileName
	case "update-check":
		return prefs.AutoUpdate.Check
	case "auto-update":
		return prefs.AutoUpdate.Apply.EqualBool(true)
	case "report-posture":
		return prefs.PostureChecking
	case "webclient":
		return prefs.RunWebClient
	case "operator":
		return prefs.OperatorUser
	case "snat-subnet-routes":
		return !prefs.NoSNAT
	case "stateful-filtering":
		val, ok := prefs.NoStatefulFiltering.Get()
		if ok && val {
			return false
		}
		return true
	case "netfilter-mode":
		return prefs.NetfilterMode.String()
	case "unattended":
		return prefs.ForceDaemon
	case "sync":
		return prefs.Sync.EqualBool(true)
	case "relay-server-port":
		if prefs.RelayServerPort != nil {
			return fmt.Sprint(*prefs.RelayServerPort)
		}
		return ""
	case "relay-server-static-endpoints":
		parts := make([]string, len(prefs.RelayServerStaticEndpoints))
		for i, ep := range prefs.RelayServerStaticEndpoints {
			parts[i] = ep.String()
		}
		return strings.Join(parts, ",")
	default:
		return nil
	}
}

func getOutputTable(settings []getSetting) error {
	w := tabwriter.NewWriter(Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "NAME\tVALUE\n")
	for _, s := range settings {
		fmt.Fprintf(w, "%s\t%v\n", s.name, s.value)
	}
	return w.Flush()
}

func getOutputJSON(settings []getSetting) error {
	m := make(map[string]any, len(settings))
	for _, s := range settings {
		m[s.name] = s.value
	}
	j, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	outln(string(j))
	return nil
}

func getOutputSetFlags(settings []getSetting) error {
	var parts []string
	for _, s := range settings {
		parts = append(parts, fmtFlagValueArg(s.name, s.value))
	}
	outln(strings.Join(parts, " "))
	return nil
}

