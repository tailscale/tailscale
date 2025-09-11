// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"flag"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/opt"
)

var getCmd = &ffcli.Command{
	Name:       "get",
	ShortUsage: "tailscale get <setting>",
	ShortHelp:  "Print specified settings",
	LongHelp: `"tailscale get" prints a specific setting.

Only one setting will be printed.

SETTINGS
` + getSettings.settings(),
	FlagSet:   newFlagSet("get"),
	Exec:      runGet,
	UsageFunc: usageFuncNoDefaultValues,
}

type getSettingsT map[string]string

// makeGetSettingsT returns a [getSettingsT] with all of the settings controlled
// by the given flagsets. Each setting gets its help text from its flag's Usage.
func makeGetSettingsT(flagsets ...*flag.FlagSet) getSettingsT {
	settings := make(getSettingsT)
	for _, fs := range flagsets {
		fs.VisitAll(func(f *flag.Flag) {
			if preflessFlag(f.Name) {
				return
			}
			if _, ok := settings[f.Name]; ok {
				return
			}

			settings[f.Name] = f.Usage
		})
	}
	return settings
}

// Settings returns a string of all the settings known to the get command.
// The result is formatted for use in help text.
func (s getSettingsT) settings() string {
	var b strings.Builder
	names := slices.Sorted(maps.Keys(s))
	for _, name := range names {
		usage := s.usage(name)
		if strings.HasPrefix(usage, hidden) {
			continue
		}
		b.WriteString("  ")
		b.WriteString(name)
		b.WriteString("\n        ")
		b.WriteString(usage)
		b.WriteString("\n")
	}
	return b.String()
}

func lookupPrefOfFlag(p *ipn.Prefs, name string) (v reflect.Value, err error) {
	prefs, ok := prefsOfFlag[name]
	if !ok {
		return reflect.Value{}, fmt.Errorf("missing pref flag mapping for %s", name)
	}
	if len(prefs) != 1 {
		return reflect.Value{}, fmt.Errorf("expected only one pref flag mapping for %s, not %q", name, prefs)
	}

	defer func() {
		switch r := recover().(type) {
		case nil: // noop
		case error:
			err = fmt.Errorf("bad pref flag %q for %s: %w", prefs, name, r)
		default:
			err = fmt.Errorf("bad pref flag %q for %s: %v", prefs, name, r)
		}
	}()
	v = reflect.ValueOf(p).Elem()
	for _, n := range strings.Split(prefs[0], ".") {
		v = v.FieldByName(n)
	}
	return v, nil
}

// Lookup returns a function that can be used to look up the associated
// preference for a given flag name.
func (s getSettingsT) lookup(name string) func(*ipn.Prefs, *ipnstate.Status) string {
	if _, ok := s[name]; !ok {
		return nil
	}

	switch name {
	case "advertise-connector":
		return func(p *ipn.Prefs, st *ipnstate.Status) string {
			value, err := lookupPrefOfFlag(p, name)
			if err != nil {
				panic(err)
			}
			return fmt.Sprintf("%v", value.FieldByName("Advertise"))
		}
	case "advertise-exit-node":
		return func(p *ipn.Prefs, st *ipnstate.Status) string {
			return strconv.FormatBool(p.AdvertisesExitNode())
		}
	case "advertise-tags":
		return func(p *ipn.Prefs, st *ipnstate.Status) string {
			value, err := lookupPrefOfFlag(p, name)
			if err != nil {
				panic(err)
			}
			v := value.Interface().([]string)
			return strings.Join(v, ",")
		}
	case "advertise-routes":
		return func(p *ipn.Prefs, st *ipnstate.Status) string {
			var b strings.Builder
			for i, r := range p.AdvertiseRoutes {
				if i > 0 {
					b.WriteRune(',')
				}
				b.WriteString(r.String())
			}
			return b.String()
		}
	case "exit-node":
		return func(p *ipn.Prefs, st *ipnstate.Status) string {
			ip := exitNodeIP(p, st)
			if ip.IsValid() {
				return ip.String()
			}
			return ""
		}
	case "snat-subnet-routes":
		return func(p *ipn.Prefs, st *ipnstate.Status) string {
			value, err := lookupPrefOfFlag(p, name)
			if err != nil {
				panic(err)
			}
			return fmt.Sprintf("%t", !value.Bool())
		}
	case "stateful-filtering":
		return func(p *ipn.Prefs, st *ipnstate.Status) string {
			value, err := lookupPrefOfFlag(p, name)
			if err != nil {
				panic(err)
			}
			v := value.Interface().(opt.Bool)
			return v.Not().String()
		}
	default:
		return func(p *ipn.Prefs, st *ipnstate.Status) string {
			value, err := lookupPrefOfFlag(p, name)
			if err != nil {
				panic(err)
			}
			return fmt.Sprintf("%v", value) // fmt prints the concrete value
		}
	}
}

// Usage returns the usage string for a given flag name.
func (s getSettingsT) usage(name string) string {
	usage, ok := s[name]
	if !ok {
		panic("unknown setting: " + name)
	}
	return usage
}

var getSettings = makeGetSettingsT(setFlagSet, upFlagSet)

func runGet(ctx context.Context, args []string) (retErr error) {
	if len(args) != 1 {
		fatalf("must provide only one non-flag argument: %q", args)
	}

	setting := args[0]
	lookup := getSettings.lookup(setting)
	if lookup == nil {
		fatalf("unknown setting: %s", setting)
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}

	status, err := localClient.Status(ctx)
	if err != nil {
		return err
	}

	outln(lookup(prefs, status))
	return nil
}
