// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

// serviceLister is the subset of [local.Client] that the service commands
// need. It is injected via the command's context (see [withServiceLister] /
// [serviceListerFromContext]) so tests can supply a mock. Outside of tests
// it is suplied by the package-level localClient var.
//
// NOTE(adrianosela): Could be replaced by a more generic way to mock
// local.Client e.g. https://github.com/tailscale/tailscale/issues/20164.
type serviceLister interface {
	GetServices(ctx context.Context) (map[tailcfg.ServiceName]tailcfg.ServiceDetails, error)
	Status(ctx context.Context) (*ipnstate.Status, error)
}

type serviceListerCtxKey struct{}

// withServiceLister returns a copy of ctx carrying sl, retrievable with
// [serviceListerFromContext].
func withServiceLister(ctx context.Context, sl serviceLister) context.Context {
	return context.WithValue(ctx, serviceListerCtxKey{}, sl)
}

// serviceListerFromContext returns the [serviceLister] stored in ctx by
// [withServiceLister], or the package-level localClient if none was injected.
func serviceListerFromContext(ctx context.Context) serviceLister {
	if sl, ok := ctx.Value(serviceListerCtxKey{}).(serviceLister); ok {
		return sl
	}
	return &localClient
}

const serviceListUsage = "tailscale service list"

func serviceCmd() *ffcli.Command {
	// The service commands are still in development and gated behind the
	// work-in-progress knob. When it's off, serviceCmd returns nil and is
	// filtered out of the root command's subcommands by nonNilCmds.
	if !envknob.UseWIPCode() {
		return nil
	}
	return &ffcli.Command{
		Name:       "service",
		ShortHelp:  "Interact with Tailscale Services",
		ShortUsage: "tailscale service",
		LongHelp: strings.TrimSpace(`
The 'tailscale service' command groups subcommands for Tailscale Services.

A Tailscale Service is a virtual service with its own IP addresses. Which
Services this node can reach is determined by the tailnet's ACLs. Use the 'list'
subcommand to see the Services currently available to this node.
`),
		UsageFunc: usageFuncNoDefaultValues,
		Exec:      func(context.Context, []string) error { return flag.ErrHelp },
		Subcommands: []*ffcli.Command{
			{
				Name:       "list",
				ShortUsage: serviceListUsage,
				ShortHelp:  "List the Tailscale Services your node can access",
				Exec:       runServiceList,
				FlagSet: func() *flag.FlagSet {
					fs := newFlagSet("list")
					fs.BoolVar(&serviceListArgs.json, "json", false, "output in JSON format")
					return fs
				}(),
			},
		},
	}
}

var serviceListArgs struct {
	json bool
}

// serviceListEntry decorates a [tailcfg.ServiceDetails] with the Service's
// MagicDNS hostname, both for the table's HOSTNAME column and so it is included
// in the JSON output.
type serviceListEntry struct {
	tailcfg.ServiceDetails
	Hostname string
}

// runServiceList is the entry point for the "tailscale service list" command.
func runServiceList(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: %s", serviceListUsage)
	}

	lc := serviceListerFromContext(ctx)

	services, err := lc.GetServices(ctx)
	if err != nil {
		return err
	}

	// We need the tailnet's MagicDNS suffix to build each Service's hostname.
	st, err := lc.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	var magicDNSSuffix string
	if st.CurrentTailnet != nil {
		magicDNSSuffix = st.CurrentTailnet.MagicDNSSuffix
	}

	// Sort the services by name for stable output.
	names := make([]tailcfg.ServiceName, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	slices.Sort(names)

	entries := make([]serviceListEntry, 0, len(names))
	for _, name := range names {
		svc := services[name]
		entries = append(entries, serviceListEntry{
			ServiceDetails: svc,
			Hostname:       serviceHostname(name, magicDNSSuffix),
		})
	}

	if serviceListArgs.json {
		enc := json.NewEncoder(Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	if len(entries) == 0 {
		fmt.Fprintln(Stdout, "No Tailscale Services are available to this node.")
		return nil
	}

	w := tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "\n %s\t%s\t%s\t%s\t%s\t", "IP", "HOSTNAME", "DISPLAY NAME", "ENDPOINTS", "TYPE")
	for _, e := range entries {
		// Show a single IP, always the first in Addrs. If a tailnet has IPv4
		// disabled, the netmap only includes the v6 address, so the 0th index
		// is the v6 address and that's what we show.
		var ip string
		if len(e.Addrs) > 0 {
			ip = e.Addrs[0].String()
		}
		fmt.Fprintf(w, "\n %s\t%s\t%s\t%s\t%s\t",
			cmp.Or(ip, "-"),
			cmp.Or(e.Hostname, "-"),
			cmp.Or(e.DisplayName, "-"),
			joinStringers(e.Ports, "-"),
			serviceActionTypes(e.ServiceDetails),
		)
	}
	fmt.Fprintln(w)
	return nil
}

// wellKnownPortActions maps well-known TCP ports to the service action type
// they conventionally correspond to. It is used to infer actions for Services
// that don't carry explicit ones.
//
// TODO(adrianosela): move this to tailcfg as
// InferredServiceActionForPort(p uint16) ServiceActionType.
var wellKnownPortActions = map[uint16]tailcfg.ServiceActionType{
	22:    tailcfg.ServiceActionTypeSSH,
	80:    tailcfg.ServiceActionTypeHTTP,
	443:   tailcfg.ServiceActionTypeHTTP,
	1433:  tailcfg.ServiceActionTypeMSSQL,
	3306:  tailcfg.ServiceActionTypeMySQL,
	3389:  tailcfg.ServiceActionTypeRDP,
	5432:  tailcfg.ServiceActionTypePostgreSQL,
	5900:  tailcfg.ServiceActionTypeVNC,
	6443:  tailcfg.ServiceActionTypeKubernetes,
	9200:  tailcfg.ServiceActionTypeElasticSearch,
	26257: tailcfg.ServiceActionTypeCockroachDB,
	27017: tailcfg.ServiceActionTypeMongoDB,
}

// maxNamedTypes is the most action types serviceActionTypes names before
// summarizing the remainder as "N other(s)".
const maxNamedTypes = 2

// serviceActionTypes renders a Service's action identifiers (types) for the
// TYPE column. Types are deduplicated; it names at most [maxNamedTypes] of them
// and summarizes any remainder, e.g. "-" for none, "http" for one, "http, ssh"
// for two, and "http, ssh, 2 others" for more.
//
// Explicit actions are shown by type. When a Service carries no explicit
// actions, types are inferred from well-known TCP ports (see
// [wellKnownPortActions]).
func serviceActionTypes(svc tailcfg.ServiceDetails) string {
	var raw []tailcfg.ServiceActionType
	if len(svc.Actions) > 0 {
		for _, a := range svc.Actions {
			raw = append(raw, a.Type)
		}
	} else {
		for _, ppr := range svc.Ports {
			// Only single TCP ports map to a well-known action.
			if ppr.Proto != 0 && ppr.Proto != int(ipproto.TCP) {
				continue
			}
			if ppr.Ports.First != ppr.Ports.Last {
				continue
			}
			if t, ok := wellKnownPortActions[ppr.Ports.First]; ok {
				raw = append(raw, t)
			}
		}
	}

	// Deduplicate, preserving first-seen order.
	var types []string
	seen := make(map[tailcfg.ServiceActionType]bool)
	for _, t := range raw {
		if seen[t] {
			continue
		}
		seen[t] = true
		types = append(types, string(t))
	}

	if len(types) == 0 {
		return "-"
	}
	if len(types) <= maxNamedTypes {
		return strings.Join(types, ", ")
	}
	extra := len(types) - maxNamedTypes
	noun := "others"
	if extra == 1 {
		noun = "other"
	}
	return fmt.Sprintf("%s, %d %s", strings.Join(types[:maxNamedTypes], ", "), extra, noun)
}

// serviceHostname returns the MagicDNS hostname for a Service, of the form
// "<name>.<magicDNSSuffix>". It returns "" if the name or suffix is missing.
func serviceHostname(name tailcfg.ServiceName, magicDNSSuffix string) string {
	bare := name.WithoutPrefix()
	if bare == "" || magicDNSSuffix == "" {
		return ""
	}
	return bare + "." + strings.Trim(magicDNSSuffix, ".")
}

// joinStringers renders a slice of fmt.Stringer-like values as a
// comma-separated string, returning empty if the slice is empty.
func joinStringers[T fmt.Stringer](vals []T, empty string) string {
	if len(vals) == 0 {
		return empty
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = v.String()
	}
	return strings.Join(strs, ", ")
}
