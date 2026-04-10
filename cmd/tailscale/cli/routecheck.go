// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn/routecheck"
)

func init() {
	maybeRoutecheckCmd = routecheckCmd
}

var routecheckCmd = func() *ffcli.Command {
	return &ffcli.Command{
		Name:       "routecheck",
		ShortUsage: "tailscale routecheck",
		ShortHelp:  "Print a reachability report for routes with multiple paths",
		Exec:       runRoutecheck,
		FlagSet:    routecheckFlagSet,
	}
}

var routecheckFlagSet = func() *flag.FlagSet {
	fs := newFlagSet("routecheck")
	fs.BoolVar(&routecheckArgs.force, "force", false, "force probe to generate a new reachability report")
	fs.StringVar(&routecheckArgs.format, "format", "", `output format: empty (for human-readable), "json" or "json-line"`)
	return fs
}()

var routecheckArgs struct {
	force  bool
	format string
}

func runRoutecheck(ctx context.Context, args []string) error {
	rp, err := localClient.RouteCheck(ctx, routecheckArgs.force)
	if err != nil {
		return fmt.Errorf("routecheck: %w", err)
	}
	if err := printRouteCheckReport(rp); err != nil {
		return err
	}
	return nil
}

func printRouteCheckReport(rp *routecheck.Report) error {
	var enc *jsontext.Encoder
	switch routecheckArgs.format {
	case "":
	case "json":
		enc = jsontext.NewEncoder(Stdout, jsontext.WithIndent("\t"))
	case "json-line":
		enc = jsontext.NewEncoder(Stdout, jsontext.Multiline(false))
	default:
		return fmt.Errorf("unknown output format %q", routecheckArgs.format)
	}

	routes := rp.RoutablePrefixes()

	if enc != nil {
		out := struct {
			Done   time.Time               `json:"done"`
			Routes routecheck.RoutingTable `json:"routes"`
		}{
			Done:   rp.Done,
			Routes: routes,
		}
		if err := jsonv2.MarshalEncode(enc, out); err != nil {
			return err
		}
		if _, err := Stdout.Write([]byte("\n")); err != nil {
			return err
		}
		return nil
	}

	w := tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "\nReachable routers at %s:\n", rp.Done.UTC().Format(time.DateTime+"Z07:00"))
	fmt.Fprintf(w, "\n %s\t%s\t%s\t", "PREFIX", "IP", "HOSTNAME")
	for prefix, nodes := range routes {
		for _, n := range nodes {
			fmt.Fprintf(w, "\n %s\t%s\t%s\t", prefix, n.Addr, strings.Trim(n.Name, "."))
		}
	}
	fmt.Fprintln(w)
	return nil
}
