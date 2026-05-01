// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command symcost analyzes a Go binary and reports binary-size cost
// attribution by receiver type, by function, or as a top-N grouped
// view across the whole binary.
//
// Usage:
//
//	symcost [flags] <binary>
//
// Discovery (default): top-N groups across the binary.
//
//	symcost                    -top=30 -package=substr
//	symcost -generic           keep only generic instantiations
//	symcost -min-count=N       require at least N members per group
//	symcost -min-bytes=N       require at least N total bytes per group
//
// Receiver mode: the cost of a type and everything associated with
// it (methods, dicts, eq/hash funcs, type descriptors, itabs).
//
//	symcost -receiver=tailscale.com/util/eventbus.Publisher
//
// Function mode: the cost of one function (or one generic template)
// across all instantiations.
//
//	symcost -func=tailscale.com/util/eventbus.(*SubscriberFunc[…]).dispatch
//
// The binary should be built without -ldflags="-s -w" so that the
// symbol table is preserved. -trimpath is recommended.
package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"tailscale.com/util/sizetest/symcost"
)

var (
	// Discovery-mode flags.
	packageSubstr = flag.String("package", "", "keep only groups whose package contains this substring (discovery mode)")
	minCount      = flag.Int("min-count", 0, "keep only groups with at least N members (discovery mode)")
	minBytes      = flag.Int64("min-bytes", 0, "keep only groups whose total size is >= N bytes (discovery mode)")
	genericOnly   = flag.Bool("generic", false, "keep only generic instantiations (discovery mode)")
	top           = flag.Int("top", 30, "show only the top N rows (0 = all)")

	// Targeted-mode flags.
	receiver = flag.String("receiver", "", "report the full cost of a receiver type and everything associated with it")
	function = flag.String("func", "", "report the cost of one function (or generic template) across all instantiations")

	format = flag.String("format", "text", "output format: text or tsv")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <binary>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	binPath := flag.Arg(0)

	switch {
	case *receiver != "":
		runReceiver(binPath, *receiver)
	case *function != "":
		runFunction(binPath, *function)
	default:
		runDiscovery(binPath)
	}
}

func runReceiver(binPath, name string) {
	b, err := symcost.Open(binPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer b.Close()
	c := b.CostByReceiver(name)
	writeCost(os.Stdout, c, "receiver")
}

func runFunction(binPath, name string) {
	b, err := symcost.Open(binPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer b.Close()
	c := b.CostByFunction(name)
	writeCost(os.Stdout, c, "function")
}

func runDiscovery(binPath string) {
	groups, err := symcost.Analyze(binPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	groups = symcost.Filter{
		PackageSubstr: *packageSubstr,
		MinCount:      *minCount,
		MinTotal:      *minBytes,
		GenericOnly:   *genericOnly,
	}.Apply(groups)
	if *top > 0 && len(groups) > *top {
		groups = groups[:*top]
	}
	switch *format {
	case "text":
		writeText(os.Stdout, groups)
	case "tsv":
		writeTSV(os.Stdout, groups)
	default:
		fmt.Fprintf(os.Stderr, "unknown -format %q\n", *format)
		os.Exit(2)
	}
}

func writeCost(w *os.File, c symcost.Cost, mode string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s\t%s\n", "Mode:", mode)
	fmt.Fprintf(tw, "%s\t%s\n", "Target:", c.Target)
	fmt.Fprintf(tw, "%s\t%d bytes\n", "Total:", c.Total)
	tw.Flush()
	fmt.Fprintln(w)

	// Section breakdown.
	fmt.Fprintln(w, "By section:")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SECTION\tBYTES")
	for sec, n := range c.Sections {
		fmt.Fprintf(tw, "  %s\t%d\n", sec, n)
	}
	tw.Flush()
	fmt.Fprintln(w)

	// Top funcs.
	if len(c.Funcs) > 0 {
		fmt.Fprintln(w, "Top functions:")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  TOTAL\tBODY\tPCLNTAB\tNAME")
		for i, f := range c.Funcs {
			if i >= 30 {
				fmt.Fprintf(tw, "  ...\t\t\t(%d more)\n", len(c.Funcs)-30)
				break
			}
			fmt.Fprintf(tw, "  %d\t%d\t%d\t%s\n", f.Total(), f.BodyBytes, f.PclntabBytes, f.Name)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	// Types summary.
	if len(c.Types) > 0 {
		var total int64
		for _, t := range c.Types {
			total += t.Total()
		}
		fmt.Fprintf(w, "Type descriptors: %d entries, %d bytes\n", len(c.Types), total)
		if len(c.Types) <= 10 {
			tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			for _, t := range c.Types {
				fmt.Fprintf(tw, "  %d\t%s\n", t.Total(), t.Name)
			}
			tw.Flush()
		}
		fmt.Fprintln(w)
	}

	// Itabs summary.
	if len(c.Itabs) > 0 {
		var total int64
		for _, it := range c.Itabs {
			total += it.Bytes
		}
		fmt.Fprintf(w, "Itabs: %d entries, %d bytes\n", len(c.Itabs), total)
		fmt.Fprintln(w)
	}

	// Named symbols summary.
	if len(c.NamedSyms) > 0 {
		var total int64
		for _, s := range c.NamedSyms {
			total += s.Bytes
		}
		fmt.Fprintf(w, "Other named symbols: %d entries, %d bytes\n", len(c.NamedSyms), total)
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  BYTES\tSECTION\tNAME")
		for i, s := range c.NamedSyms {
			if i >= 15 {
				fmt.Fprintf(tw, "  ...\t\t(%d more)\n", len(c.NamedSyms)-15)
				break
			}
			fmt.Fprintf(tw, "  %d\t%s\t%s\n", s.Bytes, s.Section, s.Name)
		}
		tw.Flush()
	}
}

func writeText(w *os.File, groups []symcost.Group) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOTAL\tCOUNT\tAVG\tMIN\tMAX\tTEMPLATE")
	for _, g := range groups {
		fmt.Fprintf(tw, "%d\t%d\t%d\t%d\t%d\t%s\n",
			g.Total, g.Count(), g.Avg, g.Min, g.Max, g.Template)
	}
	tw.Flush()
}

func writeTSV(w *os.File, groups []symcost.Group) {
	fmt.Fprintln(w, "total\tcount\tavg\tmin\tmax\tpackage\ttemplate")
	for _, g := range groups {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%d\t%s\t%s\n",
			g.Total, g.Count(), g.Avg, g.Min, g.Max, g.Package, g.Template)
	}
}
