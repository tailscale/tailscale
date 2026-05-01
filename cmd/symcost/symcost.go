// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command symcost analyzes a Go binary's symbol table and reports
// which generic functions and types are most expensive in aggregate.
//
// Usage:
//
//	symcost [flags] <binary>
//
// Flags:
//
//	-package=substr    keep only groups whose package contains substr
//	-min-count=N       keep only groups with at least N member symbols
//	-min-bytes=N       keep only groups whose total size is >= N bytes
//	-generic           keep only groups representing generic instantiations
//	-top=N             show only the top N rows (default 30; 0 = all)
//	-format=text|tsv   output format (default text)
//
// The binary should be built without -ldflags="-s -w" so that the
// symbol table is preserved. -trimpath is recommended to keep symbol
// names compact and reproducible.
package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"tailscale.com/util/sizetest/symcost"
)

var (
	packageSubstr = flag.String("package", "", "keep only groups whose package contains this substring")
	minCount      = flag.Int("min-count", 0, "keep only groups with at least N member symbols")
	minBytes      = flag.Int64("min-bytes", 0, "keep only groups whose total size is >= N bytes")
	genericOnly   = flag.Bool("generic", false, "keep only generic instantiations")
	top           = flag.Int("top", 30, "show only the top N rows (0 = all)")
	format        = flag.String("format", "text", "output format: text or tsv")
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

	groups, err := symcost.Analyze(flag.Arg(0))
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
		fmt.Fprintf(os.Stderr, "unknown -format %q (want text or tsv)\n", *format)
		os.Exit(2)
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
