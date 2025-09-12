// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The featuretags command helps other build tools select Tailscale's Go build
// tags to use.
package main

import (
	"flag"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"

	"tailscale.com/feature/featuretags"
)

var (
	min    = flag.Bool("min", false, "remove all features not mentioned in --add")
	remove = flag.String("remove", "", "a comma-separated list of features to remove from the build. (without the 'ts_omit_' prefix)")
	add    = flag.String("add", "", "a comma-separated list of features or tags to add, if --min is used.")
	list   = flag.Bool("list", false, "if true, list all known features and what they do")
)

func main() {
	flag.Parse()

	features := featuretags.Features

	if *list {
		for _, f := range slices.Sorted(maps.Keys(features)) {
			fmt.Printf("%20s: %s\n", f, features[f])
		}
		return
	}

	var keep = map[string]bool{}
	for t := range strings.SplitSeq(*add, ",") {
		if t != "" {
			keep[t] = true
		}
	}
	var tags []string
	if keep["cli"] {
		// The "cli" --add value is special in that it's a build tag
		// that adds something, rather than removes something.
		tags = append(tags, "ts_include_cli")
	}
	if *min {
		for _, f := range slices.Sorted(maps.Keys(features)) {
			if f == "" {
				continue
			}
			if !keep[f] {
				tags = append(tags, "ts_omit_"+f)
			}
		}
	}
	for f := range strings.SplitSeq(*remove, ",") {
		if f == "" {
			continue
		}
		if _, ok := features[f]; !ok {
			log.Fatalf("unknown feature %q in --remove", f)
		}
		tags = append(tags, "ts_omit_"+f)
	}
	if len(tags) != 0 {
		fmt.Println(strings.Join(tags, ","))
	}

}
