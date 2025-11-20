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
	"tailscale.com/util/set"
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
			fmt.Printf("%20s: %s\n", f, features[f].Desc)
		}
		return
	}

	var keep = map[featuretags.FeatureTag]bool{}
	for t := range strings.SplitSeq(*add, ",") {
		if t != "" {
			for ft := range featuretags.Requires(featuretags.FeatureTag(t)) {
				keep[ft] = true
			}
		}
	}
	var tags []string
	if keep[featuretags.CLI] {
		tags = append(tags, "ts_include_cli")
	}
	if *min {
		for _, f := range slices.Sorted(maps.Keys(features)) {
			if f == "" {
				continue
			}
			if !keep[f] && f.IsOmittable() {
				tags = append(tags, f.OmitTag())
			}
		}
	}
	removeSet := set.Set[featuretags.FeatureTag]{}
	for v := range strings.SplitSeq(*remove, ",") {
		if v == "" {
			continue
		}
		f := featuretags.FeatureTag(v)
		if _, ok := features[f]; !ok {
			log.Fatalf("unknown feature %q in --remove", f)
		}
		removeSet.Add(f)
	}
	for ft := range removeSet {
		set := featuretags.RequiredBy(ft)
		for dependent := range set {
			if !removeSet.Contains(dependent) {
				log.Fatalf("cannot remove %q without also removing %q, which depends on it", ft, dependent)
			}
		}
		tags = append(tags, ft.OmitTag())
	}
	slices.Sort(tags)
	tags = slices.Compact(tags)
	if len(tags) != 0 {
		fmt.Println(strings.Join(tags, ","))
	}
}
