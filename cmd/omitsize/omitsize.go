// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The omitsize tool prints out how large the Tailscale binaries are with
// different build tags.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"tailscale.com/feature/featuretags"
	"tailscale.com/util/set"
)

var (
	cacheDir = flag.String("cachedir", "", "if non-empty, use this directory to store cached size results to speed up subsequent runs. The tool does not consider the git status when deciding whether to use the cache. It's on you to nuke it between runs if the tree changed.")
	features = flag.String("features", "", "comma-separated list of features to list in the table, without the ts_omit_ prefix. It may also contain a '+' sign(s) for ANDing features together. If empty, all omittable features are considered one at a time.")

	showRemovals = flag.Bool("show-removals", false, "if true, show a table of sizes removing one feature at a time from the full set.")
)

// allOmittable returns the list of all build tags that remove features.
var allOmittable = sync.OnceValue(func() []string {
	var ret []string // all build tags that can be omitted
	for k := range featuretags.Features {
		if k.IsOmittable() {
			ret = append(ret, k.OmitTag())
		}
	}
	slices.Sort(ret)
	return ret
})

func main() {
	flag.Parse()

	// rows is a set (usually of size 1) of feature(s) to add/remove, without deps
	// included at this point (as dep direction depends on whether we're adding or removing,
	// so it's expanded later)
	var rows []set.Set[featuretags.FeatureTag]

	if *features == "" {
		for _, k := range slices.Sorted(maps.Keys(featuretags.Features)) {
			if k.IsOmittable() {
				rows = append(rows, set.Of(k))
			}
		}
	} else {
		for v := range strings.SplitSeq(*features, ",") {
			s := set.Set[featuretags.FeatureTag]{}
			for fts := range strings.SplitSeq(v, "+") {
				ft := featuretags.FeatureTag(fts)
				if _, ok := featuretags.Features[ft]; !ok {
					log.Fatalf("unknown feature %q", v)
				}
				s.Add(ft)
			}
			rows = append(rows, s)
		}
	}

	minD := measure("tailscaled", allOmittable()...)
	minC := measure("tailscale", allOmittable()...)
	minBoth := measure("tailscaled", append(slices.Clone(allOmittable()), "ts_include_cli")...)

	if *showRemovals {
		baseD := measure("tailscaled")
		baseC := measure("tailscale")
		baseBoth := measure("tailscaled", "ts_include_cli")

		fmt.Printf("Starting with everything and removing a feature...\n\n")

		fmt.Printf("%9s %9s %9s\n", "tailscaled", "tailscale", "combined (linux/amd64)")
		fmt.Printf("%9d %9d %9d\n", baseD, baseC, baseBoth)

		fmt.Printf("-%8d -%8d -%8d .. remove *\n", baseD-minD, baseC-minC, baseBoth-minBoth)

		for _, s := range rows {
			title, tags := computeRemove(s)
			sizeD := measure("tailscaled", tags...)
			sizeC := measure("tailscale", tags...)
			sizeBoth := measure("tailscaled", append(slices.Clone(tags), "ts_include_cli")...)
			saveD := max(baseD-sizeD, 0)
			saveC := max(baseC-sizeC, 0)
			saveBoth := max(baseBoth-sizeBoth, 0)
			fmt.Printf("-%8d -%8d -%8d .. remove %s\n", saveD, saveC, saveBoth, title)

		}
	}

	fmt.Printf("\nStarting at a minimal binary and adding one feature back...\n\n")
	fmt.Printf("%9s %9s %9s\n", "tailscaled", "tailscale", "combined (linux/amd64)")
	fmt.Printf("%9d %9d %9d omitting everything\n", minD, minC, minBoth)
	for _, s := range rows {
		title, tags := computeAdd(s)
		sizeD := measure("tailscaled", tags...)
		sizeC := measure("tailscale", tags...)
		sizeBoth := measure("tailscaled", append(tags, "ts_include_cli")...)

		fmt.Printf("+%8d +%8d +%8d .. add %s\n", max(sizeD-minD, 0), max(sizeC-minC, 0), max(sizeBoth-minBoth, 0), title)
	}

}

// computeAdd returns a human-readable title of a set of features and the build
// tags to use to add that set of features to a minimal binary, including their
// feature dependencies.
func computeAdd(s set.Set[featuretags.FeatureTag]) (title string, tags []string) {
	allSet := set.Set[featuretags.FeatureTag]{} // s + all their outbound dependencies
	var explicitSorted []string                 // string versions of s, sorted
	for ft := range s {
		allSet.AddSet(featuretags.Requires(ft))
		if ft.IsOmittable() {
			explicitSorted = append(explicitSorted, string(ft))
		}
	}
	slices.Sort(explicitSorted)

	var removeTags []string
	for ft := range allSet {
		if ft.IsOmittable() {
			removeTags = append(removeTags, ft.OmitTag())
		}
	}

	var titleBuf strings.Builder
	titleBuf.WriteString(strings.Join(explicitSorted, "+"))
	var and []string
	for ft := range allSet {
		if !s.Contains(ft) {
			and = append(and, string(ft))
		}
	}
	if len(and) > 0 {
		slices.Sort(and)
		fmt.Fprintf(&titleBuf, " (and %s)", strings.Join(and, "+"))
	}
	tags = allExcept(allOmittable(), removeTags)
	return titleBuf.String(), tags
}

// computeRemove returns a human-readable title of a set of features and the build
// tags to use to remove that set of features from a full binary, including removing
// any features that depend on features in the provided set.
func computeRemove(s set.Set[featuretags.FeatureTag]) (title string, tags []string) {
	allSet := set.Set[featuretags.FeatureTag]{} // s + all their inbound dependencies
	var explicitSorted []string                 // string versions of s, sorted
	for ft := range s {
		allSet.AddSet(featuretags.RequiredBy(ft))
		if ft.IsOmittable() {
			explicitSorted = append(explicitSorted, string(ft))
		}
	}
	slices.Sort(explicitSorted)

	var removeTags []string
	for ft := range allSet {
		if ft.IsOmittable() {
			removeTags = append(removeTags, ft.OmitTag())
		}
	}

	var titleBuf strings.Builder
	titleBuf.WriteString(strings.Join(explicitSorted, "+"))

	var and []string
	for ft := range allSet {
		if !s.Contains(ft) {
			and = append(and, string(ft))
		}
	}
	if len(and) > 0 {
		slices.Sort(and)
		fmt.Fprintf(&titleBuf, " (and %s)", strings.Join(and, "+"))
	}

	return titleBuf.String(), removeTags
}

func allExcept(all, omit []string) []string {
	return slices.DeleteFunc(slices.Clone(all), func(s string) bool { return slices.Contains(omit, s) })
}

func measure(bin string, tags ...string) int64 {
	tags = slices.Clone(tags)
	slices.Sort(tags)
	tags = slices.Compact(tags)
	comma := strings.Join(tags, ",")

	var cacheFile string
	if *cacheDir != "" {
		cacheFile = filepath.Join(*cacheDir, fmt.Sprintf("%02x", sha256.Sum256(fmt.Appendf(nil, "%s-%s.size", bin, comma))))
		if v, err := os.ReadFile(cacheFile); err == nil {
			if size, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64); err == nil {
				return size
			}
		}
	}

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-w -s", "-tags", strings.Join(tags, ","), "-o", "tmpbin", "./cmd/"+bin)
	log.Printf("# Measuring %v", cmd.Args)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("error measuring %q: %v, %s\n", bin, err, out)
	}
	fi, err := os.Stat("tmpbin")
	if err != nil {
		log.Fatal(err)
	}
	n := fi.Size()
	if cacheFile != "" {
		if err := os.WriteFile(cacheFile, fmt.Appendf(nil, "%d", n), 0644); err != nil {
			log.Fatalf("error writing size to cache: %v\n", err)
		}
	}
	return n
}
