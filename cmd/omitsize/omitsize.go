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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"tailscale.com/feature/featuretags"
)

var (
	cacheDir = flag.String("cachedir", "", "if non-empty, use this directory to store cached size results to speed up subsequent runs. The tool does not consider the git status when deciding whether to use the cache. It's on you to nuke it between runs if the tree changed.")
	features = flag.String("features", "", "comma-separated list of features to consider, with or without the ts_omit_ prefix")

	showRemovals = flag.Bool("show-removals", false, "if true, show a table of sizes removing one feature at a time from the full set")
)

func main() {
	flag.Parse()

	var all []string
	if *features == "" {
		for k := range featuretags.Features {
			if k.IsOmittable() {
				all = append(all, k.OmitTag())
			}
		}
	} else {
		for v := range strings.SplitSeq(*features, ",") {
			if !strings.HasPrefix(v, "ts_omit_") {
				v = "ts_omit_" + v
			}
			all = append(all, v)
		}
	}

	slices.Sort(all)
	all = slices.Compact(all)

	baseD := measure("tailscaled")
	baseC := measure("tailscale")
	baseBoth := measure("tailscaled", "ts_include_cli")

	minD := measure("tailscaled", all...)
	minC := measure("tailscale", all...)
	minBoth := measure("tailscaled", append(slices.Clone(all), "ts_include_cli")...)

	if *showRemovals {
		fmt.Printf("Starting with everything and removing a feature...\n\n")

		fmt.Printf("%9s %9s %9s\n", "tailscaled", "tailscale", "combined (linux/amd64)")
		fmt.Printf("%9d %9d %9d\n", baseD, baseC, baseBoth)

		fmt.Printf("-%8d -%8d -%8d omit-all\n", baseD-minD, baseC-minC, baseBoth-minBoth)

		for _, t := range all {
			sizeD := measure("tailscaled", t)
			sizeC := measure("tailscale", t)
			sizeBoth := measure("tailscaled", append([]string{t}, "ts_include_cli")...)
			saveD := max(baseD-sizeD, 0)
			saveC := max(baseC-sizeC, 0)
			saveBoth := max(baseBoth-sizeBoth, 0)
			fmt.Printf("-%8d -%8d -%8d %s\n", saveD, saveC, saveBoth, t)
		}
	}

	fmt.Printf("\nStarting at a minimal binary and adding one feature back...\n")
	fmt.Printf("%9s %9s %9s\n", "tailscaled", "tailscale", "combined (linux/amd64)")
	fmt.Printf("%9d %9d %9d omitting everything\n", minD, minC, minBoth)
	for _, t := range all {
		tags := allExcept(all, t)
		sizeD := measure("tailscaled", tags...)
		sizeC := measure("tailscale", tags...)
		sizeBoth := measure("tailscaled", append(tags, "ts_include_cli")...)
		fmt.Printf("+%8d +%8d +%8d .. add %s\n", max(sizeD-minD, 0), max(sizeC-minC, 0), max(sizeBoth-minBoth, 0), strings.TrimPrefix(t, "ts_omit_"))
	}

}

func allExcept(all []string, omit string) []string {
	return slices.DeleteFunc(slices.Clone(all), func(s string) bool { return s == omit })
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

	cmd := exec.Command("go", "build", "-tags", strings.Join(tags, ","), "-o", "tmpbin", "./cmd/"+bin)
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
