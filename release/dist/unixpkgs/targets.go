// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package unixpkgs

import (
	"fmt"
	"sort"
	"strings"

	"tailscale.com/release/dist"

	_ "github.com/goreleaser/nfpm/deb"
	_ "github.com/goreleaser/nfpm/rpm"
)

func Targets() []dist.Target {
	var ret []dist.Target
	for goosgoarch := range tarballs {
		goos, goarch := splitGoosGoarch(goosgoarch)
		ret = append(ret, &tgzTarget{
			goenv: map[string]string{
				"GOOS":   goos,
				"GOARCH": goarch,
			},
		})
	}
	for goosgoarch := range debs {
		goos, goarch := splitGoosGoarch(goosgoarch)
		ret = append(ret, &debTarget{
			goenv: map[string]string{
				"GOOS":   goos,
				"GOARCH": goarch,
			},
		})
	}
	for goosgoarch := range rpms {
		goos, goarch := splitGoosGoarch(goosgoarch)
		ret = append(ret, &rpmTarget{
			goenv: map[string]string{
				"GOOS":   goos,
				"GOARCH": goarch,
			},
		})
	}

	// Special case: AMD Geode is 386 with softfloat. Tarballs only since it's
	// an ancient architecture.
	ret = append(ret, &tgzTarget{
		filenameArch: "geode",
		goenv: map[string]string{
			"GOOS":   "linux",
			"GOARCH": "386",
			"GO386":  "softfloat",
		},
	})

	sort.Slice(ret, func(i, j int) bool {
		return ret[i].String() < ret[j].String()
	})

	return ret
}

var (
	tarballs = map[string]bool{
		"linux/386":      true,
		"linux/amd64":    true,
		"linux/arm":      true,
		"linux/arm64":    true,
		"linux/mips64":   true,
		"linux/mips64le": true,
		"linux/mips":     true,
		"linux/mipsle":   true,
		"linux/riscv64":  true,
		// TODO: more tarballs we could distribute, but don't currently. Leaving
		// out for initial parity with redo.
		// "darwin/amd64":  true,
		// "darwin/arm64":  true,
		// "freebsd/amd64": true,
		// "openbsd/amd64": true,
	}

	debs = map[string]bool{
		"linux/386":     true,
		"linux/amd64":   true,
		"linux/arm":     true,
		"linux/arm64":   true,
		"linux/riscv64": true,
		// TODO: maybe mipses, we accidentally started building them at some
		// point even though they probably don't work right.
		// "linux/mips":     true,
		// "linux/mipsle":   true,
		// "linux/mips64":   true,
		// "linux/mips64le": true,
	}

	rpms = map[string]bool{
		"linux/386":     true,
		"linux/amd64":   true,
		"linux/arm":     true,
		"linux/arm64":   true,
		"linux/riscv64": true,
		// TODO: maybe mipses, we accidentally started building them at some
		// point even though they probably don't work right.
		// "linux/mips":     true,
		// "linux/mipsle":   true,
		// "linux/mips64":   true,
		// "linux/mips64le": true,
	}
)

func splitGoosGoarch(s string) (string, string) {
	goos, goarch, ok := strings.Cut(s, "/")
	if !ok {
		panic(fmt.Sprintf("invalid target %q", s))
	}
	return goos, goarch
}
