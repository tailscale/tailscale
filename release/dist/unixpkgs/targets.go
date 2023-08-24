// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package unixpkgs

import (
	"fmt"
	"sort"
	"strings"

	"tailscale.com/release/dist"

	_ "github.com/goreleaser/nfpm/v2/deb"
	_ "github.com/goreleaser/nfpm/v2/rpm"
)

type Signers struct {
	Tarball dist.Signer
	RPM     dist.Signer
}

func Targets(signers Signers) []dist.Target {
	var ret []dist.Target
	for goosgoarch := range tarballs {
		goos, goarch := splitGoosGoarch(goosgoarch)
		ret = append(ret, &tgzTarget{
			goEnv: map[string]string{
				"GOOS":   goos,
				"GOARCH": goarch,
			},
			signer: signers.Tarball,
		})
	}
	for goosgoarch := range debs {
		goos, goarch := splitGoosGoarch(goosgoarch)
		ret = append(ret, &debTarget{
			goEnv: map[string]string{
				"GOOS":   goos,
				"GOARCH": goarch,
			},
		})
	}
	for goosgoarch := range rpms {
		goos, goarch := splitGoosGoarch(goosgoarch)
		ret = append(ret, &rpmTarget{
			goEnv: map[string]string{
				"GOOS":   goos,
				"GOARCH": goarch,
			},
			signer: signers.RPM,
		})
	}

	// Special case: AMD Geode is 386 with softfloat. Tarballs only since it's
	// an ancient architecture.
	ret = append(ret, &tgzTarget{
		filenameArch: "geode",
		goEnv: map[string]string{
			"GOOS":   "linux",
			"GOARCH": "386",
			"GO386":  "softfloat",
		},
		signer: signers.Tarball,
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
		"linux/386":      true,
		"linux/amd64":    true,
		"linux/arm":      true,
		"linux/arm64":    true,
		"linux/riscv64":  true,
		"linux/mipsle":   true,
		"linux/mips64le": true,
		"linux/mips":     true,
		// Debian does not support big endian mips64. Leave that out until we know
		// we need it.
		// "linux/mips64":   true,
	}

	rpms = map[string]bool{
		"linux/386":      true,
		"linux/amd64":    true,
		"linux/arm":      true,
		"linux/arm64":    true,
		"linux/riscv64":  true,
		"linux/mipsle":   true,
		"linux/mips64le": true,
		// Fedora only supports little endian mipses. Maybe some other distribution
		// supports big-endian? Leave them out for now.
		// "linux/mips":     true,
		// "linux/mips64":   true,
	}
)

func splitGoosGoarch(s string) (string, string) {
	goos, goarch, ok := strings.Cut(s, "/")
	if !ok {
		panic(fmt.Sprintf("invalid target %q", s))
	}
	return goos, goarch
}
