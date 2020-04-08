// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// mkpkg builds the Tailscale rpm and deb packages.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/goreleaser/nfpm"
	_ "github.com/goreleaser/nfpm/deb"
	_ "github.com/goreleaser/nfpm/rpm"
	"github.com/pborman/getopt"
)

// parseFiles parses a comma-separated list of colon-separated pairs
// into a map of filePathOnDisk -> filePathInPackage.
func parseFiles(s string) (map[string]string, error) {
	ret := map[string]string{}
	for _, f := range strings.Split(s, ",") {
		fs := strings.Split(f, ":")
		if len(fs) != 2 {
			return nil, fmt.Errorf("unparseable file field %q", f)
		}
		ret[fs[0]] = fs[1]
	}
	return ret, nil
}

func main() {
	out := getopt.StringLong("out", 'o', "", "output file to write")
	goarch := getopt.StringLong("arch", 'a', "amd64", "GOARCH this package is for")
	pkgType := getopt.StringLong("type", 't', "deb", "type of package to build (deb or rpm)")
	files := getopt.StringLong("files", 'F', "", "comma-separated list of files in src:dst form")
	configFiles := getopt.StringLong("configs", 'C', "", "like --files, but for files marked as user-editable config files")
	version := getopt.StringLong("version", 0, "0.0.0", "version of the package")
	postinst := getopt.StringLong("postinst", 0, "", "debian postinst script path")
	prerm := getopt.StringLong("prerm", 0, "", "debian prerm script path")
	postrm := getopt.StringLong("postrm", 0, "", "debian postrm script path")
	replaces := getopt.StringLong("replaces", 0, "", "package which this package replaces, if any")
	depends := getopt.StringLong("depends", 0, "", "comma-separated list of packages this package depends on")
	getopt.Parse()

	filesMap, err := parseFiles(*files)
	if err != nil {
		log.Fatalf("Parsing --files: %v", err)
	}
	configsMap, err := parseFiles(*configFiles)
	if err != nil {
		log.Fatalf("Parsing --configs: %v", err)
	}
	info := nfpm.WithDefaults(&nfpm.Info{
		Name:        "tailscale",
		Arch:        *goarch,
		Platform:    "linux",
		Version:     *version,
		Maintainer:  "Tailscale Inc <info@tailscale.com>",
		Description: "The easiest, most secure, cross platform way to use WireGuard + oauth2 + 2FA/SSO",
		Homepage:    "https://www.tailscale.com",
		License:     "MIT",
		Overridables: nfpm.Overridables{
			Files:       filesMap,
			ConfigFiles: configsMap,
			Scripts: nfpm.Scripts{
				PostInstall: *postinst,
				PreRemove:   *prerm,
				PostRemove:  *postrm,
			},
		},
	})

	if len(*depends) != 0 {
		info.Overridables.Depends = strings.Split(*depends, ",")
	}
	if *replaces != "" {
		info.Overridables.Replaces = []string{*replaces}
		info.Overridables.Conflicts = []string{*replaces}
	}

	switch *pkgType {
	case "deb":
		info.Section = "net"
		info.Priority = "extra"
	case "rpm":
		info.Overridables.RPM.Group = "Network"
	}

	pkg, err := nfpm.Get(*pkgType)
	if err != nil {
		log.Fatalf("Getting packager for %q: %v", *pkgType, err)
	}

	f, err := os.Create(*out)
	if err != nil {
		log.Fatalf("Creating output file %q: %v", *out, err)
	}
	defer f.Close()

	if err := pkg.Package(info, f); err != nil {
		log.Fatalf("Creating package %q: %v", *out, err)
	}
}
