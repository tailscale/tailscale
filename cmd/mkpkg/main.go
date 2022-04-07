// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// mkpkg builds the Tailscale rpm and deb packages.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/goreleaser/nfpm"
	_ "github.com/goreleaser/nfpm/deb"
	_ "github.com/goreleaser/nfpm/rpm"
)

// parseFiles parses a comma-separated list of colon-separated pairs
// into a map of filePathOnDisk -> filePathInPackage.
func parseFiles(s string) (map[string]string, error) {
	ret := map[string]string{}
	if len(s) == 0 {
		return ret, nil
	}
	for _, f := range strings.Split(s, ",") {
		fs := strings.Split(f, ":")
		if len(fs) != 2 {
			return nil, fmt.Errorf("unparseable file field %q", f)
		}
		ret[fs[0]] = fs[1]
	}
	return ret, nil
}

func parseEmptyDirs(s string) []string {
	// strings.Split("", ",") would return []string{""}, which is not suitable:
	// this would create an empty dir record with path "", breaking the package
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func main() {
	out := flag.String("out", "", "output file to write")
	name := flag.String("name", "tailscale", "package name")
	description := flag.String("description", "The easiest, most secure, cross platform way to use WireGuard + oauth2 + 2FA/SSO", "package description")
	goarch := flag.String("arch", "amd64", "GOARCH this package is for")
	pkgType := flag.String("type", "deb", "type of package to build (deb or rpm)")
	files := flag.String("files", "", "comma-separated list of files in src:dst form")
	configFiles := flag.String("configs", "", "like --files, but for files marked as user-editable config files")
	emptyDirs := flag.String("emptydirs", "", "comma-separated list of empty directories")
	version := flag.String("version", "0.0.0", "version of the package")
	postinst := flag.String("postinst", "", "debian postinst script path")
	prerm := flag.String("prerm", "", "debian prerm script path")
	postrm := flag.String("postrm", "", "debian postrm script path")
	replaces := flag.String("replaces", "", "package which this package replaces, if any")
	depends := flag.String("depends", "", "comma-separated list of packages this package depends on")
	flag.Parse()

	filesMap, err := parseFiles(*files)
	if err != nil {
		log.Fatalf("Parsing --files: %v", err)
	}
	configsMap, err := parseFiles(*configFiles)
	if err != nil {
		log.Fatalf("Parsing --configs: %v", err)
	}
	emptyDirList := parseEmptyDirs(*emptyDirs)
	info := nfpm.WithDefaults(&nfpm.Info{
		Name:        *name,
		Arch:        *goarch,
		Platform:    "linux",
		Version:     *version,
		Maintainer:  "Tailscale Inc <info@tailscale.com>",
		Description: *description,
		Homepage:    "https://www.tailscale.com",
		License:     "MIT",
		Overridables: nfpm.Overridables{
			EmptyFolders: emptyDirList,
			Files:        filesMap,
			ConfigFiles:  configsMap,
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
