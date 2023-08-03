// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// mkpkg builds the Tailscale rpm and deb packages.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/goreleaser/nfpm/v2"
	_ "github.com/goreleaser/nfpm/v2/deb"
	"github.com/goreleaser/nfpm/v2/files"
	_ "github.com/goreleaser/nfpm/v2/rpm"
)

// parseFiles parses a comma-separated list of colon-separated pairs
// into files.Contents format.
func parseFiles(s string, typ string) (files.Contents, error) {
	if len(s) == 0 {
		return nil, nil
	}
	var contents files.Contents
	for _, f := range strings.Split(s, ",") {
		fs := strings.Split(f, ":")
		if len(fs) != 2 {
			return nil, fmt.Errorf("unparseable file field %q", f)
		}
		contents = append(contents, &files.Content{Type: files.TypeFile, Source: fs[0], Destination: fs[1]})
	}
	return contents, nil
}

func parseEmptyDirs(s string) files.Contents {
	// strings.Split("", ",") would return []string{""}, which is not suitable:
	// this would create an empty dir record with path "", breaking the package
	if s == "" {
		return nil
	}
	var contents files.Contents
	for _, d := range strings.Split(s, ",") {
		contents = append(contents, &files.Content{Type: files.TypeDir, Destination: d})
	}
	return contents
}

func main() {
	out := flag.String("out", "", "output file to write")
	name := flag.String("name", "tailscale", "package name")
	description := flag.String("description", "The easiest, most secure, cross platform way to use WireGuard + oauth2 + 2FA/SSO", "package description")
	goarch := flag.String("arch", "amd64", "GOARCH this package is for")
	pkgType := flag.String("type", "deb", "type of package to build (deb or rpm)")
	regularFiles := flag.String("files", "", "comma-separated list of files in src:dst form")
	configFiles := flag.String("configs", "", "like --files, but for files marked as user-editable config files")
	emptyDirs := flag.String("emptydirs", "", "comma-separated list of empty directories")
	version := flag.String("version", "0.0.0", "version of the package")
	postinst := flag.String("postinst", "", "debian postinst script path")
	prerm := flag.String("prerm", "", "debian prerm script path")
	postrm := flag.String("postrm", "", "debian postrm script path")
	replaces := flag.String("replaces", "", "package which this package replaces, if any")
	depends := flag.String("depends", "", "comma-separated list of packages this package depends on")
	recommends := flag.String("recommends", "", "comma-separated list of packages this package recommends")
	flag.Parse()

	filesList, err := parseFiles(*regularFiles, files.TypeFile)
	if err != nil {
		log.Fatalf("Parsing --files: %v", err)
	}
	configsList, err := parseFiles(*configFiles, files.TypeConfig)
	if err != nil {
		log.Fatalf("Parsing --configs: %v", err)
	}
	emptyDirList := parseEmptyDirs(*emptyDirs)
	contents := append(filesList, append(configsList, emptyDirList...)...)
	contents, err = files.PrepareForPackager(contents, 0, *pkgType, false)
	if err != nil {
		log.Fatalf("Building package contents: %v", err)
	}
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
			Contents: contents,
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
	if len(*recommends) != 0 {
		info.Overridables.Recommends = strings.Split(*recommends, ",")
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
