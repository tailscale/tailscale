// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The mkmanifest command is a simple helper utility to create a '.syso' file
// that contains a Windows manifest file.
package main

import (
	"log"
	"os"

	"github.com/tc-hib/winres"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("usage: %s arch manifest.xml output.syso", os.Args[0])
	}

	arch := winres.Arch(os.Args[1])
	switch arch {
	case winres.ArchAMD64, winres.ArchARM64, winres.ArchI386, winres.ArchARM:
	default:
		log.Fatalf("unsupported arch: %s", arch)
	}

	manifest, err := os.ReadFile(os.Args[2])
	if err != nil {
		log.Fatalf("error reading manifest file %q: %v", os.Args[2], err)
	}

	out := os.Args[3]

	// Start by creating an empty resource set
	rs := winres.ResourceSet{}

	// Add resources
	rs.Set(winres.RT_MANIFEST, winres.ID(1), 0, manifest)

	// Compile to a COFF object file
	f, err := os.Create(out)
	if err != nil {
		log.Fatalf("error creating output file %q: %v", out, err)
	}
	if err := rs.WriteObject(f, arch); err != nil {
		log.Fatalf("error writing object: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("error writing output file %q: %v", out, err)
	}
}
