// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// The build command builds and pushes the container images used by the
// k8s-operator e2e tests, skipping any that already exist in the registry.
// It exists so CI can publish images once for a commit and fan out into
// multiple test jobs that run against them (see --registry without --build
// in the e2e package docs), and so a failed run can be retried even though
// the registry rejects tag overwrites.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"tailscale.com/cmd/k8s-operator/e2e/internal/build"
)

var (
	fRegistry  = flag.String("registry", "", "registry to push images to (required)")
	fTag       = flag.String("tag", "", "tag for the built images; defaults to the short git hash of HEAD, which requires a clean working tree")
	fArch      = flag.String("arch", "", "target node architecture, e.g. amd64; defaults to building all platforms")
	fBaseImage = flag.String("base-image", "", "if set, use this image as the base for all built images, instead of the default base image in build_docker.sh")
)

func main() {
	flag.Parse()
	if *fRegistry == "" {
		log.Fatalf("--registry is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	dir, err := build.RepoRoot()
	if err != nil {
		log.Fatal(err)
	}

	tag := *fTag
	if tag == "" {
		var dirty bool
		tag, dirty, err = build.Tag(dir)
		if err != nil {
			log.Fatal(err)
		}
		if dirty {
			// A dirty tree gets a random tag suffix, so the test jobs that
			// derive the tag from the commit would never find these images.
			log.Fatalf("working tree is dirty; commit your changes or pass an explicit --tag")
		}
	}

	// Bake in pebble's static CA so images can fetch certs from a pebble
	// ACME server when the tests run with --devcontrol. Unconditional
	// because it's harmless when testing against real control, and keeps
	// the images independent of how the test jobs will use them.
	minica := filepath.Join(dir, "cmd", "k8s-operator", "e2e", "certs", "pebble.minica.crt")
	if _, err := os.Stat(minica); err != nil {
		log.Fatalf("pebble CA cert not found (not a tailscale.com checkout?): %v", err)
	}

	err = build.EnsurePushed(ctx, build.Opts{
		Dir:          dir,
		Registry:     *fRegistry,
		Tag:          tag,
		Arch:         *fArch,
		BaseImage:    *fBaseImage,
		ExtraCACerts: []string{minica},
		Logf:         log.Printf,
	})
	if err != nil {
		log.Fatal(err)
	}
}
