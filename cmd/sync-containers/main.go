// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// The sync-containers command synchronizes container image tags from one
// registry to another.
//
// It is intended as a workaround for ghcr.io's lack of good push credentials:
// you can either authorize "classic" Personal Access Tokens in your org (which
// are a common vector of very bad compromise), or you can get a short-lived
// credential in a Github action.
//
// Since we publish to both Docker Hub and ghcr.io, we use this program in a
// Github action to effectively rsync from docker hub into ghcr.io, so that we
// can continue to forbid dangerous Personal Access Tokens in the tailscale org.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

var (
	src    = flag.String("src", "", "Source image")
	dst    = flag.String("dst", "", "Destination image")
	max    = flag.Int("max", 0, "Maximum number of tags to sync (0 for all tags)")
	dryRun = flag.Bool("dry-run", true, "Don't actually sync anything")
)

func main() {
	flag.Parse()

	if *src == "" {
		log.Fatalf("--src is required")
	}
	if *dst == "" {
		log.Fatalf("--dst is required")
	}

	keychain := authn.NewMultiKeychain(authn.DefaultKeychain, github.Keychain)
	opts := []remote.Option{
		remote.WithAuthFromKeychain(keychain),
		remote.WithContext(context.Background()),
	}

	stags, err := listTags(*src, opts...)
	if err != nil {
		log.Fatalf("listing source tags: %v", err)
	}
	dtags, err := listTags(*dst, opts...)
	if err != nil {
		log.Fatalf("listing destination tags: %v", err)
	}

	add, remove := diffTags(stags, dtags)
	if ln := len(add); ln > 0 {
		log.Printf("%d tags to push: %s", len(add), strings.Join(add, ", "))
		if *max > 0 && ln > *max {
			log.Printf("Limiting sync to %d tags", *max)
			add = add[:*max]
		}
	}
	for _, tag := range add {
		if !*dryRun {
			log.Printf("Syncing tag %q", tag)
			if err := copyTag(*src, *dst, tag, opts...); err != nil {
				log.Printf("Syncing tag %q: progress error: %v", tag, err)
			}
		} else {
			log.Printf("Dry run: would sync tag %q", tag)
		}
	}

	if len(remove) > 0 {
		log.Printf("%d tags to remove: %s\n", len(remove), strings.Join(remove, ", "))
		log.Printf("Not removing any tags for safety.\n")
	}

	var wellKnown = [...]string{"latest", "stable"}
	for _, tag := range wellKnown {
		if needsUpdate(*src, *dst, tag) {
			if err := copyTag(*src, *dst, tag, opts...); err != nil {
				log.Printf("Updating tag %q: progress error: %v", tag, err)
			}
		}
	}
}

func copyTag(srcStr, dstStr, tag string, opts ...remote.Option) error {
	src, err := name.ParseReference(fmt.Sprintf("%s:%s", srcStr, tag))
	if err != nil {
		return err
	}
	dst, err := name.ParseReference(fmt.Sprintf("%s:%s", dstStr, tag))
	if err != nil {
		return err
	}

	desc, err := remote.Get(src)
	if err != nil {
		return err
	}

	ch := make(chan v1.Update, 10)
	opts = append(opts, remote.WithProgress(ch))
	progressDone := make(chan struct{})

	go func() {
		defer close(progressDone)
		for p := range ch {
			fmt.Printf("Syncing tag %q: %d%% (%d/%d)\n", tag, int(float64(p.Complete)/float64(p.Total)*100), p.Complete, p.Total)
			if p.Error != nil {
				fmt.Printf("error: %v\n", p.Error)
			}
		}
	}()

	switch desc.MediaType {
	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		img, err := desc.Image()
		if err != nil {
			return err
		}
		if err := remote.Write(dst, img, opts...); err != nil {
			return err
		}
	case types.OCIImageIndex, types.DockerManifestList:
		idx, err := desc.ImageIndex()
		if err != nil {
			return err
		}
		if err := remote.WriteIndex(dst, idx, opts...); err != nil {
			return err
		}
	}

	<-progressDone
	return nil
}

func listTags(repoStr string, opts ...remote.Option) ([]string, error) {
	repo, err := name.NewRepository(repoStr)
	if err != nil {
		return nil, err
	}

	tags, err := remote.List(repo, opts...)
	if err != nil {
		return nil, err
	}

	sort.Strings(tags)
	return tags, nil
}

func diffTags(src, dst []string) (add, remove []string) {
	srcd := make(map[string]bool)
	for _, tag := range src {
		srcd[tag] = true
	}
	dstd := make(map[string]bool)
	for _, tag := range dst {
		dstd[tag] = true
	}

	for _, tag := range src {
		if !dstd[tag] {
			add = append(add, tag)
		}
	}
	for _, tag := range dst {
		if !srcd[tag] {
			remove = append(remove, tag)
		}
	}
	sort.Strings(add)
	sort.Strings(remove)
	return add, remove
}

func needsUpdate(srcStr, dstStr, tag string) bool {
	src, err := name.ParseReference(fmt.Sprintf("%s:%s", srcStr, tag))
	if err != nil {
		return false
	}
	dst, err := name.ParseReference(fmt.Sprintf("%s:%s", dstStr, tag))
	if err != nil {
		return false
	}

	srcDesc, err := remote.Get(src)
	if err != nil {
		return false
	}

	dstDesc, err := remote.Get(dst)
	if err != nil {
		return true
	}

	return srcDesc.Digest != dstDesc.Digest
}
