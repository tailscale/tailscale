// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ignore

// The install-git-hooks program installs git hooks by delegating to
// githook.Install. See that function's doc for what it does.
package main

import (
	"log"

	"tailscale.com/misc/git_hook/githook"
)

func main() {
	log.SetFlags(0)
	if err := githook.Install(); err != nil {
		log.Fatalf("install-git-hooks: %v", err)
	}
}
