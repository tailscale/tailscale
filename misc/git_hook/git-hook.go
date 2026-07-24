// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The git-hook command is Tailscale's git hook binary, built and
// installed under .git/hooks/ts-git-hook-bin by the launcher at
// .git/hooks/ts-git-hook. misc/add-git-hooks.go writes the initial
// launcher; subsequent HOOK_VERSION bumps trigger self-rebuilds.
//
// # Adding your own hooks
//
// To add your own hook alongside one we already hook, create an executable
// file .git/hooks/<hook-name>.local (e.g. pre-commit.local). It runs after
// the built-in hook succeeds.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"tailscale.com/misc/git_hook/githook"
)

// maxPushBlobSize is the largest new or changed blob allowed in a
// push. It matches the 1.5 MB limit enforced by the check-file-size CI
// workflow. Set TS_SKIP_LARGE_FILE_CHECK=1 to override.
const maxPushBlobSize = 1_500_000

var pushRemotes = []string{
	"git@github.com:tailscale/tailscale",
	"git@github.com:tailscale/tailscale.git",
	"https://github.com/tailscale/tailscale",
	"https://github.com/tailscale/tailscale.git",
}

// hooks are the hook names this binary handles. Used by install to
// write per-hook wrappers; must stay in sync with the dispatcher below.
var hooks = []string{"pre-commit", "commit-msg", "pre-push"}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		return
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "version":
		fmt.Print(strings.TrimSpace(githook.HookVersion) + ":0")
	case "install":
		err = githook.WriteHooks(hooks)
	case "pre-commit":
		err = githook.CheckForbiddenMarkers()
	case "commit-msg":
		err = githook.AddChangeID(args)
	case "pre-push":
		err = githook.CheckPrePush(args, githook.PrePushConfig{
			WatchedRemotes: pushRemotes,
			MaxBlobSize:    maxPushBlobSize,
		})
	}
	if err != nil {
		log.Fatalf("git-hook: %v: %v", cmd, err)
	}
	if err := githook.RunLocalHook(cmd, args); err != nil {
		log.Fatalf("git-hook: %v", err)
	}
}
