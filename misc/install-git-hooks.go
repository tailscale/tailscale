// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ignore

// The install-git-hooks program installs git hooks.
//
// It installs a Go binary at .git/hooks/ts-git-hook and a pre-hook
// forwarding shell wrapper to .git/hooks/NAME.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var hooks = []string{
	"pre-push",
	"pre-commit",
	"commit-msg",
	"post-checkout",
}

func fatalf(format string, a ...any) {
	log.SetFlags(0)
	log.Fatalf("install-git-hooks: "+format, a...)
}

func main() {
	out, err := exec.Command("git", "rev-parse", "--git-common-dir").CombinedOutput()
	if err != nil {
		fatalf("finding git dir: %v, %s", err, out)
	}
	gitDir := strings.TrimSpace(string(out))

	hookDir := filepath.Join(gitDir, "hooks")
	if fi, err := os.Stat(hookDir); err != nil {
		fatalf("checking hooks dir: %v", err)
	} else if !fi.IsDir() {
		fatalf("%s is not a directory", hookDir)
	}

	buildOut, err := exec.Command(goBin(), "build",
		"-o", filepath.Join(hookDir, "ts-git-hook"+exe()),
		"./misc/git_hook").CombinedOutput()
	if err != nil {
		log.Fatalf("go build git-hook: %v, %s", err, buildOut)
	}

	for _, hook := range hooks {
		content := fmt.Sprintf(hookScript, hook)
		file := filepath.Join(hookDir, hook)
		// Install the hook. If it already exists, overwrite it, in case there's
		// been changes.
		if err := os.WriteFile(file, []byte(content), 0755); err != nil {
			fatalf("%v", err)
		}
	}
}

const hookScript = `#!/usr/bin/env bash
exec "$(dirname ${BASH_SOURCE[0]})/ts-git-hook" %s "$@"
`

func goBin() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return "go"
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
