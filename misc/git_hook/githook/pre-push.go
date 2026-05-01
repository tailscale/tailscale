// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package githook

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/mod/modfile"
)

// CheckGoModReplaces reads pushes from stdin and, for pushes to a
// remote URL in watchedRemotes, rejects any commit whose go.mod has a
// directory-path replace that is not in allowedReplaceDirs. args is
// the pre-push hook's argv (remoteName, remoteLoc).
//
// Intended as a pre-push hook.
// https://git-scm.com/docs/githooks#_pre_push
func CheckGoModReplaces(args []string, watchedRemotes, allowedReplaceDirs []string) error {
	if len(args) < 2 {
		return fmt.Errorf("pre-push: expected 2 args, got %d", len(args))
	}
	remoteLoc := args[1]

	watched := false
	for _, r := range watchedRemotes {
		if r == remoteLoc {
			watched = true
			break
		}
	}
	if !watched {
		return nil
	}

	pushes, err := readPushes()
	if err != nil {
		return fmt.Errorf("reading pushes: %w", err)
	}
	for _, p := range pushes {
		if p.isDoNotMergeRef() {
			continue
		}
		if err := checkCommit(p.localSHA, allowedReplaceDirs); err != nil {
			return fmt.Errorf("not allowing push of %v to %v: %v", p.localSHA, p.remoteRef, err)
		}
	}
	return nil
}

func checkCommit(sha string, allowedReplaceDirs []string) error {
	if sha == zeroRef {
		// Allow ref deletions.
		return nil
	}
	goMod, err := exec.Command("git", "show", sha+":go.mod").Output()
	if err != nil {
		return err
	}
	mf, err := modfile.Parse("go.mod", goMod, nil)
	if err != nil {
		return fmt.Errorf("failed to parse its go.mod: %v", err)
	}
	for _, r := range mf.Replace {
		if !modfile.IsDirectoryPath(r.New.Path) {
			continue
		}
		allowed := false
		for _, a := range allowedReplaceDirs {
			if a == r.New.Path {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("go.mod contains replace from %v => %v", r.Old.Path, r.New.Path)
		}
	}
	return nil
}

const zeroRef = "0000000000000000000000000000000000000000"

type push struct {
	localRef  string
	localSHA  string
	remoteRef string
	remoteSHA string
}

func (p *push) isDoNotMergeRef() bool {
	return strings.HasSuffix(p.remoteRef, "/DO-NOT-MERGE")
}

func readPushes() (pushes []push, err error) {
	bs := bufio.NewScanner(os.Stdin)
	for bs.Scan() {
		f := strings.Fields(bs.Text())
		if len(f) != 4 {
			return nil, fmt.Errorf("unexpected push line %q", bs.Text())
		}
		pushes = append(pushes, push{f[0], f[1], f[2], f[3]})
	}
	if err := bs.Err(); err != nil {
		return nil, err
	}
	return pushes, nil
}
