// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package githook

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
)

// PrePushConfig configures CheckPrePush.
type PrePushConfig struct {
	// WatchedRemotes are the remote URLs whose pushes are subject to
	// the go.mod replace check.
	WatchedRemotes []string

	// AllowedReplaceDirs are the directory-path go.mod replace targets
	// that are permitted in pushed commits.
	AllowedReplaceDirs []string

	// MaxBlobSize, if positive, is the largest new or changed blob in
	// bytes allowed in a push to any remote. Pushes adding larger
	// blobs are rejected unless the TS_SKIP_LARGE_FILE_CHECK
	// environment variable is set to a non-empty value.
	MaxBlobSize int64
}

// CheckPrePush reads pushes from stdin and validates them per cfg.
// args is the pre-push hook's argv (remoteName, remoteLoc).
//
// Intended as a pre-push hook.
// https://git-scm.com/docs/githooks#_pre_push
func CheckPrePush(args []string, cfg PrePushConfig) error {
	if len(args) < 2 {
		return fmt.Errorf("pre-push: expected 2 args, got %d", len(args))
	}
	remoteName, remoteLoc := args[0], args[1]

	pushes, err := readPushes()
	if err != nil {
		return fmt.Errorf("reading pushes: %w", err)
	}
	watched := slices.Contains(cfg.WatchedRemotes, remoteLoc)
	for _, p := range pushes {
		if watched && !p.isDoNotMergeRef() {
			if err := checkCommit(p.localSHA, cfg.AllowedReplaceDirs); err != nil {
				return fmt.Errorf("not allowing push of %v to %v: %v", p.localSHA, p.remoteRef, err)
			}
		}
		if cfg.MaxBlobSize > 0 {
			if err := checkLargeBlobs(remoteName, p, cfg.MaxBlobSize); err != nil {
				return fmt.Errorf("not allowing push of %v to %v: %v", p.localSHA, p.remoteRef, err)
			}
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
		allowed := slices.Contains(allowedReplaceDirs, r.New.Path)
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
