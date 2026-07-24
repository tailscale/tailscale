// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package githook

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// skipLargeFileCheckEnv is the environment variable that, when set to a
// non-empty value, permits pushing new or changed blobs larger than the
// configured maximum size. It matches the "skip-large-file-check" commit
// message tag honored by the corp check-file-size CI workflow.
const skipLargeFileCheckEnv = "TS_SKIP_LARGE_FILE_CHECK"

// checkLargeBlobs rejects the push p if it adds or changes any blob
// larger than maxSize bytes, comparing the tree being pushed against
// the remote's previous tree (or, for new refs, the merge base with the
// remote's default branch). The same tree diff logic runs in CI via the
// check-git-accidental-large-file GitHub Action; this catches mistakes
// before they permanently bloat the remote repo.
func checkLargeBlobs(remoteName string, p push, maxSize int64) error {
	if p.localSHA == zeroRef {
		// Allow ref deletions.
		return nil
	}
	if os.Getenv(skipLargeFileCheckEnv) != "" {
		return nil
	}
	afterTree, err := treeOf(p.localSHA)
	if err != nil {
		return fmt.Errorf("resolving tree of %v: %v", p.localSHA, err)
	}
	beforeTree := findBaseTree(remoteName, p)
	if beforeTree == "" {
		fmt.Fprintf(os.Stderr, "git-hook: pre-push: no base tree found for %s; skipping large file check\n", p.remoteRef)
		return nil
	}
	large := appendLargeAdditions(nil, beforeTree, afterTree, "", maxSize)
	if len(large) == 0 {
		return nil
	}
	var sb strings.Builder
	for _, f := range large {
		fmt.Fprintf(&sb, "\t%s: %d bytes (%0.1f MiB)\n", f.path, f.size, float64(f.size)/(1<<20))
	}
	return fmt.Errorf("push adds files larger than %d bytes:\n%sset %s=1 to push anyway", maxSize, sb.String(), skipLargeFileCheckEnv)
}

// findBaseTree returns the tree hash to diff the push against, or the
// empty string if no suitable base is available locally. For updates to
// an existing remote ref it uses the remote's old commit. For new refs
// it falls back to the merge base with the remote's default branch.
func findBaseTree(remoteName string, p push) string {
	if p.remoteSHA != zeroRef {
		if tree, err := treeOf(p.remoteSHA); err == nil {
			return tree
		}
	}
	for _, ref := range []string{
		"refs/remotes/" + remoteName + "/HEAD",
		"refs/remotes/" + remoteName + "/main",
		"refs/remotes/" + remoteName + "/master",
	} {
		out, err := exec.Command("git", "merge-base", p.localSHA, ref).Output()
		if err != nil {
			continue
		}
		if tree, err := treeOf(strings.TrimSpace(string(out))); err == nil {
			return tree
		}
	}
	return ""
}

// treeOf resolves a git ref or commit to its tree hash.
func treeOf(ref string) (string, error) {
	out, err := exec.Command("git", "rev-parse", "--verify", ref+"^{tree}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// treeEntry is a single entry from git ls-tree.
type treeEntry struct {
	mode string
	typ  string // "blob", "tree", or "commit"
	hash string
	size int64 // -1 for non-blob entries
	name string
}

// lsTree returns the entries of the given tree object.
func lsTree(treeHash string) ([]treeEntry, error) {
	out, err := exec.Command("git", "ls-tree", "-z", "--long", treeHash).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-tree %s: %v", treeHash, err)
	}
	var entries []treeEntry
	for record := range bytes.SplitSeq(out, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		// Format: "<mode> <type> <hash> <size>\t<name>"
		metaPart, name, ok := bytes.Cut(record, []byte{'\t'})
		if !ok {
			continue
		}
		meta := strings.Fields(string(metaPart))
		if len(meta) != 4 {
			continue
		}
		var size int64 = -1
		if meta[3] != "-" {
			size, _ = strconv.ParseInt(meta[3], 10, 64)
		}
		entries = append(entries, treeEntry{
			mode: meta[0],
			typ:  meta[1],
			hash: meta[2],
			size: size,
			name: string(name),
		})
	}
	return entries, nil
}

type largeFile struct {
	path string
	size int64
}

// appendLargeAdditions walks two trees and returns dst plus any new or
// changed blobs exceeding maxSize. If beforeHash is empty, all blobs in
// afterHash are considered new. Unchanged subtrees are skipped without
// recursing, so the walk only visits the changed parts of the tree.
func appendLargeAdditions(dst []largeFile, beforeHash, afterHash, prefix string, maxSize int64) []largeFile {
	afterEntries, err := lsTree(afterHash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-hook: pre-push: %v\n", err)
		return dst
	}

	var beforeByName map[string]treeEntry
	if beforeHash != "" {
		beforeEntries, err := lsTree(beforeHash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "git-hook: pre-push: %v\n", err)
		}
		beforeByName = make(map[string]treeEntry, len(beforeEntries))
		for _, e := range beforeEntries {
			beforeByName[e.name] = e
		}
	}

	for _, ae := range afterEntries {
		if ae.mode == "160000" {
			continue // skip submodules
		}

		be, inBefore := beforeByName[ae.name]

		switch ae.typ {
		case "tree":
			if inBefore && be.hash == ae.hash {
				continue // subtree unchanged
			}
			var beforeSub string
			if inBefore && be.typ == "tree" {
				beforeSub = be.hash
			}
			dst = appendLargeAdditions(dst, beforeSub, ae.hash, prefix+ae.name+"/", maxSize)
		case "blob":
			if inBefore && be.hash == ae.hash {
				continue // blob unchanged
			}
			if ae.size > maxSize {
				dst = append(dst, largeFile{path: prefix + ae.name, size: ae.size})
			}
		}
	}
	return dst
}
