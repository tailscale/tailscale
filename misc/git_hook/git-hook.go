// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The git-hook command is Tailscale's git hooks. It's built by
// misc/install-git-hooks.go and installed into .git/hooks
// as .git/hooks/ts-git-hook, with shell wrappers.
//
// # Adding your own hooks
//
// To add your own hook for one that we have already hooked, create a file named
// <hook-name>.local in .git/hooks. For example, to add your own pre-commit hook,
// create .git/hooks/pre-commit.local and make it executable. It will be run after
// the ts-git-hook, if ts-git-hook executes successfully.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/sourcegraph/go-diff/diff"
	"golang.org/x/mod/modfile"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		return
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "pre-commit":
		err = preCommit(args)
	case "commit-msg":
		err = commitMsg(args)
	case "pre-push":
		err = prePush(args)
	case "post-checkout":
		err = postCheckout(args)
	}
	if err != nil {
		p := log.Fatalf
		if nfe, ok := err.(nonFatalErr); ok {
			p = log.Printf
			err = nfe
		}
		p("git-hook: %v: %v", cmd, err)
	}

	if err == nil || errors.Is(err, nonFatalErr{}) {
		err := runLocalHook(cmd, args)
		if err != nil {
			log.Fatalf("git-hook: %v", err)
		}
	}
}

func runLocalHook(hookName string, args []string) error {
	cmdPath, err := os.Executable()
	if err != nil {
		return err
	}
	hookDir := filepath.Dir(cmdPath)
	localHookPath := filepath.Join(hookDir, hookName+".local")
	if _, err := os.Stat(localHookPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("checking for local hook: %w", err)
	}

	cmd := exec.Command(localHookPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running local hook %q: %w", localHookPath, err)
	}
	return nil
}

// pre-commit: "It takes no parameters, and is invoked before
// obtaining the proposed commit log message and making a
// commit. Exiting with a non-zero status from this script causes the
// git commit command to abort before creating a commit."
//
// https://git-scm.com/docs/githooks#_pre_commit
func preCommit(_ []string) error {
	diffOut, err := exec.Command("git", "diff", "--cached").Output()
	if err != nil {
		return fmt.Errorf("Could not get git diff: %w", err)
	}

	diffs, err := diff.ParseMultiFileDiff(diffOut)
	if err != nil {
		return fmt.Errorf("Could not parse diff: %w", err)
	}

	foundForbidden := false
	for _, diff := range diffs {
		for _, hunk := range diff.Hunks {
			lines := bytes.Split(hunk.Body, []byte{'\n'})
			for i, line := range lines {
				if len(line) == 0 || line[0] != '+' {
					continue
				}
				for _, forbidden := range preCommitForbiddenPatterns {
					if bytes.Contains(line, forbidden) {
						if !foundForbidden {
							color.New(color.Bold, color.FgRed, color.Underline).Printf("%s found:\n", forbidden)
						}
						// Output file name (dropping the b/ prefix) and line
						// number so that it can be linkified by terminals.
						fmt.Printf("%s:%d: %s\n", diff.NewName[2:], int(hunk.NewStartLine)+i, line[1:])
						foundForbidden = true
					}
				}
			}
		}
	}
	if foundForbidden {
		return fmt.Errorf("Found forbidden string")
	}

	return nil
}

var preCommitForbiddenPatterns = [][]byte{
	// Use concatenation to avoid including the forbidden literals (and thus
	// triggering the pre-commit hook).
	[]byte("NOCOM" + "MIT"),
	[]byte("DO NOT " + "SUBMIT"),
}

// https://git-scm.com/docs/githooks#_commit_msg
func commitMsg(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: commit-msg message.txt")
	}
	file := args[0]
	msg, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	msg = filterCutLine(msg)

	var id [20]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return fmt.Errorf("could not generate Change-Id: %v", err)
	}
	cmdLines := [][]string{
		// Trim whitespace and comments.
		{"git", "stripspace", "--strip-comments"},
		// Add Change-Id trailer.
		{"git", "interpret-trailers", "--no-divider", "--where=start", "--if-exists", "doNothing", "--trailer", fmt.Sprintf("Change-Id: I%x", id)},
	}
	for _, cmdLine := range cmdLines {
		if len(msg) == 0 {
			// Don't allow commands to go from empty commit message to non-empty (issue 2205).
			break
		}
		cmd := exec.Command(cmdLine[0], cmdLine[1:]...)
		cmd.Stdin = bytes.NewReader(msg)
		msg, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to run '%v': %w\n%s", cmd, err, msg)
		}
	}

	return os.WriteFile(file, msg, 0666)
}

// pre-push: "this hook is called by git-push and can be used to
// prevent a push from taking place. The hook is called with two
// parameters which provide the name and location of the destination
// remote, if a named remote is not being used both values will be the
// same.
//
// Information about what is to be pushed is provided on the hook's
// standard input with lines of the form:
//
//	<local ref> SP <local sha1> SP <remote ref> SP <remote sha1> LF
//
// More: https://git-scm.com/docs/githooks#_pre_push
func prePush(args []string) error {
	remoteName, remoteLoc := args[0], args[1]
	_ = remoteName

	pushes, err := readPushes()
	if err != nil {
		return fmt.Errorf("reading pushes: %w", err)
	}

	switch remoteLoc {
	case "git@github.com:tailscale/tailscale", "git@github.com:tailscale/tailscale.git",
		"https://github.com/tailscale/tailscale", "https://github.com/tailscale/tailscale.git":
		for _, p := range pushes {
			if p.isDoNotMergeRef() {
				continue
			}
			if err := checkCommit(p.localSHA); err != nil {
				return fmt.Errorf("not allowing push of %v to %v: %v", p.localSHA, p.remoteRef, err)
			}
		}
	}

	return nil
}

//go:embed HOOK_VERSION
var compiledHookVersion string

// post-checkout: "This hook is invoked when a git-checkout[1] or
// git-switch[1] is run after having updated the worktree. The hook is
// given three parameters: the ref of the previous HEAD, the ref of
// the new HEAD (which may or may not have changed), and a flag
// indicating whether the checkout was a branch checkout (changing
// branches, flag=1) or a file checkout (retrieving a file from the
// index, flag=0).
//
// More: https://git-scm.com/docs/githooks#_post_checkout
func postCheckout(_ []string) error {
	compiled, err := strconv.Atoi(strings.TrimSpace(compiledHookVersion))
	if err != nil {
		return fmt.Errorf("couldn't parse compiled-in hook version: %v", err)
	}

	bs, err := os.ReadFile("misc/git_hook/HOOK_VERSION")
	if errors.Is(err, os.ErrNotExist) {
		// Probably checked out a commit that predates the existence
		// of HOOK_VERSION, don't complain.
		return nil
	}
	actual, err := strconv.Atoi(strings.TrimSpace(string(bs)))
	if err != nil {
		return fmt.Errorf("couldn't parse misc/git_hook/HOOK_VERSION: %v", err)
	}

	if actual > compiled {
		return nonFatalErr{fmt.Errorf("a newer git hook script is available, please run `./tool/go run ./misc/install-git-hooks.go`")}
	}
	return nil
}

func checkCommit(sha string) error {
	// Allow people to delete remote refs.
	if sha == zeroRef {
		return nil
	}
	// Check that go.mod doesn't contain replacements to directories.
	goMod, err := exec.Command("git", "show", sha+":go.mod").Output()
	if err != nil {
		return err
	}
	mf, err := modfile.Parse("go.mod", goMod, nil)
	if err != nil {
		return fmt.Errorf("failed to parse its go.mod: %v", err)
	}
	for _, r := range mf.Replace {
		if modfile.IsDirectoryPath(r.New.Path) {
			return fmt.Errorf("go.mod contains replace from %v => %v", r.Old.Path, r.New.Path)
		}
	}

	return nil
}

const zeroRef = "0000000000000000000000000000000000000000"

type push struct {
	localRef  string // "refs/heads/bradfitz/githooks"
	localSHA  string // what's being pushed
	remoteRef string // "refs/heads/bradfitz/githooks", "refs/heads/main"
	remoteSHA string // old value being replaced, or zeroRef if it doesn't exist
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

// nonFatalErr is an error wrapper type to indicate that main() should
// not exit fatally.
type nonFatalErr struct {
	error
}

var gitCutLine = []byte("# ------------------------ >8 ------------------------")

// filterCutLine searches for a git cutline (see above) and filters it and any
// following lines from the given message.  This is typically produced in a
// commit message file by `git commit -v`.
func filterCutLine(msg []byte) []byte {
	if before, _, ok := bytes.Cut(msg, gitCutLine); ok {
		return before
	}
	return msg
}
