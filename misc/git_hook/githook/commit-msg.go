// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package githook

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// AddChangeID strips comments from the commit message at args[0] and
// prepends a random Change-Id trailer.
//
// Intended as a commit-msg hook.
// https://git-scm.com/docs/githooks#_commit_msg
func AddChangeID(args []string) error {
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
		{"git", "stripspace", "--strip-comments"},
		{"git", "interpret-trailers", "--no-divider", "--where=start", "--if-exists", "doNothing", "--trailer", fmt.Sprintf("Change-Id: I%x", id)},
	}
	for _, cmdLine := range cmdLines {
		if len(msg) == 0 {
			// Don't let commands turn an empty message into a non-empty one (issue 2205).
			break
		}
		cmd := exec.Command(cmdLine[0], cmdLine[1:]...)
		cmd.Stdin = bytes.NewReader(msg)
		msg, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to run %v: %w\n%s", cmd, err, msg)
		}
	}
	return os.WriteFile(file, msg, 0666)
}

var gitCutLine = []byte("# ------------------------ >8 ------------------------")

// filterCutLine strips a `git commit -v`-style cutline and everything
// after it from msg.
func filterCutLine(msg []byte) []byte {
	if before, _, ok := bytes.Cut(msg, gitCutLine); ok {
		return before
	}
	return msg
}
