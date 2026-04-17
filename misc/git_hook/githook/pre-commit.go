// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package githook

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"

	"github.com/fatih/color"
	"github.com/sourcegraph/go-diff/diff"
)

var preCommitForbiddenPatterns = [][]byte{
	// Concatenation avoids tripping the check on this file.
	[]byte("NOCOM" + "MIT"),
	[]byte("DO NOT " + "SUBMIT"),
}

// CheckForbiddenMarkers scans the staged diff for forbidden markers
// and returns an error if any are found.
//
// Intended as a pre-commit hook.
// https://git-scm.com/docs/githooks#_pre_commit
func CheckForbiddenMarkers() error {
	diffOut, err := exec.Command("git", "diff", "--cached").Output()
	if err != nil {
		return fmt.Errorf("could not get git diff: %w", err)
	}

	diffs, err := diff.ParseMultiFileDiff(diffOut)
	if err != nil {
		return fmt.Errorf("could not parse diff: %w", err)
	}

	foundForbidden := false
	for _, d := range diffs {
		for _, hunk := range d.Hunks {
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
						fmt.Printf("%s:%d: %s\n", d.NewName[2:], int(hunk.NewStartLine)+i, line[1:])
						foundForbidden = true
					}
				}
			}
		}
	}
	if foundForbidden {
		return errors.New("found forbidden string")
	}
	return nil
}
