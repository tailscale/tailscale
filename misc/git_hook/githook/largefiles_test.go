// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package githook

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// testMaxSize is the large-blob threshold used by the tests, chosen
// small so test fixtures stay tiny.
const testMaxSize = 100

func git(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Env = append(cmd.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeAndCommit(t *testing.T, name, contents, msg string) string {
	t.Helper()
	if err := os.WriteFile(name, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", "-A")
	git(t, "commit", "-q", "-m", msg)
	return git(t, "rev-parse", "HEAD")
}

// setupRepo creates a scratch repo laying out the rebase scenario:
//
//	c1 (initial) -- c2 (adds big.bin on main, origin/main)
//	 \
//	  f1 (old branch tip, as previously pushed)
//
// It returns the three commit hashes.
func setupRepo(t *testing.T) (c1, c2, f1 string) {
	t.Chdir(t.TempDir())
	git(t, "init", "-q", "-b", "main")
	c1 = writeAndCommit(t, "small.txt", "hello", "initial")

	git(t, "checkout", "-q", "-b", "feature")
	f1 = writeAndCommit(t, "feature.txt", "feature work", "feature commit")

	git(t, "checkout", "-q", "main")
	c2 = writeAndCommit(t, "big.bin", strings.Repeat("x", 2*testMaxSize), "add big file on main")
	git(t, "update-ref", "refs/remotes/origin/main", c2)
	return c1, c2, f1
}

// TestCheckLargeBlobsRebasePastLargeFile verifies that pushing a
// branch rebased past an unrelated large-file change on main is not
// flagged: the large blob is already on the remote via main.
func TestCheckLargeBlobsRebasePastLargeFile(t *testing.T) {
	t.Setenv(skipLargeFileCheckEnv, "")
	_, _, f1 := setupRepo(t)

	git(t, "checkout", "-q", "feature")
	git(t, "rebase", "-q", "main")
	f2 := git(t, "rev-parse", "HEAD")

	err := checkLargeBlobs("origin", push{
		localRef:  "refs/heads/feature",
		localSHA:  f2,
		remoteRef: "refs/heads/feature",
		remoteSHA: f1,
	}, testMaxSize)
	if err != nil {
		t.Errorf("checkLargeBlobs = %v; want nil (big.bin is already on origin/main)", err)
	}
}

// TestCheckLargeBlobsNewLargeFile verifies that a genuinely new large
// blob on the branch is flagged, both for updates to an existing
// remote ref and for new refs.
func TestCheckLargeBlobsNewLargeFile(t *testing.T) {
	t.Setenv(skipLargeFileCheckEnv, "")
	_, _, f1 := setupRepo(t)

	git(t, "checkout", "-q", "feature")
	git(t, "rebase", "-q", "main")
	f2 := writeAndCommit(t, "mine.bin", strings.Repeat("y", 2*testMaxSize), "add my own big file")

	for _, remoteSHA := range []string{f1, zeroRef} {
		err := checkLargeBlobs("origin", push{
			localRef:  "refs/heads/feature",
			localSHA:  f2,
			remoteRef: "refs/heads/feature",
			remoteSHA: remoteSHA,
		}, testMaxSize)
		if err == nil {
			t.Errorf("remoteSHA=%s: checkLargeBlobs = nil; want error flagging mine.bin", remoteSHA)
		} else if !strings.Contains(err.Error(), "mine.bin") {
			t.Errorf("remoteSHA=%s: error %v does not mention mine.bin", remoteSHA, err)
		} else if strings.Contains(err.Error(), "big.bin") {
			t.Errorf("remoteSHA=%s: error %v should not mention big.bin", remoteSHA, err)
		}
	}
}
