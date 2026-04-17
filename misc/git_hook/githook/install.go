// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package githook

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Install writes the launcher to .git/hooks/ts-git-hook and runs it
// once with "version", bootstrapping the binary build and per-hook
// wrappers. Called from each repo's misc/install-git-hooks.go.
func Install() error {
	hookDir, err := findHookDir()
	if err != nil {
		return err
	}
	target := filepath.Join(hookDir, "ts-git-hook")
	if err := writeLauncher(target); err != nil {
		return err
	}

	// The launcher execs the binary with our arg at the end; we pass
	// "version" only to trigger the rebuild-if-stale path, and discard
	// its stdout so the version string doesn't leak to the caller.
	cmd := exec.Command(target, "version")
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("initial hook setup failed: %v", err)
	}
	return nil
}

// WriteHooks writes the launcher to .git/hooks/ts-git-hook and a wrapper
// for each name in hooks to .git/hooks/<name>. Stale wrappers from
// prior versions (ours, but no longer in hooks) are removed. If a path
// we are about to write exists and is not one of our wrappers,
// WriteHooks aborts with an error rather than clobber the user's hook.
// Called by the binary's "install" handler (after a rebuild) and by
// Install (initial setup).
func WriteHooks(hooks []string) error {
	hookDir, err := findHookDir()
	if err != nil {
		return err
	}
	if err := writeLauncher(filepath.Join(hookDir, "ts-git-hook")); err != nil {
		return err
	}
	want := make(map[string]bool, len(hooks))
	for _, h := range hooks {
		want[h] = true
	}
	entries, err := os.ReadDir(hookDir)
	if err != nil {
		return fmt.Errorf("reading hooks dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(hookDir, name)
		mine, err := isOurWrapper(path)
		if err != nil {
			return fmt.Errorf("inspecting %s: %v", path, err)
		}
		switch {
		case want[name] && !mine:
			return fmt.Errorf("%s exists and is not a ts-git-hook wrapper; "+
				"move your hook to %s.local (it will be chained after the wrapper) or delete it, then re-run: ./tool/go run ./misc/install-git-hooks.go",
				path, name)
		case !want[name] && mine:
			// Stale wrapper from a prior version (e.g. a hook we used
			// to install but no longer do).
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("removing stale wrapper %s: %v", name, err)
			}
		}
	}
	for _, h := range hooks {
		content := fmt.Sprintf(wrapperScript, h)
		if err := os.WriteFile(filepath.Join(hookDir, h), []byte(content), 0755); err != nil {
			return fmt.Errorf("writing wrapper for %s: %v", h, err)
		}
	}
	return nil
}

// isOurWrapper reports whether path is a hook wrapper written by us
// (in any historical format). Files we will never own (the launcher
// itself, user-chained .local hooks, git's .sample examples) return
// false unconditionally and are not read. An I/O error other than
// "not found" is returned to the caller; a missing file is not an
// error.
func isOurWrapper(path string) (bool, error) {
	name := filepath.Base(path)
	if name == "ts-git-hook" ||
		strings.HasSuffix(name, ".local") ||
		strings.HasSuffix(name, ".sample") {
		return false, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return wrapperRE.Match(b), nil
}

// writeLauncher writes the embedded launcher to target via atomic rename,
// so a currently-running launcher keeps reading its old inode.
func writeLauncher(target string) error {
	dir, name := filepath.Split(target)
	f, err := os.CreateTemp(dir, name+".*")
	if err != nil {
		return fmt.Errorf("creating temp launcher: %v", err)
	}
	tmp := f.Name()
	if _, err := f.Write(Launcher); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("writing temp launcher: %v", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("installing launcher: %v", err)
	}
	return nil
}

func findHookDir() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--git-path", "hooks").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("finding hooks dir: %v, %s", err, out)
	}
	hookDir, err := filepath.Abs(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(hookDir)
	if err != nil {
		return "", fmt.Errorf("checking hooks dir: %v", err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory", hookDir)
	}
	return hookDir, nil
}

const wrapperScript = `#!/usr/bin/env bash
exec "$(dirname "${BASH_SOURCE[0]}")/ts-git-hook" %s "$@"
`

// wrapperRE matches every historical shape of wrapperScript: a tiny
// bash script that execs a sibling ts-git-hook with a single hook-name
// argument. The inner quoting of ${BASH_SOURCE[0]} changed between
// versions, hence the "?s.
var wrapperRE = regexp.MustCompile(
	`\A#!/usr/bin/env bash\nexec "\$\(dirname "?\$\{BASH_SOURCE\[0\]\}"?\)/ts-git-hook" [\w-]+ "\$@"\n?\z`,
)
