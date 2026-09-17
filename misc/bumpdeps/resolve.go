// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// resolver looks up versions on the module proxy.
type resolver struct {
	client *http.Client
	base   string    // proxy URL without a trailing slash
	cutoff time.Time // versions committed after this are too new; zero means no cooldown

	// lsRemote returns the commit hash at the head of branch in the git
	// repo at repoURL. It's a field so tests can fake it.
	lsRemote func(ctx context.Context, repoURL, branch string) (string, error)
}

// heldError says a newer version exists but is younger than the cooldown.
type heldError struct {
	version string
	t       time.Time
}

func (e *heldError) Error() string {
	return fmt.Sprintf("%s is only %.1f days old", e.version, time.Since(e.t).Hours()/24)
}

// versionInfo is the proxy's @latest and @v/<version>.info response.
type versionInfo struct {
	Version string
	Time    time.Time
}

// tooNew reports whether a version committed at t is younger than the
// cooldown.
func (r *resolver) tooNew(t time.Time) bool {
	return !r.cutoff.IsZero() && t.After(r.cutoff)
}

// lookupNewer asks the module proxy for the newest version of mod, or for
// the head of its branch if it's in specialBranches. It returns "" if there
// is nothing newer than the version already in go.mod or if the newer
// version isn't usable under mod's path, and a *heldError if the only
// newer versions are younger than the cooldown.
//
// mod.Version may be empty for a module that's not yet in go.mod, in
// which case anything the proxy offers is newer.
func (r *resolver) lookupNewer(ctx context.Context, mod module.Version) (string, error) {
	escaped, err := module.EscapePath(mod.Path)
	if err != nil {
		return "", err
	}
	base := r.base + "/" + escaped

	var info versionInfo
	if bi, ok := specialBranches[mod.Path]; ok {
		info, err = r.branchHead(ctx, base, bi)
		if err != nil {
			return "", err
		}
	} else {
		if err := fetchJSON(ctx, r.client, base+"/@latest", &info); err != nil {
			return "", err
		}
		if isNewer(info.Version, mod.Version) && r.tooNew(info.Time) {
			// Fall back to the newest release that has aged enough, if any.
			// Only tagged versions are listed, so branch heads (above)
			// have nothing to fall back to and get held instead.
			aged, err := r.newestAged(ctx, base, mod.Version)
			if err != nil {
				return "", err
			}
			if aged.Version == "" {
				return "", &heldError{info.Version, info.Time}
			}
			info = aged
		}
	}
	if !semver.IsValid(info.Version) {
		return "", fmt.Errorf("proxy returned invalid version %q", info.Version)
	}

	// Only ever move forward. The proxy's @latest is the newest tagged
	// release, which can be older than a pseudo-version already in go.mod.
	if !isNewer(info.Version, mod.Version) {
		return "", nil
	}
	if r.tooNew(info.Time) {
		return "", &heldError{info.Version, info.Time}
	}

	// Also never move backward in time. Forks sometimes carry stray tags
	// that sort above their real development branch (github.com/tailscale/
	// golang-x-crypto has a v0.91.0 from 2024, say), and the proxy happily
	// reports those as @latest.
	if mod.Version != "" {
		curTime, err := r.versionTime(ctx, base, mod.Version)
		if err != nil {
			return "", err
		}
		if !info.Time.After(curTime) {
			return "", fmt.Errorf("%s (%s) is older than current %s (%s); probably a stray tag, so add it to specialBranches or bump by hand",
				info.Version, info.Time.Format(time.DateOnly), mod.Version, curTime.Format(time.DateOnly))
		}
	}

	// Modules sometimes move (github.com/imdario/mergo became
	// dario.cat/mergo, say) and keep tagging releases under the new path.
	// The proxy still reports those as @latest for the old path, but go
	// get rejects them, so check the go.mod of the candidate version.
	escapedVer, err := module.EscapeVersion(info.Version)
	if err != nil {
		return "", err
	}
	gomod, err := fetch(ctx, r.client, base+"/@v/"+escapedVer+".mod")
	if err != nil {
		return "", err
	}
	if got := modfile.ModulePath(gomod); got != mod.Path {
		return "", fmt.Errorf("%s declares module path %s; update the import path by hand", info.Version, got)
	}
	return info.Version, nil
}

// isNewer reports whether candidate is newer than cur, where an empty cur
// (module not yet in go.mod) is older than everything.
func isNewer(candidate, cur string) bool {
	return cur == "" || semver.Compare(candidate, cur) > 0
}

// branchHead returns the version at the head of the branch that bi
// describes, for the module served at base. It asks the git repo directly
// for the head commit, so a just-pushed commit is seen even if the proxy
// hasn't noticed it yet, and then asks the proxy for the pseudo-version of
// that commit. If git isn't available it falls back to the proxy's idea of
// the branch head.
func (r *resolver) branchHead(ctx context.Context, base string, bi branchInfo) (versionInfo, error) {
	var info versionInfo
	rev, err := r.lsRemote(ctx, bi.repo, bi.branch)
	if err != nil {
		log.Printf("git ls-remote %s %s failed (%v); asking the proxy instead", bi.repo, bi.branch, err)
		rev = bi.branch
	}
	if err := fetchJSON(ctx, r.client, base+"/@v/"+rev+".info", &info); err != nil {
		return versionInfo{}, err
	}
	return info, nil
}

// gitLsRemote returns the commit hash at the head of branch in repoURL.
func gitLsRemote(ctx context.Context, repoURL, branch string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "ls-remote", "--exit-code", repoURL, "refs/heads/"+branch).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("%w: %s", err, bytes.TrimSpace(ee.Stderr))
		}
		return "", err
	}
	hash, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\t")
	if len(hash) != 40 && len(hash) != 64 {
		return "", fmt.Errorf("unexpected ls-remote output %q", out)
	}
	return hash, nil
}

// newestAged returns the newest tagged release of the module served at base
// that is both newer than cur and older than the cooldown, or a zero
// versionInfo if there is none. Prereleases are skipped, matching what
// @latest would pick.
func (r *resolver) newestAged(ctx context.Context, base, cur string) (versionInfo, error) {
	list, err := fetch(ctx, r.client, base+"/@v/list")
	if err != nil {
		return versionInfo{}, err
	}
	var candidates []string
	for _, v := range strings.Fields(string(list)) {
		if semver.IsValid(v) && semver.Prerelease(v) == "" && isNewer(v, cur) {
			candidates = append(candidates, v)
		}
	}
	semver.Sort(candidates)
	slices.Reverse(candidates)
	for _, v := range candidates {
		escapedVer, err := module.EscapeVersion(v)
		if err != nil {
			return versionInfo{}, err
		}
		var info versionInfo
		if err := fetchJSON(ctx, r.client, base+"/@v/"+escapedVer+".info", &info); err != nil {
			return versionInfo{}, err
		}
		if !r.tooNew(info.Time) {
			return info, nil
		}
	}
	return versionInfo{}, nil
}

// versionTime returns the commit time of version ver of the module served
// at base. Pseudo-versions carry it in their name, so only tagged versions
// need a proxy round trip.
func (r *resolver) versionTime(ctx context.Context, base, ver string) (time.Time, error) {
	if module.IsPseudoVersion(ver) {
		return module.PseudoVersionTime(ver)
	}
	escapedVer, err := module.EscapeVersion(ver)
	if err != nil {
		return time.Time{}, err
	}
	var info versionInfo
	if err := fetchJSON(ctx, r.client, base+"/@v/"+escapedVer+".info", &info); err != nil {
		return time.Time{}, err
	}
	return info.Time, nil
}

// statusError is a non-2xx response from the proxy.
type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("proxy returned %d: %s", e.code, strings.TrimSpace(e.body))
}

// fetchJSON fetches url from the proxy and decodes its JSON body into dst.
func fetchJSON(ctx context.Context, client *http.Client, url string, dst any) error {
	body, err := fetch(ctx, client, url)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

// fetch fetches url from the proxy and returns its body. It retries once
// on transient errors, since the proxy occasionally returns those under
// load. Client errors are final.
func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		body, err := fetchOnce(ctx, client, url)
		if err == nil {
			return body, nil
		}
		var se *statusError
		if attempt > 0 || (errors.As(err, &se) && se.code < 500) {
			return nil, err
		}
	}
}

func fetchOnce(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
		return nil, &statusError{res.StatusCode, string(body)}
	}
	return io.ReadAll(res.Body)
}
