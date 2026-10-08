// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/module"
)

// githubEnv is what the bumpdep workflow tells us through the environment
// GitHub Actions sets up for every step.
type githubEnv struct {
	workflow    string // GITHUB_WORKFLOW, the workflow's name ("bumpdep", "gokrazy-bump")
	event       string // GITHUB_EVENT_NAME: "workflow_dispatch", "schedule", ...
	actor       string // GITHUB_TRIGGERING_ACTOR, the user who dispatched the workflow
	repo        string // GITHUB_REPOSITORY, "owner/repo"
	outputFile  string // GITHUB_OUTPUT, where step outputs go
	summaryFile string // GITHUB_STEP_SUMMARY, Markdown shown on the run page
	tempDir     string // RUNNER_TEMP
}

// scheduled reports whether the workflow ran on its cron schedule rather
// than because somebody dispatched it. The actor is then whoever last
// touched the workflow file, which isn't worth naming.
func (env *githubEnv) scheduled() bool {
	return env.event == "schedule"
}

// githubEnvFromOS reads the GitHub Actions environment.
func githubEnvFromOS() (*githubEnv, error) {
	env := &githubEnv{
		workflow:    os.Getenv("GITHUB_WORKFLOW"),
		event:       os.Getenv("GITHUB_EVENT_NAME"),
		actor:       cmp.Or(os.Getenv("GITHUB_TRIGGERING_ACTOR"), os.Getenv("GITHUB_ACTOR")),
		repo:        os.Getenv("GITHUB_REPOSITORY"),
		outputFile:  os.Getenv("GITHUB_OUTPUT"),
		summaryFile: os.Getenv("GITHUB_STEP_SUMMARY"),
		tempDir:     cmp.Or(os.Getenv("RUNNER_TEMP"), os.TempDir()),
	}
	for _, v := range []struct{ name, val string }{
		{"GITHUB_WORKFLOW", env.workflow},
		{"GITHUB_TRIGGERING_ACTOR", env.actor},
		{"GITHUB_REPOSITORY", env.repo},
		{"GITHUB_OUTPUT", env.outputFile},
	} {
		if v.val == "" {
			return nil, fmt.Errorf("-github: $%s is not set; are we running in GitHub Actions?", v.name)
		}
	}
	return env, nil
}

var issueURLRx = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/issues/([0-9]+)$`)
var issueShortRx = regexp.MustCompile(`^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?#([0-9]+)$`)

// parseIssueRef turns an issue given as a GitHub URL, "#123", or
// "owner/repo#123" into the short form used in commit messages: "#123"
// for an issue in repo (an "owner/repo" string), "owner/repo#123" for
// one elsewhere.
func parseIssueRef(s, repo string) (string, error) {
	s = strings.TrimSpace(s)
	var owner, num string
	if m := issueURLRx.FindStringSubmatch(s); m != nil {
		owner, num = m[1], m[2]
	} else if m := issueShortRx.FindStringSubmatch(s); m != nil {
		owner, num = cmp.Or(m[1], repo), m[2]
	} else {
		return "", fmt.Errorf("issue must be a GitHub issue URL like https://github.com/tailscale/tailscale/issues/12345 (or #12345, or owner/repo#12345); got %q", s)
	}
	if strings.EqualFold(owner, repo) {
		return "#" + num, nil
	}
	return owner + "#" + num, nil
}

// reportInput is everything buildReport needs to describe a run.
type reportInput struct {
	updated   []update       // modules that changed, with their final versions
	unchanged []string       // selected modules that were already current
	held      []heldInfo     // selected modules held by the cooldown
	requested []string       // what the command line asked for, used when nothing changed
	toolchain *toolchainBump // nil if not requested
	issueRef  string         // "#123" or "owner/repo#123", or "" for none
	env       *githubEnv     // nil outside the workflow
	now       time.Time
}

// report is the commit message and branch for a run.
type report struct {
	title  string
	branch string // only set when running as the workflow
	body   string // Markdown body, without the title
}

// commitMessage returns the title and body as a commit message.
func (r *report) commitMessage() string {
	return r.title + "\n\n" + r.body
}

// maxTitleNames is how many changed things get named in the title before
// it falls back to a count.
const maxTitleNames = 3

// buildReport renders in as a report.
func buildReport(in reportInput) *report {
	var prefixes, names []string
	if len(in.updated) > 0 {
		prefixes = append(prefixes, "go.mod")
		if len(in.updated) > maxTitleNames {
			names = append(names, fmt.Sprintf("%d modules", len(in.updated)))
		} else {
			for _, u := range in.updated {
				names = append(names, u.Path)
			}
		}
	}
	if in.toolchain.changed() {
		prefixes = append(prefixes, "go.toolchain.rev")
		names = append(names, "Go toolchain")
	}
	if len(prefixes) == 0 {
		// Nothing changed, so this only shows up in the step summary.
		prefixes = append(prefixes, "go.mod")
		names = append(names, in.requested...)
	}
	title := strings.Join(prefixes, ",") + ": bump " + strings.Join(names, ", ")

	var body strings.Builder
	for _, u := range in.updated {
		fmt.Fprintf(&body, "* %s: %s\n", u.Path, describeChange(u))
	}
	for _, path := range in.unchanged {
		fmt.Fprintf(&body, "* %s: already current\n", path)
	}
	for _, h := range in.held {
		fmt.Fprintf(&body, "* %s: held by the cooldown; %v\n", h.Path, h.Err)
	}
	if tc := in.toolchain; tc != nil {
		if tc.changed() {
			fmt.Fprintf(&body, "* Go toolchain: %s/compare/%s...%s\n", toolchainRepo, tc.before, tc.after)
		} else {
			fmt.Fprintf(&body, "* Go toolchain: already at %s\n", tc.after)
		}
	}
	if env := in.env; env != nil {
		if env.scheduled() {
			fmt.Fprintf(&body, "\nTriggered by the %s workflow's schedule.\n", env.workflow)
		} else {
			fmt.Fprintf(&body, "\nTriggered by @%s via the %s workflow.\n", env.actor, env.workflow)
		}
	}
	if in.issueRef != "" {
		fmt.Fprintf(&body, "\nUpdates %s\n", in.issueRef)
	}

	r := &report{title: title, body: body.String()}
	if in.env != nil {
		r.branch = branchName(in.env, in.now)
	}
	return r
}

// describeChange says how u moved, as a GitHub compare link if the
// module's repo is known and a plain "from to to" otherwise.
func describeChange(u update) string {
	if u.Current == "" {
		return "added at " + u.Latest
	}
	repo := repoURL(u.Path)
	if repo == "" {
		return u.Current + " to " + u.Latest
	}
	return fmt.Sprintf("%s/compare/%s...%s", repo, gitRef(u.Path, u.Current), gitRef(u.Path, u.Latest))
}

// repoURL returns the https URL of the GitHub repo that serves module
// path, or "" if it's not known.
func repoURL(path string) string {
	if bi, ok := specialBranches[path]; ok {
		return bi.repo
	}
	parts := strings.SplitN(path, "/", 4)
	if len(parts) >= 3 && parts[0] == "github.com" {
		return "https://github.com/" + parts[1] + "/" + parts[2]
	}
	return ""
}

// gitRef returns something GitHub's compare view understands for version
// ver of module path: the commit hash of a pseudo-version, or the tag of a
// release. Modules in a subdirectory of their repo are tagged with the
// subdirectory as a prefix ("sub/v1.2.3").
func gitRef(path, ver string) string {
	if module.IsPseudoVersion(ver) {
		if rev, err := module.PseudoVersionRev(ver); err == nil {
			return rev
		}
	}
	ver = strings.TrimSuffix(ver, "+incompatible")
	prefix, _, ok := module.SplitPathVersion(path)
	if !ok {
		return ver
	}
	if parts := strings.SplitN(prefix, "/", 4); len(parts) == 4 && parts[0] == "github.com" {
		return parts[3] + "/" + ver
	}
	return ver
}

var unsafeRefChars = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// branchName returns the branch the workflow should push to:
// actions/<workflow>/<actor>/<timestamp>, or without the actor for
// scheduled runs. It's short and unique per run rather than descriptive:
// the old scheme of joining every module path produced names like
// actions/bumpdep/github.com-gokrazy-kernel.amd64-main-github.com-gokrazy-kernel.arm64-main-github.
func branchName(env *githubEnv, now time.Time) string {
	clean := func(s, fallback string) string {
		return cmp.Or(strings.Trim(unsafeRefChars.ReplaceAllString(s, "-"), "-"), fallback)
	}
	parts := []string{"actions", clean(env.workflow, "bumpdep")}
	if !env.scheduled() {
		parts = append(parts, clean(env.actor, "unknown"))
	}
	parts = append(parts, now.UTC().Format("20060102-150405"))
	return strings.Join(parts, "/")
}

// writeGitHubOutputs publishes r as step outputs (title, branch,
// commit-message, body-path) and appends it to the step summary.
func (r *report) writeGitHubOutputs(env *githubEnv) error {
	bodyPath := filepath.Join(env.tempDir, "bumpdeps-pr-body.md")
	if err := os.WriteFile(bodyPath, []byte(r.body), 0o644); err != nil {
		return err
	}
	var out strings.Builder
	for _, kv := range []struct{ k, v string }{
		{"title", r.title},
		{"branch", r.branch},
		{"body-path", bodyPath},
		{"commit-message", r.commitMessage()},
	} {
		writeGitHubOutput(&out, kv.k, kv.v)
	}
	if err := appendFile(env.outputFile, out.String()); err != nil {
		return err
	}
	if env.summaryFile != "" {
		if err := appendFile(env.summaryFile, "### "+r.title+"\n\n"+r.body); err != nil {
			return err
		}
	}
	return nil
}

// writeGitHubOutput appends "key=value" to w in the $GITHUB_OUTPUT file
// format, using the heredoc form for multi-line values.
func writeGitHubOutput(w *strings.Builder, key, value string) {
	if !strings.Contains(value, "\n") {
		fmt.Fprintf(w, "%s=%s\n", key, value)
		return
	}
	var buf [8]byte
	rand.Read(buf[:])
	delim := "BUMPDEPS_" + hex.EncodeToString(buf[:])
	fmt.Fprintf(w, "%s<<%s\n%s\n%s\n", key, delim, strings.TrimRight(value, "\n"), delim)
}

// appendFile appends s to the file at path, creating it if needed.
func appendFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(s); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
