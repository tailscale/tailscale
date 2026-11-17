// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

const testGoMod = `module example.com/app

go 1.27

require (
	github.com/gokrazy/kernel.amd64 v0.0.0-20260101000000-aaaaaaaaaaaa
	github.com/gokrazy/kernel.arm64 v0.0.0-20260101000000-bbbbbbbbbbbb
	github.com/tailscale/wireguard-go v0.0.0-20260201000000-cccccccccccc
	golang.org/x/net v0.50.0
	gvisor.dev/gvisor v0.0.0-20260301000000-dddddddddddd
)

require github.com/gobwas/glob v0.2.3 // indirect

require github.com/replaced/mod v1.0.0

replace github.com/replaced/mod => ../mod
`

func testGoModParsed(t *testing.T) *goMod {
	t.Helper()
	gm, err := parseGoMod([]byte(testGoMod))
	if err != nil {
		t.Fatal(err)
	}
	return gm
}

func TestParseArgs(t *testing.T) {
	gm := testGoModParsed(t)
	paths := func(mods []module.Version) []string {
		var out []string
		for _, m := range mods {
			out = append(out, m.Path)
		}
		return out
	}
	tests := []struct {
		name         string
		args         []string
		indirect     bool
		wantLookups  []string
		wantExplicit []update
		wantTC       bool
		wantNames    []string
		wantErr      string
	}{
		{
			name:        "no_args_selects_direct_deps",
			wantLookups: []string{"github.com/gokrazy/kernel.amd64", "github.com/gokrazy/kernel.arm64", "github.com/tailscale/wireguard-go", "golang.org/x/net", "gvisor.dev/gvisor"},
		},
		{
			name:        "indirect_flag",
			indirect:    true,
			wantLookups: []string{"github.com/gokrazy/kernel.amd64", "github.com/gokrazy/kernel.arm64", "github.com/tailscale/wireguard-go", "golang.org/x/net", "gvisor.dev/gvisor", "github.com/gobwas/glob"},
		},
		{
			name:        "substring_filter",
			args:        []string{"Kernel"},
			wantLookups: []string{"github.com/gokrazy/kernel.amd64", "github.com/gokrazy/kernel.arm64"},
			wantNames:   []string{"Kernel"},
		},
		{
			name:    "substring_filter_skips_indirect",
			args:    []string{"glob"},
			wantErr: `no modules in go.mod match "glob"`,
		},
		{
			name:        "substring_filter_matches_indirect_with_flag",
			args:        []string{"glob"},
			indirect:    true,
			wantLookups: []string{"github.com/gobwas/glob"},
			wantNames:   []string{"glob"},
		},
		{
			name:        "exact_path_selects_indirect",
			args:        []string{"github.com/gobwas/glob"},
			wantLookups: []string{"github.com/gobwas/glob"},
			wantNames:   []string{"github.com/gobwas/glob"},
		},
		{
			name:        "aliases_and_toolchain_comma_separated",
			args:        []string{"go, gvisor,wireguard-go"},
			wantLookups: []string{"gvisor.dev/gvisor", "github.com/tailscale/wireguard-go"},
			wantTC:      true,
			wantNames:   []string{"Go toolchain", "gvisor", "wireguard-go"},
		},
		{
			name:        "exact_path",
			args:        []string{"golang.org/x/net"},
			wantLookups: []string{"golang.org/x/net"},
			wantNames:   []string{"golang.org/x/net"},
		},
		{
			name:         "explicit_version",
			args:         []string{"github.com/gokrazy/kernel.amd64@main"},
			wantExplicit: []update{{"github.com/gokrazy/kernel.amd64", "v0.0.0-20260101000000-aaaaaaaaaaaa", "main"}},
			wantNames:    []string{"github.com/gokrazy/kernel.amd64"},
		},
		{
			name:        "explicit_latest_is_a_lookup",
			args:        []string{"golang.org/x/net@latest"},
			wantLookups: []string{"golang.org/x/net"},
			wantNames:   []string{"golang.org/x/net"},
		},
		{
			name:        "new_module",
			args:        []string{"github.com/new/mod"},
			wantLookups: []string{"github.com/new/mod"},
			wantNames:   []string{"github.com/new/mod"},
		},
		{
			name:         "new_module_at_version",
			args:         []string{"github.com/new/mod@v1.2.3"},
			wantExplicit: []update{{"github.com/new/mod", "", "v1.2.3"}},
			wantNames:    []string{"github.com/new/mod"},
		},
		{
			name:        "duplicate_selection_collapses",
			args:        []string{"gvisor", "gvisor.dev/gvisor", "gvisor"},
			wantLookups: []string{"gvisor.dev/gvisor"},
			wantNames:   []string{"gvisor", "gvisor.dev/gvisor", "gvisor"},
		},
		{
			name:    "no_match",
			args:    []string{"nonesuch"},
			wantErr: `no modules in go.mod match "nonesuch"`,
		},
		{
			name:    "replaced_explicit",
			args:    []string{"github.com/replaced/mod@v2.0.0"},
			wantErr: "replace directive",
		},
		{
			name:    "empty_version",
			args:    []string{"golang.org/x/net@"},
			wantErr: "empty version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel, err := parseArgs(gm, tt.args, tt.indirect)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := paths(sel.lookups); !reflect.DeepEqual(got, tt.wantLookups) {
				t.Errorf("lookups = %q; want %q", got, tt.wantLookups)
			}
			if !reflect.DeepEqual(sel.explicit, tt.wantExplicit) {
				t.Errorf("explicit = %+v; want %+v", sel.explicit, tt.wantExplicit)
			}
			if sel.toolchain != tt.wantTC {
				t.Errorf("toolchain = %v; want %v", sel.toolchain, tt.wantTC)
			}
			if !reflect.DeepEqual(sel.names, tt.wantNames) {
				t.Errorf("names = %q; want %q", sel.names, tt.wantNames)
			}
		})
	}
}

func TestParseArgsKeepsCurrentVersions(t *testing.T) {
	gm := testGoModParsed(t)
	sel, err := parseArgs(gm, []string{"golang.org/x/net", "github.com/new/mod"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []module.Version{
		{Path: "golang.org/x/net", Version: "v0.50.0"},
		{Path: "github.com/new/mod"},
	}
	if !reflect.DeepEqual(sel.lookups, want) {
		t.Errorf("lookups = %+v; want %+v", sel.lookups, want)
	}
}

func TestCheckDowngrades(t *testing.T) {
	before := testGoModParsed(t)
	after, err := parseGoMod([]byte(strings.NewReplacer(
		"golang.org/x/net v0.50.0", "golang.org/x/net v0.49.0",
		"gvisor.dev/gvisor v0.0.0-20260301000000-dddddddddddd", "gvisor.dev/gvisor v0.0.0-20260401000000-eeeeeeeeeeee",
	).Replace(testGoMod)))
	if err != nil {
		t.Fatal(err)
	}
	err = checkDowngrades(before, after)
	if err == nil || !strings.Contains(err.Error(), "golang.org/x/net v0.50.0 => v0.49.0") {
		t.Fatalf("err = %v; want x/net downgrade", err)
	}
	if strings.Contains(err.Error(), "gvisor") {
		t.Errorf("upgrade reported as downgrade: %v", err)
	}
	if err := checkDowngrades(before, before); err != nil {
		t.Errorf("unchanged go.mod: %v", err)
	}
}

func TestParseIssueRef(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://github.com/tailscale/tailscale/issues/12345", "#12345"},
		{" https://github.com/tailscale/tailscale/issues/12345\n", "#12345"},
		{"https://github.com/tailscale/corp/issues/7", "tailscale/corp#7"},
		{"#42", "#42"},
		{"tailscale/corp#42", "tailscale/corp#42"},
		{"tailscale/tailscale#42", "#42"},
		{"https://github.com/tailscale/tailscale/pull/12345", ""},
		{"12345", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got, err := parseIssueRef(tt.in, "tailscale/tailscale")
		if tt.want == "" {
			if err == nil {
				t.Errorf("%q: got %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
		} else if got != tt.want {
			t.Errorf("%q = %q; want %q", tt.in, got, tt.want)
		}
	}
}

func TestDescribeChange(t *testing.T) {
	tests := []struct {
		u    update
		want string
	}{
		{
			update{"github.com/gokrazy/kernel.amd64", "v0.0.0-20260101000000-aaaaaaaaaaaa", "v0.0.0-20260201000000-bbbbbbbbbbbb"},
			"https://github.com/gokrazy/kernel.amd64/compare/aaaaaaaaaaaa...bbbbbbbbbbbb",
		},
		{
			update{"gvisor.dev/gvisor", "v0.0.0-20260101000000-aaaaaaaaaaaa", "v0.0.0-20260201000000-bbbbbbbbbbbb"},
			"https://github.com/google/gvisor/compare/aaaaaaaaaaaa...bbbbbbbbbbbb",
		},
		{
			update{"github.com/foo/bar", "v1.2.3", "v1.3.0"},
			"https://github.com/foo/bar/compare/v1.2.3...v1.3.0",
		},
		{
			update{"github.com/foo/bar/v2", "v2.0.0", "v2.1.0"},
			"https://github.com/foo/bar/compare/v2.0.0...v2.1.0",
		},
		{
			update{"github.com/foo/bar/sub", "v1.0.0", "v1.1.0"},
			"https://github.com/foo/bar/compare/sub/v1.0.0...sub/v1.1.0",
		},
		{
			update{"github.com/foo/bar/sub/v3", "v3.0.0", "v3.1.0"},
			"https://github.com/foo/bar/compare/sub/v3.0.0...sub/v3.1.0",
		},
		{
			update{"github.com/foo/bar", "v2.0.0+incompatible", "v2.1.0+incompatible"},
			"https://github.com/foo/bar/compare/v2.0.0...v2.1.0",
		},
		{
			update{"golang.org/x/net", "v0.50.0", "v0.51.0"},
			"v0.50.0 to v0.51.0",
		},
		{
			update{"golang.org/x/net", "", "v0.51.0"},
			"added at v0.51.0",
		},
	}
	for _, tt := range tests {
		if got := describeChange(tt.u); got != tt.want {
			t.Errorf("%+v = %q; want %q", tt.u, got, tt.want)
		}
	}
}

func TestBranchName(t *testing.T) {
	now := time.Date(2026, 9, 17, 15, 4, 5, 0, time.FixedZone("PDT", -7*3600))
	tests := []struct {
		env  githubEnv
		want string
	}{
		{githubEnv{workflow: "bumpdep", event: "workflow_dispatch", actor: "bradfitz"}, "actions/bumpdep/bradfitz/20260917-220405"},
		{githubEnv{workflow: "bumpdep", event: "workflow_dispatch", actor: "some one/../evil"}, "actions/bumpdep/some-one-evil/20260917-220405"},
		{githubEnv{workflow: "bumpdep", event: "workflow_dispatch"}, "actions/bumpdep/unknown/20260917-220405"},
		{githubEnv{event: "workflow_dispatch", actor: "bradfitz"}, "actions/bumpdep/bradfitz/20260917-220405"},
		{githubEnv{workflow: "gokrazy-bump", event: "schedule", actor: "bradfitz"}, "actions/gokrazy-bump/20260917-220405"},
		{githubEnv{workflow: "gokrazy-bump", event: "workflow_dispatch", actor: "bradfitz"}, "actions/gokrazy-bump/bradfitz/20260917-220405"},
	}
	for _, tt := range tests {
		if got := branchName(&tt.env, now); got != tt.want {
			t.Errorf("branchName(%+v) = %q; want %q", tt.env, got, tt.want)
		}
	}
}

func TestBuildReport(t *testing.T) {
	now := time.Date(2026, 9, 17, 22, 4, 5, 0, time.UTC)
	env := &githubEnv{workflow: "bumpdep", event: "workflow_dispatch", actor: "bradfitz", repo: "tailscale/tailscale"}
	cronEnv := &githubEnv{workflow: "gokrazy-bump", event: "schedule", actor: "bradfitz", repo: "tailscale/tailscale"}
	held := &heldError{"v0.52.0", time.Now().Add(-36 * time.Hour)}
	tests := []struct {
		name       string
		in         reportInput
		wantTitle  string
		wantBranch string
		wantBody   string
	}{
		{
			name: "workflow_run_with_everything",
			in: reportInput{
				updated: []update{
					{"github.com/gokrazy/kernel.amd64", "v0.0.0-20260101000000-aaaaaaaaaaaa", "v0.0.0-20260201000000-bbbbbbbbbbbb"},
					{"github.com/new/mod", "", "v1.0.0"},
				},
				unchanged: []string{"github.com/gokrazy/kernel.arm64"},
				held:      []heldInfo{{"golang.org/x/net", held}},
				toolchain: &toolchainBump{"1111111", "2222222"},
				issueRef:  "#123",
				env:       env,
				now:       now,
			},
			wantTitle:  "go.mod,go.toolchain.rev: bump github.com/gokrazy/kernel.amd64, github.com/new/mod, Go toolchain",
			wantBranch: "actions/bumpdep/bradfitz/20260917-220405",
			wantBody: `* github.com/gokrazy/kernel.amd64: https://github.com/gokrazy/kernel.amd64/compare/aaaaaaaaaaaa...bbbbbbbbbbbb
* github.com/new/mod: added at v1.0.0
* github.com/gokrazy/kernel.arm64: already current
* golang.org/x/net: held by the cooldown; v0.52.0 is only 1.5 days old
* Go toolchain: https://github.com/tailscale/go/compare/1111111...2222222

Triggered by @bradfitz via the bumpdep workflow.

Updates #123
`,
		},
		{
			name: "local_run_many_modules_no_issue",
			in: reportInput{
				updated: []update{
					{"a.example/a", "v1.0.0", "v1.1.0"},
					{"b.example/b", "v1.0.0", "v1.1.0"},
					{"c.example/c", "v1.0.0", "v1.1.0"},
					{"d.example/d", "v1.0.0", "v1.1.0"},
				},
				now: now,
			},
			wantTitle: "go.mod: bump 4 modules",
			wantBody: `* a.example/a: v1.0.0 to v1.1.0
* b.example/b: v1.0.0 to v1.1.0
* c.example/c: v1.0.0 to v1.1.0
* d.example/d: v1.0.0 to v1.1.0
`,
		},
		{
			name: "scheduled_run",
			in: reportInput{
				updated: []update{
					{"github.com/gokrazy/kernel.amd64", "v0.0.0-20260101000000-aaaaaaaaaaaa", "v0.0.0-20260201000000-bbbbbbbbbbbb"},
				},
				issueRef: "#1866",
				env:      cronEnv,
				now:      now,
			},
			wantTitle:  "go.mod: bump github.com/gokrazy/kernel.amd64",
			wantBranch: "actions/gokrazy-bump/20260917-220405",
			wantBody: `* github.com/gokrazy/kernel.amd64: https://github.com/gokrazy/kernel.amd64/compare/aaaaaaaaaaaa...bbbbbbbbbbbb

Triggered by the gokrazy-bump workflow's schedule.

Updates #1866
`,
		},
		{
			name: "toolchain_only",
			in: reportInput{
				toolchain: &toolchainBump{"1111111", "2222222"},
				issueRef:  "tailscale/corp#9",
				now:       now,
			},
			wantTitle: "go.toolchain.rev: bump Go toolchain",
			wantBody: `* Go toolchain: https://github.com/tailscale/go/compare/1111111...2222222

Updates tailscale/corp#9
`,
		},
		{
			name: "nothing_changed",
			in: reportInput{
				unchanged: []string{"gvisor.dev/gvisor"},
				requested: []string{"gvisor", "Go toolchain"},
				toolchain: &toolchainBump{"1111111", "1111111"},
				env:       env,
				now:       now,
			},
			wantTitle:  "go.mod: bump gvisor, Go toolchain",
			wantBranch: "actions/bumpdep/bradfitz/20260917-220405",
			wantBody: `* gvisor.dev/gvisor: already current
* Go toolchain: already at 1111111

Triggered by @bradfitz via the bumpdep workflow.
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := buildReport(tt.in)
			if r.title != tt.wantTitle {
				t.Errorf("title = %q; want %q", r.title, tt.wantTitle)
			}
			if r.branch != tt.wantBranch {
				t.Errorf("branch = %q; want %q", r.branch, tt.wantBranch)
			}
			if r.body != tt.wantBody {
				t.Errorf("body = %q; want %q", r.body, tt.wantBody)
			}
		})
	}
}

func TestWriteGitHubOutputs(t *testing.T) {
	dir := t.TempDir()
	env := &githubEnv{
		actor:       "bradfitz",
		repo:        "tailscale/tailscale",
		outputFile:  filepath.Join(dir, "output"),
		summaryFile: filepath.Join(dir, "summary"),
		tempDir:     dir,
	}
	r := &report{
		title:  "go.mod: bump gvisor",
		branch: "actions/bumpdep/bradfitz/20260917-220405",
		body:   "* gvisor.dev/gvisor: v1 to v2\n\nUpdates #1\n",
	}
	if err := r.writeGitHubOutputs(env); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(env.outputFile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"title=go.mod: bump gvisor\n",
		"branch=actions/bumpdep/bradfitz/20260917-220405\n",
		"body-path=" + filepath.Join(dir, "bumpdeps-pr-body.md") + "\n",
		"commit-message<<BUMPDEPS_",
		"\ngo.mod: bump gvisor\n\n* gvisor.dev/gvisor: v1 to v2\n\nUpdates #1\nBUMPDEPS_",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	// The heredoc delimiter must open and close with the same token.
	lines := strings.Split(strings.TrimSpace(got), "\n")
	_, delim, _ := strings.Cut(lines[3], "<<")
	if lines[len(lines)-1] != delim {
		t.Errorf("heredoc not closed with %q; last line %q", delim, lines[len(lines)-1])
	}

	body, err := os.ReadFile(filepath.Join(dir, "bumpdeps-pr-body.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != r.body {
		t.Errorf("body file = %q; want %q", body, r.body)
	}
	summary, err := os.ReadFile(env.summaryFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := "### go.mod: bump gvisor\n\n" + r.body; string(summary) != want {
		t.Errorf("summary = %q; want %q", summary, want)
	}
}

// fakeProxy is an in-memory Go module proxy serving a fixed set of
// versions per module.
type fakeProxy struct {
	// versions maps module path to its known versions; the .mod content
	// for each declares modPath[path] if set, else path.
	versions map[string][]versionInfo
	modPath  map[string]string
	// commits maps a module path and commit hash to the pseudo-version
	// the proxy would mint for it.
	commits map[string]versionInfo
}

func (p *fakeProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/")
	modPath, rest, ok := strings.Cut(path, "/@")
	if !ok {
		http.NotFound(w, req)
		return
	}
	modPath, _ = module.UnescapePath(modPath)
	vers, known := p.versions[modPath]
	if !known {
		http.Error(w, "not found: unknown module", http.StatusNotFound)
		return
	}
	switch {
	case rest == "latest":
		var latest versionInfo
		for _, v := range vers {
			if module.IsPseudoVersion(v.Version) || semver.Prerelease(v.Version) != "" {
				continue
			}
			if latest.Version == "" || compareVersions(v.Version, latest.Version) > 0 {
				latest = v
			}
		}
		json.NewEncoder(w).Encode(latest)
	case rest == "v/list":
		for _, v := range vers {
			if !module.IsPseudoVersion(v.Version) {
				fmt.Fprintln(w, v.Version)
			}
		}
	case strings.HasSuffix(rest, ".info"):
		q := strings.TrimSuffix(strings.TrimPrefix(rest, "v/"), ".info")
		if info, ok := p.commits[modPath+"@"+q]; ok {
			json.NewEncoder(w).Encode(info)
			return
		}
		for _, v := range vers {
			if v.Version == q {
				json.NewEncoder(w).Encode(v)
				return
			}
		}
		http.Error(w, "not found: unknown revision", http.StatusNotFound)
	case strings.HasSuffix(rest, ".mod"):
		declared := modPath
		if mp, ok := p.modPath[modPath]; ok {
			declared = mp
		}
		fmt.Fprintf(w, "module %s\n", declared)
	default:
		http.NotFound(w, req)
	}
}

func compareVersions(a, b string) int {
	return strings.Compare(a, b) // good enough for the single-digit versions in tests
}

func TestLookupNewer(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	proxy := &fakeProxy{
		versions: map[string][]versionInfo{
			"example.com/tagged": {
				{"v1.0.0", now.Add(-30 * day)},
				{"v1.1.0", now.Add(-10 * day)},
				{"v1.2.0", now.Add(-2 * day)},
				{"v1.3.0-rc1", now.Add(-1 * day)},
			},
			"example.com/stray": {
				{"v0.91.0", now.Add(-700 * day)},
			},
			"example.com/renamed": {
				{"v1.0.0", now.Add(-100 * day)},
				{"v2.0.0", now.Add(-10 * day)},
			},
			"gvisor.dev/gvisor": {
				{"v0.0.0-20260301000000-dddddddddddd", now.Add(-20 * day)},
			},
		},
		modPath: map[string]string{
			"example.com/renamed": "example.com/newname",
		},
		commits: map[string]versionInfo{
			"gvisor.dev/gvisor@" + strings.Repeat("e", 40): {"v0.0.0-20260401000000-eeeeeeeeeeee", now.Add(-5 * day)},
			"gvisor.dev/gvisor@go":                         {"v0.0.0-20260301000000-dddddddddddd", now.Add(-20 * day)},
		},
	}
	srv := httptest.NewServer(proxy)
	defer srv.Close()

	newResolver := func(cooldownDays int, lsRemote func(ctx context.Context, repo, branch string) (string, error)) *resolver {
		r := &resolver{client: srv.Client(), base: srv.URL, lsRemote: lsRemote}
		if cooldownDays > 0 {
			r.cutoff = now.Add(-time.Duration(cooldownDays) * day)
		}
		return r
	}
	headIsE := func(ctx context.Context, repo, branch string) (string, error) {
		if repo != "https://github.com/google/gvisor" || branch != "go" {
			return "", fmt.Errorf("unexpected ls-remote %s %s", repo, branch)
		}
		return strings.Repeat("e", 40), nil
	}
	lsRemoteFails := func(context.Context, string, string) (string, error) {
		return "", errors.New("no git")
	}

	tests := []struct {
		name     string
		r        *resolver
		mod      module.Version
		want     string
		wantHeld bool
		wantErr  string
	}{
		{
			name: "newer_tagged_release",
			r:    newResolver(0, nil),
			mod:  module.Version{Path: "example.com/tagged", Version: "v1.1.0"},
			want: "v1.2.0",
		},
		{
			name: "already_latest",
			r:    newResolver(0, nil),
			mod:  module.Version{Path: "example.com/tagged", Version: "v1.2.0"},
			want: "",
		},
		{
			name: "new_module_gets_latest",
			r:    newResolver(0, nil),
			mod:  module.Version{Path: "example.com/tagged"},
			want: "v1.2.0",
		},
		{
			name: "cooldown_falls_back_to_aged_release",
			r:    newResolver(7, nil),
			mod:  module.Version{Path: "example.com/tagged", Version: "v1.0.0"},
			want: "v1.1.0",
		},
		{
			name:     "cooldown_holds_when_nothing_aged_is_newer",
			r:        newResolver(7, nil),
			mod:      module.Version{Path: "example.com/tagged", Version: "v1.1.0"},
			wantHeld: true,
		},
		{
			name:    "stray_old_tag_is_rejected",
			r:       newResolver(0, nil),
			mod:     module.Version{Path: "example.com/stray", Version: "v0.0.0-20260101000000-aaaaaaaaaaaa"},
			wantErr: "probably a stray tag",
		},
		{
			name:    "renamed_module_is_rejected",
			r:       newResolver(0, nil),
			mod:     module.Version{Path: "example.com/renamed", Version: "v1.0.0"},
			wantErr: "declares module path example.com/newname",
		},
		{
			name:    "unknown_module",
			r:       newResolver(0, nil),
			mod:     module.Version{Path: "example.com/private", Version: "v1.0.0"},
			wantErr: "proxy returned 404",
		},
		{
			name: "branch_head_via_ls-remote",
			r:    newResolver(0, headIsE),
			mod:  module.Version{Path: "gvisor.dev/gvisor", Version: "v0.0.0-20260301000000-dddddddddddd"},
			want: "v0.0.0-20260401000000-eeeeeeeeeeee",
		},
		{
			name:     "branch_head_held_by_cooldown",
			r:        newResolver(7, headIsE),
			mod:      module.Version{Path: "gvisor.dev/gvisor", Version: "v0.0.0-20260301000000-dddddddddddd"},
			wantHeld: true,
		},
		{
			name: "branch_head_falls_back_to_proxy_when_git_fails",
			r:    newResolver(0, lsRemoteFails),
			mod:  module.Version{Path: "gvisor.dev/gvisor", Version: "v0.0.0-20260301000000-dddddddddddd"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.r.lookupNewer(context.Background(), tt.mod)
			var held *heldError
			switch {
			case tt.wantHeld:
				if !errors.As(err, &held) {
					t.Fatalf("err = %v; want heldError", err)
				}
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v; want containing %q", err, tt.wantErr)
				}
			case err != nil:
				t.Fatal(err)
			case got != tt.want:
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}

func TestSplitArgs(t *testing.T) {
	got := splitArgs([]string{"go, gvisor,,wireguard-go", " a@v1 \n", "", "b"})
	want := []string{"go", "gvisor", "wireguard-go", "a@v1", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}
