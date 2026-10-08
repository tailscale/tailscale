// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The bumpdeps program updates dependencies in go.mod (and, on request,
// the Go toolchain), tidies up afterwards, and writes a commit message
// describing what changed. With no arguments it bumps every direct
// dependency to its latest version.
//
// It is also the brain of the bumpdep and gokrazy-bump GitHub workflows
// (.github/workflows/bumpdep.yml and gokrazy-bump.yml), which run it with
// -github and turn its outputs into a pull request.
//
// Each argument selects something to bump. Arguments may also be
// comma-separated, which is how the workflow passes them through.
//
//   - "path@version" bumps (or adds) exactly that module at that
//     version. The version is anything go get accepts: a tag, "latest",
//     a branch name, or a commit hash. Only "latest" goes through the
//     safety checks below; other versions are handed to go get as is.
//   - "go" updates the Go toolchain by running ./pull-toolchain.sh.
//   - "wireguard-go" and "gvisor" are aliases for the modules of the same
//     name; see aliases.
//   - An exact module path already in go.mod selects that module.
//   - Anything else is a case-insensitive substring of module paths:
//     "bumpdeps kernel" considers both gokrazy kernel modules. Indirect
//     dependencies only match with -indirect; name them exactly to
//     bump one on its own.
//   - A module path that isn't in go.mod and matches nothing is added at
//     its latest version.
//
// Versions come from the Go module proxy, asked concurrently. A few
// modules follow a branch rather than tagged releases; see
// specialBranches. Their head is found with git ls-remote so a
// just-pushed commit is picked up even if the proxy hasn't seen it yet,
// and the proxy then supplies the pseudo-version for that commit.
// Everything selected is bumped with a single "go get", followed by
// "make tidy" and "make updatedeps" unless -tidy=false.
//
// The program refuses to downgrade anything. A downgrade means something
// went wrong (a retracted release, a stray tag) and wants a human's
// rollback commit, not an unattended bump.
//
// The --exclude-newer-than-days flag is a cooldown, as described at
// https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down.html:
// releases younger than that many days are ignored and the newest release
// old enough is used instead, so a compromised upstream has to go unnoticed
// for that long before we pick it up. Go's proxy only knows commit times,
// not upload times, so the age is measured from the commit the version
// points at. Branch-tracked modules have no older release to fall back to,
// so they're held until their head is old enough.
//
// Indirect dependencies are only updated as far as the direct ones pull
// them, unless -indirect is set or they're named explicitly. Bumping them
// individually to @latest tends to break the build, since their importers
// haven't necessarily caught up. (github.com/gobwas/glob v1.0.0 removed
// packages that github.com/goreleaser/fileglob still imports, for
// instance.)
//
// Modules with a replace directive are left alone, as are modules the proxy
// doesn't know about (such as private modules) and modules whose latest
// release declares a different module path (renamed projects).
//
// # Running
//
// From the repo root:
//
//	./tool/go run ./misc/bumpdeps                      # all direct deps
//	./tool/go run ./misc/bumpdeps gvisor wireguard-go  # just those two
//	./tool/go run ./misc/bumpdeps -issue https://github.com/tailscale/tailscale/issues/123 go
//
// The last form prints a commit message with an "Updates #123" line.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/sync/errgroup"
)

// branchInfo says which branch of which git repo a module tracks.
type branchInfo struct {
	repo   string // https URL of the git repo, for git ls-remote and compare links
	branch string
}

// specialBranches maps module paths to the branch they should track
// instead of the proxy's notion of @latest.
var specialBranches = map[string]branchInfo{
	// Upstream's convention for the Go-module-friendly branch.
	"gvisor.dev/gvisor": {"https://github.com/google/gvisor", "go"},
	// Our fork's main branch.
	"github.com/tailscale/wireguard-go": {"https://github.com/tailscale/wireguard-go", "tailscale"},
	// Our fork has stray upstream-style tags; see tempfork/acme.
	"github.com/tailscale/golang-x-crypto": {"https://github.com/tailscale/golang-x-crypto", "main"},
}

// aliases maps short names accepted on the command line to module paths.
var aliases = map[string]string{
	"gvisor":       "gvisor.dev/gvisor",
	"wireguard-go": "github.com/tailscale/wireguard-go",
}

// toolchainRepo is the git repo that go.toolchain.rev points into.
const toolchainRepo = "https://github.com/tailscale/go"

var (
	dryRun               = flag.Bool("n", false, "print what would be updated without changing anything")
	goBin                = flag.String("go", "", "path to the go binary to run; defaults to ./tool/go if present, else go from $PATH")
	proxyURL             = flag.String("proxy", "https://proxy.golang.org", "base URL of the Go module proxy to query")
	parallel             = flag.Int("j", 32, "maximum number of concurrent proxy requests")
	indirect             = flag.Bool("indirect", false, "also update modules marked // indirect; risky, since their importers may not build against newer versions")
	excludeNewerThanDays = flag.Int("exclude-newer-than-days", 0, "ignore versions younger than this many days and use the newest older one instead; 0 means no cooldown")
	tidy                 = flag.Bool("tidy", true, "run \"make tidy\" and \"make updatedeps\" after updating")
	issue                = flag.String("issue", "", "GitHub issue motivating the bump, as a URL or #123 or owner/repo#123; becomes the \"Updates\" line of the commit message; required with -github")
	github               = flag.Bool("github", false, "run as the bumpdep GitHub workflow: read the actor and repo from the environment and write the title, branch, and commit message to $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY")
)

func main() {
	log.SetFlags(0)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: bumpdeps [flags] [dep ...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := run(context.Background(), flag.Args()); err != nil {
		log.Fatalf("bumpdeps: %v", err)
	}
}

// update describes one module that has a newer version available, or
// that was asked for at an explicit version.
type update struct {
	Path    string
	Current string // version in go.mod before, or "" if it's being added
	Latest  string // version to bump to; after go get, the version go.mod ended up with
}

func run(ctx context.Context, args []string) error {
	var env *githubEnv
	if *github {
		var err error
		if env, err = githubEnvFromOS(); err != nil {
			return err
		}
		if *issue == "" {
			return errors.New("-issue is required with -github")
		}
	}
	var issueRef string
	if *issue != "" {
		repo := "tailscale/tailscale"
		if env != nil {
			repo = env.repo
		}
		var err error
		if issueRef, err = parseIssueRef(*issue, repo); err != nil {
			return err
		}
	}

	before, err := readGoMod()
	if err != nil {
		return err
	}
	sel, err := parseArgs(before, args, *indirect)
	if err != nil {
		return err
	}

	r := &resolver{
		client:   &http.Client{Timeout: 2 * time.Minute},
		base:     strings.TrimSuffix(*proxyURL, "/"),
		lsRemote: gitLsRemote,
	}
	if *excludeNewerThanDays > 0 {
		r.cutoff = time.Now().Add(-time.Duration(*excludeNewerThanDays) * 24 * time.Hour)
	}
	res, err := resolveAll(ctx, r, sel.lookups)
	if err != nil {
		return err
	}
	updates := append(res.updates, sel.explicit...)
	slices.SortFunc(updates, func(a, b update) int { return cmp.Compare(a.Path, b.Path) })

	switch {
	case len(updates) > 0:
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "MODULE\tCURRENT\tLATEST")
		for _, u := range updates {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", u.Path, cmp.Or(u.Current, "(new)"), u.Latest)
		}
		tw.Flush()
	case len(res.held) > 0:
		fmt.Printf("nothing to update; %d module(s) held by the %d-day cooldown\n", len(res.held), *excludeNewerThanDays)
	case !sel.toolchain:
		fmt.Println("all dependencies are up to date")
	}
	if *dryRun {
		if sel.toolchain {
			fmt.Println("would also run ./pull-toolchain.sh")
		}
		return res.err()
	}

	if len(updates) > 0 {
		if err := goGet(ctx, updates); err != nil {
			return err
		}
		after, err := readGoMod()
		if err != nil {
			return err
		}
		if err := checkDowngrades(before, after); err != nil {
			return err
		}
		for i := range updates {
			if v, ok := after.versions[updates[i].Path]; ok {
				updates[i].Latest = v
			}
		}
	}

	var tc *toolchainBump
	if sel.toolchain {
		if tc, err = bumpToolchain(ctx); err != nil {
			return err
		}
	}

	if *tidy && (len(updates) > 0 || tc.changed()) {
		for _, target := range []string{"tidy", "updatedeps"} {
			if err := runCommand(ctx, "make", target); err != nil {
				return err
			}
		}
	}

	rep := buildReport(reportInput{
		updated:   updates,
		unchanged: res.upToDate,
		held:      res.held,
		requested: sel.names,
		toolchain: tc,
		issueRef:  issueRef,
		env:       env,
		now:       time.Now(),
	})
	if env != nil {
		if err := rep.writeGitHubOutputs(env); err != nil {
			return err
		}
	} else if len(updates) > 0 || tc.changed() {
		fmt.Printf("\nSuggested commit message:\n\n%s", rep.commitMessage())
	}
	return res.err()
}

// resolveResult is what resolveAll learned about the modules it was asked
// to look up.
type resolveResult struct {
	updates  []update
	upToDate []string   // paths with nothing newer
	held     []heldInfo // paths whose only newer versions are inside the cooldown
	failures int        // lookups that errored, already logged
}

// heldInfo describes a module held back by the cooldown.
type heldInfo struct {
	Path string
	Err  *heldError
}

// err returns an error if any lookups failed, so the program's exit
// status reflects them even though the successful updates were applied.
func (r *resolveResult) err() error {
	if r.failures > 0 {
		return fmt.Errorf("%d module lookups failed; see above", r.failures)
	}
	return nil
}

// resolveAll asks the proxy about every module in mods concurrently.
func resolveAll(ctx context.Context, r *resolver, mods []module.Version) (*resolveResult, error) {
	var (
		mu  sync.Mutex
		res resolveResult
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(*parallel)
	for _, mod := range mods {
		g.Go(func() error {
			latest, err := r.lookupNewer(gctx, mod)
			mu.Lock()
			defer mu.Unlock()
			var held *heldError
			switch {
			case errors.As(err, &held):
				res.held = append(res.held, heldInfo{mod.Path, held})
				log.Printf("holding %s: %v", mod.Path, err)
			case err != nil:
				res.failures++
				log.Printf("skipping %s: %v", mod.Path, err)
			case latest != "":
				res.updates = append(res.updates, update{mod.Path, mod.Version, latest})
			default:
				res.upToDate = append(res.upToDate, mod.Path)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	slices.Sort(res.upToDate)
	slices.SortFunc(res.held, func(a, b heldInfo) int { return cmp.Compare(a.Path, b.Path) })
	return &res, nil
}

// goBinary returns the go binary to run, honoring the -go flag.
func goBinary() string {
	if *goBin != "" {
		return *goBin
	}
	if fi, err := os.Stat(filepath.Join("tool", "go")); err == nil && !fi.IsDir() {
		return filepath.Join(".", "tool", "go")
	}
	return "go"
}

// goGet runs a single go get for all of updates.
func goGet(ctx context.Context, updates []update) error {
	args := []string{"get"}
	for _, u := range updates {
		args = append(args, u.Path+"@"+u.Latest)
	}
	fmt.Fprintf(os.Stderr, "running: %s get ... (%d modules)\n", goBinary(), len(updates))
	if err := runCommand(ctx, goBinary(), args...); err != nil {
		return fmt.Errorf("go get: %w", err)
	}
	return nil
}

// runCommand runs name with args, passing through its output.
func runCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// toolchainBump records a run of ./pull-toolchain.sh.
type toolchainBump struct {
	before, after string // contents of go.toolchain.rev
}

// changed reports whether the toolchain moved. It's safe on a nil receiver
// so callers needn't check whether a bump was requested.
func (t *toolchainBump) changed() bool {
	return t != nil && t.before != t.after
}

// bumpToolchain runs ./pull-toolchain.sh and reports what it did to
// go.toolchain.rev.
func bumpToolchain(ctx context.Context) (*toolchainBump, error) {
	const revFile = "go.toolchain.rev"
	before, err := os.ReadFile(revFile)
	if err != nil {
		return nil, err
	}
	if err := runCommand(ctx, "./pull-toolchain.sh"); err != nil {
		return nil, err
	}
	after, err := os.ReadFile(revFile)
	if err != nil {
		return nil, err
	}
	return &toolchainBump{
		before: strings.TrimSpace(string(before)),
		after:  strings.TrimSpace(string(after)),
	}, nil
}
