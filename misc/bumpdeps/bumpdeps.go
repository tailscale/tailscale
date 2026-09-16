// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The bumpdeps program updates every direct dependency in go.mod to its
// latest version, or just the ones named on the command line.
//
// It parses go.mod, asks the Go module proxy concurrently for the newest
// version of each required module, and then runs a single "go get" with
// the modules that have something newer. A few modules follow a branch
// rather than tagged releases; see specialBranches.
//
// Arguments, if any, are case-insensitive substrings of module paths:
// "bumpdeps gvisor wireguard" only considers modules whose path contains
// one of those. Explicitly named modules are considered even if they're
// only indirect dependencies.
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
// them, unless -indirect is set. Bumping them individually to @latest
// tends to break the build, since their importers haven't necessarily
// caught up. (github.com/gobwas/glob v1.0.0 removed packages that
// github.com/goreleaser/fileglob still imports, for instance.)
//
// Modules with a replace directive are left alone, as are modules the proxy
// doesn't know about (such as private modules) and modules whose latest
// release declares a different module path (renamed projects).
//
// # Running
//
// From the repo root, run: `./tool/go run ./misc/bumpdeps` and then
// `make tidy && make updatedeps`.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
)

// specialBranches maps module paths to the branch they should track
// instead of the proxy's notion of @latest.
var specialBranches = map[string]string{
	"gvisor.dev/gvisor":                    "go",        // upstream convention for the Go-module-friendly branch
	"github.com/tailscale/wireguard-go":    "tailscale", // our fork's main branch
	"github.com/tailscale/golang-x-crypto": "main",      // our fork has stray upstream-style tags; see tempfork/acme
}

var (
	dryRun               = flag.Bool("n", false, "print what would be updated without running go get")
	goBin                = flag.String("go", "", "path to the go binary to run; defaults to ./tool/go if present, else go from $PATH")
	proxyURL             = flag.String("proxy", "https://proxy.golang.org", "base URL of the Go module proxy to query")
	parallel             = flag.Int("j", 32, "maximum number of concurrent proxy requests")
	indirect             = flag.Bool("indirect", false, "also update modules marked // indirect; risky, since their importers may not build against newer versions")
	excludeNewerThanDays = flag.Int("exclude-newer-than-days", 0, "ignore versions younger than this many days and use the newest older one instead; 0 means no cooldown")
)

func main() {
	log.SetFlags(0)
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: bumpdeps [flags] [module-path-substring ...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := run(context.Background(), flag.Args()); err != nil {
		log.Fatalf("bumpdeps: %v", err)
	}
}

// update describes one module that has a newer version available.
type update struct {
	Path    string
	Current string
	Latest  string
}

// resolver looks up versions on the module proxy.
type resolver struct {
	client *http.Client
	base   string    // proxy URL without a trailing slash
	cutoff time.Time // versions committed after this are too new; zero means no cooldown
}

func run(ctx context.Context, filters []string) error {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return err
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return err
	}
	replaced := map[string]bool{}
	for _, r := range mf.Replace {
		replaced[r.Old.Path] = true
	}

	r := &resolver{
		client: &http.Client{Timeout: 30 * time.Second},
		base:   strings.TrimSuffix(*proxyURL, "/"),
	}
	if *excludeNewerThanDays > 0 {
		r.cutoff = time.Now().Add(-time.Duration(*excludeNewerThanDays) * 24 * time.Hour)
	}

	var (
		mu       sync.Mutex
		updates  []update
		failures int
		numHeld  int
		matched  int
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(*parallel)
	for _, req := range mf.Require {
		if len(filters) > 0 {
			if !matchesAny(req.Mod.Path, filters) {
				continue
			}
			matched++
		} else if req.Indirect && !*indirect {
			continue
		}
		if replaced[req.Mod.Path] {
			log.Printf("skipping %s: has a replace directive", req.Mod.Path)
			continue
		}
		g.Go(func() error {
			latest, err := r.lookupNewer(gctx, req.Mod)
			mu.Lock()
			defer mu.Unlock()
			var held *heldError
			switch {
			case errors.As(err, &held):
				numHeld++
				log.Printf("holding %s: %v", req.Mod.Path, err)
			case err != nil:
				failures++
				log.Printf("skipping %s: %v", req.Mod.Path, err)
			case latest != "":
				updates = append(updates, update{req.Mod.Path, req.Mod.Version, latest})
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	if len(filters) > 0 && matched == 0 {
		return fmt.Errorf("no modules in go.mod match %q", filters)
	}
	slices.SortFunc(updates, func(a, b update) int { return cmp.Compare(a.Path, b.Path) })

	if len(updates) == 0 {
		if numHeld > 0 {
			fmt.Printf("nothing to update; %d module(s) held by the %d-day cooldown\n", numHeld, *excludeNewerThanDays)
		} else {
			fmt.Println("all dependencies are up to date")
		}
	} else {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "MODULE\tCURRENT\tLATEST")
		for _, u := range updates {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", u.Path, u.Current, u.Latest)
		}
		tw.Flush()
	}

	if len(updates) > 0 && !*dryRun {
		args := []string{"get"}
		for _, u := range updates {
			args = append(args, u.Path+"@"+u.Latest)
		}
		cmd := exec.CommandContext(ctx, goBinary(), args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Fprintf(os.Stderr, "running: %s get ... (%d modules)\n", cmd.Path, len(updates))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("go get: %w", err)
		}
		fmt.Fprintln(os.Stderr, "done; now run \"make tidy && make updatedeps\" (or \"go mod tidy\")")
	}

	if failures > 0 {
		return fmt.Errorf("%d module lookups failed; see above", failures)
	}
	return nil
}

// matchesAny reports whether modPath contains any of the filters,
// ignoring case.
func matchesAny(modPath string, filters []string) bool {
	lower := strings.ToLower(modPath)
	for _, f := range filters {
		if strings.Contains(lower, strings.ToLower(f)) {
			return true
		}
	}
	return false
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
func (r *resolver) lookupNewer(ctx context.Context, mod module.Version) (string, error) {
	escaped, err := module.EscapePath(mod.Path)
	if err != nil {
		return "", err
	}
	base := r.base + "/" + escaped

	var info versionInfo
	if branch, ok := specialBranches[mod.Path]; ok {
		if err := fetchJSON(ctx, r.client, base+"/@v/"+branch+".info", &info); err != nil {
			return "", err
		}
	} else {
		if err := fetchJSON(ctx, r.client, base+"/@latest", &info); err != nil {
			return "", err
		}
		if semver.Compare(info.Version, mod.Version) > 0 && r.tooNew(info.Time) {
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
	if semver.Compare(info.Version, mod.Version) <= 0 {
		return "", nil
	}
	if r.tooNew(info.Time) {
		return "", &heldError{info.Version, info.Time}
	}

	// Also never move backward in time. Forks sometimes carry stray tags
	// that sort above their real development branch (github.com/tailscale/
	// golang-x-crypto has a v0.91.0 from 2024, say), and the proxy happily
	// reports those as @latest.
	curTime, err := r.versionTime(ctx, base, mod.Version)
	if err != nil {
		return "", err
	}
	if !info.Time.After(curTime) {
		return "", fmt.Errorf("%s (%s) is older than current %s (%s); probably a stray tag, so add it to specialBranches or bump by hand",
			info.Version, info.Time.Format(time.DateOnly), mod.Version, curTime.Format(time.DateOnly))
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
		if semver.IsValid(v) && semver.Prerelease(v) == "" && semver.Compare(v, cur) > 0 {
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
