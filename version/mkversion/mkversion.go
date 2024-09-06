// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mkversion gets version info from git and provides a bunch of
// differently formatted version strings that get used elsewhere in the build
// system to embed version numbers into binaries.
package mkversion

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/mod/modfile"
)

// VersionInfo is version information extracted from a git checkout.
type VersionInfo struct {
	// Major is the major version number portion of Short.
	Major int
	// Minor is the minor version number portion of Short.
	Minor int
	// Patch is the patch version number portion of Short.
	Patch int
	// Short is the short version string. See the documentation of version.Short
	// for possible values.
	Short string
	// Long is the long version string. See the documentation for version.Long
	// for possible values.
	Long string
	// GitHash is the git hash of the tailscale.com Go module.
	GitHash string
	// OtherHash is the git hash of a supplemental git repository, if any. For
	// example, the commit of the tailscale-android repository.
	OtherHash string
	// Xcode is the version string that gets embedded into Xcode builds for the
	// Tailscale iOS app and macOS standalone (aka "macsys") app.
	//
	// It is the same as Short, but with 100 added to the major version number.
	// This is because Apple requires monotonically increasing version numbers,
	// and very early builds of Tailscale used a single incrementing integer,
	// which the Apple interprets as the major version number. When we switched
	// to the current scheme, we started the major version number at 100 (v0,
	// plus 100) to make the transition.
	Xcode string
	// XcodeMacOS is the version string that gets embedded into Xcode builds for
	// the Tailscale macOS app store app.
	//
	// This used to be the same as Xcode, but at some point Xcode reverted to
	// auto-incrementing build numbers instead of using the version we embedded.
	// As a result, we had to alter the version scheme again, and switched to
	// GitHash's commit date, in the format "YYYY.DDD.HHMMSS"
	XcodeMacOS string
	// Winres is the version string that gets embedded into Windows exe
	// metadata. It is of the form "x,y,z,0".
	Winres string
	// Synology is a map of Synology DSM version to the
	// Tailscale numeric version that gets embedded in Synology spk
	// files.
	Synology map[int]int64
	// GitDate is the unix timestamp of GitHash's commit date.
	GitDate string
	// OtherDate is the unix timestamp of OtherHash's commit date, if any.
	OtherDate string
	// Track is the release track of this build: "stable" if the minor version
	// number is even, "unstable" if it's odd.
	Track string
	// MSIProductCodes is a map of Windows CPU architecture names to UUIDv5
	// hashes that uniquely identify the version of the build. These are used in
	// the MSI installer logic to uniquely identify particular builds.
	MSIProductCodes map[string]string
}

// String returns v's information as shell variable assignments.
func (v VersionInfo) String() string {
	f := fmt.Fprintf
	var b bytes.Buffer
	f(&b, "VERSION_MAJOR=%d\n", v.Major)
	f(&b, "VERSION_MINOR=%d\n", v.Minor)
	f(&b, "VERSION_PATCH=%d\n", v.Patch)
	f(&b, "VERSION_SHORT=%q\n", v.Short)
	f(&b, "VERSION_LONG=%q\n", v.Long)
	f(&b, "VERSION_GIT_HASH=%q\n", v.GitHash)
	f(&b, "VERSION_TRACK=%q\n", v.Track)
	if v.OtherHash != "" {
		f(&b, "VERSION_EXTRA_HASH=%q\n", v.OtherHash)
		f(&b, "VERSION_XCODE=%q\n", v.Xcode)
		f(&b, "VERSION_XCODE_MACOS=%q\n", v.XcodeMacOS)
		f(&b, "VERSION_WINRES=%q\n", v.Winres)
		// Ensure a predictable order for these variables for testing purposes.
		for _, k := range []string{"amd64", "arm64", "x86"} {
			f(&b, "VERSION_MSIPRODUCT_%s=%q\n", strings.ToUpper(k), v.MSIProductCodes[k])
		}
	}

	return b.String()
}

// Info constructs a VersionInfo from the current working directory and returns
// it, or terminates the process via log.Fatal.
func Info() VersionInfo {
	v, err := InfoFrom("")
	if err != nil {
		log.Fatal(err)
	}
	return v
}

// InfoFrom constructs a VersionInfo from dir and returns it, or an error.
func InfoFrom(dir string) (VersionInfo, error) {
	runner := dirRunner(dir)

	gitRoot, err := runner.output("git", "rev-parse", "--show-toplevel")
	if err != nil {
		return VersionInfo{}, fmt.Errorf("finding git root: %w", err)
	}
	runner = dirRunner(gitRoot)

	modBs, err := os.ReadFile(filepath.Join(gitRoot, "go.mod"))
	if err != nil {
		return VersionInfo{}, fmt.Errorf("reading go.mod: %w", err)
	}
	modPath := modfile.ModulePath(modBs)

	if modPath == "" {
		return VersionInfo{}, fmt.Errorf("no module path in go.mod")
	}
	if modPath == "tailscale.com" {
		// Invoked in the tailscale.com repo directly, just no further info to
		// collect.
		v, err := infoFromDir(gitRoot)
		if err != nil {
			return VersionInfo{}, err
		}
		return mkOutput(v)
	}

	// We seem to be in a repo that imports tailscale.com. Find the
	// tailscale.com repo and collect additional info from it.
	otherHash, err := runner.output("git", "rev-parse", "HEAD")
	if err != nil {
		return VersionInfo{}, fmt.Errorf("getting git hash: %w", err)
	}
	otherDate, err := runner.output("git", "log", "-n1", "--format=%ct", "HEAD")
	if err != nil {
		return VersionInfo{}, fmt.Errorf("getting git date: %w", err)
	}

	// Note, this mechanism doesn't correctly support go.mod replacements,
	// or go workdirs. We only parse out the commit ref from go.mod's
	// "require" line, nothing else.
	tailscaleRef, err := tailscaleModuleRef(modBs)
	if err != nil {
		return VersionInfo{}, err
	}

	v, err := infoFromCache(tailscaleRef, runner)
	if err != nil {
		return VersionInfo{}, err
	}
	v.otherHash = otherHash
	v.otherDate = otherDate

	if !runner.ok("git", "diff-index", "--quiet", "HEAD") {
		v.otherHash = v.otherHash + "-dirty"
	}

	return mkOutput(v)
}

// tailscaleModuleRef returns the git ref of the 'require tailscale.com' line
// in the given go.mod bytes. The ref is either a short commit hash, or a git
// tag.
func tailscaleModuleRef(modBs []byte) (string, error) {
	mod, err := modfile.Parse("go.mod", modBs, nil)
	if err != nil {
		return "", err
	}
	for _, req := range mod.Require {
		if req.Mod.Path != "tailscale.com" {
			continue
		}
		// Get the last - separated part of req.Mod.Version
		// (which is the git hash).
		if i := strings.LastIndexByte(req.Mod.Version, '-'); i != -1 {
			return req.Mod.Version[i+1:], nil
		}
		// If there are no dashes, the version is a tag.
		return req.Mod.Version, nil
	}
	return "", fmt.Errorf("no require tailscale.com line in go.mod")
}

func mkOutput(v verInfo) (VersionInfo, error) {
	if override := os.Getenv("TS_VERSION_OVERRIDE"); override != "" {
		var err error
		v.major, v.minor, v.patch, err = parseVersion(override)
		if err != nil {
			return VersionInfo{}, fmt.Errorf("failed to parse TS_VERSION_OVERRIDE: %w", err)
		}
	}
	var changeSuffix string
	if v.minor%2 == 1 {
		// Odd minor numbers are unstable builds.
		if v.patch != 0 {
			return VersionInfo{}, fmt.Errorf("unstable release %d.%d.%d has a non-zero patch number, which is not allowed", v.major, v.minor, v.patch)
		}
		v.patch = v.changeCount
	} else if v.changeCount != 0 {
		// Even minor numbers are stable builds, but stable builds are
		// supposed to have a zero change count. Therefore, we're currently
		// describing a commit that's on a release branch, but hasn't been
		// tagged as a patch release yet.
		//
		// We used to change the version number to 0.0.0 in that case, but that
		// caused some features to get disabled due to the low version number.
		// Instead, add yet another suffix to the version number, with a change
		// count.
		changeSuffix = "-" + strconv.Itoa(v.changeCount)
	}

	var hashes string
	if v.otherHash != "" {
		hashes = "-g" + shortHash(v.otherHash)
	}
	if v.hash != "" {
		hashes = "-t" + shortHash(v.hash) + hashes
	}

	var track string
	if v.minor%2 == 1 {
		track = "unstable"
	} else {
		track = "stable"
	}

	ret := VersionInfo{
		Major:   v.major,
		Minor:   v.minor,
		Patch:   v.patch,
		Short:   fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch),
		Long:    fmt.Sprintf("%d.%d.%d%s%s", v.major, v.minor, v.patch, changeSuffix, hashes),
		GitHash: fmt.Sprintf("%s", v.hash),
		GitDate: fmt.Sprintf("%s", v.date),
		Track:   track,
		Synology: map[int]int64{
			// Synology requires that version numbers be in a specific format.
			// Builds with version numbers that don't start with "60", "70", or "72" will fail,
			// and the full version number must be within int32 range.
			// So, we do the following mapping from our Tailscale version to Synology version,
			// giving major version three decimal places, minor version three, and patch two.
			60: 60*10_000_000 + int64(v.major-1)*1_000_000 + int64(v.minor)*1_000 + int64(v.patch),
			70: 70*10_000_000 + int64(v.major-1)*1_000_000 + int64(v.minor)*1_000 + int64(v.patch),
			72: 72*10_000_000 + int64(v.major-1)*1_000_000 + int64(v.minor)*1_000 + int64(v.patch),
		},
	}

	if v.otherHash != "" {
		ret.OtherHash = fmt.Sprintf("%s", v.otherHash)

		// Technically we could populate these fields without the otherHash, but
		// these version numbers only make sense when building from Tailscale's
		// proprietary repo, so don't clutter open-source-only outputs with
		// them.
		ret.Xcode = fmt.Sprintf("%d.%d.%d", v.major+100, v.minor, v.patch)
		ret.Winres = fmt.Sprintf("%d,%d,%d,0", v.major, v.minor, v.patch)
		ret.MSIProductCodes = makeMSIProductCodes(v, track)
	}
	if v.otherDate != "" {
		ret.OtherDate = fmt.Sprintf("%s", v.otherDate)

		// Generate a monotonically increasing version number for the macOS app, as
		// expected by Apple. We use the date so that it's always increasing (if we
		// based it on the actual version number we'd run into issues when doing
		// cherrypick stable builds from a release branch after unstable builds from
		// HEAD).
		otherSec, err := strconv.ParseInt(v.otherDate, 10, 64)
		if err != nil {
			return VersionInfo{}, fmt.Errorf("Could not parse otherDate %q: %w", v.otherDate, err)
		}
		otherTime := time.Unix(otherSec, 0).UTC()
		// We started to need to do this in 2023, and the last Apple-generated
		// incrementing build number was 273. To avoid using up the space, we
		// use <year - 1750> as the major version (thus 273.*, 274.* in 2024, etc.),
		// so that we we're still in the same range. This way if Apple goes back to
		// auto-incrementing the number for us, we can go back to it with
		// reasonable-looking numbers.
		// In May 2024, a build with version number 275 was uploaded to the App Store
		// by mistake, causing any 274.* build to be rejected. To address this, +1 was
		// added, causing all builds to use the 275.* prefix.
		ret.XcodeMacOS = fmt.Sprintf("%d.%d.%d", otherTime.Year()-1750+1, otherTime.YearDay(), otherTime.Hour()*60*60+otherTime.Minute()*60+otherTime.Second())
	}

	return ret, nil
}

// makeMSIProductCodes produces per-architecture v5 UUIDs derived from the pkgs
// url that would be used for the current version, thus ensuring that product IDs
// are mapped 1:1 to a unique version number.
func makeMSIProductCodes(v verInfo, track string) map[string]string {
	urlBase := fmt.Sprintf("https://pkgs.tailscale.com/%s/tailscale-setup-%d.%d.%d-", track, v.major, v.minor, v.patch)

	result := map[string]string{}

	for _, arch := range []string{"amd64", "arm64", "x86"} {
		url := fmt.Sprintf("%s%s.msi", urlBase, arch)
		curUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(url))
		// MSI prefers hex digits in UUIDs to be uppercase.
		result[arch] = strings.ToUpper(curUUID.String())
	}

	return result
}

type verInfo struct {
	major, minor, patch int
	changeCount         int
	hash                string
	date                string

	otherHash string
	otherDate string
}

// unknownPatchVersion is the patch version used when the tailscale.com package
// doesn't contain enough version information to derive the correct version.
// Such builds only get used when generating bug reports in an ephemeral working
// environment, so will never be distributed. As such, we use a highly visible
// sentinel patch number.
const unknownPatchVersion = 9999999

func infoFromCache(ref string, runner dirRunner) (verInfo, error) {
	tailscaleCache := os.Getenv("TS_MKVERSION_OSS_GIT_CACHE")
	if tailscaleCache == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return verInfo{}, fmt.Errorf("Getting user cache dir: %w", err)
		}
		tailscaleCache = filepath.Join(cacheDir, "tailscale-oss")
	}
	r := dirRunner(tailscaleCache)

	if _, err := os.Stat(tailscaleCache); err != nil {
		if !runner.ok("git", "clone", "https://github.com/tailscale/tailscale", tailscaleCache) {
			return verInfo{}, fmt.Errorf("cloning tailscale.com repo failed")
		}
	}

	if !r.ok("git", "cat-file", "-e", ref) {
		if !r.ok("git", "fetch", "origin") {
			return verInfo{}, fmt.Errorf("updating OSS repo failed")
		}
	}
	hash, err := r.output("git", "rev-parse", ref)
	if err != nil {
		return verInfo{}, err
	}
	date, err := r.output("git", "log", "-n1", "--format=%ct", ref)
	if err != nil {
		return verInfo{}, err
	}
	baseHash, err := r.output("git", "rev-list", "--max-count=1", hash, "--", "VERSION.txt")
	if err != nil {
		return verInfo{}, err
	}
	s, err := r.output("git", "show", baseHash+":VERSION.txt")
	if err != nil {
		return verInfo{}, err
	}
	major, minor, patch, err := parseVersion(s)
	if err != nil {
		return verInfo{}, err
	}
	s, err = r.output("git", "rev-list", "--count", hash, "^"+baseHash)
	if err != nil {
		return verInfo{}, err
	}
	changeCount, err := strconv.Atoi(s)
	if err != nil {
		return verInfo{}, fmt.Errorf("infoFromCache: parsing changeCount %q: %w", changeCount, err)
	}

	return verInfo{
		major:       major,
		minor:       minor,
		patch:       patch,
		changeCount: changeCount,
		hash:        hash,
		date:        date,
	}, nil
}

func infoFromDir(dir string) (verInfo, error) {
	r := dirRunner(dir)
	gitDir := filepath.Join(dir, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		// Raw directory fetch, get as much info as we can and make up the rest.
		bs, err := os.ReadFile(filepath.Join(dir, "VERSION.txt"))
		if err != nil {
			return verInfo{}, err
		}
		major, minor, patch, err := parseVersion(strings.TrimSpace(string(bs)))
		return verInfo{
			major:       major,
			minor:       minor,
			patch:       patch,
			changeCount: unknownPatchVersion,
		}, err
	}

	hash, err := r.output("git", "rev-parse", "HEAD")
	if err != nil {
		return verInfo{}, err
	}
	date, err := r.output("git", "log", "-n1", "--format=%%ct", "HEAD")
	if err != nil {
		return verInfo{}, err
	}
	baseHash, err := r.output("git", "rev-list", "--max-count=1", hash, "--", "VERSION.txt")
	if err != nil {
		return verInfo{}, err
	}
	s, err := r.output("git", "show", baseHash+":VERSION.txt")
	if err != nil {
		return verInfo{}, err
	}
	major, minor, patch, err := parseVersion(s)
	if err != nil {
		return verInfo{}, err
	}
	s, err = r.output("git", "rev-list", "--count", hash, "^"+baseHash)
	if err != nil {
		return verInfo{}, err
	}
	changeCount, err := strconv.Atoi(s)
	if err != nil {
		return verInfo{}, err
	}

	return verInfo{
		major:       major,
		minor:       minor,
		patch:       patch,
		changeCount: changeCount,
		hash:        hash,
		date:        date,
	}, nil
}

func parseVersion(s string) (major, minor, patch int, err error) {
	fs := strings.Split(strings.TrimSpace(s), ".")
	if len(fs) != 3 {
		err = fmt.Errorf("parseVersion: parsing %q: wrong number of parts: %d", s, len(fs))
		return
	}
	ints := make([]int, 0, 3)
	for _, s := range fs {
		var i int
		i, err = strconv.Atoi(s)
		if err != nil {
			err = fmt.Errorf("parseVersion: parsing %q: %w", s, err)
			return
		}
		ints = append(ints, i)
	}
	return ints[0], ints[1], ints[2], nil
}

func shortHash(hash string) string {
	if len(hash) < 9 {
		return hash
	}
	return hash[:9]
}

// dirRunner executes commands in the specified dir.
type dirRunner string

func (r dirRunner) output(prog string, args ...string) (string, error) {
	cmd := exec.Command(prog, args...)
	// Sometimes, our binaries end up running in a world where
	// GO111MODULE=off, because x/tools/go/packages disables Go
	// modules on occasion and then runs other Go code. This breaks
	// executing "go mod edit", which requires that Go modules be
	// enabled.
	//
	// Since nothing we do here ever wants Go modules to be turned
	// off, force it on here so that we can read module data
	// regardless of the environment.
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	cmd.Dir = string(r)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("running %v: %w, out=%s, err=%s", cmd.Args, err, out, ee.Stderr)
		}
		return "", fmt.Errorf("running %v: %w, %s", cmd.Args, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func (r dirRunner) ok(prog string, args ...string) bool {
	cmd := exec.Command(prog, args...)
	cmd.Dir = string(r)
	return cmd.Run() == nil
}
