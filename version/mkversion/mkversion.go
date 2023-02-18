// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mkversion gets version info from git and provides a bunch of
// differently formatted version strings that get used elsewhere in the build
// system to embed version numbers into binaries.
package mkversion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type VersionInfo struct {
	Short           string
	Long            string
	OSSHash         string
	CorpHash        string
	Xcode           string // For embedding into Xcode metadata (iOS and macsys)
	XcodeMacOS      string // For embedding into Xcode metadata (macOS)
	Winres          string // For embedding into Windows metadata
	OSSDate         string // Unix timestamp of commit date (git: %ct)
	CorpDate        string // Unix timestamp of commit date (git: %ct)
	Track           string
	MSIProductCodes map[string]string
}

func (v VersionInfo) String() string {
	f := fmt.Fprintf
	var b bytes.Buffer
	f(&b, "VERSION_SHORT=%q\n", v.Short)
	f(&b, "VERSION_LONG=%q\n", v.Long)
	f(&b, "VERSION_GIT_HASH=%q\n", v.OSSHash)
	f(&b, "VERSION_EXTRA_HASH=%q\n", v.CorpHash)
	f(&b, "VERSION_XCODE=%q\n", v.Xcode)
	f(&b, "VERSION_XCODE_MACOS=%q\n", v.XcodeMacOS)
	f(&b, "VERSION_WINRES=%q\n", v.Winres)
	f(&b, "VERSION_TRACK=%q\n", v.Track)

	// Ensure a predictable order for these variables for testing purposes.
	for _, k := range []string{"amd64", "arm64", "x86"} {
		f(&b, "VERSION_MSIPRODUCT_%s=%q\n", strings.ToUpper(k), v.MSIProductCodes[k])
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

	var v verInfo
	var err error
	v.corpHash, err = runner.output("git", "rev-parse", "HEAD")
	if err != nil {
		return VersionInfo{}, err
	}
	v.corpDate, err = runner.output("git", "log", "-n1", "--format=%ct", "HEAD")
	if err != nil {
		return VersionInfo{}, err
	}
	if !runner.ok("git", "diff-index", "--quiet", "HEAD") {
		v.corpHash = v.corpHash + "-dirty"
	}

	ossHash, ossDir, err := parseGoMod(runner)
	if err != nil {
		return VersionInfo{}, err
	}
	if ossHash != "" {
		v.ossInfo, err = infoFromCache(ossHash, runner)
	} else {
		v.ossInfo, err = infoFromDir(ossDir)
	}
	if err != nil {
		return VersionInfo{}, err
	}

	return mkOutput(v)

}

func mkOutput(v verInfo) (VersionInfo, error) {
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
	if v.corpHash != "" {
		hashes = "-g" + shortHash(v.corpHash)
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

	// Generate a monotonically increasing version number for the macOS app, as
	// expected by Apple. We use the date so that it's always increasing (if we
	// based it on the actual version number we'd run into issues when doing
	// cherrypick stable builds from a release branch after unstable builds from
	// HEAD).
	corpSec, err := strconv.ParseInt(v.corpDate, 10, 64)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("Culd not parse corpDate %q: %w", v.corpDate, err)
	}
	corpTime := time.Unix(corpSec, 0).UTC()
	// We started to need to do this in 2023, and the last Apple-generated
	// incrementing build number was 273. To avoid using up the space, we
	// use <year - 1750> as the major version (thus 273.*, 274.* in 2024, etc.),
	// so that we we're still in the same range. This way if Apple goes back to
	// auto-incrementing the number for us, we can go back to it with
	// reasonable-looking numbers.
	xcodeMacOS := fmt.Sprintf("%d.%d.%d", corpTime.Year()-1750, corpTime.YearDay(), corpTime.Hour()*60*60+corpTime.Minute()*60+corpTime.Second())

	return VersionInfo{
		Short:           fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch),
		Long:            fmt.Sprintf("%d.%d.%d%s%s", v.major, v.minor, v.patch, changeSuffix, hashes),
		OSSHash:         fmt.Sprintf("%s", v.hash),
		OSSDate:         fmt.Sprintf("%s", v.ossInfo.date),
		CorpHash:        fmt.Sprintf("%s", v.corpHash),
		CorpDate:        fmt.Sprintf("%s", v.corpDate),
		Xcode:           fmt.Sprintf("%d.%d.%d", v.major+100, v.minor, v.patch),
		XcodeMacOS:      xcodeMacOS,
		Winres:          fmt.Sprintf("%d,%d,%d,0", v.major, v.minor, v.patch),
		Track:           track,
		MSIProductCodes: makeMSIProductCodes(v, track),
	}, nil
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

func gitRootDir() (string, error) {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("failed to find git top level (not in corp git?): %w", err)
	}
	return strings.TrimSpace(string(top)), nil
}

func parseGoMod(runner dirRunner) (ossShortHash, localCheckout string, err error) {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go"+exe())
	if !strings.HasPrefix(goBin, "/") {
		// GOROOT got -trimpath'd, fall back to hoping $PATH has a
		// working go.
		goBin = "go"
	}
	mod, err := runner.output(goBin, "mod", "edit", "--json")
	if err != nil {
		return "", "", err
	}
	var mj modJSON
	if err := json.Unmarshal([]byte(mod), &mj); err != nil {
		return "", "", fmt.Errorf("parsing go.mod: %w", err)
	}

	for _, r := range mj.Replace {
		if r.Old.Path != "tailscale.com" {
			continue
		}
		if filepath.IsAbs(r.New.Path) {
			return "", r.New.Path, nil
		}
		gitRoot, err := gitRootDir()
		if err != nil {
			return "", "", err
		}
		return "", filepath.Join(gitRoot, r.New.Path), nil
	}
	for _, r := range mj.Require {
		if r.Path != "tailscale.com" {
			continue
		}
		shortHash := r.Version[strings.LastIndex(r.Version, "-")+1:]
		return shortHash, "", nil
	}
	return "", "", fmt.Errorf("failed to find tailscale.com module in go.mod")
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

type verInfo struct {
	ossInfo
	corpHash string
	corpDate string
}

// unknownPatchVersion is the patch version used when the oss package
// doesn't contain enough version information to derive the correct
// version. Such builds only get used when generating bug reports in
// an ephemeral working environment, so will never be distributed. As
// such, we use a highly visible sentinel patch number.
const unknownPatchVersion = 9999999

type ossInfo struct {
	major, minor, patch int
	changeCount         int
	hash                string
	date                string
}

func isBareRepo(r dirRunner) (bool, error) {
	s, err := r.output("git", "rev-parse", "--is-bare-repository")
	if err != nil {
		return false, err
	}
	o := strings.TrimSpace(s)
	return o == "true", nil
}

func infoFromCache(shortHash string, runner dirRunner) (ossInfo, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return ossInfo{}, fmt.Errorf("Getting user cache dir: %w", err)
	}
	ossCache := filepath.Join(cacheDir, "tailscale-oss")
	r := dirRunner(ossCache)

	cloneRequired := false
	if _, err := os.Stat(ossCache); err != nil {
		cloneRequired = true
	} else {
		isBare, err := isBareRepo(r)
		if err != nil {
			return ossInfo{}, err
		}
		if isBare {
			cloneRequired = true
			if err := os.RemoveAll(ossCache); err != nil {
				return ossInfo{}, fmt.Errorf("removing old cache dir failed: %w", err)
			}
		}
	}

	if cloneRequired {
		if !runner.ok("git", "clone", "https://github.com/tailscale/tailscale", ossCache) {
			return ossInfo{}, fmt.Errorf("cloning OSS repo failed")
		}
	}

	if !r.ok("git", "cat-file", "-e", shortHash) {
		if !r.ok("git", "fetch", "origin") {
			return ossInfo{}, fmt.Errorf("updating OSS repo failed")
		}
	}
	hash, err := r.output("git", "rev-parse", shortHash)
	if err != nil {
		return ossInfo{}, err
	}
	date, err := r.output("git", "log", "-n1", "--format=%ct", shortHash)
	if err != nil {
		return ossInfo{}, err
	}
	baseHash, err := r.output("git", "rev-list", "--max-count=1", hash, "--", "VERSION.txt")
	if err != nil {
		return ossInfo{}, err
	}
	s, err := r.output("git", "show", baseHash+":VERSION.txt")
	if err != nil {
		return ossInfo{}, err
	}
	major, minor, patch, err := parseVersion(s)
	if err != nil {
		return ossInfo{}, err
	}
	s, err = r.output("git", "rev-list", "--count", hash, "^"+baseHash)
	if err != nil {
		return ossInfo{}, err
	}
	changeCount, err := strconv.Atoi(s)
	if err != nil {
		return ossInfo{}, fmt.Errorf("infoFromCache: parsing changeCount %q: %w", changeCount, err)
	}

	return ossInfo{
		major:       major,
		minor:       minor,
		patch:       patch,
		changeCount: changeCount,
		hash:        hash,
		date:        date,
	}, nil
}

func infoFromDir(dir string) (ossInfo, error) {
	r := dirRunner(dir)
	gitDir := filepath.Join(dir, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		// Raw directory fetch, get as much info as we can and make up the rest.
		s, err := readFile(filepath.Join(dir, "VERSION.txt"))
		if err != nil {
			return ossInfo{}, err
		}
		major, minor, patch, err := parseVersion(s)
		return ossInfo{
			major:       major,
			minor:       minor,
			patch:       patch,
			changeCount: unknownPatchVersion,
		}, err
	}

	hash, err := r.output("git", "rev-parse", "HEAD")
	if err != nil {
		return ossInfo{}, err
	}
	date, err := r.output("git", "log", "-n1", "--format=%%ct", "HEAD")
	if err != nil {
		return ossInfo{}, err
	}
	baseHash, err := r.output("git", "rev-list", "--max-count=1", hash, "--", "VERSION.txt")
	if err != nil {
		return ossInfo{}, err
	}
	s, err := r.output("git", "show", baseHash+":VERSION.txt")
	if err != nil {
		return ossInfo{}, err
	}
	major, minor, patch, err := parseVersion(s)
	if err != nil {
		return ossInfo{}, err
	}
	s, err = r.output("git", "rev-list", "--count", hash, "^"+baseHash)
	if err != nil {
		return ossInfo{}, err
	}
	changeCount, err := strconv.Atoi(s)
	if err != nil {
		return ossInfo{}, err
	}

	return ossInfo{
		major:       major,
		minor:       minor,
		patch:       patch,
		changeCount: changeCount,
		hash:        hash,
		date:        date,
	}, nil
}

type modJSON struct {
	Require []goPath
	Replace []modReplace
}

type modReplace struct {
	Old, New goPath
}

type goPath struct {
	Path    string
	Version string
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

func readFile(path string) (string, error) {
	bs, err := ioutil.ReadFile(path)
	return strings.TrimSpace(string(bs)), err
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
