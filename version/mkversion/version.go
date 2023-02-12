// The version package gets version info from git and provides a bunch
// of differently formatted version strings get used elsewhere in the
// build system to embed version numbers into binaries.
package version

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"tailscale.com/tailcfg"
)

// VersionInfo is all the version and related metadata we embed into binaries at
// build time.
type VersionInfo struct {
	// Short is the short version string, like "1.2.3". It is what
	// version.Short() returns.
	Short string
	// Long is the long version string, like "1.2.3-0-gabcdef123456". It is what
	// version.Long() returns.
	Long string
	// GitCommit is the git commit hash of the tailscale/tailscale repository.
	GitCommit string
	// OtherCommit is the git commit hash of another repository used in the
	// build. The exact other repository depends on what is being built, but
	// could be for example tailscale/tailscale-android.
	OtherCommit string
	// Xcode is like Short, but with a much larger major version number.
	//
	// This exists because Xcode enforces monotonically increasing app versions,
	// and early Tailscale app releases used a single incrementing number. When
	// we transitioned to major.minor.patch format, we were forced to use a much
	// higher major number to keep the versions sequential.
	//
	// This version number is used for the app metadata of the iOS and macsys
	// (aka "standalone version" on pkgs.tailscale.com) apps.
	Xcode string // For embedding into Xcode metadata (iOS and macsys)
	// XcodeMacOS is like Xcode, but for the macOS app store app.
	//
	// For unclear reasons, at some point around Tailscale 1.15, our macOS app
	// build stopped embedding Info.Xcode as the app version, and reverted to
	// apple-managed sequentially increasing ints. Then, around 1.36, it stopped
	// auto-incrementing those numbers, and we needed to do our own embedding
	// again, at a version higher than the highest apple-generated number (273).
	//
	// So, we switched to embedding a version based on the timestamp of the
	// commit being built. This version, like Info.Xcode, is never shown to
	// users outside of TestFlight, so it should hopefully not be confusing to
	// anyone but Tailscale devs.
	XcodeMacOS string
	// Winres is like Short, but formatted for use in Windows resource files
	// (.rc). This is what populates the "Product Version" field when you
	// right-click->Properties on a Tailscale executable.
	Winres string // For embedding into Windows metadata
	// Track is the release track of the build: "stable" for even minor
	// versions, and "unstable" for odd minor versions.
	Track string
	// MSIProductCodes is a map of Windows CPU architecture names to a v5 UUID
	// for the corresponding build. The UUIDs are unique and deterministic for a
	// unique major.minor.patch and CPU architecture.
	//
	// As the name suggests, these UUIDs get embedded into Tailscale's Windows
	// MSI files. See
	// https://learn.microsoft.com/en-us/windows/win32/msi/product-codes for
	// more information.
	MSIProductCodes map[string]string
	// Copyright is a Tailscale copyright string, stamped with the year in which
	// Info was generated. It gets embedded into Apple app metadata.
	Copyright string
	// CapabilityVersion is the capability version of the control protocol. See
	// tailscale.com/tailcfg.CurrentCapabilityVersion for more information.
	//
	// The version is mirrored from tailcfg into this struct so that it can be
	// exposed to non-Go languages that some of our builds interface with (e.g.
	// Swift for Apple builds).
	CapabilityVersion int
}

// String returns v as a series of shell variable assignments
// ("VERSION_SHORT=...").
func (v VersionInfo) String() string {
	return v.export("")
}

// Export returns v as a series of shell variable exports ("export
// VERSION_SHORT=...").
func (v VersionInfo) Export() string {
	return v.export("export ")
}

func (v VersionInfo) export(prefix string) string {
	var b bytes.Buffer
	f := func(format string, args ...any) {
		fmt.Fprintf(&b, prefix+format, args...)
	}
	f("VERSION_SHORT=%q\n", v.Short)
	f("VERSION_LONG=%q\n", v.Long)
	f("VERSION_GIT_HASH=%q\n", v.GitCommit)
	f("VERSION_EXTRA_HASH=%q\n", v.OtherCommit)
	f("VERSION_XCODE=%q\n", v.Xcode)
	f("VERSION_XCODE_MACOS=%q\n", v.XcodeMacOS)
	f("VERSION_WINRES=%q\n", v.Winres)
	f("VERSION_TRACK=%q\n", v.Track)

	// Ensure a predictable order for these variables for testing purposes.
	keys := make([]string, 0, len(v.MSIProductCodes))
	for k := range v.MSIProductCodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f("VERSION_MSIPRODUCT_%s=%q\n", strings.ToUpper(k), v.MSIProductCodes[k])
	}

	fmt.Fprintf(&b, "VERSION_COPYRIGHT=%q\n", v.Copyright)
	fmt.Fprintf(&b, "VERSION_CAPABILITY=%d\n", v.CapabilityVersion)

	return b.String()
}

// Info returns a VersionInfo from dir. dir must be within a git checkout,
// either of the tailscale.com Go module or a Go module that imports the
// tailscale.com module.
func Info(dir string) (VersionInfo, error) {
	runner := dirRunner(dir)

	repoRoot, err := runner.output("git", "rev-parse", "--show-toplevel")
	if err != nil {
		return VersionInfo{}, fmt.Errorf("couldn't find git repo root: %w", err)
	}
	runner = dirRunner(repoRoot)

	goTool := filepath.Join(repoRoot, "tool/go")
	if _, err := os.Stat(goTool); errors.Is(err, os.ErrNotExist) {
		// Fall back to $PATH lookup and hope that Go version is recent enough
		// to handle our go.mod.
		goTool = "go"
	} else if err != nil {
		return VersionInfo{}, fmt.Errorf("looking for %s: %w", goTool, err)
	}

	// Find the tailscale.com module, which may or may not be repoRoot.
	tailscaleDir, tailscaleCommit, err := locateTailscaleModule(runner, goTool)
	if err != nil {
		return VersionInfo{}, err
	}

	trunner := dirRunner(tailscaleDir)
	baseCommit, err := trunner.output("git", "rev-list", "--max-count=1", tailscaleCommit, "--", "VERSION.txt")
	if err != nil {
		return VersionInfo{}, fmt.Errorf("getting tailscale.com release base commit: %w", err)
	}
	baseVersion, err := trunner.output("git", "show", baseCommit+":VERSION.txt")
	if err != nil {
		return VersionInfo{}, fmt.Errorf("getting tailscale.com release base version: %w", err)
	}
	major, minor, patch, err := parseVersion(baseVersion)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("parsing tailscale.com release base version: %w", err)
	}
	s, err := trunner.output("git", "rev-list", "--count", tailscaleCommit, "^"+baseCommit)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("getting tailscale.com release change count: %w", err)
	}
	changeCount, err := strconv.Atoi(s)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("parsing tailscale.com release change count: %w", err)
	}

	v := verInfo{
		major:       major,
		minor:       minor,
		patch:       patch,
		changeCount: changeCount,
		commit:      tailscaleCommit,
	}

	if !trunner.ok("git", "diff-index", "--quiet", "HEAD") {
		v.dirty = true
	}

	var ts string
	if tailscaleDir != repoRoot {
		// Building from a different repo that imports tailscale.com, grab its
		// info as well.
		v.otherCommit, err = runner.output("git", "rev-parse", "HEAD")
		if err != nil {
			return VersionInfo{}, err
		}
		if !runner.ok("git", "diff-index", "--quiet", "HEAD") {
			v.dirty = true
		}
		ts, err = runner.output("git", "log", "-n1", "--format=%ct", v.otherCommit)
		if err != nil {
			return VersionInfo{}, fmt.Errorf("getting commit timestamp of %q: %w", v.otherCommit, err)
		}
	} else {
		ts, err = trunner.output("git", "log", "-n1", "--format=%ct", v.commit)
		if err != nil {
			return VersionInfo{}, fmt.Errorf("getting commit timestamp of %q: %w", v.commit, err)
		}
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("parsing commit timestamp %q: %w", ts, err)
	}
	v.timestamp = time.Unix(tsInt, 0).UTC()

	return mkOutput(v)
}

func mkOutput(v verInfo) (VersionInfo, error) {
	var (
		changeSuffix string
		track        string
	)
	if v.minor%2 == 1 {
		// Odd minor numbers are unstable builds.
		if v.patch != 0 {
			return VersionInfo{}, fmt.Errorf("unstable release %d.%d.%d has a non-zero patch number, which is not allowed", v.major, v.minor, v.patch)
		}
		track = "unstable"
		v.patch, v.changeCount = v.changeCount, 0
	} else {
		track = "stable"
		if v.changeCount != 0 {
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
	}

	var hashes string
	if v.otherCommit != "" {
		hashes = "-g" + shortHash(v.otherCommit)
	}
	if v.commit != "" {
		hashes = "-t" + shortHash(v.commit) + hashes
	}

	// Generate a monotonically increasing version number for the macOS app, as
	// expected by Apple. We use the date so that it's always increasing (if we
	// based it on the actual version number we'd run into issues when doing
	// cherrypick stable builds from a release branch after unstable builds from
	// HEAD).
	//
	// We started to need to do this in 2023, and the last Apple-generated
	// incrementing build number was 273. To avoid using up the space, we
	// use <year - 1750> as the major version (thus 273.*, 274.* in 2024, etc.),
	// so that we we're still in the same range. This way if Apple goes back to
	// auto-incrementing the number for us, we can go back to it with
	// reasonable-looking numbers.
	xcodeMacOS := fmt.Sprintf("%d.%d.%d", v.timestamp.Year()-1750, v.timestamp.YearDay(), v.timestamp.Hour()*60*60+v.timestamp.Minute()*60+v.timestamp.Second())

	return VersionInfo{
		Short:             fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch),
		Long:              fmt.Sprintf("%d.%d.%d%s%s", v.major, v.minor, v.patch, changeSuffix, hashes),
		GitCommit:         v.commit,
		OtherCommit:       v.otherCommit,
		Xcode:             fmt.Sprintf("%d.%d.%d", v.major+100, v.minor, v.patch),
		XcodeMacOS:        xcodeMacOS,
		Winres:            fmt.Sprintf("%d,%d,%d,0", v.major, v.minor, v.patch),
		Track:             track,
		MSIProductCodes:   makeMSIProductCodes(v, track),
		Copyright:         fmt.Sprintf("Copyright © %d Tailscale Inc. All Rights Reserved.", time.Now().Year()),
		CapabilityVersion: int(tailcfg.CurrentCapabilityVersion),
	}, nil
}

// makeMSIProductCodes produces per-architecture v5 UUIDs derived from the pkgs
// url that would be used for the current version, thus ensuring that product IDs
// are mapped 1:1 to a unique version number.
func makeMSIProductCodes(v verInfo, track string) map[string]string {
	urlBase := fmt.Sprintf("https://pkgs.tailscale.com/%s/tailscale-setup-%d.%d.%d-", track, v.major, v.minor, v.patch)

	ret := map[string]string{}

	for _, arch := range []string{"amd64", "arm64", "x86"} {
		url := fmt.Sprintf("%s%s.msi", urlBase, arch)
		curUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(url))
		// MSI prefers hex digits in UUIDs to be uppercase.
		ret[arch] = strings.ToUpper(curUUID.String())
	}

	return ret
}

// locateTailscaleModule returns the directory of a git checkout of the
// tailscale.com Go module, and the commit hash from which to build from.
//
// If necessary, locateTailscaleModule fetches a git clone of the tailscale.com
// repository into a cache dir.
func locateTailscaleModule(runner dirRunner, goTool string) (dir, commit string, err error) {
	modDir, err := runner.output(goTool, "list", "-m", "-f", "{{.Dir}}", "tailscale.com")
	if err != nil {
		return "", "", fmt.Errorf("getting tailscale.com module dir: %w", err)
	}
	if modDir != "" {
		ok, err := exists(filepath.Join(modDir, ".git"))
		if err != nil {
			return "", "", fmt.Errorf("checking for .git in %q: %w", modDir, err)
		}
		if ok {
			commit, err := dirRunner(modDir).output("git", "rev-parse", "HEAD")
			if err != nil {
				return "", "", fmt.Errorf("getting git commit in %q: %w", modDir, err)
			}
			return modDir, commit, nil
		}
		// Otherwise, fall through, we have to fetch a git clone.
	}
	commit, err = runner.output(goTool, "list", "-m", "-f", "{{.Version}}", "tailscale.com")
	if err != nil {
		return "", "", fmt.Errorf("getting tailscale.com module version: %w", err)
	}
	// Last dash-separated portion of version is a commit hash.
	commit = commit[strings.LastIndex(commit, "-")+1:]

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", "", fmt.Errorf("finding user cache dir: %w", err)
	}
	tailscaleCache := filepath.Join(cacheDir, "tailscale-oss")
	ok, err := exists(tailscaleCache)
	if err != nil {
		return "", "", fmt.Errorf("checking for tailscale cache dir: %w", err)
	}
	if !ok {
		if !runner.ok("git", "clone", "https://github.com/tailscale/tailscale", tailscaleCache) {
			return "", "", fmt.Errorf("cloning tailscale repo failed")
		}
	}
	r := dirRunner(tailscaleCache)
	if !r.ok("git", "cat-file", "-e", commit) {
		if !r.ok("git", "fetch", "origin") {
			return "", "", fmt.Errorf("updating cached tailscale repo failed")
		}
		if !r.ok("git", "cat-file", "-e", commit) {
			return "", "", fmt.Errorf("commit %q not found in tailscale repo after fetch", commit)
		}
	}
	// Expand the commit to its full form.
	commit, err = r.output("git", "rev-parse", commit)
	if err != nil {
		return "", "", fmt.Errorf("expanding commit %q: %w", commit, err)
	}
	return tailscaleCache, commit, nil
}

type verInfo struct {
	major, minor, patch int
	changeCount         int
	commit              string
	otherCommit         string
	dirty               bool      // either commit or otherCommit is in a dirty repo
	timestamp           time.Time // of otherCommit if present, otherwise of commit
}

func parseVersion(s string) (major, minor, patch int, err error) {
	fs := strings.Split(s, ".")
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
	// Sometimes, our binaries end up running in a world where GO111MODULE=off,
	// because x/tools/go/packages disables Go modules on occasion and then runs
	// other Go code. This breaks executing "go mod edit", which requires that
	// Go modules be enabled.
	//
	// Since nothing we do here ever wants Go modules to be turned off, force it
	// on here so that we can read module data regardless of the environment.
	//
	// Similarly, our internal build system (gocross) uses this code to generate
	// version numbers for embedding, so we have to bypass it here in order to
	// avoid an infinite recursion.
	cmd.Env = append(os.Environ(), "GO111MODULE=on", "GOCROSS_BYPASS=1")
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

func exists(path string) (ok bool, err error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}
