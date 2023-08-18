// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package clientupdate implements tailscale client update for all supported
// platforms. This package can be used from both tailscaled and tailscale
// binaries.
package clientupdate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
	"tailscale.com/util/winutil"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

const (
	CurrentTrack  = ""
	StableTrack   = "stable"
	UnstableTrack = "unstable"
)

func versionToTrack(v string) (string, error) {
	_, rest, ok := strings.Cut(v, ".")
	if !ok {
		return "", fmt.Errorf("malformed version %q", v)
	}
	minorStr, _, ok := strings.Cut(rest, ".")
	if !ok {
		return "", fmt.Errorf("malformed version %q", v)
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return "", fmt.Errorf("malformed version %q", v)
	}
	if minor%2 == 0 {
		return "stable", nil
	}
	return "unstable", nil
}

type updater struct {
	UpdateArgs
	track  string
	update func() error
}

// UpdateArgs contains arguments needed to run an update.
type UpdateArgs struct {
	// Version can be a specific version number or one of the predefined track
	// constants:
	//
	//   - CurrentTrack will use the latest version from the same track as the
	//     running binary
	//   - StableTrack and UnstableTrack will use the latest versions of the
	//     corresponding tracks
	//
	// Leaving this empty is the same as using CurrentTrack.
	Version string
	// AppStore forces a local app store check, even if the current binary was
	// not installed via an app store.
	AppStore bool
	// Logf is a logger for update progress messages.
	Logf logger.Logf
	// Confirm is called when a new version is available and should return true
	// if this new version should be installed. When Confirm returns false, the
	// update is aborted.
	Confirm func(newVer string) bool
}

func (args UpdateArgs) validate() error {
	if args.Confirm == nil {
		return errors.New("missing Confirm callback in UpdateArgs")
	}
	if args.Logf == nil {
		return errors.New("missing Logf callback in UpdateArgs")
	}
	return nil
}

// Update runs a single update attempt using the platform-specific mechanism.
//
// On Windows, this copies the calling binary and re-executes it to apply the
// update. The calling binary should handle an "update" subcommand and call
// this function again for the re-executed binary to proceed.
func Update(args UpdateArgs) error {
	if err := args.validate(); err != nil {
		return err
	}
	up := &updater{
		UpdateArgs: args,
	}
	switch up.Version {
	case StableTrack, UnstableTrack:
		up.track = up.Version
	case CurrentTrack:
		if version.IsUnstableBuild() {
			up.track = UnstableTrack
		} else {
			up.track = StableTrack
		}
	default:
		var err error
		up.track, err = versionToTrack(args.Version)
		if err != nil {
			return err
		}
	}
	switch runtime.GOOS {
	case "windows":
		up.update = up.updateWindows
	case "linux":
		switch distro.Get() {
		case distro.Synology:
			up.update = up.updateSynology
		case distro.Debian: // includes Ubuntu
			up.update = up.updateDebLike
		case distro.Arch:
			up.update = up.updateArchLike
		case distro.Alpine:
			up.update = up.updateAlpineLike
		}
		switch {
		case haveExecutable("pacman"):
			up.update = up.updateArchLike
		case haveExecutable("apt-get"): // TODO(awly): add support for "apt"
			// The distro.Debian switch case above should catch most apt-based
			// systems, but add this fallback just in case.
			up.update = up.updateDebLike
		case haveExecutable("dnf"):
			up.update = up.updateFedoraLike("dnf")
		case haveExecutable("yum"):
			up.update = up.updateFedoraLike("yum")
		case haveExecutable("apk"):
			up.update = up.updateAlpineLike
		}
	case "darwin":
		switch {
		case !args.AppStore && !version.IsSandboxedMacOS():
			return errors.ErrUnsupported
		case !args.AppStore && strings.HasSuffix(os.Getenv("HOME"), "/io.tailscale.ipn.macsys/Data"):
			up.update = up.updateMacSys
		default:
			up.update = up.updateMacAppStore
		}
	case "freebsd":
		up.update = up.updateFreeBSD
	}
	if up.update == nil {
		return errors.ErrUnsupported
	}
	return up.update()
}

func (up *updater) confirm(ver string) bool {
	if version.Short() == ver {
		up.Logf("already running %v; no update needed", ver)
		return false
	}
	if up.Confirm != nil {
		return up.Confirm(ver)
	}
	return true
}

const synoinfoConfPath = "/etc/synoinfo.conf"

func (up *updater) updateSynology() error {
	if up.Version != "" {
		return errors.New("installing a specific version on Synology is not supported")
	}

	// Get the latest version and list of SPKs from pkgs.tailscale.com.
	osName := fmt.Sprintf("dsm%d", distro.DSMVersion())
	arch, err := synoArch(runtime.GOARCH, synoinfoConfPath)
	if err != nil {
		return err
	}
	latest, err := latestPackages(up.track)
	if err != nil {
		return err
	}
	if latest.Version == "" {
		return fmt.Errorf("no latest version found for %q track", up.track)
	}
	spkName := latest.SPKs[osName][arch]
	if spkName == "" {
		return fmt.Errorf("cannot find Synology package for os=%s arch=%s, please report a bug with your device model", osName, arch)
	}

	if !up.confirm(latest.Version) {
		return nil
	}
	if err := requireRoot(); err != nil {
		return err
	}

	// Download the SPK into a temporary directory.
	spkDir, err := os.MkdirTemp("", "tailscale-update")
	if err != nil {
		return err
	}
	url := fmt.Sprintf("https://pkgs.tailscale.com/%s/%s", up.track, spkName)
	spkPath := filepath.Join(spkDir, path.Base(url))
	// TODO(awly): we should sign SPKs and validate signatures here too.
	if err := up.downloadURLToFile(url, spkPath); err != nil {
		return err
	}

	// Install the SPK. Run via nohup to allow install to succeed when we're
	// connected over tailscale ssh and this parent process dies. Otherwise, if
	// you abort synopkg install mid-way, tailscaled is not restarted.
	cmd := exec.Command("nohup", "synopkg", "install", spkPath)
	// Don't attach cmd.Stdout to os.Stdout because nohup will redirect that
	// into nohup.out file. synopkg doesn't have any progress output anyway, it
	// just spits out a JSON result when done.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("synopkg install failed: %w\noutput:\n%s", err, out)
	}
	return nil
}

// synoArch returns the Synology CPU architecture matching one of the SPK
// architectures served from pkgs.tailscale.com.
func synoArch(goArch, synoinfoPath string) (string, error) {
	// Most Synology boxes just use a different arch name from GOARCH.
	arch := map[string]string{
		"amd64": "x86_64",
		"386":   "i686",
		"arm64": "armv8",
	}[goArch]

	if arch == "" {
		// Here's the fun part, some older ARM boxes require you to use SPKs
		// specifically for their CPU. See
		// https://github.com/SynoCommunity/spksrc/wiki/Synology-and-SynoCommunity-Package-Architectures
		// for a complete list.
		//
		// Some CPUs will map to neither this list nor the goArch map above, and we
		// don't have SPKs for them.
		cpu, err := parseSynoinfo(synoinfoPath)
		if err != nil {
			return "", fmt.Errorf("failed to get CPU architecture: %w", err)
		}
		switch cpu {
		case "88f6281", "88f6282", "hi3535", "alpine", "armada370",
			"armada375", "armada38x", "armadaxp", "comcerto2k", "monaco":
			arch = cpu
		default:
			return "", fmt.Errorf("unsupported Synology CPU architecture %q (Go arch %q), please report a bug at https://github.com/tailscale/tailscale/issues/new/choose", cpu, goArch)
		}
	}
	return arch, nil
}

func parseSynoinfo(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Look for a line like:
	// unique="synology_88f6282_413j"
	// Extract the CPU in the middle (88f6282 in the above example).
	s := bufio.NewScanner(f)
	for s.Scan() {
		l := s.Text()
		if !strings.HasPrefix(l, "unique=") {
			continue
		}
		parts := strings.SplitN(l, "_", 3)
		if len(parts) != 3 {
			return "", fmt.Errorf(`malformed %q: found %q, expected format like 'unique="synology_$cpu_$model'`, path, l)
		}
		return parts[1], nil
	}
	return "", fmt.Errorf(`missing "unique=" field in %q`, path)
}

func (up *updater) updateDebLike() error {
	ver, err := requestedTailscaleVersion(up.Version, up.track)
	if err != nil {
		return err
	}
	if !up.confirm(ver) {
		return nil
	}

	if err := requireRoot(); err != nil {
		return err
	}

	if updated, err := updateDebianAptSourcesList(up.track); err != nil {
		return err
	} else if updated {
		up.Logf("Updated %s to use the %s track", aptSourcesFile, up.track)
	}

	cmd := exec.Command("apt-get", "update",
		// Only update the tailscale repo, not the other ones, treating
		// the tailscale.list file as the main "sources.list" file.
		"-o", "Dir::Etc::SourceList=sources.list.d/tailscale.list",
		// Disable the "sources.list.d" directory:
		"-o", "Dir::Etc::SourceParts=-",
		// Don't forget about packages in the other repos just because
		// we're not updating them:
		"-o", "APT::Get::List-Cleanup=0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("apt-get", "install", "--yes", "--allow-downgrades", "tailscale="+ver)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

const aptSourcesFile = "/etc/apt/sources.list.d/tailscale.list"

// updateDebianAptSourcesList updates the /etc/apt/sources.list.d/tailscale.list
// file to make sure it has the provided track (stable or unstable) in it.
//
// If it already has the right track (including containing both stable and
// unstable), it does nothing.
func updateDebianAptSourcesList(dstTrack string) (rewrote bool, err error) {
	was, err := os.ReadFile(aptSourcesFile)
	if err != nil {
		return false, err
	}
	newContent, err := updateDebianAptSourcesListBytes(was, dstTrack)
	if err != nil {
		return false, err
	}
	if bytes.Equal(was, newContent) {
		return false, nil
	}
	return true, os.WriteFile(aptSourcesFile, newContent, 0644)
}

func updateDebianAptSourcesListBytes(was []byte, dstTrack string) (newContent []byte, err error) {
	trackURLPrefix := []byte("https://pkgs.tailscale.com/" + dstTrack + "/")
	var buf bytes.Buffer
	var changes int
	bs := bufio.NewScanner(bytes.NewReader(was))
	hadCorrect := false
	commentLine := regexp.MustCompile(`^\s*\#`)
	pkgsURL := regexp.MustCompile(`\bhttps://pkgs\.tailscale\.com/((un)?stable)/`)
	for bs.Scan() {
		line := bs.Bytes()
		if !commentLine.Match(line) {
			line = pkgsURL.ReplaceAllFunc(line, func(m []byte) []byte {
				if bytes.Equal(m, trackURLPrefix) {
					hadCorrect = true
				} else {
					changes++
				}
				return trackURLPrefix
			})
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if hadCorrect || (changes == 1 && bytes.Equal(bytes.TrimSpace(was), bytes.TrimSpace(buf.Bytes()))) {
		// Unchanged or close enough.
		return was, nil
	}
	if changes != 1 {
		// No changes, or an unexpected number of changes (what?). Bail.
		// They probably editted it by hand and we don't know what to do.
		return nil, fmt.Errorf("unexpected/unsupported %s contents", aptSourcesFile)
	}
	return buf.Bytes(), nil
}

func (up *updater) updateArchLike() (err error) {
	if up.Version != "" {
		return errors.New("installing a specific version on Arch-based distros is not supported")
	}
	if err := requireRoot(); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = fmt.Errorf(`%w; you can try updating using "pacman --sync --refresh tailscale"`, err)
		}
	}()

	out, err := exec.Command("pacman", "--sync", "--refresh", "--info", "tailscale").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed checking pacman for latest tailscale version: %w, output: %q", err, out)
	}
	ver, err := parsePacmanVersion(out)
	if err != nil {
		return err
	}
	if !up.confirm(ver) {
		return nil
	}

	cmd := exec.Command("pacman", "--sync", "--noconfirm", "tailscale")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed tailscale update using pacman: %w", err)
	}
	return nil
}

func parsePacmanVersion(out []byte) (string, error) {
	for _, line := range strings.Split(string(out), "\n") {
		// The line we're looking for looks like this:
		// Version         : 1.44.2-1
		if !strings.HasPrefix(line, "Version") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("version output from pacman is malformed: %q, cannot determine upgrade version", line)
		}
		ver := strings.TrimSpace(parts[1])
		// Trim the Arch patch version.
		ver = strings.Split(ver, "-")[0]
		if ver == "" {
			return "", fmt.Errorf("version output from pacman is malformed: %q, cannot determine upgrade version", line)
		}
		return ver, nil
	}
	return "", fmt.Errorf("could not find latest version of tailscale via pacman")
}

const yumRepoConfigFile = "/etc/yum.repos.d/tailscale.repo"

// updateFedoraLike updates tailscale on any distros in the Fedora family,
// specifically anything that uses "dnf" or "yum" package managers. The actual
// package manager is passed via packageManager.
func (up *updater) updateFedoraLike(packageManager string) func() error {
	return func() (err error) {
		if err := requireRoot(); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				err = fmt.Errorf(`%w; you can try updating using "%s upgrade tailscale"`, err, packageManager)
			}
		}()

		ver, err := requestedTailscaleVersion(up.Version, up.track)
		if err != nil {
			return err
		}
		if !up.confirm(ver) {
			return nil
		}

		if updated, err := updateYUMRepoTrack(yumRepoConfigFile, up.track); err != nil {
			return err
		} else if updated {
			up.Logf("Updated %s to use the %s track", yumRepoConfigFile, up.track)
		}

		cmd := exec.Command(packageManager, "install", "--assumeyes", fmt.Sprintf("tailscale-%s-1", ver))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		return nil
	}
}

// updateYUMRepoTrack updates the repoFile file to make sure it has the
// provided track (stable or unstable) in it.
func updateYUMRepoTrack(repoFile, dstTrack string) (rewrote bool, err error) {
	was, err := os.ReadFile(repoFile)
	if err != nil {
		return false, err
	}

	urlRe := regexp.MustCompile(`^(baseurl|gpgkey)=https://pkgs\.tailscale\.com/(un)?stable/`)
	urlReplacement := fmt.Sprintf("$1=https://pkgs.tailscale.com/%s/", dstTrack)

	s := bufio.NewScanner(bytes.NewReader(was))
	newContent := bytes.NewBuffer(make([]byte, 0, len(was)))
	for s.Scan() {
		line := s.Text()
		// Handle repo section name, like "[tailscale-stable]".
		if len(line) > 0 && line[0] == '[' {
			if !strings.HasPrefix(line, "[tailscale-") {
				return false, fmt.Errorf("%q does not look like a tailscale repo file, it contains an unexpected %q section", repoFile, line)
			}
			fmt.Fprintf(newContent, "[tailscale-%s]\n", dstTrack)
			continue
		}
		// Update the track mentioned in repo name.
		if strings.HasPrefix(line, "name=") {
			fmt.Fprintf(newContent, "name=Tailscale %s\n", dstTrack)
			continue
		}
		// Update the actual repo URLs.
		if strings.HasPrefix(line, "baseurl=") || strings.HasPrefix(line, "gpgkey=") {
			fmt.Fprintln(newContent, urlRe.ReplaceAllString(line, urlReplacement))
			continue
		}
		fmt.Fprintln(newContent, line)
	}
	if bytes.Equal(was, newContent.Bytes()) {
		return false, nil
	}
	return true, os.WriteFile(repoFile, newContent.Bytes(), 0644)
}

func (up *updater) updateAlpineLike() (err error) {
	if up.Version != "" {
		return errors.New("installing a specific version on Alpine-based distros is not supported")
	}
	if err := requireRoot(); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = fmt.Errorf(`%w; you can try updating using "apk upgrade tailscale"`, err)
		}
	}()

	out, err := exec.Command("apk", "update").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed refresh apk repository indexes: %w, output: %q", err, out)
	}
	out, err = exec.Command("apk", "info", "tailscale").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed checking apk for latest tailscale version: %w, output: %q", err, out)
	}
	ver, err := parseAlpinePackageVersion(out)
	if err != nil {
		return fmt.Errorf(`failed to parse latest version from "apk info tailscale": %w`, err)
	}
	if !up.confirm(ver) {
		return nil
	}

	cmd := exec.Command("apk", "upgrade", "tailscale")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed tailscale update using apk: %w", err)
	}
	return nil
}

func parseAlpinePackageVersion(out []byte) (string, error) {
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		// The line should look like this:
		// tailscale-1.44.2-r0 description:
		line := strings.TrimSpace(s.Text())
		if !strings.HasPrefix(line, "tailscale-") {
			continue
		}
		parts := strings.SplitN(line, "-", 3)
		if len(parts) < 3 {
			return "", fmt.Errorf("malformed info line: %q", line)
		}
		return parts[1], nil
	}
	return "", errors.New("tailscale version not found in output")
}

func (up *updater) updateMacSys() error {
	// use sparkle? do we have permissions from this context? does sudo help?
	// We can at least fail with a command they can run to update from the shell.
	// Like "tailscale update --macsys | sudo sh" or something.
	//
	// TODO(bradfitz,mihai): implement. But for now:
	return errors.ErrUnsupported
}

func (up *updater) updateMacAppStore() error {
	out, err := exec.Command("defaults", "read", "/Library/Preferences/com.apple.commerce.plist", "AutoUpdate").CombinedOutput()
	if err != nil {
		return fmt.Errorf("can't check App Store auto-update setting: %w, output: %q", err, string(out))
	}
	const on = "1\n"
	if string(out) != on {
		up.Logf("NOTE: Automatic updating for App Store apps is turned off. You can change this setting in System Settings (search for ‘update’).")
	}

	out, err = exec.Command("softwareupdate", "--list").CombinedOutput()
	if err != nil {
		return fmt.Errorf("can't check App Store for available updates: %w, output: %q", err, string(out))
	}

	newTailscale := parseSoftwareupdateList(out)
	if newTailscale == "" {
		up.Logf("no Tailscale update available")
		return nil
	}

	newTailscaleVer := strings.TrimPrefix(newTailscale, "Tailscale-")
	if !up.confirm(newTailscaleVer) {
		return nil
	}

	cmd := exec.Command("sudo", "softwareupdate", "--install", newTailscale)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("can't install App Store update for Tailscale: %w", err)
	}
	return nil
}

var macOSAppStoreListPattern = regexp.MustCompile(`(?m)^\s+\*\s+Label:\s*(Tailscale-\d[\d\.]+)`)

// parseSoftwareupdateList searches the output of `softwareupdate --list` on
// Darwin and returns the matching Tailscale package label. If there is none,
// returns the empty string.
//
// See TestParseSoftwareupdateList for example inputs.
func parseSoftwareupdateList(stdout []byte) string {
	matches := macOSAppStoreListPattern.FindSubmatch(stdout)
	if len(matches) < 2 {
		return ""
	}
	return string(matches[1])
}

// winMSIEnv is the environment variable that, if set, is the MSI file for the
// update command to install. It's passed like this so we can stop the
// tailscale.exe process from running before the msiexec process runs and tries
// to overwrite ourselves.
const winMSIEnv = "TS_UPDATE_WIN_MSI"

var (
	verifyAuthenticode func(string) error // or nil on non-Windows
	markTempFileFunc   func(string) error // or nil on non-Windows
)

func (up *updater) updateWindows() error {
	if msi := os.Getenv(winMSIEnv); msi != "" {
		up.Logf("installing %v ...", msi)
		if err := up.installMSI(msi); err != nil {
			up.Logf("MSI install failed: %v", err)
			return err
		}
		up.Logf("success.")
		return nil
	}
	ver, err := requestedTailscaleVersion(up.Version, up.track)
	if err != nil {
		return err
	}
	arch := runtime.GOARCH
	if arch == "386" {
		arch = "x86"
	}

	if !up.confirm(ver) {
		return nil
	}
	if !winutil.IsCurrentProcessElevated() {
		return errors.New("must be run as Administrator")
	}

	tsDir := filepath.Join(os.Getenv("ProgramData"), "Tailscale")
	msiDir := filepath.Join(tsDir, "MSICache")
	if fi, err := os.Stat(tsDir); err != nil {
		return fmt.Errorf("expected %s to exist, got stat error: %w", tsDir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("expected %s to be a directory; got %v", tsDir, fi.Mode())
	}
	if err := os.MkdirAll(msiDir, 0700); err != nil {
		return err
	}
	url := fmt.Sprintf("https://pkgs.tailscale.com/%s/tailscale-setup-%s-%s.msi", up.track, ver, arch)
	msiTarget := filepath.Join(msiDir, path.Base(url))
	if err := up.downloadURLToFile(url, msiTarget); err != nil {
		return err
	}

	up.Logf("verifying MSI authenticode...")
	if err := verifyAuthenticode(msiTarget); err != nil {
		return fmt.Errorf("authenticode verification of %s failed: %w", msiTarget, err)
	}
	up.Logf("authenticode verification succeeded")

	up.Logf("making tailscale.exe copy to switch to...")
	selfCopy, err := makeSelfCopy()
	if err != nil {
		return err
	}
	defer os.Remove(selfCopy)
	up.Logf("running tailscale.exe copy for final install...")

	cmd := exec.Command(selfCopy, "update")
	cmd.Env = append(os.Environ(), winMSIEnv+"="+msiTarget)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		return err
	}
	// Once it's started, exit ourselves, so the binary is free
	// to be replaced.
	os.Exit(0)
	panic("unreachable")
}

func (up *updater) installMSI(msi string) error {
	var err error
	for tries := 0; tries < 2; tries++ {
		cmd := exec.Command("msiexec.exe", "/i", filepath.Base(msi), "/quiet", "/promptrestart", "/qn")
		cmd.Dir = filepath.Dir(msi)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		err = cmd.Run()
		if err == nil {
			break
		}
		uninstallVersion := version.Short()
		if v := os.Getenv("TS_DEBUG_UNINSTALL_VERSION"); v != "" {
			uninstallVersion = v
		}
		// Assume it's a downgrade, which msiexec won't permit. Uninstall our current version first.
		up.Logf("Uninstalling current version %q for downgrade...", uninstallVersion)
		cmd = exec.Command("msiexec.exe", "/x", msiUUIDForVersion(uninstallVersion), "/norestart", "/qn")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		err = cmd.Run()
		up.Logf("msiexec uninstall: %v", err)
	}
	return err
}

func msiUUIDForVersion(ver string) string {
	arch := runtime.GOARCH
	if arch == "386" {
		arch = "x86"
	}
	track, err := versionToTrack(ver)
	if err != nil {
		track = UnstableTrack
	}
	msiURL := fmt.Sprintf("https://pkgs.tailscale.com/%s/tailscale-setup-%s-%s.msi", track, ver, arch)
	return "{" + strings.ToUpper(uuid.NewSHA1(uuid.NameSpaceURL, []byte(msiURL)).String()) + "}"
}

func makeSelfCopy() (tmpPathExe string, err error) {
	selfExe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(selfExe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	f2, err := os.CreateTemp("", "tailscale-updater-*.exe")
	if err != nil {
		return "", err
	}
	if f := markTempFileFunc; f != nil {
		if err := f(f2.Name()); err != nil {
			return "", err
		}
	}
	if _, err := io.Copy(f2, f); err != nil {
		f2.Close()
		return "", err
	}
	return f2.Name(), f2.Close()
}

func (up *updater) downloadURLToFile(urlSrc, fileDst string) (ret error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = tshttpproxy.ProxyFromEnvironment
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr}

	quickCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	headReq := must.Get(http.NewRequestWithContext(quickCtx, "HEAD", urlSrc, nil))

	res, err := c.Do(headReq)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HEAD %s: %v", urlSrc, res.Status)
	}
	if res.ContentLength <= 0 {
		return fmt.Errorf("HEAD %s: unexpected Content-Length %v", urlSrc, res.ContentLength)
	}
	up.Logf("Download size: %v", res.ContentLength)

	hashReq := must.Get(http.NewRequestWithContext(quickCtx, "GET", urlSrc+".sha256", nil))
	hashRes, err := c.Do(hashReq)
	if err != nil {
		return err
	}
	hashHex, err := io.ReadAll(io.LimitReader(hashRes.Body, 100))
	hashRes.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s.sha256: %v", urlSrc, res.Status)
	}
	if err != nil {
		return err
	}
	wantHash, err := hex.DecodeString(string(strings.TrimSpace(string(hashHex))))
	if err != nil {
		return err
	}
	hash := sha256.New()

	dlReq := must.Get(http.NewRequestWithContext(context.Background(), "GET", urlSrc, nil))
	dlRes, err := c.Do(dlReq)
	if err != nil {
		return err
	}
	// TODO(bradfitz): resume from existing partial file on disk
	if dlRes.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %v", urlSrc, dlRes.Status)
	}

	of, err := os.Create(fileDst)
	if err != nil {
		return err
	}
	defer func() {
		if ret != nil {
			of.Close()
			// TODO(bradfitz): os.Remove(fileDst) too? or keep it to resume from/debug later.
		}
	}()
	pw := &progressWriter{total: res.ContentLength, logf: up.Logf}
	n, err := io.Copy(io.MultiWriter(hash, of, pw), io.LimitReader(dlRes.Body, res.ContentLength))
	if err != nil {
		return err
	}
	if n != res.ContentLength {
		return fmt.Errorf("downloaded %v; want %v", n, res.ContentLength)
	}
	if err := of.Close(); err != nil {
		return err
	}
	pw.print()

	if !bytes.Equal(hash.Sum(nil), wantHash) {
		return fmt.Errorf("SHA-256 of downloaded MSI didn't match expected value")
	}
	up.Logf("hash matched")

	return nil
}

type progressWriter struct {
	done      int64
	total     int64
	lastPrint time.Time
	logf      logger.Logf
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	pw.done += int64(len(p))
	if time.Since(pw.lastPrint) > 2*time.Second {
		pw.print()
	}
	return len(p), nil
}

func (pw *progressWriter) print() {
	pw.lastPrint = time.Now()
	pw.logf("Downloaded %v/%v (%.1f%%)", pw.done, pw.total, float64(pw.done)/float64(pw.total)*100)
}

func (up *updater) updateFreeBSD() (err error) {
	if up.Version != "" {
		return errors.New("installing a specific version on FreeBSD is not supported")
	}
	if err := requireRoot(); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = fmt.Errorf(`%w; you can try updating using "pkg upgrade tailscale"`, err)
		}
	}()

	out, err := exec.Command("pkg", "update").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed refresh pkg repository indexes: %w, output: %q", err, out)
	}
	out, err = exec.Command("pkg", "rquery", "%v", "tailscale").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed checking pkg for latest tailscale version: %w, output: %q", err, out)
	}
	ver := string(bytes.TrimSpace(out))
	if !up.confirm(ver) {
		return nil
	}

	cmd := exec.Command("pkg", "upgrade", "tailscale")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed tailscale update using pkg: %w", err)
	}
	return nil
}

func haveExecutable(name string) bool {
	path, err := exec.LookPath(name)
	return err == nil && path != ""
}

func requestedTailscaleVersion(ver, track string) (string, error) {
	if ver != "" {
		return ver, nil
	}
	return LatestTailscaleVersion(track)
}

// LatestTailscaleVersion returns the latest released version for the given
// track from pkgs.tailscale.com.
func LatestTailscaleVersion(track string) (string, error) {
	if track == CurrentTrack {
		if version.IsUnstableBuild() {
			track = UnstableTrack
		} else {
			track = StableTrack
		}
	}

	latest, err := latestPackages(track)
	if err != nil {
		return "", err
	}
	if latest.Version == "" {
		return "", fmt.Errorf("no latest version found for %q track", track)
	}
	return latest.Version, nil
}

type trackPackages struct {
	Version  string
	Tarballs map[string]string
	Exes     []string
	MSIs     map[string]string
	MacZips  map[string]string
	SPKs     map[string]map[string]string
}

func latestPackages(track string) (*trackPackages, error) {
	url := fmt.Sprintf("https://pkgs.tailscale.com/%s/?mode=json&os=%s", track, runtime.GOOS)
	res, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching latest tailscale version: %w", err)
	}
	defer res.Body.Close()
	var latest trackPackages
	if err := json.NewDecoder(res.Body).Decode(&latest); err != nil {
		return nil, fmt.Errorf("decoding JSON: %v: %w", res.Status, err)
	}
	return &latest, nil
}

func requireRoot() error {
	if os.Geteuid() == 0 {
		return nil
	}
	switch runtime.GOOS {
	case "linux":
		return errors.New("must be root; use sudo")
	case "freebsd", "openbsd":
		return errors.New("must be root; use doas")
	default:
		return errors.New("must be root")
	}
}
